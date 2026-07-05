"""Pipeline orchestrator — fetch -> parse -> validate -> aggregate -> publish.

``PipelineRunner`` ties together every stage of the VPN config pipeline:

1. **Fetch**   — ``SourceManager.fetch_all()`` pulls files from configured sources.
2. **Parse**   — ``_parse_all()`` extracts proxy links and turns them into
                 ``Config`` objects via ``ALL_PARSERS`` (with subscription-blob
                 support via ``SubscriptionParser``).
3. **Validate**— TCP connect (L1) -> TLS handshake (L2) -> GeoIP enrichment (L3).
4. **Aggregate**— dedup -> sort -> per-country limit -> global cap.
5. **Write**   — ``write_subscription()`` emits the output file.
6. **Publish** — (optional) commit the output to a GitHub repo.

Each stage is wrapped so a failure is logged and, where possible, the pipeline
continues with whatever data survived the previous stage.
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Any

import yaml

from src.parsers import ALL_PARSERS
from src.parsers.base import Config, find_all_links, is_garbage_config
from src.parsers.subscription import SubscriptionParser

logger = logging.getLogger(__name__)


class PipelineRunner:
    """Orchestrates the full pipeline: fetch -> parse -> validate -> aggregate -> publish."""

    def __init__(
        self,
        settings_path: str = "config/settings.yaml",
        sources_path: str = "config/sources.json",
        github_token: str | None = None,
    ) -> None:
        self.settings_path = settings_path
        self.sources_path = sources_path
        self.github_token = github_token or os.environ.get("GITHUB_TOKEN")
        self.settings: dict[str, Any] = self._load_settings(settings_path)

    # --- settings ---

    @staticmethod
    def _load_settings(path: str) -> dict[str, Any]:
        """Load settings from a YAML file, returning an empty dict on failure."""
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
        except FileNotFoundError:
            logger.error("Settings file not found: %s — using defaults.", path)
            return {}
        except yaml.YAMLError as exc:
            logger.error("Failed to parse settings %s: %s — using defaults.", path, exc)
            return {}
        return data or {}

    def _section(self, key: str) -> dict[str, Any]:
        """Return a settings section (empty dict if missing)."""
        section = self.settings.get(key, {})
        return section if isinstance(section, dict) else {}

    # --- main entry point ---

    async def run(
        self,
        output_file: str = "output/subscription.txt",
        publish: bool = False,
    ) -> int:
        """Run the full pipeline. Returns the number of configs written to output.

        Args:
            output_file: Path to the output subscription file.
            publish: If True, commit the output to a GitHub repo (requires
                ``GITHUB_TOKEN`` and repo config).
        """
        start = time.monotonic()
        logger.info("Pipeline started.")

        # 1. Fetch all sources.
        results = await self._fetch_sources()
        if not results:
            logger.warning("No source results fetched — pipeline produced nothing.")
            self._write_empty_output(output_file)
            return 0

        # 2. Parse all content into Config objects.
        configs = await self._parse_all(results)
        logger.info("Parsed %d configs total.", len(configs))
        if not configs:
            logger.warning(
                "No configs parsed from sources — pipeline produced nothing."
            )
            self._write_empty_output(output_file)
            return 0

        # 2b. Filter out garbage/placeholder configs (UUID, SERVER_IP, etc).
        configs, garbage_count = self._filter_garbage(configs)
        if garbage_count:
            logger.info("Filtered %d garbage/placeholder configs.", garbage_count)
        if not configs:
            logger.warning("All configs were garbage — pipeline produced nothing.")
            self._write_empty_output(output_file)
            return 0

        # 2c. Sample if too many configs (620K is not feasible to process).
        vcfg = self._section("validator")
        max_to_process = int(vcfg.get("max_configs_to_validate", 20000))
        if max_to_process > 0 and len(configs) > max_to_process:
            import random

            logger.info(
                "Sampling %d configs from %d for processing.",
                max_to_process,
                len(configs),
            )
            configs = random.sample(configs, max_to_process)

        # 3. Dedup FIRST — one server = one config (address, port).
        #    Deduping before country detection saves CPU: detect_country is
        #    the most expensive step (~12µs/call), so fewer configs = faster.
        configs = self._dedup_only(configs)
        logger.info("After dedup: %d configs.", len(configs))

        # 4. Country filter (no network — instant for remaining configs).
        configs = self._filter_countries(configs)
        logger.info("After country filter: %d configs.", len(configs))

        if not configs:
            logger.warning("No configs matched allowed countries.")
            self._write_empty_output(output_file)
            return 0

        # 5. Aggregate: sort -> limit (dedup already done).
        configs = self._sort_and_limit(configs)
        logger.info("After aggregation: %d configs.", len(configs))

        # 5. Write output.
        count = self._write_output(configs, output_file)
        logger.info("Wrote %d configs to %s.", count, output_file)

        # 6. Publish (optional).
        if publish:
            await self._publish(output_file)

        elapsed = time.monotonic() - start
        logger.info("Pipeline finished in %.2fs with %d configs.", elapsed, count)
        return count

    # --- stage 1: fetch ---

    async def _fetch_sources(self) -> list[Any]:
        """Fetch all sources via SourceManager.

        Imports SourceManager lazily so a missing/broken module does not break
        pipeline startup — it only fails when this stage actually runs. The
        manager's HTTP client is cleaned up via ``async with``.
        """
        try:
            from src.sources.manager import SourceManager
        except ImportError as exc:
            logger.error("Cannot import SourceManager: %s — fetch stage skipped.", exc)
            return []

        try:
            manager = SourceManager(
                sources_file=self.sources_path,
                settings_file=self.settings_path,
                github_token=self.github_token,
            )
        except Exception as exc:
            logger.error("Failed to construct SourceManager: %s", exc)
            return []

        try:
            async with manager:
                results = await manager.fetch_all()
        except Exception as exc:
            logger.error("SourceManager.fetch_all() failed: %s", exc)
            return []

        logger.info("Fetched %d source results.", len(results) if results else 0)
        return list(results) if results else []

    # --- stage 2: parse ---

    async def _parse_all(self, results: list[Any]) -> list[Config]:
        """Parse all source results into Config objects.

        For each source result:
        - Iterate ``result.files`` as ``(filename, content)`` tuples.
        - If ``SubscriptionParser.is_subscription(content)`` -> extract links
          from the subscription blob.
        - Otherwise ``find_all_links(content)`` extracts links from raw text.
        - For each link, try each parser in ``ALL_PARSERS`` until one succeeds.
        """
        configs: list[Config] = []
        sub_parser = SubscriptionParser()

        for result in results:
            files = self._result_files(result)
            source_name = self._result_name(result)

            for filename, content in files:
                if not content or not content.strip():
                    continue

                links = await self._extract_links(
                    sub_parser, content, filename, source_name
                )
                if not links:
                    logger.debug("No links found in %s (%s).", filename, source_name)
                    continue

                parsed_here = 0
                for link in links:
                    cfg = self._parse_one_link(link)
                    if cfg is not None:
                        configs.append(cfg)
                        parsed_here += 1
                logger.debug(
                    "Parsed %d/%d links from %s (%s).",
                    parsed_here,
                    len(links),
                    filename,
                    source_name,
                )

        return configs

    @staticmethod
    def _result_files(result: Any) -> list[tuple[str, str]]:
        """Extract ``[(filename, content), ...]`` from a SourceResult.

        Supports both attribute (``result.files``) and mapping
        (``result["files"]``) shapes, and tolerates a plain list of tuples.
        """
        files: Any = None
        if hasattr(result, "files"):
            files = result.files
        elif isinstance(result, dict):
            files = result.get("files")
        elif isinstance(result, list):
            files = result
        if not files:
            return []
        out: list[tuple[str, str]] = []
        for entry in files:
            if isinstance(entry, tuple) and len(entry) == 2:
                out.append((str(entry[0]), str(entry[1])))
            elif isinstance(entry, dict):
                name = entry.get("name") or entry.get("filename") or ""
                content = entry.get("content") or ""
                out.append((str(name), str(content)))
        return out

    @staticmethod
    def _result_name(result: Any) -> str:
        """Best-effort source name for logging."""
        for attr in ("name", "source_name"):
            if hasattr(result, attr):
                return str(getattr(result, attr) or "?")
        if isinstance(result, dict):
            return str(result.get("name") or result.get("source_name") or "?")
        return "?"

    async def _extract_links(
        self,
        sub_parser: SubscriptionParser,
        content: str,
        filename: str,
        source_name: str,
    ) -> list[str]:
        """Extract proxy links from a content blob.

        Tries the subscription detector first; falls back to ``find_all_links``
        on any error or non-subscription content.  When regex finds 0 links
        and LLM is enabled, tries LLM extraction as a last resort.
        """
        try:
            is_sub = sub_parser.is_subscription(content)
        except Exception as exc:
            logger.debug(
                "is_subscription raised for %s (%s): %s — treating as raw.",
                filename,
                source_name,
                exc,
            )
            is_sub = False

        if is_sub:
            try:
                links = sub_parser.parse_subscription(content) or []
                logger.debug(
                    "Subscription blob %s (%s) -> %d links.",
                    filename,
                    source_name,
                    len(links),
                )
                return [ln for ln in links if isinstance(ln, str) and ln]
            except Exception as exc:
                logger.warning(
                    "SubscriptionParser.parse_subscription failed for %s (%s): %s — "
                    "falling back to find_all_links.",
                    filename,
                    source_name,
                    exc,
                )

        links = find_all_links(content)

        # LLM fallback: if regex found 0 links and text is long enough, try LLM.
        if not links:
            links = await self._llm_fallback(content, filename, source_name)

        return links

    async def _llm_fallback(
        self, content: str, filename: str, source_name: str
    ) -> list[str]:
        """Try LLM extraction when regex found 0 links.

        Reads LLM settings from ``settings.yaml``.  If LLM is disabled or
        no API key is set, returns an empty list silently.
        """
        lcfg = self._section("llm")
        if not lcfg.get("enabled", False):
            return []

        api_key_env = lcfg.get("api_key_env", "LLM_API_KEY")
        api_key = os.environ.get(api_key_env, "")
        if not api_key:
            logger.debug("LLM fallback skipped: no API key in env %s", api_key_env)
            return []

        provider = lcfg.get("provider", "gemini")
        model = lcfg.get("model", "gemini-2.0-flash")
        min_text_length = int(lcfg.get("min_text_length", 100))

        from src.parsers.llm_fallback import LLMFallbackParser, should_use_llm

        if not should_use_llm(content, [], min_text_length=min_text_length):
            return []

        logger.info(
            "Trying LLM fallback for %s (%s) — regex found 0 links in %d chars.",
            filename,
            source_name,
            len(content),
        )

        try:
            llm = LLMFallbackParser(
                provider=provider,
                model=model,
                api_key=api_key,
            )
            links = await llm.extract_links(content)
        except Exception as exc:
            logger.warning(
                "LLM fallback failed for %s (%s): %s", filename, source_name, exc
            )
            return []

        if links:
            logger.info(
                "LLM fallback extracted %d links from %s (%s).",
                len(links),
                filename,
                source_name,
            )
        return links

    def _parse_one_link(self, link: str) -> Config | None:
        """Try every parser in ALL_PARSERS against a single link.

        Returns the first successful Config, or None if no parser matched.
        """
        for parser in ALL_PARSERS:
            try:
                if not parser.can_parse(link):
                    continue
                cfg = parser.parse(link)
                if cfg is not None:
                    return cfg
            except Exception as exc:
                logger.debug("Parser %s raised on link: %s", type(parser).__name__, exc)
                continue
        return None

    @staticmethod
    def _filter_garbage(configs: list[Config]) -> tuple[list[Config], int]:
        """Remove placeholder/template configs (UUID, SERVER_IP, example.com).

        Returns (clean_configs, garbage_count).
        """
        clean: list[Config] = []
        garbage = 0
        for cfg in configs:
            if is_garbage_config(cfg):
                garbage += 1
                logger.debug(
                    "Garbage filtered: %s://%s:%d (%s)",
                    cfg.protocol,
                    cfg.address,
                    cfg.port,
                    (cfg.remark or "")[:50],
                )
            else:
                clean.append(cfg)
        return clean, garbage

    # --- stage 3: country filter ---

    def _filter_countries(self, configs: list[Config]) -> list[Config]:
        """Filter configs by allowed countries (no network — instant).

        Detects country from each config's remark using emoji flags,
        country names, and ISO codes. Only configs matching the
        ``allowed_countries`` list are kept.

        When ``allowed_countries`` is empty, all configs pass through.
        """
        vcfg = self._section("validator")
        allowed = vcfg.get("allowed_countries", [])

        if not allowed:
            logger.info("No country filter configured — keeping all configs.")
            # Still try to detect country for sorting purposes.
            from src.validators.country_filter import detect_country

            for cfg in configs:
                if cfg.country is None:
                    cfg.country = detect_country(
                        cfg.remark,
                        getattr(cfg, "address", None),
                        getattr(cfg, "sni", None),
                        getattr(cfg, "host", None),
                    )
            return configs

        allowed_list = [str(c).upper() for c in allowed]
        logger.info("Filtering to allowed countries: %s", allowed_list)

        from src.validators.country_filter import filter_by_country

        return filter_by_country(configs, allowed_list)

    async def _run_validator(
        self,
        module_path: str,
        func_name: str,
        configs: list[Config],
        *,
        stage_name: str,
        **kwargs: Any,
    ) -> list[Config]:
        """Dynamically import and call a validator function.

        On any failure, the input ``configs`` is returned unchanged so the
        pipeline can continue with the previous stage's results.
        """
        try:
            import importlib

            module = importlib.import_module(module_path)
            func = getattr(module, func_name)
        except (ImportError, AttributeError) as exc:
            logger.error(
                "Validator %s.%s unavailable: %s — skipping %s stage.",
                module_path,
                func_name,
                exc,
                stage_name,
            )
            return configs

        try:
            logger.info(
                "Running %s validation on %d configs...", stage_name, len(configs)
            )
            result = await func(configs, **kwargs)
        except TypeError as exc:
            # Signature mismatch (e.g. validator doesn't accept a kwarg) —
            # retry positionally with just the configs.
            logger.warning(
                "%s validator rejected kwargs (%s) — retrying with configs only.",
                stage_name,
                exc,
            )
            try:
                result = await func(configs)
            except Exception as exc2:
                logger.error(
                    "%s validation failed (fallback): %s — passing through.",
                    stage_name,
                    exc2,
                )
                return configs
        except Exception as exc:
            logger.error("%s validation failed: %s — passing through.", stage_name, exc)
            return configs

        survived = len(result) if result else 0
        logger.info(
            "%s validation: %d/%d configs survived.", stage_name, survived, len(configs)
        )
        return list(result) if result else []

    # --- stage 3+5: aggregate (split into dedup + sort/limit) ---

    def _dedup_only(self, configs: list[Config]) -> list[Config]:
        """Deduplicate configs by (address, port). Called before country filter."""
        try:
            from src.aggregator.merger import deduplicate
        except (ImportError, AttributeError) as exc:
            logger.error("Cannot import deduplicate: %s — skipping dedup.", exc)
            return configs
        try:
            return deduplicate(configs)
        except Exception as exc:
            logger.error("deduplicate failed: %s — passing through.", exc)
            return configs

    def _sort_and_limit(self, configs: list[Config]) -> list[Config]:
        """Sort and limit configs (dedup already done). Called after country filter."""
        acfg = self._section("aggregator")
        max_configs = int(acfg.get("max_configs_in_output", 500))
        sort_by = str(acfg.get("sort_by", "country"))
        max_per_country = int(acfg.get("max_per_country", 0))

        try:
            from src.aggregator.merger import sort_configs, limit_per_country
        except (ImportError, AttributeError) as exc:
            logger.error("Cannot import sort_configs: %s — skipping sort.", exc)
            return configs[:max_configs]

        try:
            sorted_configs = sort_configs(configs, sort_by=sort_by)
            if max_per_country > 0:
                sorted_configs = limit_per_country(sorted_configs, max_per_country)
            return sorted_configs[:max_configs]
        except Exception as exc:
            logger.error("sort_and_limit failed: %s — passing through.", exc)
            return configs[:max_configs]

    def _aggregate(self, configs: list[Config]) -> list[Config]:
        """Dedup -> sort -> limit via ``merge_and_filter``."""
        acfg = self._section("aggregator")
        max_configs = int(acfg.get("max_configs_in_output", 500))
        sort_by = str(acfg.get("sort_by", "latency"))
        max_per_country = int(acfg.get("max_per_country", 0))

        try:
            from src.aggregator.merger import merge_and_filter
        except (ImportError, AttributeError) as exc:
            logger.error(
                "Cannot import merge_and_filter: %s — skipping aggregation.", exc
            )
            return configs

        try:
            result = merge_and_filter(
                configs,
                max_total=max_configs,
                sort_by=sort_by,
                max_per_country=max_per_country,
            )
        except Exception as exc:
            logger.error("merge_and_filter failed: %s — passing through.", exc)
            return configs

        return list(result) if result else []

    # --- stage 5: write ---

    def _write_output(self, configs: list[Config], output_file: str) -> int:
        """Write the subscription file via ``write_subscription``."""
        try:
            from src.aggregator.output import write_subscription
        except (ImportError, AttributeError) as exc:
            logger.error(
                "Cannot import write_subscription: %s — writing plain fallback.", exc
            )
            return self._write_plain_fallback(configs, output_file)

        try:
            count = write_subscription(configs, output_file)
        except Exception as exc:
            logger.error("write_subscription failed: %s — plain fallback.", exc)
            return self._write_plain_fallback(configs, output_file)

        return int(count) if count else 0

    def _write_empty_output(self, output_file: str) -> None:
        """Ensure the output file exists (empty) so the publish step is a no-op."""
        try:
            self._write_plain_fallback([], output_file)
        except Exception as exc:
            logger.warning("Could not write empty output %s: %s", output_file, exc)

    @staticmethod
    def _write_plain_fallback(configs: list[Config], output_file: str) -> int:
        """Last-resort writer: one ``raw_link`` per line (or ``to_dict``-derived)."""
        try:
            path = Path(output_file)
            path.parent.mkdir(parents=True, exist_ok=True)
            lines = [c.raw_link for c in configs if c.raw_link]
            with path.open("w", encoding="utf-8") as fh:
                fh.write("\n".join(lines))
                if lines:
                    fh.write("\n")
            return len(lines)
        except Exception as exc:
            logger.error("Plain fallback write failed for %s: %s", output_file, exc)
            return 0

    # --- stage 6: publish ---

    async def _publish(self, output_file: str) -> None:
        """Publish the output file to a GitHub repo via ``GitHubPublisher``."""
        if not self.github_token:
            logger.warning("Publish requested but GITHUB_TOKEN is not set — skipping.")
            return

        pcfg = self._section("publisher")
        owner = pcfg.get("owner") or os.environ.get("GITHUB_OWNER")
        repo = pcfg.get("repo") or os.environ.get("GITHUB_REPO")
        branch = pcfg.get("branch") or os.environ.get("GITHUB_BRANCH") or "main"
        repo_path = pcfg.get("output_file") or output_file
        commit_tpl = pcfg.get("commit_message", "auto-update configs [{timestamp}]")

        if not owner or not repo:
            logger.warning(
                "Publish requested but GitHub owner/repo not configured "
                "(set publisher.owner/repo in settings or GITHUB_OWNER/GITHUB_REPO env) — skipping."
            )
            return

        # Read the output file content.
        try:
            content = Path(output_file).read_text(encoding="utf-8")
        except FileNotFoundError:
            logger.error("Cannot publish: output file %s does not exist.", output_file)
            return
        except Exception as exc:
            logger.error("Cannot read output file %s for publish: %s", output_file, exc)
            return

        commit_message = commit_tpl.replace(
            "{timestamp}", time.strftime("%Y-%m-%d %H:%M:%S")
        )

        try:
            from src.publisher.github import GitHubPublisher
        except ImportError as exc:
            logger.error("Cannot import GitHubPublisher: %s — skipping publish.", exc)
            return

        try:
            async with GitHubPublisher(
                token=self.github_token,
                owner=owner,
                repo=repo,
                branch=branch,
            ) as publisher:
                ok = await publisher.publish_file(repo_path, content, commit_message)
                if not ok:
                    logger.error(
                        "Publish completed but reported failure for %s.", repo_path
                    )
        except Exception as exc:
            logger.error("Publish failed: %s", exc)
