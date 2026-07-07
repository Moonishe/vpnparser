"""Pipeline orchestrator — fetch -> parse -> filter -> aggregate -> write -> publish.

``PipelineRunner`` ties together every stage of the VPN config pipeline:

1. **Fetch**    — ``SourceManager.fetch_all()`` pulls files from configured sources.
2. **Parse**    — ``_parse_all_by_list()`` extracts proxy links and turns them into
                  ``Config`` objects grouped by source ``list_type`` (blacklist/whitelist).
3. **Filter**   — garbage/placeholder filter -> sample -> dedup -> country filter.
4. **Aggregate**— interleave blacklist+whitelist -> sort -> per-country limit.
5. **Write**    — ``write_subscription()`` emits combined, mix, and split files.
6. **Publish**  — (optional) commit outputs to a GitHub repo via Contents API.

Each stage is wrapped so a failure is logged and, where possible, the pipeline
continues with whatever data survived the previous stage.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from pathlib import Path
from typing import Any

import yaml

from src.parsers import PARSER_BY_SCHEME
from src.parsers.base import Config, find_all_links, is_garbage_config
from src.parsers.subscription import SubscriptionParser
from src.sources.list_types import normalize_list_type

logger = logging.getLogger(__name__)

_TCP_SKIP_PROTOCOLS = {"tuic", "hysteria2"}


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
        self._validator_proxy_urls_cache: list[str] | None = None

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

    def _max_configs(self) -> int:
        """Canonical ``max_configs_in_output`` (single source of truth).

        Both ``run()`` (interleave cap) and ``_sort_and_limit`` (final cap)
        read ``aggregator.max_configs_in_output``.  Previously they used
        different defaults (75 vs 500), so when the setting was absent the
        interleave capped at 150 while the sort capped at 500 — producing
        ~150 configs instead of a consistent value.  This helper guarantees
        every call site agrees.  The default (500) matches
        :func:`src.aggregator.merger.merge_and_filter`.
        """
        try:
            return int(self._section("aggregator").get("max_configs_in_output", 500))
        except (TypeError, ValueError):
            return 500

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
            self._write_empty_secondary_outputs(output_file)
            return 0

        # 2. Parse all content into Config objects grouped by source list type.
        configs_by_list = await self._parse_all_by_list(results)
        total_count = sum(len(v) for v in configs_by_list.values())
        logger.info(
            "Parsed %d configs total across %d list group(s).",
            total_count,
            len(configs_by_list),
        )
        if total_count == 0:
            logger.warning(
                "No configs parsed from sources — pipeline produced nothing."
            )
            self._write_empty_output(output_file)
            self._write_empty_secondary_outputs(output_file)
            return 0

        # 3. Preprocess each list type: garbage -> sample -> dedup -> country.
        #    Sorting is deferred to step 4 (combined) and step 7 (splits) so
        #    each config is sorted exactly once, not twice.  This gives a fair
        #    share to each list in the combined output (blacklist + whitelist
        #    balanced 50/50 instead of blacklist dominating).
        preprocessed_by_list: dict[str, list[Config]] = {}
        for list_type, group in configs_by_list.items():
            preprocessed = self._preprocess_configs(list(group), label=list_type)
            if preprocessed:
                preprocessed_by_list[list_type] = preprocessed

        if not preprocessed_by_list:
            logger.warning("No configs matched allowed countries.")
            self._write_empty_output(output_file)
            self._write_empty_secondary_outputs(output_file)
            return 0

        preprocessed_by_list = await self._validate_liveness_by_list(
            preprocessed_by_list
        )
        if not preprocessed_by_list:
            logger.warning("No configs survived liveness validation.")
            self._write_empty_output(output_file)
            self._write_empty_secondary_outputs(output_file)
            return 0

        # 4. Build combined output: interleave blacklist + whitelist for balance.
        #    Each list is pre-sorted + per-country limited so no single country
        #    dominates the combined output.
        max_total = self._max_configs()
        acfg = self._section("aggregator")
        try:
            max_per_country = int(acfg.get("max_per_country", 0))
        except (TypeError, ValueError):
            max_per_country = 0

        lists = list(preprocessed_by_list.values())
        combined: list[Config] = []
        i = 0
        while len(combined) < max_total * 2 and any(i < len(group) for group in lists):
            for configs in lists:
                if i < len(configs):
                    combined.append(configs[i])
            i += 1

        # Dedup (same server in both lists).
        combined = self._dedup_only(combined)

        # Sort + limit per country so all countries are represented.
        from src.aggregator.merger import limit_per_country, sort_configs

        combined = sort_configs(combined, sort_by="country")
        if max_per_country > 0:
            combined = limit_per_country(combined, max_per_country)
        combined = combined[:max_total]
        logger.info("Combined after interleave+dedup+sort: %d configs.", len(combined))

        # 5. Write combined output.
        count = self._write_output(combined, output_file)
        logger.info("Wrote %d configs to %s.", count, output_file)
        output_files = [output_file]
        split_output_files = self._split_output_files(output_file)

        mix_output_file = self._mix_output_file(output_file, split_output_files)
        if mix_output_file:
            mix_configs = self._build_mixed_output(preprocessed_by_list, max_total)
            if mix_configs:
                mix_count = self._write_output(mix_configs, mix_output_file)
                logger.info("Wrote %d mix configs to %s.", mix_count, mix_output_file)
            else:
                self._write_empty_output(mix_output_file)
                logger.warning("No configs for mix output.")
            output_files.append(mix_output_file)

        # 6. Write split outputs — sort+limit each preprocessed list now
        #    (deferred from step 3 so the combined path sorts only once).
        for list_type, split_file in split_output_files.items():
            split_pre = preprocessed_by_list.get(list_type, [])
            if split_pre:
                if list_type == "whitelist":
                    # Whitelist: 80% RU servers, 20% EU countries by default.
                    split_configs = self._whitelist_balance(split_pre, max_total)
                else:
                    split_configs = self._sort_and_limit(split_pre)
                split_count = self._write_output(split_configs, split_file)
                logger.info(
                    "Wrote %d %s configs to %s.", split_count, list_type, split_file
                )
            else:
                self._write_empty_output(split_file)
                logger.warning("No configs for %s output.", list_type)
            output_files.append(split_file)

        # 7. Publish (optional).
        if publish:
            await self._publish_files(output_files, combined_output_file=output_file)

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

    async def _parse_all_by_list(
        self,
        results: list[Any],
    ) -> dict[str, list[Config]]:
        """Parse all source results grouped by normalized list type."""
        grouped: dict[str, list[Config]] = {}
        sub_parser = SubscriptionParser()

        for result in results:
            list_type = normalize_list_type(getattr(result, "list_type", "mixed"))
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
                bucket = grouped.setdefault(list_type, [])
                for link in links:
                    cfg = self._parse_one_link(link)
                    if cfg is not None:
                        source_default_country = self._result_default_country(result)
                        if source_default_country:
                            setattr(
                                cfg,
                                "source_default_country",
                                source_default_country,
                            )
                        bucket.append(cfg)
                        parsed_here += 1
                logger.debug(
                    "Parsed %d/%d links from %s (%s, %s).",
                    parsed_here,
                    len(links),
                    filename,
                    source_name,
                    list_type,
                )

        return grouped

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

    @staticmethod
    def _result_default_country(result: Any) -> str | None:
        """Best-effort default country hint carried by a source result."""
        raw: Any = None
        if hasattr(result, "default_country"):
            raw = getattr(result, "default_country")
        elif isinstance(result, dict):
            raw = result.get("default_country")
        if raw is None:
            return None
        text = str(raw).strip().upper()
        return text if len(text) == 2 and text.isalpha() else None

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
        try:
            min_text_length = int(lcfg.get("min_text_length", 100))
        except (TypeError, ValueError):
            min_text_length = 100

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
        """Parse a single link via O(1) scheme dispatch.

        The scheme is extracted from the link and looked up in
        :data:`PARSER_BY_SCHEME`.  This replaces the previous O(N) loop over
        ``ALL_PARSERS`` that called ``can_parse()`` (strip+lower+startswith)
        on every parser for every link.

        ``parse()`` still re-checks the scheme internally (defence in depth),
        so a corrupt dispatch entry cannot cause a wrong parser to run.

        Returns the parsed :class:`Config`, or ``None`` if no parser matched.
        """
        low = link.strip().lower()
        idx = low.find("://")
        if idx < 0:
            return None
        parser = PARSER_BY_SCHEME.get(low[:idx])
        if parser is None:
            return None
        try:
            return parser.parse(link)
        except Exception as exc:
            logger.debug("Parser %s raised on link: %s", type(parser).__name__, exc)
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

    def _filter_countries(
        self, configs: list[Config], *, list_type: str = "mixed"
    ) -> list[Config]:
        """Filter configs by allowed countries (no network — instant).

        Detects country from each config's remark using emoji flags,
        country names, and ISO codes. Only configs matching the
        ``allowed_countries`` list are kept.

        When ``allowed_countries`` is empty, all configs pass through.
        """
        vcfg = self._section("validator")
        allowed = vcfg.get("allowed_countries", [])
        by_list = vcfg.get("allowed_countries_by_list", {})
        if isinstance(by_list, dict):
            specific = by_list.get(normalize_list_type(list_type))
            if specific is not None:
                allowed = specific
        # Guard: YAML scalar string (e.g. "RU" instead of ["RU"]) would
        # iterate character-by-character → ["R","U"] → 0 matches.
        if isinstance(allowed, str):
            allowed = [allowed]

        from src.validators.country_filter import detect_country

        for cfg in configs:
            if cfg.country is None:
                cfg.country = detect_country(
                    cfg.remark,
                    getattr(cfg, "address", None),
                    getattr(cfg, "sni", None),
                    getattr(cfg, "host", None),
                )
            if cfg.country is None:
                default_country = getattr(cfg, "source_default_country", None)
                if default_country:
                    cfg.country = str(default_country).upper()

        if not allowed:
            logger.info("No country filter configured — keeping all configs.")
            # Still try to detect country for sorting purposes.
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
        logger.info("Filtering %s to allowed countries: %s", list_type, allowed_list)

        from src.validators.country_filter import filter_by_country

        return filter_by_country(configs, allowed_list)

    # --- optional network liveness validation ---

    @staticmethod
    def _as_bool(value: Any, default: bool = False) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return default
        text = str(value).strip().lower()
        if text in {"1", "true", "yes", "on"}:
            return True
        if text in {"0", "false", "no", "off"}:
            return False
        return default

    @staticmethod
    def _as_int(value: Any, default: int, *, minimum: int = 0) -> int:
        if isinstance(value, bool):
            return default
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return default
        return max(minimum, parsed)

    @staticmethod
    def _as_float(value: Any, default: float, *, minimum: float = 0.0) -> float:
        if isinstance(value, bool):
            return default
        try:
            parsed = float(value)
        except (TypeError, ValueError):
            return default
        return max(minimum, parsed)

    @staticmethod
    def _source_list(value: Any) -> list[str] | None:
        if value is None:
            return None
        if isinstance(value, str):
            text = value.strip()
            return [text] if text else []
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        return []

    def _liveness_min_alive(self, total: int) -> int:
        if total <= 0:
            return 0
        vcfg = self._section("validator")
        raw = vcfg.get("min_alive_to_filter", 1)
        threshold = self._as_int(raw, 1, minimum=1)
        return min(threshold, total)

    def _proxy_pool_config(self) -> dict[str, Any]:
        raw = self._section("validator").get("proxy_pool", {})
        return raw if isinstance(raw, dict) else {}

    async def _validator_proxy_urls(self) -> list[str]:
        """Return configured validator proxies, including optional free pool."""
        if self._validator_proxy_urls_cache is not None:
            return list(self._validator_proxy_urls_cache)

        vcfg = self._section("validator")
        urls: list[str] = []
        explicit = str(vcfg.get("proxy_url") or os.environ.get("VALIDATOR_PROXY") or "")
        explicit = explicit.strip()
        if explicit:
            urls.append(explicit)

        pool_cfg = self._proxy_pool_config()
        if self._as_bool(pool_cfg.get("enabled"), False):
            try:
                from src.validators.proxy_pool import load_proxy_pool
            except ImportError as exc:
                logger.warning("Proxy pool unavailable: %s", exc)
            else:
                sources = self._source_list(pool_cfg.get("sources"))
                try:
                    pool_urls = await load_proxy_pool(
                        sources,
                        fetch_timeout=self._as_float(
                            pool_cfg.get("fetch_timeout_seconds"), 10.0, minimum=1.0
                        ),
                        max_candidates=self._as_int(
                            pool_cfg.get("max_candidates"), 200, minimum=1
                        ),
                        max_candidates_per_source=self._as_int(
                            pool_cfg.get("max_candidates_per_source"), 80, minimum=1
                        ),
                        max_proxies=self._as_int(
                            pool_cfg.get("max_proxies"), 20, minimum=1
                        ),
                        validate=self._as_bool(pool_cfg.get("validate"), True),
                        validation_timeout=self._as_float(
                            pool_cfg.get("validation_timeout_seconds"),
                            5.0,
                            minimum=1.0,
                        ),
                        validation_concurrency=self._as_int(
                            pool_cfg.get("validation_concurrency"),
                            50,
                            minimum=1,
                        ),
                        probe_host=str(pool_cfg.get("probe_host") or "api.github.com"),
                        probe_port=self._as_int(
                            pool_cfg.get("probe_port"), 443, minimum=1
                        ),
                    )
                except Exception as exc:
                    logger.warning("Proxy pool load failed: %s", exc)
                else:
                    for proxy_url in pool_urls:
                        if proxy_url not in urls:
                            urls.append(proxy_url)

        self._validator_proxy_urls_cache = urls
        return list(urls)

    async def _validate_liveness_by_list(
        self, configs_by_list: dict[str, list[Config]]
    ) -> dict[str, list[Config]]:
        """Optionally run TCP/TLS liveness checks for each list type."""
        vcfg = self._section("validator")
        tcp_enabled = self._as_bool(vcfg.get("tcp_enabled"), False)
        tls_enabled = self._as_bool(vcfg.get("tls_enabled"), False)
        if not tcp_enabled and not tls_enabled:
            return configs_by_list

        validated: dict[str, list[Config]] = {}
        for list_type, configs in configs_by_list.items():
            alive = await self._validate_liveness_configs(
                list(configs),
                label=list_type,
                tcp_enabled=tcp_enabled,
                tls_enabled=tls_enabled,
            )
            if alive:
                validated[list_type] = alive
        return validated

    async def _validate_liveness_configs(
        self,
        configs: list[Config],
        *,
        label: str,
        tcp_enabled: bool,
        tls_enabled: bool,
    ) -> list[Config]:
        if not configs:
            return []

        vcfg = self._section("validator")
        proxy_urls = await self._validator_proxy_urls()
        pool_cfg = self._proxy_pool_config()
        pool_required = self._as_bool(pool_cfg.get("required"), False)
        pool_enabled = self._as_bool(pool_cfg.get("enabled"), False)
        if pool_enabled and pool_required and not proxy_urls:
            logger.warning(
                "Liveness validation for %s skipped: proxy_pool.required=true "
                "but no proxies are available.",
                label,
            )
            return configs

        current = list(configs)

        if tcp_enabled:
            checkable = [c for c in current if c.protocol not in _TCP_SKIP_PROTOCOLS]
            passthrough = [c for c in current if c.protocol in _TCP_SKIP_PROTOCOLS]
            if checkable:
                from src.validators.tcp_check import validate_configs_tcp

                candidate_limit = self._as_int(
                    vcfg.get("tcp_candidate_limit"), 1000, minimum=0
                )
                if candidate_limit > 0 and len(checkable) > candidate_limit:
                    logger.info(
                        "%s TCP validation candidate cap: checking first %d/%d.",
                        label,
                        candidate_limit,
                        len(checkable),
                    )
                    checkable = checkable[:candidate_limit]

                tcp_max_alive = self._as_int(vcfg.get("tcp_max_alive"), 0, minimum=0)
                tcp_max_alive_by_list = vcfg.get("tcp_max_alive_by_list", {})
                if isinstance(tcp_max_alive_by_list, dict):
                    specific_max_alive = tcp_max_alive_by_list.get(
                        normalize_list_type(label)
                    )
                    if specific_max_alive is not None:
                        tcp_max_alive = self._as_int(
                            specific_max_alive,
                            tcp_max_alive,
                            minimum=0,
                        )

                alive_tcp = await validate_configs_tcp(
                    checkable,
                    timeout=self._as_float(
                        vcfg.get("tcp_timeout_seconds"), 5.0, minimum=0.1
                    ),
                    concurrency=self._as_int(
                        vcfg.get("tcp_concurrency"), 300, minimum=1
                    ),
                    max_alive=tcp_max_alive,
                    proxy_urls=proxy_urls,
                    proxy_attempts_per_config=self._as_int(
                        vcfg.get("proxy_attempts_per_config"), 5, minimum=0
                    ),
                )
                min_alive = self._liveness_min_alive(len(checkable))
                if len(alive_tcp) < min_alive:
                    logger.warning(
                        "%s TCP validation found %d/%d alive (<%d). "
                        "Keeping unfiltered configs.",
                        label,
                        len(alive_tcp),
                        len(checkable),
                        min_alive,
                    )
                    return configs
                current = alive_tcp + passthrough
                logger.info(
                    "%s after TCP validation: %d alive, %d TCP-skipped.",
                    label,
                    len(alive_tcp),
                    len(passthrough),
                )

        if tls_enabled:
            tls_checkable = [c for c in current if c.security in ("tls", "reality")]
            if tls_checkable:
                from src.validators.tls_check import validate_configs_tls

                before_tls = list(current)
                candidate_limit = self._as_int(
                    vcfg.get("tls_candidate_limit"), 1000, minimum=0
                )
                if candidate_limit > 0 and len(current) > candidate_limit:
                    logger.info(
                        "%s TLS validation candidate cap: checking first %d/%d.",
                        label,
                        candidate_limit,
                        len(current),
                    )
                    current = current[:candidate_limit]
                alive_tls = await validate_configs_tls(
                    current,
                    timeout=self._as_float(
                        vcfg.get("tls_timeout_seconds"), 5.0, minimum=0.1
                    ),
                    concurrency=self._as_int(
                        vcfg.get("tls_concurrency"), 100, minimum=1
                    ),
                    proxy_urls=proxy_urls,
                    proxy_attempts_per_config=self._as_int(
                        vcfg.get("proxy_attempts_per_config"), 5, minimum=0
                    ),
                )
                min_alive = self._liveness_min_alive(len(current))
                if len(alive_tls) < min_alive:
                    logger.warning(
                        "%s TLS validation left %d/%d configs (<%d). "
                        "Keeping pre-TLS configs.",
                        label,
                        len(alive_tls),
                        len(current),
                        min_alive,
                    )
                    return before_tls
                current = alive_tls
                logger.info("%s after TLS validation: %d configs.", label, len(current))

        return current

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
        max_configs = self._max_configs()
        sort_by = str(acfg.get("sort_by", "country"))
        try:
            max_per_country = int(acfg.get("max_per_country", 0))
        except (TypeError, ValueError):
            max_per_country = 0

        try:
            from src.aggregator.merger import sort_configs, limit_per_country
        except (ImportError, AttributeError) as exc:
            logger.error("Cannot import sort_configs: %s — skipping sort.", exc)
            return configs[:max_configs]

        try:
            # Filter out configs with no country detected — they waste output slots.
            configs = [c for c in configs if c.country is not None]
            sorted_configs = sort_configs(configs, sort_by=sort_by)
            if max_per_country > 0:
                sorted_configs = limit_per_country(sorted_configs, max_per_country)
            return sorted_configs[:max_configs]
        except Exception as exc:
            logger.error("sort_and_limit failed: %s — passing through.", exc)
            return configs[:max_configs]

    def _preprocess_configs(
        self,
        configs: list[Config],
        *,
        label: str,
    ) -> list[Config]:
        """Preprocess configs: garbage -> sample -> dedup -> country filter.

        This is the per-list ``process`` stage of the pipeline.  It does NOT
        sort or limit — sorting is deferred so the combined output (step 4 of
        :meth:`run`) and each split output (step 6) sort exactly once instead
        of twice (previously ``_process_configs`` sorted per-list and
        :meth:`run` re-sorted the combined list).

        Dedup is kept here (before the country filter) so intra-list
        duplicates are removed early; the combined path in :meth:`run` then
        dedups cross-list duplicates after interleaving.

        Returns preprocessed configs (or empty list if nothing survived).
        Preserves insertion order (no sort).
        """
        if not configs:
            return []

        configs, garbage_count = self._filter_garbage(configs)
        if garbage_count:
            logger.info(
                "Filtered %d garbage/placeholder configs for %s.",
                garbage_count,
                label,
            )
        if not configs:
            return []

        vcfg = self._section("validator")
        try:
            max_to_process = int(vcfg.get("max_configs_to_validate", 20000))
        except (TypeError, ValueError):
            max_to_process = 20000
        if max_to_process > 0 and len(configs) > max_to_process:
            import random

            logger.info(
                "Sampling %d configs from %d for %s processing.",
                max_to_process,
                len(configs),
                label,
            )
            configs = random.sample(configs, max_to_process)

        configs = self._dedup_only(configs)
        logger.info("%s after dedup: %d configs.", label, len(configs))

        configs = self._filter_countries(configs, list_type=label)
        logger.info("%s after country filter: %d configs.", label, len(configs))
        if not configs:
            return []

        return configs

    def _whitelist_balance(self, configs: list[Config], max_total: int) -> list[Config]:
        """Build whitelist output: mostly RU servers plus EU fallback servers.

        Defaults to 80% RU and 20% EU. Falls back to the other side if one side
        has too few configs so the output can still reach the configured cap.
        """
        from src.aggregator.merger import limit_per_country, sort_configs

        acfg = self._section("aggregator")
        vcfg = self._section("validator")
        try:
            max_per = int(acfg.get("max_per_country", 0))
        except (TypeError, ValueError):
            max_per = 0
        try:
            ru_ratio = float(vcfg.get("whitelist_ru_ratio", 0.8))
        except (TypeError, ValueError):
            ru_ratio = 0.8
        ru_ratio = min(1.0, max(0.0, ru_ratio))
        eu_raw = vcfg.get("whitelist_eu_countries", ["DE", "FI", "NL", "FR"])
        if isinstance(eu_raw, str):
            eu_raw = [eu_raw]
        eu_countries = {str(code).upper() for code in eu_raw}

        ru = [c for c in configs if c.country == "RU"]
        eu = [c for c in configs if c.country in eu_countries]

        ru_target = int(max_total * ru_ratio)
        eu_target = max_total - ru_target

        # Sort + limit each side.
        ru_sorted = sort_configs(ru, sort_by="country")
        eu_sorted = sort_configs(eu, sort_by="country")
        if max_per > 0:
            ru_sorted = limit_per_country(ru_sorted, max_per)
            eu_sorted = limit_per_country(eu_sorted, max_per)

        ru_result = ru_sorted[:ru_target]
        eu_result = eu_sorted[:eu_target]

        # Fill shortfall from the other side.
        shortfall = max_total - len(ru_result) - len(eu_result)
        if shortfall > 0:
            if len(ru_result) < ru_target and len(eu_sorted) > len(eu_result):
                extra = eu_sorted[len(eu_result) : len(eu_result) + shortfall]
                eu_result.extend(extra)
            elif len(eu_result) < eu_target and len(ru_sorted) > len(ru_result):
                extra = ru_sorted[len(ru_result) : len(ru_result) + shortfall]
                ru_result.extend(extra)

        result = ru_result + eu_result
        logger.info(
            "Whitelist balance: %d RU + %d EU = %d total.",
            len(ru_result),
            len(eu_result),
            len(result),
        )
        return result

    def _build_mixed_output(
        self, preprocessed_by_list: dict[str, list[Config]], max_total: int
    ) -> list[Config]:
        """Build a strict 50/50 blacklist + whitelist mix from live configs."""
        if max_total <= 0:
            return []

        blacklist_target = max_total // 2
        whitelist_target = max_total - blacklist_target
        used_keys: set[Any] = set()

        blacklist_candidates = self._sort_and_limit(
            preprocessed_by_list.get("blacklist", [])
        )
        blacklist_part = self._take_unique_configs(
            blacklist_candidates, blacklist_target, used_keys
        )

        whitelist_source = [
            cfg
            for cfg in preprocessed_by_list.get("whitelist", [])
            if cfg.dedup_key not in used_keys
        ]
        whitelist_candidates = self._whitelist_balance(whitelist_source, whitelist_target)
        whitelist_part = self._take_unique_configs(
            whitelist_candidates, whitelist_target, used_keys
        )

        if len(blacklist_part) < blacklist_target:
            logger.warning(
                "Mix output short on blacklist configs: %d/%d.",
                len(blacklist_part),
                blacklist_target,
            )
        if len(whitelist_part) < whitelist_target:
            logger.warning(
                "Mix output short on whitelist configs: %d/%d.",
                len(whitelist_part),
                whitelist_target,
            )

        result = blacklist_part + whitelist_part
        logger.info(
            "Mix output: %d blacklist + %d whitelist = %d total.",
            len(blacklist_part),
            len(whitelist_part),
            len(result),
        )
        return result

    @staticmethod
    def _take_unique_configs(
        configs: list[Config], target: int, used_keys: set[Any]
    ) -> list[Config]:
        """Take up to target configs, skipping keys already used by another list."""
        if target <= 0:
            return []

        selected: list[Config] = []
        for cfg in configs:
            key = cfg.dedup_key
            if key in used_keys:
                continue
            selected.append(cfg)
            used_keys.add(key)
            if len(selected) >= target:
                break
        return selected

    def _process_configs(
        self,
        configs: list[Config],
        *,
        label: str,
    ) -> list[Config]:
        """Run configs through the full pipeline: preprocess -> sort -> limit.

        This is the *standalone* path used by :meth:`_process_and_write_configs`
        (and tests) when a single list is processed and written directly,
        without interleaving.  The combined path in :meth:`run` calls
        :meth:`_preprocess_configs` instead and defers sort/limit to avoid
        double-sorting.

        Returns processed, sorted, limited configs (or empty list if nothing
        survived).  Does NOT write to disk — caller handles output.
        """
        configs = self._preprocess_configs(configs, label=label)
        if not configs:
            return []
        configs = self._sort_and_limit(configs)
        logger.info("%s after aggregation: %d configs.", label, len(configs))
        return configs

    def _process_and_write_configs(
        self,
        configs: list[Config],
        output_file: str,
        *,
        label: str,
    ) -> int:
        """Filter, aggregate, and write a single output file."""
        configs = self._process_configs(configs, label=label)
        if not configs:
            logger.warning("No configs for %s output.", label)
            self._write_empty_output(output_file)
            return 0

        count = self._write_output(configs, output_file)
        logger.info("Wrote %d %s configs to %s.", count, label, output_file)
        return count

    def _split_output_files(self, combined_output_file: str) -> dict[str, str]:
        """Return configured split output files keyed by normalized list type.

        Two collision types are detected — in both the **first** entry wins
        and the duplicate is skipped with a warning (no silent data loss):

        - **Same list_type**: two keys normalize to the same list type
          (e.g. ``blacklist`` and ``bl`` both -> ``blacklist``).
        - **Same path**: two different list_types point to the same file
          path — without this check ``run()`` would write the file twice
          and the second write would silently clobber the first.
        """
        pcfg = self._section("publisher")
        raw = pcfg.get("split_output_files", {})
        if not isinstance(raw, dict):
            return {}

        result: dict[str, str] = {}
        seen_paths: set[str] = set()
        for key, path in raw.items():
            list_type = normalize_list_type(key)
            if list_type == "mixed" or not path:
                continue
            path_str = str(path)
            if path_str == combined_output_file:
                continue
            if list_type in result:
                logger.warning(
                    "split_output_files: key '%s' normalizes to '%s' which is "
                    "already mapped to '%s' — ignoring path '%s'. "
                    "Fix: remove the duplicate key or use a distinct list_type.",
                    key,
                    list_type,
                    result[list_type],
                    path_str,
                )
                continue
            if path_str in seen_paths:
                owner = next((lt for lt, p in result.items() if p == path_str), "?")
                logger.warning(
                    "split_output_files: path '%s' is already used by "
                    "list_type '%s' — ignoring duplicate for '%s' to "
                    "prevent overwriting. Fix: use a distinct output path.",
                    path_str,
                    owner,
                    list_type,
                )
                continue
            seen_paths.add(path_str)
            result[list_type] = path_str
        return result

    def _mix_output_file(
        self,
        combined_output_file: str,
        split_output_files: dict[str, str] | None = None,
    ) -> str | None:
        """Return configured 50/50 mix output path, if enabled and non-conflicting."""
        pcfg = self._section("publisher")
        path = pcfg.get("mix_output_file")
        if not path:
            return None

        path_str = str(path)
        if path_str == combined_output_file:
            logger.warning(
                "mix_output_file points to the combined output '%s' — ignoring.",
                combined_output_file,
            )
            return None

        split_paths = set((split_output_files or {}).values())
        if path_str in split_paths:
            logger.warning(
                "mix_output_file path '%s' is already used by a split output — "
                "ignoring to prevent overwriting.",
                path_str,
            )
            return None

        return path_str

    def _write_empty_secondary_outputs(self, combined_output_file: str) -> None:
        """Clear configured split and mix outputs on empty runs."""
        split_output_files = self._split_output_files(combined_output_file)
        self._write_empty_split_outputs(combined_output_file)
        mix_output_file = self._mix_output_file(
            combined_output_file, split_output_files
        )
        if mix_output_file:
            self._write_empty_output(mix_output_file)

    def _write_empty_split_outputs(self, combined_output_file: str) -> None:
        """Clear configured split outputs on empty runs."""
        for split_file in self._split_output_files(combined_output_file).values():
            self._write_empty_output(split_file)

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
        """Ensure the output file exists as a valid base64 subscription.

        Even on empty / early-exit runs the file must be a decodable base64
        subscription (containing at least the watermark entry) so that
        consumers like Happ can always decode it and the CI ``verify output``
        step counts configs consistently with the normal path.  Previously
        this wrote a 0-byte plain file via ``_write_plain_fallback``, which
        diverged from the normal path's ``write_subscription`` (base64 +
        watermark) and left Happ with an undecodable file.  Falls back to a
        plain empty file only if the subscription writer is unavailable.
        """
        try:
            self._write_output([], output_file)
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

    async def _publish_files(
        self,
        output_files: list[str],
        *,
        combined_output_file: str | None = None,
    ) -> None:
        """Publish multiple output files, preserving each repo path."""
        pcfg = self._section("publisher")
        configured_combined_path = pcfg.get("output_file")

        for output_file in dict.fromkeys(output_files):
            repo_path = output_file
            if combined_output_file is not None and output_file == combined_output_file:
                repo_path = str(configured_combined_path or output_file)
            await self._publish(output_file, repo_path=repo_path)

    async def _publish(self, output_file: str, repo_path: str | None = None) -> None:
        """Publish the output file to a GitHub repo via ``GitHubPublisher``."""
        if not self.github_token:
            logger.warning("Publish requested but GITHUB_TOKEN is not set — skipping.")
            return

        pcfg = self._section("publisher")
        owner = pcfg.get("owner") or os.environ.get("GITHUB_OWNER")
        repo = pcfg.get("repo") or os.environ.get("GITHUB_REPO")
        branch = pcfg.get("branch") or os.environ.get("GITHUB_BRANCH") or "main"
        repo_path = repo_path or str(pcfg.get("output_file") or output_file)
        commit_tpl = pcfg.get("commit_message", "auto-update configs [{timestamp}]")

        if not owner or not repo:
            logger.warning(
                "Publish requested but GitHub owner/repo not configured "
                "(set publisher.owner/repo in settings or GITHUB_OWNER/GITHUB_REPO env) — skipping."
            )
            return

        # Read the output file content in a worker thread so a slow/disk-bound
        # read does not block the event loop (publish may run concurrently with
        # other coroutines, and _publish_files could later be parallelised).
        try:
            content = await asyncio.to_thread(
                Path(output_file).read_text, encoding="utf-8"
            )
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
