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
import hashlib
import json
import logging
import os
import time
from collections import Counter
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
        self._liveness_stats: dict[str, Any] = {}
        self._output_stats: dict[str, Any] = {}
        self._health_history: dict[str, Any] | None = None

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
        self._liveness_stats = {}
        self._output_stats = {}
        logger.info("Pipeline started.")

        # 1. Fetch all sources.
        results = await self._fetch_sources()
        if not results:
            logger.warning("No source results fetched — pipeline produced nothing.")
            self._write_empty_output(output_file)
            self._write_empty_secondary_outputs(output_file)
            self._write_run_summary("no_sources")
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
            self._write_run_summary("no_configs_parsed")
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
            self._write_run_summary("no_allowed_countries")
            return 0

        preprocessed_by_list = await self._validate_liveness_by_list(
            preprocessed_by_list
        )
        if not preprocessed_by_list:
            logger.warning("No configs survived liveness validation.")
            self._write_empty_output(output_file)
            self._write_empty_secondary_outputs(output_file)
            self._write_run_summary("no_live_configs")
            return 0
        preprocessed_by_list = self._apply_quality_filters(preprocessed_by_list)
        if not preprocessed_by_list:
            logger.warning("No configs survived quality/history filters.")
            self._write_empty_output(output_file)
            self._write_empty_secondary_outputs(output_file)
            self._write_run_summary("no_quality_configs")
            return 0

        # 4. Build combined output from all live configs, then round-robin by
        #    country so no single country dominates while alternatives exist.
        max_total = self._max_configs()

        combined: list[Config] = []
        for configs in preprocessed_by_list.values():
            combined.extend(configs)

        # Dedup (same server in both lists).
        all_live_configs = self._dedup_only(combined)

        combined = self._country_balanced_limit(all_live_configs, max_total)
        logger.info(
            "Combined after dedup+country-balance: %d configs.",
            len(combined),
        )

        # 5. Write combined output.
        count = self._write_output(combined, output_file)
        self._record_output_stats("combined", output_file, combined)
        logger.info("Wrote %d configs to %s.", count, output_file)
        output_files = [output_file]
        split_output_files = self._split_output_files(output_file)

        mix_output_file = self._mix_output_file(output_file, split_output_files)
        if mix_output_file:
            mix_configs = self._build_mixed_output(preprocessed_by_list, max_total)
            if mix_configs:
                mix_count = self._write_output(mix_configs, mix_output_file)
                self._record_output_stats("mix", mix_output_file, mix_configs)
                logger.info("Wrote %d mix configs to %s.", mix_count, mix_output_file)
            else:
                self._write_empty_output(mix_output_file)
                self._record_output_stats("mix", mix_output_file, [])
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
                self._record_output_stats(list_type, split_file, split_configs)
                logger.info(
                    "Wrote %d %s configs to %s.", split_count, list_type, split_file
                )
            else:
                self._write_empty_output(split_file)
                self._record_output_stats(list_type, split_file, [])
                logger.warning("No configs for %s output.", list_type)
            output_files.append(split_file)

        location_output_files = self._write_location_outputs(all_live_configs)
        output_files.extend(location_output_files)

        summary_file = self._write_run_summary("ok")
        if summary_file:
            output_files.append(summary_file)
        health_file = self._write_health_history()
        if health_file:
            output_files.append(health_file)

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
                        setattr(cfg, "source_name", source_name)
                        setattr(cfg, "source_file", filename)
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

    async def _search_validator_proxy_pool(
        self,
        load_proxy_pool: Any,
        sources: list[str] | None,
        pool_cfg: dict[str, Any],
    ) -> list[str]:
        """Search for working SOCKS5 proxies, widening candidates on retries."""
        max_proxies = self._as_int(pool_cfg.get("max_proxies"), 20, minimum=1)
        min_proxies = self._as_int(
            pool_cfg.get("min_proxies"), min(10, max_proxies), minimum=1
        )
        if min_proxies > max_proxies:
            max_proxies = min_proxies

        search_rounds = self._as_int(pool_cfg.get("search_rounds"), 3, minimum=1)
        candidate_growth = self._as_float(
            pool_cfg.get("candidate_growth_factor"), 2.0, minimum=1.0
        )
        retry_delay = self._as_float(
            pool_cfg.get("retry_delay_seconds"), 0.0, minimum=0.0
        )
        base_max_candidates = self._as_int(
            pool_cfg.get("max_candidates"), 200, minimum=1
        )
        base_per_source = self._as_int(
            pool_cfg.get("max_candidates_per_source"), 80, minimum=1
        )

        self._liveness_stats.update(
            {
                "proxy_min_proxies": min_proxies,
                "proxy_search_round_limit": search_rounds,
                "proxy_search_rounds": 0,
                "proxy_search": [],
            }
        )

        pool_urls: list[str] = []
        for round_index in range(search_rounds):
            multiplier = candidate_growth**round_index
            max_candidates = max(
                base_max_candidates, int(base_max_candidates * multiplier)
            )
            max_candidates_per_source = max(
                base_per_source, int(base_per_source * multiplier)
            )
            pool_urls = await load_proxy_pool(
                sources,
                fetch_timeout=self._as_float(
                    pool_cfg.get("fetch_timeout_seconds"), 10.0, minimum=1.0
                ),
                max_candidates=max_candidates,
                max_candidates_per_source=max_candidates_per_source,
                max_proxies=max_proxies,
                validate=self._as_bool(pool_cfg.get("validate"), True),
                validation_timeout=self._as_float(
                    pool_cfg.get("validation_timeout_seconds"), 5.0, minimum=1.0
                ),
                validation_concurrency=self._as_int(
                    pool_cfg.get("validation_concurrency"), 50, minimum=1
                ),
                probe_host=str(pool_cfg.get("probe_host") or "api.github.com"),
                probe_port=self._as_int(pool_cfg.get("probe_port"), 443, minimum=1),
            )
            self._liveness_stats["proxy_search_rounds"] = round_index + 1
            self._liveness_stats["proxy_search"].append(
                {
                    "round": round_index + 1,
                    "max_candidates": max_candidates,
                    "max_candidates_per_source": max_candidates_per_source,
                    "working": len(pool_urls),
                }
            )
            if len(pool_urls) >= min_proxies:
                break
            if retry_delay > 0 and round_index + 1 < search_rounds:
                await asyncio.sleep(retry_delay)

        if len(pool_urls) < min_proxies:
            logger.warning(
                "Proxy pool search found only %d/%d working SOCKS5 proxies "
                "after %d round(s).",
                len(pool_urls),
                min_proxies,
                search_rounds,
            )
        return pool_urls

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
        self._liveness_stats.update(
            {
                "explicit_proxy": bool(explicit),
                "proxy_pool_enabled": self._as_bool(pool_cfg.get("enabled"), False),
                "proxy_pool_required": self._as_bool(pool_cfg.get("required"), False),
                "proxy_pool_validate": self._as_bool(pool_cfg.get("validate"), True),
            }
        )
        if self._as_bool(pool_cfg.get("enabled"), False):
            try:
                from src.validators.proxy_pool import load_proxy_pool
            except ImportError as exc:
                logger.warning("Proxy pool unavailable: %s", exc)
            else:
                sources = self._source_list(pool_cfg.get("sources"))
                try:
                    pool_urls = await self._search_validator_proxy_pool(
                        load_proxy_pool,
                        sources,
                        pool_cfg,
                    )
                except Exception as exc:
                    logger.warning("Proxy pool load failed: %s", exc)
                else:
                    for proxy_url in pool_urls:
                        if proxy_url not in urls:
                            urls.append(proxy_url)

        self._validator_proxy_urls_cache = urls
        self._liveness_stats["proxy_count"] = len(urls)
        return list(urls)

    async def _validate_liveness_by_list(
        self, configs_by_list: dict[str, list[Config]]
    ) -> dict[str, list[Config]]:
        """Optionally run TCP/TLS liveness checks for each list type."""
        vcfg = self._section("validator")
        tcp_enabled = self._as_bool(vcfg.get("tcp_enabled"), False)
        tls_enabled = self._as_bool(vcfg.get("tls_enabled"), False)
        xray_enabled = self._as_bool(vcfg.get("xray_enabled"), False)
        pool_cfg = self._proxy_pool_config()
        self._liveness_stats = {
            "tcp_enabled": tcp_enabled,
            "tls_enabled": tls_enabled,
            "xray_enabled": xray_enabled,
            "fail_open_on_low_alive": self._as_bool(
                vcfg.get("fail_open_on_low_alive"), True
            ),
            "drop_unchecked_after_tls": self._as_bool(
                vcfg.get("drop_unchecked_after_tls"), False
            ),
            "proxy_pool_enabled": self._as_bool(pool_cfg.get("enabled"), False),
            "proxy_pool_required": self._as_bool(pool_cfg.get("required"), False),
            "proxy_pool_validate": self._as_bool(pool_cfg.get("validate"), True),
            "proxy_attempts_per_config": self._as_int(
                vcfg.get("proxy_attempts_per_config"), 5, minimum=0
            ),
            "tls_proxy_attempts_per_config": self._as_int(
                vcfg.get("tls_proxy_attempts_per_config"),
                self._as_int(vcfg.get("proxy_attempts_per_config"), 5, minimum=0),
                minimum=0,
            ),
            "proxy_count": 0,
            "lists": {},
        }
        if not tcp_enabled and not tls_enabled and not xray_enabled:
            self._liveness_stats["status"] = "disabled"
            return configs_by_list
        self._liveness_stats["status"] = "enabled"

        validated: dict[str, list[Config]] = {}
        for list_type, configs in configs_by_list.items():
            alive = await self._validate_liveness_configs(
                list(configs),
                label=list_type,
                tcp_enabled=tcp_enabled,
                tls_enabled=tls_enabled,
                xray_enabled=xray_enabled,
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
        xray_enabled: bool = False,
    ) -> list[Config]:
        if not configs:
            return []

        vcfg = self._section("validator")
        proxy_urls = await self._validator_proxy_urls()
        pool_cfg = self._proxy_pool_config()
        pool_required = self._as_bool(pool_cfg.get("required"), False)
        pool_enabled = self._as_bool(pool_cfg.get("enabled"), False)
        fail_open_on_low_alive = self._as_bool(
            vcfg.get("fail_open_on_low_alive"), True
        )
        drop_unchecked_after_tls = self._as_bool(
            vcfg.get("drop_unchecked_after_tls"), False
        )
        list_key = normalize_list_type(label)
        list_stats = {
            "input": len(configs),
            "proxy_count": len(proxy_urls),
            "checked": False,
            "filtered": False,
            "fail_open": False,
            "reason": "",
        }
        self._liveness_stats.setdefault("lists", {})[list_key] = list_stats
        if pool_enabled and pool_required and not proxy_urls:
            list_stats["reason"] = "no_proxies"
            if not xray_enabled:
                logger.warning(
                    "Liveness validation for %s skipped: proxy_pool.required=true "
                    "but no proxies are available.",
                    label,
                )
                return configs
            logger.warning(
                "%s proxy pool is empty; continuing with required direct Xray "
                "validation and skipping proxy-network score.",
                label,
            )

        current = list(configs)

        if tcp_enabled:
            checkable = [c for c in current if c.protocol not in _TCP_SKIP_PROTOCOLS]
            passthrough = [c for c in current if c.protocol in _TCP_SKIP_PROTOCOLS]
            list_stats["tcp_candidates"] = len(checkable)
            list_stats["tcp_skipped_protocol"] = len(passthrough)
            if checkable:
                from src.validators.tcp_check import validate_configs_tcp

                candidate_limit = self._as_int(
                    vcfg.get("tcp_candidate_limit"), 1000, minimum=0
                )
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
                list_stats["tcp_max_alive"] = tcp_max_alive

                min_alive = self._liveness_min_alive(len(checkable))
                list_stats["min_alive_to_filter"] = min_alive
                tcp_search_rounds = self._as_int(
                    vcfg.get("tcp_search_rounds"), 3, minimum=1
                )
                if candidate_limit <= 0:
                    tcp_search_rounds = 1
                    candidate_limit = len(checkable)
                list_stats["tcp_search_round_limit"] = tcp_search_rounds

                alive_tcp: list[Config] = []
                alive_keys: set[Any] = set()
                checked_total = 0
                offset = 0
                round_count = 0
                while offset < len(checkable) and round_count < tcp_search_rounds:
                    batch = checkable[offset : offset + candidate_limit]
                    if not batch:
                        break
                    round_count += 1
                    offset += len(batch)
                    checked_total += len(batch)
                    remaining_alive = (
                        max(0, tcp_max_alive - len(alive_tcp))
                        if tcp_max_alive > 0
                        else 0
                    )
                    if tcp_max_alive > 0 and remaining_alive <= 0:
                        break
                    logger.info(
                        "%s TCP validation round %d: checking %d/%d candidates.",
                        label,
                        round_count,
                        checked_total,
                        len(checkable),
                    )
                    batch_alive = await validate_configs_tcp(
                        batch,
                        timeout=self._as_float(
                            vcfg.get("tcp_timeout_seconds"), 5.0, minimum=0.1
                        ),
                        concurrency=self._as_int(
                            vcfg.get("tcp_concurrency"), 300, minimum=1
                        ),
                        max_alive=remaining_alive,
                        proxy_urls=proxy_urls,
                        proxy_attempts_per_config=self._as_int(
                            vcfg.get("proxy_attempts_per_config"), 5, minimum=0
                        ),
                    )
                    for cfg in batch_alive:
                        if cfg.dedup_key in alive_keys:
                            continue
                        alive_keys.add(cfg.dedup_key)
                        alive_tcp.append(cfg)
                    if tcp_max_alive > 0 and len(alive_tcp) >= tcp_max_alive:
                        break

                list_stats["tcp_checked"] = checked_total
                list_stats["tcp_search_rounds"] = round_count
                list_stats["checked"] = True
                list_stats["tcp_alive"] = len(alive_tcp)
                if len(alive_tcp) < min_alive:
                    list_stats["reason"] = "below_min_alive"
                    if fail_open_on_low_alive:
                        logger.warning(
                            "%s TCP validation found %d/%d alive (<%d). "
                            "Keeping unfiltered configs.",
                            label,
                            len(alive_tcp),
                            len(checkable),
                            min_alive,
                        )
                        list_stats["fail_open"] = True
                        return configs
                    logger.warning(
                        "%s TCP validation found %d/%d alive (<%d). "
                        "Strict mode keeps only alive configs.",
                        label,
                        len(alive_tcp),
                        len(checkable),
                        min_alive,
                    )
                current = alive_tcp + passthrough
                list_stats["filtered"] = True
                list_stats["output_after_tcp"] = len(current)
                logger.info(
                    "%s after TCP validation: %d alive, %d TCP-skipped.",
                    label,
                    len(alive_tcp),
                    len(passthrough),
                )

        if tls_enabled:
            tls_checkable = [
                c for c in current if str(c.security or "").lower() in ("tls", "reality")
            ]
            if tls_checkable:
                from src.validators.tls_check import validate_configs_tls

                before_tls = list(current)
                tls_passthrough = [
                    c
                    for c in current
                    if str(c.security or "").lower() not in ("tls", "reality")
                ]
                list_stats["tls_unchecked_passthrough"] = len(tls_passthrough)
                list_stats["tls_drop_unchecked"] = drop_unchecked_after_tls
                if drop_unchecked_after_tls:
                    tls_passthrough = []
                list_stats["tls_candidates"] = len(tls_checkable)
                candidate_limit = self._as_int(
                    vcfg.get("tls_candidate_limit"), 1000, minimum=0
                )
                if candidate_limit > 0 and len(tls_checkable) > candidate_limit:
                    logger.info(
                        "%s TLS validation candidate cap: checking first %d/%d.",
                        label,
                        candidate_limit,
                        len(tls_checkable),
                    )
                    tls_checkable = tls_checkable[:candidate_limit]
                list_stats["tls_checked"] = len(tls_checkable)
                alive_tls = await validate_configs_tls(
                    tls_checkable,
                    timeout=self._as_float(
                        vcfg.get("tls_timeout_seconds"), 5.0, minimum=0.1
                    ),
                    concurrency=self._as_int(
                        vcfg.get("tls_concurrency"), 100, minimum=1
                    ),
                    proxy_urls=proxy_urls,
                    proxy_attempts_per_config=self._as_int(
                        vcfg.get("tls_proxy_attempts_per_config"),
                        self._as_int(
                            vcfg.get("proxy_attempts_per_config"), 5, minimum=0
                        ),
                        minimum=0,
                    ),
                )
                list_stats["checked"] = True
                list_stats["tls_alive"] = len(alive_tls)
                min_alive = self._liveness_min_alive(len(tls_checkable))
                if len(alive_tls) < min_alive:
                    list_stats["reason"] = "tls_below_min_alive"
                    if fail_open_on_low_alive:
                        logger.warning(
                            "%s TLS validation left %d/%d configs (<%d). "
                            "Keeping pre-TLS configs.",
                            label,
                            len(alive_tls),
                            len(tls_checkable),
                            min_alive,
                        )
                        list_stats["fail_open"] = True
                        return before_tls
                    logger.warning(
                        "%s TLS validation left %d/%d configs (<%d). "
                        "Strict mode keeps only TLS-alive configs.",
                        label,
                        len(alive_tls),
                        len(tls_checkable),
                        min_alive,
                    )
                current = alive_tls + tls_passthrough
                list_stats["filtered"] = True
                list_stats["output_after_tls"] = len(current)
                logger.info("%s after TLS validation: %d configs.", label, len(current))
            elif drop_unchecked_after_tls:
                list_stats["checked"] = True
                list_stats["tls_candidates"] = 0
                list_stats["tls_checked"] = 0
                list_stats["tls_alive"] = 0
                list_stats["tls_unchecked_passthrough"] = len(current)
                list_stats["tls_drop_unchecked"] = True
                list_stats["filtered"] = True
                list_stats["output_after_tls"] = 0
                logger.warning(
                    "%s TLS validation has no TLS/REALITY candidates. "
                    "Strict mode drops %d TCP-only configs.",
                    label,
                    len(current),
                )
                current = []

        if xray_enabled and current:
            from src.validators.xray_probe import (
                find_xray_executable,
                is_xray_supported,
                validate_configs_xray,
            )

            xray_path = find_xray_executable(str(vcfg.get("xray_executable") or ""))
            xray_required = self._as_bool(vcfg.get("xray_required"), False)
            list_stats["xray_required"] = xray_required
            list_stats["xray_available"] = bool(xray_path)
            if not xray_path:
                list_stats["xray_checked"] = 0
                list_stats["xray_alive"] = 0
                list_stats["reason"] = "xray_unavailable"
                if xray_required:
                    logger.warning(
                        "%s Xray validation required but xray executable "
                        "is unavailable. Dropping configs.",
                        label,
                    )
                    return []
                logger.warning(
                    "%s Xray validation skipped: xray executable unavailable.",
                    label,
                )
                return current

            supported = [cfg for cfg in current if is_xray_supported(cfg)]
            unsupported = len(current) - len(supported)
            drop_unsupported = self._as_bool(
                vcfg.get("xray_drop_unsupported"), True
            )
            list_stats["xray_candidates"] = len(supported)
            list_stats["xray_unsupported"] = unsupported
            list_stats["xray_drop_unsupported"] = drop_unsupported
            if not supported:
                list_stats["xray_checked"] = 0
                list_stats["xray_alive"] = 0
                list_stats["reason"] = "xray_no_supported_candidates"
                return [] if drop_unsupported else current

            candidate_limit = self._as_int(
                vcfg.get("xray_candidate_limit"), 0, minimum=0
            )
            xray_candidate_limit_by_list = vcfg.get("xray_candidate_limit_by_list", {})
            if isinstance(xray_candidate_limit_by_list, dict):
                specific_candidate_limit = xray_candidate_limit_by_list.get(list_key)
                if specific_candidate_limit is not None:
                    candidate_limit = self._as_int(
                        specific_candidate_limit,
                        candidate_limit,
                        minimum=0,
                    )
            if candidate_limit > 0:
                supported = self._xray_candidate_preselect(
                    supported,
                    candidate_limit,
                    list_key,
                )
            list_stats["xray_preselected"] = len(supported)

            xray_max_alive = self._as_int(vcfg.get("xray_max_alive"), 0, minimum=0)
            xray_max_alive_by_list = vcfg.get("xray_max_alive_by_list", {})
            if isinstance(xray_max_alive_by_list, dict):
                specific_max_alive = xray_max_alive_by_list.get(
                    normalize_list_type(label)
                )
                if specific_max_alive is not None:
                    xray_max_alive = self._as_int(
                        specific_max_alive,
                        xray_max_alive,
                        minimum=0,
                    )

            list_stats["xray_checked"] = len(supported)
            list_stats["xray_max_alive"] = xray_max_alive
            probe_urls_raw = vcfg.get("xray_probe_urls")
            if isinstance(probe_urls_raw, str):
                xray_probe_urls = [
                    part.strip()
                    for part in probe_urls_raw.replace(";", ",").split(",")
                    if part.strip()
                ]
            elif isinstance(probe_urls_raw, list):
                xray_probe_urls = [
                    str(part).strip() for part in probe_urls_raw if str(part).strip()
                ]
            else:
                xray_probe_urls = []
            if not xray_probe_urls:
                xray_probe_urls = [
                    str(
                        vcfg.get("xray_probe_url")
                        or "https://www.gstatic.com/generate_204"
                    )
                ]
            xray_min_probe_successes = self._as_int(
                vcfg.get("xray_min_probe_successes"),
                1,
                minimum=1,
            )
            xray_min_probe_successes = min(
                xray_min_probe_successes,
                len(xray_probe_urls),
            )
            xray_attempts_per_config = self._as_int(
                vcfg.get("xray_attempts_per_config"),
                1,
                minimum=1,
            )
            xray_min_attempt_successes = self._as_int(
                vcfg.get("xray_min_attempt_successes"),
                xray_attempts_per_config,
                minimum=1,
            )
            xray_min_attempt_successes = min(
                xray_min_attempt_successes,
                xray_attempts_per_config,
            )
            list_stats["xray_probe_count"] = len(xray_probe_urls)
            list_stats["xray_min_probe_successes"] = xray_min_probe_successes
            list_stats["xray_attempts_per_config"] = xray_attempts_per_config
            list_stats["xray_min_attempt_successes"] = xray_min_attempt_successes
            proxy_probe_count = self._as_int(
                vcfg.get("xray_proxy_probe_count"),
                0,
                minimum=0,
            )
            xray_proxy_urls = proxy_urls[:proxy_probe_count] if proxy_probe_count else []
            xray_min_proxy_successes = self._as_int(
                vcfg.get("xray_min_proxy_successes"),
                0,
                minimum=0,
            )
            xray_min_proxy_successes = min(
                xray_min_proxy_successes,
                len(xray_proxy_urls),
            )
            list_stats["xray_proxy_checks"] = len(xray_proxy_urls)
            list_stats["xray_min_proxy_successes"] = xray_min_proxy_successes
            alive_xray = await validate_configs_xray(
                supported,
                xray_path=xray_path,
                probe_urls=xray_probe_urls,
                min_probe_successes=xray_min_probe_successes,
                attempts_per_config=xray_attempts_per_config,
                min_attempt_successes=xray_min_attempt_successes,
                probe_proxy_urls=xray_proxy_urls,
                min_proxy_successes=xray_min_proxy_successes,
                timeout=self._as_float(
                    vcfg.get("xray_timeout_seconds"), 12.0, minimum=1.0
                ),
                startup_timeout=self._as_float(
                    vcfg.get("xray_startup_timeout_seconds"), 4.0, minimum=0.5
                ),
                concurrency=self._as_int(
                    vcfg.get("xray_concurrency"), 6, minimum=1
                ),
                max_alive=xray_max_alive,
            )
            list_stats["checked"] = True
            list_stats["filtered"] = True
            list_stats["xray_alive"] = len(alive_xray)
            self._update_health_history(supported)
            self._update_source_health(supported, list_stats)
            alive_xray = [
                cfg for cfg in alive_xray if not self._is_health_or_source_banned(cfg)
            ]
            list_stats["output_after_health"] = len(alive_xray)
            list_stats["output_after_xray"] = len(alive_xray)
            current = alive_xray
            logger.info("%s after Xray validation: %d configs.", label, len(current))

        return current

    # --- stage 3+5: aggregate (split into dedup + sort/limit) ---

    def _xray_candidate_preselect(
        self, configs: list[Config], max_total: int, list_type: str
    ) -> list[Config]:
        """Preselect only configs that could enter the final subscription."""
        if normalize_list_type(list_type) == "whitelist":
            return self._whitelist_balance(configs, max_total)
        return self._country_balanced_limit(configs, max_total)

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
        max_configs = self._max_configs()
        try:
            return self._country_balanced_limit(configs, max_configs)
        except Exception as exc:
            logger.error("sort_and_limit failed: %s — passing through.", exc)
            return configs[:max_configs]

    def _country_balanced_limit(
        self, configs: list[Config], max_total: int
    ) -> list[Config]:
        """Limit configs by taking one server per country in repeated rounds."""
        if max_total <= 0 or not configs:
            return []

        acfg = self._section("aggregator")
        sort_by = str(acfg.get("sort_by", "country"))
        try:
            max_per_country = int(acfg.get("max_per_country", 0))
        except (TypeError, ValueError):
            max_per_country = 0

        try:
            from src.aggregator.merger import sort_configs
        except (ImportError, AttributeError) as exc:
            logger.error("Cannot import sort_configs: %s — skipping sort.", exc)
            sorted_configs = list(configs)
        else:
            sorted_configs = sort_configs(
                [cfg for cfg in configs if cfg.country is not None],
                sort_by=sort_by,
            )

        groups: dict[str, list[Config]] = {}
        for cfg in sorted_configs:
            if cfg.country is None:
                continue
            country = str(cfg.country).upper()
            bucket = groups.setdefault(country, [])
            if max_per_country > 0 and len(bucket) >= max_per_country:
                continue
            bucket.append(cfg)

        for bucket in groups.values():
            bucket.sort(
                key=lambda cfg: (
                    -float(getattr(cfg, "quality_score", 0) or 0),
                    cfg.latency_ms is None,
                    float(cfg.latency_ms if cfg.latency_ms is not None else 10**9),
                )
            )

        countries = sorted(groups)
        result: list[Config] = []
        indexes = {country: 0 for country in countries}
        while len(result) < max_total:
            progressed = False
            for country in countries:
                index = indexes[country]
                bucket = groups[country]
                if index >= len(bucket):
                    continue
                result.append(bucket[index])
                indexes[country] = index + 1
                progressed = True
                if len(result) >= max_total:
                    break
            if not progressed:
                break

        return result

    def _quality_cfg(self) -> dict[str, Any]:
        cfg = self._section("quality")
        return cfg if isinstance(cfg, dict) else {}

    def _health_history_file(self) -> str | None:
        raw = self._quality_cfg().get("health_history_file", "output/health-history.json")
        return str(raw) if raw else None

    def _load_health_history(self) -> dict[str, Any]:
        if self._health_history is not None:
            return self._health_history
        path = self._health_history_file()
        if not path:
            self._health_history = {"configs": {}, "sources": {}}
            return self._health_history
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except Exception:
            data = {}
        if not isinstance(data, dict):
            data = {}
        data.setdefault("configs", {})
        data.setdefault("sources", {})
        self._health_history = data
        return data

    def _write_health_history(self) -> str | None:
        path = self._health_history_file()
        if not path or self._health_history is None:
            return None
        payload = dict(self._health_history)
        payload["updated_at"] = int(time.time())
        try:
            target = Path(path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
                encoding="utf-8",
            )
        except Exception as exc:
            logger.warning("Could not write health history %s: %s", path, exc)
            return None
        return path

    @staticmethod
    def _config_health_key(cfg: Config) -> str:
        raw = cfg.raw_link or "|".join(
            [
                str(cfg.protocol),
                str(cfg.address),
                str(cfg.port),
                str(cfg.uuid_or_password),
                str(cfg.network),
                str(cfg.security),
            ]
        )
        return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()

    def _update_health_history(self, checked_configs: list[Config]) -> None:
        if not self._as_bool(self._quality_cfg().get("health_history_enabled"), True):
            return
        history = self._load_health_history()
        records = history.setdefault("configs", {})
        now = int(time.time())
        max_recent = self._as_int(
            self._quality_cfg().get("health_recent_window"), 5, minimum=1
        )
        fail_threshold = self._as_int(
            self._quality_cfg().get("ban_after_consecutive_failures"), 2, minimum=1
        )
        cooldown_seconds = int(
            self._as_float(
                self._quality_cfg().get("ban_cooldown_hours"), 12.0, minimum=0.1
            )
            * 3600
        )
        for cfg in checked_configs:
            key = self._config_health_key(cfg)
            record = records.setdefault(
                key,
                {
                    "passes": 0,
                    "fails": 0,
                    "consecutive_failures": 0,
                    "recent": [],
                    "banned_until": 0,
                },
            )
            alive = bool(getattr(cfg, "is_alive", False))
            recent = list(record.get("recent") or [])
            recent.append(alive)
            record["recent"] = recent[-max_recent:]
            record["last_seen"] = now
            record["last_alive"] = now if alive else int(record.get("last_alive") or 0)
            record["source"] = getattr(cfg, "source_name", "")
            record["country"] = getattr(cfg, "country", "")
            if alive:
                record["passes"] = int(record.get("passes") or 0) + 1
                record["consecutive_failures"] = 0
                record["banned_until"] = 0
            else:
                failures = int(record.get("consecutive_failures") or 0) + 1
                record["fails"] = int(record.get("fails") or 0) + 1
                record["consecutive_failures"] = failures
                if failures >= fail_threshold:
                    record["banned_until"] = now + cooldown_seconds
            setattr(cfg, "health_record", record)

    def _source_run_stats(self, checked_configs: list[Config]) -> dict[str, dict[str, int]]:
        stats: dict[str, dict[str, int]] = {}
        for cfg in checked_configs:
            source = str(getattr(cfg, "source_name", "?") or "?")
            item = stats.setdefault(source, {"checked": 0, "alive": 0})
            item["checked"] += 1
            if getattr(cfg, "is_alive", False):
                item["alive"] += 1
        return stats

    def _update_source_health(
        self, checked_configs: list[Config], list_stats: dict[str, Any]
    ) -> None:
        qcfg = self._quality_cfg()
        source_stats = self._source_run_stats(checked_configs)
        list_stats["sources"] = source_stats
        if not self._as_bool(qcfg.get("source_health_enabled"), True):
            return
        min_checked = self._as_int(qcfg.get("source_min_checked"), 50, minimum=1)
        bad_rate = self._as_float(qcfg.get("source_bad_alive_rate"), 0.02, minimum=0.0)
        bad_runs = self._as_int(qcfg.get("source_bad_runs_to_ban"), 2, minimum=1)
        cooldown_seconds = int(
            self._as_float(qcfg.get("source_ban_cooldown_hours"), 12.0, minimum=0.1)
            * 3600
        )
        now = int(time.time())
        history = self._load_health_history().setdefault("sources", {})
        for source, stats in source_stats.items():
            checked = int(stats["checked"])
            alive = int(stats["alive"])
            rate = alive / checked if checked else 0.0
            record = history.setdefault(
                source, {"runs": 0, "bad_runs": 0, "banned_until": 0}
            )
            record["runs"] = int(record.get("runs") or 0) + 1
            record["last_checked"] = checked
            record["last_alive"] = alive
            record["last_alive_rate"] = rate
            record["updated_at"] = now
            if checked >= min_checked and rate <= bad_rate:
                record["bad_runs"] = int(record.get("bad_runs") or 0) + 1
                if int(record["bad_runs"]) >= bad_runs:
                    record["banned_until"] = now + cooldown_seconds
            else:
                record["bad_runs"] = 0
                record["banned_until"] = 0

    def _is_health_or_source_banned(self, cfg: Config) -> bool:
        if not self._as_bool(self._quality_cfg().get("health_history_enabled"), True):
            return False
        now = int(time.time())
        history = self._load_health_history()
        record = history.get("configs", {}).get(self._config_health_key(cfg), {})
        if int(record.get("banned_until") or 0) > now:
            setattr(cfg, "quality_block_reason", "health_ban")
            return True
        source = str(getattr(cfg, "source_name", "?") or "?")
        source_record = history.get("sources", {}).get(source, {})
        if int(source_record.get("banned_until") or 0) > now:
            setattr(cfg, "quality_block_reason", "source_ban")
            return True
        return False

    def _quality_score(self, cfg: Config) -> float:
        qcfg = self._quality_cfg()
        score = 60.0 if getattr(cfg, "is_alive", False) else 0.0
        record = self._load_health_history().get("configs", {}).get(
            self._config_health_key(cfg),
            {},
        )
        recent = list(record.get("recent") or [])
        if sum(1 for item in recent[-3:] if item) >= 2:
            score += 20.0
        if cfg.latency_ms is not None:
            max_latency = self._as_float(qcfg.get("max_latency_ms"), 10000.0, minimum=1.0)
            if cfg.latency_ms <= max_latency:
                score += max(0.0, 10.0 * (1.0 - (float(cfg.latency_ms) / max_latency)))
        if getattr(cfg, "country", None):
            score += 5.0
        source = str(getattr(cfg, "source_name", "?") or "?")
        source_record = self._load_health_history().get("sources", {}).get(source, {})
        source_rate = float(source_record.get("last_alive_rate") or 0.0)
        if source_rate >= self._as_float(qcfg.get("source_good_alive_rate"), 0.2, minimum=0.0):
            score += 5.0
        proxy_checks = int(getattr(cfg, "xray_proxy_checks", 0) or 0)
        proxy_successes = int(getattr(cfg, "xray_proxy_successes", 0) or 0)
        if proxy_checks:
            score += min(5.0, 5.0 * (proxy_successes / proxy_checks))
        return score

    def _apply_quality_filters(
        self, configs_by_list: dict[str, list[Config]]
    ) -> dict[str, list[Config]]:
        qcfg = self._quality_cfg()
        max_latency = self._as_float(qcfg.get("max_latency_ms"), 10000.0, minimum=1.0)
        drop_slow = self._as_bool(qcfg.get("drop_slow_configs"), True)
        result: dict[str, list[Config]] = {}
        quality_stats: dict[str, Any] = {"drop_slow": drop_slow, "max_latency_ms": max_latency}
        for list_type, configs in configs_by_list.items():
            kept: list[Config] = []
            slow_dropped = 0
            for cfg in configs:
                if drop_slow and cfg.latency_ms is not None and cfg.latency_ms > max_latency:
                    slow_dropped += 1
                    continue
                score = self._quality_score(cfg)
                setattr(cfg, "quality_score", score)
                kept.append(cfg)
            kept.sort(
                key=lambda cfg: (
                    -float(getattr(cfg, "quality_score", 0) or 0),
                    cfg.latency_ms is None,
                    float(cfg.latency_ms if cfg.latency_ms is not None else 10**9),
                )
            )
            if kept:
                result[list_type] = kept
            quality_stats[list_type] = {
                "input": len(configs),
                "kept": len(kept),
                "slow_dropped": slow_dropped,
                "avg_score": (
                    sum(float(getattr(cfg, "quality_score", 0) or 0) for cfg in kept)
                    / len(kept)
                    if kept
                    else 0
                ),
            }
        self._liveness_stats["quality"] = quality_stats
        return result

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
        vcfg = self._section("validator")
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

        ru_sorted = self._country_balanced_limit(ru, max_total)
        eu_sorted = self._country_balanced_limit(eu, max_total)

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
        self._clear_location_outputs()

    def _write_empty_split_outputs(self, combined_output_file: str) -> None:
        """Clear configured split outputs on empty runs."""
        for split_file in self._split_output_files(combined_output_file).values():
            self._write_empty_output(split_file)

    def _location_output_config(self) -> tuple[bool, str, int]:
        pcfg = self._section("publisher")
        enabled = self._as_bool(pcfg.get("location_outputs_enabled"), True)
        output_dir = str(pcfg.get("location_output_dir") or "output/locations")
        limit = self._as_int(pcfg.get("location_output_limit"), 50, minimum=1)
        return enabled, output_dir, limit

    @staticmethod
    def _location_output_filename(country: str) -> str:
        code = "".join(ch for ch in country.upper() if ch.isalnum())
        return f"subscription-{code or 'XX'}.txt"

    def _clear_location_outputs(self) -> None:
        enabled, output_dir, _limit = self._location_output_config()
        if not enabled:
            return
        root = Path(output_dir)
        if not root.exists():
            return
        for path in root.glob("subscription-*.txt"):
            try:
                path.unlink()
            except OSError as exc:
                logger.warning("Failed to remove stale location output %s: %s", path, exc)

    def _build_location_outputs(
        self, configs: list[Config], per_location_limit: int
    ) -> dict[str, list[Config]]:
        groups: dict[str, list[Config]] = {}
        for cfg in configs:
            if not cfg.raw_link or not getattr(cfg, "country", None):
                continue
            country = str(cfg.country).upper()
            groups.setdefault(country, []).append(cfg)

        return {
            country: self._country_balanced_limit(country_configs, per_location_limit)
            for country, country_configs in sorted(groups.items())
        }

    def _write_location_outputs(self, configs: list[Config]) -> list[str]:
        enabled, output_dir, limit = self._location_output_config()
        if not enabled:
            return []

        self._clear_location_outputs()
        outputs = self._build_location_outputs(configs, limit)
        output_files: list[str] = []
        for country, country_configs in outputs.items():
            output_file = str(Path(output_dir) / self._location_output_filename(country))
            count = self._write_output(country_configs, output_file)
            self._record_output_stats(f"location_{country.lower()}", output_file, country_configs)
            output_files.append(output_file)
            logger.info(
                "Wrote %d %s location configs to %s.",
                count,
                country,
                output_file,
            )
        return output_files

    def _status_output_file(self) -> str | None:
        """Return run-summary output path, if configured."""
        pcfg = self._section("publisher")
        raw = pcfg.get("status_output_file")
        if not raw:
            return None
        return str(raw)

    def _record_output_stats(
        self, name: str, output_file: str, configs: list[Config]
    ) -> None:
        """Store exact output counts/countries before raw links lose metadata."""
        country_counts = Counter(
            str(cfg.country).upper()
            for cfg in configs
            if cfg.raw_link and getattr(cfg, "country", None)
        )
        self._output_stats[name] = {
            "file": output_file,
            "count": sum(1 for cfg in configs if cfg.raw_link),
            "countries": dict(country_counts.most_common()),
        }

    def _write_run_summary(self, status: str) -> str | None:
        """Write machine-readable run metadata for Telegram and debugging."""
        output_file = self._status_output_file()
        if not output_file:
            return None

        payload = {
            "status": status,
            "outputs": self._output_stats,
            "validation": self._liveness_stats,
        }
        path = Path(output_file)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
                encoding="utf-8",
            )
        except Exception as exc:
            logger.warning("Could not write run summary %s: %s", output_file, exc)
            return None
        return output_file

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
