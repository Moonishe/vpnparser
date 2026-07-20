"""Pipeline orchestrator — fetch -> parse -> filter -> aggregate -> write -> publish.

``PipelineRunner`` ties together every stage of the VPN config pipeline:

1. **Fetch**    — ``SourceManager.fetch_all()`` pulls files from configured sources.
2. **Parse**    — ``_parse_all_by_list()`` extracts proxy links and turns them into
                   ``Config`` objects grouped by source ``list_type`` (list type).
3. **Filter**   — garbage/placeholder filter -> sample -> dedup -> country filter.
4. **Aggregate**— interleave blacklist+whitelist -> sort -> per-country limit.
5. **Write**    — ``write_subscription()`` emits combined, mix, and split files.
6. **Publish**  — (optional) commit outputs to a GitHub repo via Contents API.

Each stage is wrapped so a failure is logged and, where possible, the pipeline
continues with whatever data survived the previous stage.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from collections import Counter
from typing import Any

from src.parsers.base import Config
from src.scheduler.context import PipelineContext, PipelineState
from src.scheduler.health_history import HealthHistory
from src.scheduler.settings import Settings, load_settings
from src.scheduler.stages.aggregate import Aggregator
from src.scheduler.stages.fetch import SourceFetcher
from src.scheduler.stages.filter import (
    CountryFilter,
    DedupFilter,
    GarbageFilter,
    PreprocessFilter,
)
from src.scheduler.stages.liveness import LivenessValidator
from src.scheduler.stages.parse import LinkParser
from src.scheduler.stages.quality import QualityFilter
from src.scheduler.stages.write import OutputWriter
from src.sources.list_types import normalize_list_type
from src.utils.paths import resolve_safe_output_path

logger = logging.getLogger(__name__)

_TCP_SKIP_PROTOCOLS = {"tuic", "hysteria2"}


class PipelineRunner:
    """Orchestrates the full pipeline: fetch -> parse -> validate -> aggregate -> publish."""  # noqa: E501

    def __init__(
        self,
        settings_path: str = "config/settings.yaml",
        sources_path: str = "config/sources.json",
        github_token: str | None = None,
    ) -> None:
        self.settings_path = settings_path
        self.sources_path = sources_path
        self.github_token = github_token or os.environ.get("GITHUB_TOKEN")
        self._settings = Settings(load_settings(settings_path))
        # Public attribute retained for compatibility with tests/debug code.
        self.settings: dict[str, Any] = self._settings._data
        self._context = PipelineContext(
            settings=self._settings,
            github_token=self.github_token,
            sources_path=self.sources_path,
            settings_path=self.settings_path,
        )
        self._validator_proxy_urls_cache: list[str] | None = None
        self._liveness_stats: dict[str, Any] = {}
        self._output_stats: dict[str, Any] = {}
        self._health_history: dict[str, Any] | None = None
        self._proxy_health_history: Any | None = None
        self._proxy_health_file: str | None = None
        self._fetcher = SourceFetcher()
        self._parser = LinkParser(self._context)
        self._preprocessor = PreprocessFilter(self._context)
        self._aggregator = Aggregator(self._context)
        self._writer = OutputWriter(self._context)
        self._health_history = HealthHistory(self._settings)
        self._liveness = LivenessValidator(
            self._context,
            health=self._health_history,
            proxy_url_getter=lambda: self._validator_proxy_urls(),
            update_health_callback=lambda configs: self._update_health_history(configs),
            update_source_health_callback=lambda configs, stats: (
                self._update_source_health(configs, stats)
            ),
        )
        self._quality = QualityFilter(self._context, health=self._health_history)
        self._state = PipelineState()
        # Delegate proxy health history to the LivenessValidator (single source
        # of truth) so _save_proxy_health_history() actually persists it.
        self._proxy_health_history = self._liveness._proxy_health_history
        self._proxy_health_file = self._liveness._proxy_health_file

    # --- settings ---

    @staticmethod
    def _load_settings(path: str) -> dict[str, Any]:
        """Deprecated: use ``src.scheduler.settings.load_settings``."""
        return load_settings(path)

    def _section(self, key: str) -> dict[str, Any]:
        """Return a settings section (empty dict if missing)."""
        return self._settings.section(key)

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
        self._publish_ok = False
        self._liveness.reset_proxy_cache()
        logger.info("Pipeline started.")

        # 1. Fetch all sources.
        results = await self._fetch_sources()
        if not results:
            logger.warning("No source results fetched — pipeline produced nothing.")
            return await self._finish_empty_run(
                output_file,
                status="no_sources",
                publish=publish,
            )

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
                "No configs parsed from sources — pipeline produced nothing.",
            )
            return await self._finish_empty_run(
                output_file,
                status="no_configs_parsed",
                publish=publish,
            )

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
            return await self._finish_empty_run(
                output_file,
                status="no_allowed_countries",
                publish=publish,
            )

        preprocessed_by_list = await self._validate_liveness_by_list(
            preprocessed_by_list,
        )
        if not preprocessed_by_list:
            logger.warning("No configs survived liveness validation.")
            return await self._finish_empty_run(
                output_file,
                status="no_live_configs",
                publish=publish,
            )
        preprocessed_by_list = self._apply_quality_filters(preprocessed_by_list)
        if not preprocessed_by_list:
            logger.warning("No configs survived quality/history filters.")
            return await self._finish_empty_run(
                output_file,
                status="no_quality_configs",
                publish=publish,
            )

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
                    "Wrote %d %s configs to %s.",
                    split_count,
                    list_type,
                    split_file,
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

        self._save_proxy_health_history()

        # 7. Publish (optional).
        if publish:
            self._publish_ok = await self._publish_files(
                output_files,
                combined_output_file=output_file,
            )

        elapsed = time.monotonic() - start
        logger.info("Pipeline finished in %.2fs with %d configs.", elapsed, count)
        return count

    # --- stage 1: fetch ---

    async def _fetch_sources(self) -> list[Any]:
        """Fetch all sources via the SourceFetcher stage."""
        self._state = await self._fetcher.run(self._state, self._context)
        return self._state.sources

    # --- stage 2: parse ---

    async def _parse_all_by_list(
        self,
        results: list[Any],
    ) -> dict[str, list[Config]]:
        """Parse all source results grouped by normalized list type."""
        self._state.sources = list(results)
        self._state = await self._parser.run(self._state, self._context)
        return self._state.parsed

    @staticmethod
    def _filter_garbage(configs: list[Config]) -> tuple[list[Config], int]:
        """Remove placeholder/template configs. Delegates to GarbageFilter."""
        return GarbageFilter.filter_garbage(configs)

    # --- stage 3: country filter ---

    def _filter_countries(
        self,
        configs: list[Config],
        *,
        list_type: str = "mixed",
    ) -> list[Config]:
        """Filter configs by allowed countries. Delegates to CountryFilter."""
        return CountryFilter(self._context).filter_countries(
            configs,
            list_type=list_type,
        )

    # --- optional network liveness validation ---

    async def _validator_proxy_urls(self) -> list[str]:
        """Return configured validator proxies, including optional free pool."""
        return await self._liveness._validator_proxy_urls()

    async def _search_validator_proxy_pool(
        self,
        load_proxy_pool: Any,
        sources: list[str] | None,
        pool_cfg: dict[str, Any],
    ) -> list[str]:
        """Search for working SOCKS5 proxies. Kept for compatibility."""
        result = await self._liveness._search_validator_proxy_pool(
            load_proxy_pool,
            sources,
            pool_cfg,
        )
        self._liveness_stats = self._context.liveness_stats
        return result

    @staticmethod
    def _redact_proxy_url(proxy_url: str) -> str:
        """Redact credentials from a proxy URL."""
        return LivenessValidator._redact_proxy_url(proxy_url)

    async def _validate_liveness_by_list(
        self,
        configs_by_list: dict[str, list[Config]],
    ) -> dict[str, list[Config]]:
        """Optionally run TCP/TLS/Xray liveness checks for each list type."""
        result = await self._liveness.validate_by_list(configs_by_list)
        self._liveness_stats = self._context.liveness_stats
        return result

    async def _validate_liveness_configs(
        self,
        configs: list[Config],
        *,
        label: str,
        tcp_enabled: bool,
        tls_enabled: bool,
        xray_enabled: bool = False,
    ) -> list[Config]:
        """Validate a single list's configs."""
        result = await self._liveness.validate_configs(
            configs,
            label=label,
            tcp_enabled=tcp_enabled,
            tls_enabled=tls_enabled,
            xray_enabled=xray_enabled,
        )
        self._liveness_stats = self._context.liveness_stats
        return result

    # --- stage 3+5: aggregate (split into dedup + sort/limit) ---

    def _xray_candidate_preselect(
        self,
        configs: list[Config],
        max_total: int,
        list_type: str,
    ) -> list[Config]:
        """Preselect only configs that could enter the final subscription."""
        if normalize_list_type(list_type) == "whitelist":
            return self._whitelist_balance(configs, max_total)
        return self._country_balanced_limit(configs, max_total)

    def _dedup_only(self, configs: list[Config]) -> list[Config]:
        """Deduplicate configs by (address, port). Delegates to DedupFilter."""
        return DedupFilter.dedup_only(configs)

    def _sort_and_limit(self, configs: list[Config]) -> list[Config]:
        """Sort and limit configs (dedup already done). Delegates to Aggregator."""
        return self._aggregator._sort_and_limit(configs)

    def _country_balanced_limit(
        self,
        configs: list[Config],
        max_total: int,
    ) -> list[Config]:
        """Limit configs by taking one server per country in repeated rounds."""
        return self._aggregator._country_balanced_limit(configs, max_total)

    def _quality_cfg(self) -> dict[str, Any]:
        """Access the quality settings section. Kept for compatibility."""
        return self._quality.settings.section("quality")

    def _health_history_file(self) -> str | None:
        return self._quality.health._file()

    def _load_health_history(self) -> dict[str, Any]:
        """Load health history. Kept for compatibility."""
        return self._quality.health.load()

    def _write_health_history(self) -> str | None:
        """Persist health history. Kept for compatibility."""
        return self._quality.health.save()

    @staticmethod
    def _config_health_key(cfg: Config) -> str:
        """Stable key for a config in health history."""
        return HealthHistory.config_key(cfg)

    def _update_health_history(self, checked_configs: list[Config]) -> None:
        """Update per-config health history. Kept for compatibility."""
        self._quality.health.update(checked_configs)

    def _source_run_stats(
        self,
        checked_configs: list[Config],
    ) -> dict[str, dict[str, int]]:
        """Compute source run statistics. Kept for compatibility."""
        return self._quality.health.source_run_stats(checked_configs)

    def _update_source_health(
        self,
        checked_configs: list[Config],
        list_stats: dict[str, Any],
    ) -> None:
        """Update per-source health history. Kept for compatibility."""
        self._quality.health.update_sources(checked_configs, list_stats)

    def _is_health_or_source_banned(self, cfg: Config) -> bool:
        """Check if a config is banned. Kept for compatibility."""
        return self._quality.is_banned(cfg)

    def _quality_score(self, cfg: Config) -> float:
        """Compute quality score. Kept for compatibility."""
        return self._quality.health.score(cfg)

    def _apply_quality_filters(
        self,
        configs_by_list: dict[str, list[Config]],
    ) -> dict[str, list[Config]]:
        """Apply quality filters. Delegates to QualityFilter."""
        result = self._quality.apply(configs_by_list)
        self._liveness_stats["quality"] = self._context.liveness_stats["quality"]
        return result

    def _preprocess_configs(
        self,
        configs: list[Config],
        *,
        label: str,
    ) -> list[Config]:
        """Preprocess configs: garbage -> sample -> dedup -> country filter."""
        return self._preprocessor.preprocess(configs, label=label)

    def _whitelist_balance(self, configs: list[Config], max_total: int) -> list[Config]:
        """Build whitelist output: mostly RU servers plus EU fallback servers."""
        return self._aggregator._whitelist_balance(configs, max_total)

    def _build_mixed_output(
        self,
        preprocessed_by_list: dict[str, list[Config]],
        max_total: int,
    ) -> list[Config]:
        """Build a strict 50/50 blacklist + whitelist mix from live configs."""
        return self._aggregator._build_mixed_output(preprocessed_by_list, max_total)

    @staticmethod
    def _take_unique_configs(
        configs: list[Config],
        target: int,
        used_keys: set[Any],
    ) -> list[Config]:
        """Take up to target configs, skipping keys already used by another list."""
        return Aggregator._take_unique_configs(configs, target, used_keys)

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
            combined_output_file,
            split_output_files,
        )
        if mix_output_file:
            self._write_empty_output(mix_output_file)
        self._clear_location_outputs()

    def _configured_subscription_output_paths(
        self,
        combined_output_file: str,
    ) -> list[str]:
        """Return all subscription paths that should stay in sync on every run.

        Includes combined, mix, and split outputs. Location files are omitted
        here because empty runs clear them rather than rewriting placeholders.
        """
        paths: list[str] = [combined_output_file]
        split_output_files = self._split_output_files(combined_output_file)
        paths.extend(split_output_files.values())
        mix_output_file = self._mix_output_file(
            combined_output_file,
            split_output_files,
        )
        if mix_output_file:
            paths.append(mix_output_file)
        return list(dict.fromkeys(paths))

    async def _finish_empty_run(
        self,
        output_file: str,
        *,
        status: str,
        publish: bool,
    ) -> int:
        """Write empty subscription artifacts and optionally publish all of them.

        Previously failed runs often published only ``run-summary.json`` +
        health history, leaving remote ``subscription*.txt`` stale while the
        summary reported zero live configs. Always publish the full set so
        consumers never see outdated "live" lists after a dead run.
        """
        self._write_empty_output(output_file)
        self._write_empty_secondary_outputs(output_file)

        # Keep run-summary outputs in sync with the empty files we just wrote.
        self._output_stats = {}
        self._record_output_stats("combined", output_file, [])
        split_output_files = self._split_output_files(output_file)
        for list_type, split_file in split_output_files.items():
            self._record_output_stats(list_type, split_file, [])
        mix_output_file = self._mix_output_file(output_file, split_output_files)
        if mix_output_file:
            self._record_output_stats("mix", mix_output_file, [])

        summary_file = self._write_run_summary(status)
        health_file = self._write_health_history()
        self._save_proxy_health_history()
        if publish:
            publish_paths = self._configured_subscription_output_paths(output_file)
            if summary_file:
                publish_paths.append(summary_file)
            if health_file:
                publish_paths.append(health_file)
            await self._publish_files(
                publish_paths,
                combined_output_file=output_file,
            )
        return 0

    def _write_empty_split_outputs(self, combined_output_file: str) -> None:
        """Clear configured split outputs on empty runs."""
        for split_file in self._split_output_files(combined_output_file).values():
            self._write_empty_output(split_file)

    def _location_output_config(self) -> tuple[bool, str, int]:
        return self._writer._location_output_config()

    @staticmethod
    def _location_output_filename(country: str) -> str:
        return OutputWriter._location_output_filename(country)

    def _clear_location_outputs(self) -> None:
        self._writer._clear_location_outputs()

    def _build_location_outputs(
        self,
        configs: list[Config],
        per_location_limit: int,
    ) -> dict[str, list[Config]]:
        return self._writer._build_location_outputs(configs, per_location_limit)

    def _write_location_outputs(self, configs: list[Config]) -> list[str]:
        result = self._writer._write_location_outputs(configs)
        for key, value in self._writer.context.output_stats.items():
            if key.startswith("location_"):
                self._output_stats[key] = value
        return result

    def _save_proxy_health_history(self) -> None:
        if self._proxy_health_history is None or not self._proxy_health_file:
            return
        try:
            self._proxy_health_history.save(self._proxy_health_file)
            logger.info(
                "Saved proxy health history (%d entries) to %s.",
                len(self._proxy_health_history.records),
                self._proxy_health_file,
            )
        except Exception as exc:
            logger.warning("Failed to save proxy health history: %s", exc)

    def _status_output_file(self) -> str | None:
        """Return run-summary output path, if configured."""
        pcfg = self._section("publisher")
        raw = pcfg.get("status_output_file")
        if not raw:
            return None
        return str(raw)

    def _record_output_stats(
        self,
        name: str,
        output_file: str,
        configs: list[Config],
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

        # Never publish working SOCKS5 proxy URLs in the summary output.
        # Internal liveness stats keep the raw URLs for debugging only.
        validation = dict(self._liveness_stats)
        validation.pop("proxy_urls", None)
        payload = {
            "status": status,
            "outputs": self._output_stats,
            "validation": validation,
        }
        try:
            path = resolve_safe_output_path(output_file)
        except ValueError:
            logger.exception("Unsafe run summary path %r rejected", output_file)
            return None
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
        return self._writer._write_output(configs, output_file)

    def _write_empty_output(self, output_file: str) -> None:
        """Ensure the output file exists as a valid base64 subscription."""
        self._writer._write_empty_output(output_file)

    @staticmethod
    def _write_plain_fallback(configs: list[Config], output_file: str) -> int:
        """Last-resort writer: one ``raw_link`` per line."""
        return OutputWriter._write_plain_fallback(configs, output_file)

    # --- stage 6: publish ---

    async def _publish_files(
        self,
        output_files: list[str],
        *,
        combined_output_file: str | None = None,
    ) -> bool:
        """Publish multiple output files, preserving each repo path.
        Returns True if all files were published successfully."""
        pcfg = self._section("publisher")
        configured_combined_path = pcfg.get("output_file")

        all_ok = True
        for output_file in dict.fromkeys(output_files):
            repo_path = output_file
            if combined_output_file is not None and output_file == combined_output_file:
                repo_path = str(configured_combined_path or output_file)
            if not await self._publish(output_file, repo_path=repo_path):
                all_ok = False
        return all_ok

    async def _publish(self, output_file: str, repo_path: str | None = None) -> bool:
        """Publish the output file to a GitHub repo via ``GitHubPublisher``.
        Returns True on success, False on failure/skip."""
        if not self.github_token:
            logger.warning("Publish requested but GITHUB_TOKEN is not set — skipping.")
            return False

        pcfg = self._section("publisher")
        owner = pcfg.get("owner") or os.environ.get("GITHUB_OWNER")
        repo = pcfg.get("repo") or os.environ.get("GITHUB_REPO")
        branch = pcfg.get("branch") or os.environ.get("GITHUB_BRANCH") or "main"
        repo_path = repo_path or str(pcfg.get("output_file") or output_file)
        commit_tpl = pcfg.get("commit_message", "auto-update configs [{timestamp}]")

        if not owner or not repo:
            logger.warning(
                "Publish requested but GitHub owner/repo not configured "
                "(set publisher.owner/repo in settings or GITHUB_OWNER/GITHUB_REPO env) — skipping.",  # noqa: E501
            )
            return False

        try:
            safe_path = resolve_safe_output_path(output_file)
        except ValueError:
            logger.exception("Unsafe output path for publish %r", output_file)
            return False
        try:
            content = await asyncio.to_thread(safe_path.read_text, encoding="utf-8")
        except FileNotFoundError:
            logger.exception(
                "Cannot publish: output file %s does not exist.",
                output_file,
            )
            return False
        except Exception:
            logger.exception("Cannot read output file %s for publish", output_file)
            return False

        commit_message = commit_tpl.replace(
            "{timestamp}",
            time.strftime("%Y-%m-%d %H:%M:%S"),
        )

        try:
            from src.publisher.github import GitHubPublisher
        except ImportError:
            logger.exception("Cannot import GitHubPublisher — skipping publish.")
            return False

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
                        "Publish completed but reported failure for %s.",
                        repo_path,
                    )
                return bool(ok)
        except Exception:
            logger.exception("Publish failed")
            return False
