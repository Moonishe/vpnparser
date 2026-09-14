"""Pipeline orchestrator — fetch -> parse -> filter -> aggregate -> write -> publish.

``PipelineRunner`` ties together every stage of the VPN config pipeline:

1. **Fetch**    — ``SourceManager.fetch_all()`` pulls files from configured sources.
2. **Parse**    — ``_parse_all_by_list()`` extracts proxy links and turns them into
                   ``Config`` objects grouped by source ``list_type`` (list type).
3. **Filter**   — garbage/placeholder filter -> dedup -> sample -> country filter.
4. **Aggregate**— interleave blacklist+whitelist -> sort -> per-country limit.
5. **Write**    — ``write_subscription()`` emits combined, mix, and split files.
6. **Publish**  — (optional) commit outputs to a GitHub repo via Contents API.

Each stage is wrapped so a failure is logged and, where possible, the pipeline
continues with whatever data survived the previous stage.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import time
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from src.aggregator.output import _safe_raw_link, is_watermark_vmess
from src.parsers.base import Config
from src.publisher.github import GitHubPublishError
from src.scheduler.context import PipelineContext, PipelineState
from src.scheduler.health_history import HealthHistory
from src.scheduler.settings import Settings, load_settings, load_settings_strict
from src.scheduler.stages.aggregate import Aggregator
from src.scheduler.stages.fetch import SourceFetcher
from src.scheduler.stages.filter import (
    DedupFilter,
    PreprocessFilter,
)
from src.scheduler.stages.liveness import LivenessValidator
from src.scheduler.stages.parse import LinkParser
from src.scheduler.stages.quality import QualityFilter
from src.scheduler.stages.write import OutputWriter
from src.sources.list_types import normalize_list_type
from src.utils.paths import resolve_safe_output_path, write_text_atomic


def _canonical_output_path(p: str) -> str:
    """Normalise an output path to a comparable canonical form.

    Relative paths resolve against the project root (not CWD) so "output/x.txt"
    and its absolute counterpart produce the same key even when the process
    runs outside the repo (console `vpnparser` + VPNPARSER_PROJECT_ROOT).
    Backslashes are folded to "/" first: on POSIX "\\" is a valid filename
    character, so without this "output\\x.txt" (pathlib spelling on Windows)
    and "output/x.txt" (settings spelling) canonicalise to different keys
    and the same file is published twice. `pathlib` accepts "/" on every
    platform, so the fold is a no-op for genuinely Windows paths.
    Falls back to CWD resolution when the project root cannot be determined.
    Module-level (not async): ASYNC240 only fires inside async functions,
    and this is pure I/O on run-local paths with no concurrent hazard.
    """
    raw = str(p).replace("\\", "/")
    try:
        from src.utils.paths import _find_project_root

        root = Path(_find_project_root()).resolve()
        candidate = Path(raw)
        if not candidate.is_absolute():
            candidate = root / candidate
        return os.path.normcase(os.path.normpath(str(candidate.resolve())))
    except Exception:
        return os.path.normcase(os.path.normpath(str(Path(raw).resolve())))


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
        self._shared_publisher: Any | None = None
        self._liveness_stats: dict[str, Any] = {}
        self._output_stats: dict[str, Any] = {}
        # Fetch outcome of THIS run (what run-summary.json "sources" reports).
        # Captured in _fetch_sources and reset per run: the context attribute
        # the fetch stage writes is overwritten too late for fast-track runs —
        # clearing it in _prepare_run_state used to wipe it before the summary
        # was written (every run reported "sources": {} and the Telegram
        # broken-source alert never fired).
        self._run_source_stats: dict[str, Any] = {}
        # Subscription slices dropped by the per-file publish floor this run:
        # {file path: config count}. Surfaced in run-summary.json so an
        # operator can see WHY a file did not update.
        self._publish_floor_applied: dict[str, int] = {}
        # Paths of outputs written as empty this run (watermark placeholder, so
        # they are NOT 0 bytes). The per-file publish floor skips these so they
        # do not overwrite a previously working published slice.
        self._empty_output_files: set[str] = set()
        self._health_history: HealthHistory | None = None
        self._proxy_health_history: Any | None = None
        self._proxy_health_file: str | None = None
        self._last_summary_path: str | None = None
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

    def _require_settings_file(self) -> None:
        """Refuse to run the pipeline on the built-in defaults.

        A mistyped ``--settings`` path used to leave the run on defaults, where
        ``tcp/tls/xray_enabled`` are false and ``allowed_countries`` is empty:
        unvalidated configs were written, published, and the process still
        exited 0. Building the runner stays tolerant — helpers and tools use it
        without a settings file — but a full run insists on a settings file
        that exists *and* parses: a truncated commit or invalid YAML would
        otherwise silently produce the same fail-open run via ``{}``.

        Raises:
            FileNotFoundError: If the configured settings file does not exist.
            SettingsParseError: If the file exists but does not parse into a
                non-empty mapping.
        """
        # Strict load covers both "missing" and "exists but broken".
        load_settings_strict(self.settings_path)

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
        # as_int, not bare int(): bool is an int subclass, so a YAML
        # ``max_configs_in_output: true`` typo used to become limit 1 and
        # ``false`` unlimited — exactly the fail-mode Settings.as_int guards
        # (the aggregate stage already uses it).
        value = Settings.as_int(
            self._section("aggregator").get("max_configs_in_output"),
            500,
        )
        if value < 0:
            logger.warning(
                "aggregator.max_configs_in_output=%r is negative; using 0 "
                "(unlimited) is ambiguous — clamping to 0.",
                self._section("aggregator").get("max_configs_in_output"),
            )
            return 0
        return value

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

        Raises:
            FileNotFoundError: If the configured settings file does not exist —
                running on the built-in defaults would publish unvalidated
                configs and still look successful.
        """
        self._require_settings_file()
        results = await self._fetch_sources()
        return await self._pipeline(results, output_file, publish)

    async def rerun_published(
        self,
        output_file: str = "output/subscription.txt",
        publish: bool = False,
    ) -> int:
        """Re-validate the currently published set without refetching sources.

        A full run takes ~2h while published keys die within hours. This mode
        re-probes just the last published split files (committed to the repo),
        so an hourly fast-track job can refresh the subscription in minutes
        between full discovery runs.

        Raises:
            FileNotFoundError: Same contract as :meth:`run`, plus when neither
                published split file is readable — revalidating "nothing" must
                not fall through to an empty-run publish that would wipe the
                live subscription.
        """
        self._require_settings_file()
        # Blocking file IO off the event loop: published splits are read here.
        results = await asyncio.to_thread(self._published_source_results, output_file)
        if not results:
            # Revalidating "nothing" must not fall through to an empty-run
            # publish that would wipe the live subscription.
            msg = (
                "rerun_published found no readable published split files "
                f"next to {output_file} — nothing to revalidate."
            )
            raise FileNotFoundError(msg)
        return await self._pipeline(results, output_file, publish)

    def _prepare_run_state(self) -> float:
        """Reset per-run state shared by full and fast-track runs."""
        start = time.monotonic()
        self._liveness_stats = {}
        self._output_stats = {}
        self._empty_output_files = set()
        self._publish_floor_applied = {}
        # The stage context outlives a single run: stale ``location_*`` entries
        # would leak into this run's summary via _write_location_outputs(), and
        # stale liveness stats would leak the *previous* run's validation block
        # into an empty run's summary when the runner object is reused.
        self._context.output_stats.clear()
        self._context.liveness_stats.clear()
        self._context.source_stats.clear()
        # PipelineState is equally reusable (continuous mode reuses the runner):
        # stale parsed/preprocessed/validated maps would leak the previous
        # run's configs into an empty run's summary and publish set.
        self._state.parsed.clear()
        self._state.preprocessed.clear()
        self._state.validated.clear()
        self._state.aggregated.clear()
        self._state.output_files.clear()
        self._publish_ok = False
        self._last_summary_path = None
        self._liveness.reset_proxy_cache()
        logger.info("Pipeline started.")
        return start

    async def _pipeline(
        self,
        results: list[Any],
        output_file: str,
        publish: bool,
    ) -> int:
        """Shared body for full and fast-track runs, from parse to publish."""
        start = self._prepare_run_state()

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

        # 5. Write combined output (blocking file IO off the event loop).
        count = await asyncio.to_thread(self._write_output, combined, output_file)
        self._record_output_stats("combined", output_file, combined)
        logger.info("Wrote %d configs to %s.", count, output_file)
        output_files = [output_file]
        split_output_files = self._split_output_files(output_file)

        # Blocking file IO off the event loop (see _write_output above).
        clash_file = await asyncio.to_thread(self._writer._write_clash_output, combined)
        if clash_file:
            output_files.append(clash_file)
            # Copied (not recomputed): the writer counted exactly the set the
            # YAML keeps (alive + expressible). Recomputing here with the
            # base64 predicate would count inexpressible configs the file
            # does not hold. _finish_empty_run already records it the same
            # way, so both summary shapes stay comparable.
            clash_stats = self._writer.context.output_stats.get("clash")
            if isinstance(clash_stats, dict):
                self._output_stats["clash"] = clash_stats
            else:
                self._record_output_stats("clash", clash_file, combined)

        mix_output_file = self._mix_output_file(output_file, split_output_files)
        if mix_output_file:
            mix_configs = self._build_mixed_output(preprocessed_by_list, max_total)
            if mix_configs:
                mix_count = await asyncio.to_thread(
                    self._write_output, mix_configs, mix_output_file
                )
                self._record_output_stats("mix", mix_output_file, mix_configs)
                logger.info("Wrote %d mix configs to %s.", mix_count, mix_output_file)
            else:
                await asyncio.to_thread(self._write_empty_output, mix_output_file)
                self._record_output_stats("mix", mix_output_file, [])
                logger.warning("No configs for mix output.")
            output_files.append(mix_output_file)

        # 6. Write split outputs — sort+limit each preprocessed list now
        #    (deferred from step 3 so the combined path sorts only once).
        #    A non-empty input can still sort to zero configs (whitelist
        #    balance with no RU servers, max_configs_in_output <= 0); such a
        #    slice must go through _write_empty_output so it is registered as
        #    empty and skipped by the per-file publish floor — a watermark
        #    written via _write_output is non-zero on disk and would
        #    overwrite the working published file.
        for list_type, split_file in split_output_files.items():
            split_pre = preprocessed_by_list.get(list_type, [])
            if list_type == "whitelist":
                # Whitelist: 80% RU servers, 20% EU countries by default.
                split_configs = (
                    self._whitelist_balance(split_pre, max_total) if split_pre else []
                )
            else:
                split_configs = self._sort_and_limit(split_pre) if split_pre else []
            if split_configs:
                split_count = await asyncio.to_thread(
                    self._write_output, split_configs, split_file
                )
                self._record_output_stats(list_type, split_file, split_configs)
                logger.info(
                    "Wrote %d %s configs to %s.",
                    split_count,
                    list_type,
                    split_file,
                )
            else:
                await asyncio.to_thread(self._write_empty_output, split_file)
                self._record_output_stats(list_type, split_file, [])
                logger.warning("No configs for %s output.", list_type)
            output_files.append(split_file)

        # The subscription paths are reserved: location_output_dir may point at
        # the directory that holds them, and the cleanup mask would delete the
        # split/mix files written a few lines above.
        location_output_files = await asyncio.to_thread(
            self._write_location_outputs,
            all_live_configs,
            self._configured_subscription_output_paths(output_file),
        )
        output_files.extend(location_output_files)

        # A run with every validator disabled writes watermark-only files and
        # still follows the success path (it is not an "empty run": configs
        # were parsed and then deliberately excluded) — reporting "ok" there
        # hid the misconfiguration. The summary carries the diagnostic status.
        run_status = (
            "validation_disabled"
            if self._liveness_stats.get("status") == "disabled"
            else "ok"
        )
        # Blocking file IO off the event loop: summary/health/stats are tens
        # of thousands of records of JSON.
        summary_file = await asyncio.to_thread(self._write_run_summary, run_status)
        if summary_file:
            output_files.append(summary_file)
        # health-history.json is written locally (Telegram report and the
        # workflow cache read it) but deliberately NOT published: at 69k
        # records it exceeds the Contents API's practical body size, so the
        # single PUT failed on every run — the failure surfaced as
        # EXIT_PUBLISH_FAILED for the whole batch. The Actions cache
        # (update.yml) persists it instead.
        await asyncio.to_thread(self._write_health_history)
        output_files.extend(
            await asyncio.to_thread(self._write_stats_history, run_status)
        )

        await asyncio.to_thread(self._save_proxy_health_history)

        # 7. Publish (optional).
        if publish:
            # Floor: never overwrite a working subscription with a near-empty
            # one. When fewer than min_publish_configs configs survived, drop the
            # subscription files (combined/mix/split/location/clash) from the
            # publish set and keep the last good published subscription; metadata
            # (summary, stats, health) is still published so tooling sees the
            # degraded status.
            min_publish = self._min_publish_configs()
            if count < min_publish:
                logger.warning(
                    "Only %d configs survived validation, below "
                    "publisher.min_publish_configs=%d. Keeping the previously "
                    "published subscription files rather than overwriting a "
                    "working subscription with a near-empty one.",
                    count,
                    min_publish,
                )
                subscription_paths: list[str] = list(
                    self._configured_subscription_output_paths(output_file)
                )
                subscription_paths.extend(location_output_files)
                if clash_file:
                    subscription_paths.append(clash_file)
                output_files = [
                    f for f in output_files if f not in set(subscription_paths)
                ]
            self._publish_ok = await self._publish_files(
                output_files,
                combined_output_file=output_file,
            )
            if not self._publish_ok and summary_file:
                # The local run-summary was written with "ok" before the publish
                # result existed; with a failed publish the repo copy may hold
                # the optimistic status until a later run refreshes it. Rewrite
                # the local copy truthfully so local tooling and the next run
                # see the failure (blocking IO off the event loop).
                await asyncio.to_thread(
                    self._rewrite_summary_status, summary_file, "publish_failed"
                )

        elapsed = time.monotonic() - start
        logger.info("Pipeline finished in %.2fs with %d configs.", elapsed, count)
        return count

    # --- stage 1: fetch ---

    def _published_source_results(self, output_file: str) -> list[Any]:
        """Build parse-stage inputs from the last published split files.

        Each split file becomes one synthetic source result, so the regular
        parse stage (link extraction, per-link parsing) runs unchanged. The
        watermark vmess line is dropped: it is display-only and would otherwise
        be re-validated and republished as a fake config.
        """
        import base64

        splits = self._split_output_files(output_file)
        results: list[Any] = []
        for list_type, path in splits.items():
            if list_type not in ("blacklist", "whitelist"):
                continue
            try:
                raw = resolve_safe_output_path(path).read_text(
                    encoding="utf-8",
                )
            except Exception as exc:
                logger.warning("Published %s file unreadable: %s", list_type, exc)
                continue
            text = raw.strip()
            # validate=True (unlike the default decoder, which silently drops
            # non-alphabet characters) + a URL-scheme check first: a plain-text
            # fallback file must not decode into garbage instead of failing
            # the decode and keeping its raw lines.
            if "://" not in text:
                with contextlib.suppress(Exception):
                    text = base64.b64decode(text, validate=True).decode("utf-8")
            links = [
                line.strip()
                for line in text.splitlines()
                if "://" in line.strip() and not is_watermark_vmess(line.strip())
            ]
            if not links:
                logger.warning("Published %s file has no links: %s", list_type, path)
                continue
            results.append(
                SimpleNamespace(
                    name=f"published-{list_type}",
                    list_type=list_type,
                    files=[(path, "\n".join(links))],
                    default_country=None,
                )
            )
        # Every CONFIGURED split must be revalidated, or not at all: the guard
        # above fired only when BOTH files were unreadable, so one dead file
        # let the run republish just the other list — silently erasing half
        # the live subscription. The required set derives from the configured
        # splits instead of a hardcoded pair: a deployment with only one split
        # made the fast-track permanently unusable.
        configured_types = {
            list_type for list_type in splits if list_type in ("blacklist", "whitelist")
        }
        found_types = {str(getattr(result, "list_type", "")) for result in results}
        missing = sorted(configured_types - found_types)
        if configured_types and missing:
            msg = (
                "rerun_published requires every published split file to be "
                f"readable next to {output_file}; unreadable or link-less: "
                f"{', '.join(missing)}. Revalidating a partial set would "
                "overwrite the healthy subscription with part of it."
            )
            raise FileNotFoundError(msg)
        return results

    async def _fetch_sources(self) -> list[Any]:
        """Fetch all sources via the SourceFetcher stage."""
        # Reset first: this is the per-run boundary for the fetch outcome (a
        # rerun_published path never gets here and reports {}), and
        # _prepare_run_state runs AFTER fetch, where a reset would erase the
        # stats this very run just captured.
        self._run_source_stats = {}
        self._state = await self._fetcher.run(self._state, self._context)
        # Snapshot the fetch outcome for this run's summary; see
        # _run_source_stats for why the context attribute alone is not enough.
        self._run_source_stats = dict(self._context.source_stats)
        return self._state.sources

    # --- stage 2: parse ---

    async def _parse_all_by_list(
        self,
        results: list[Any],
    ) -> dict[str, list[Config]]:
        """Parse all source results grouped by normalized list type."""
        self._state.sources = list(results)
        try:
            self._state = await self._parser.run(self._state, self._context)
        finally:
            # The parse stage owns one shared LLM client; its run is over, so
            # the connection must not outlive the stage (and in --continuous
            # mode, accumulate one open client per run).
            await self._parser.aclose()
        return self._state.parsed

    # --- stage 3: country filter ---

    # --- optional network liveness validation ---

    async def _validator_proxy_urls(self) -> list[str]:
        """Return configured validator proxies, including optional free pool."""
        return await self._liveness._validator_proxy_urls()

    async def _validate_liveness_by_list(
        self,
        configs_by_list: dict[str, list[Config]],
    ) -> dict[str, list[Config]]:
        """Optionally run TCP/TLS/Xray liveness checks for each list type."""
        result = await self._liveness.validate_by_list(configs_by_list)
        self._liveness_stats = self._context.liveness_stats
        return result

    # --- stage 3+5: aggregate (split into dedup + sort/limit) ---

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

    def _write_health_history(self) -> str | None:
        """Persist health history. Kept for compatibility."""
        return self._quality.health.save()

    def _update_health_history(self, checked_configs: list[Config]) -> None:
        """Update per-config health history. Kept for compatibility."""
        self._quality.health.update(checked_configs)

    def _update_source_health(
        self,
        checked_configs: list[Config],
        list_stats: dict[str, Any],
    ) -> None:
        """Update per-source health history. Kept for compatibility."""
        self._quality.health.update_sources(checked_configs, list_stats)

    def _apply_quality_filters(
        self,
        configs_by_list: dict[str, list[Config]],
    ) -> dict[str, list[Config]]:
        """Apply quality filters. Delegates to QualityFilter."""
        result = self._quality.apply(configs_by_list)
        # Quality writes its stats onto the shared context. The runner's
        # snapshot is only re-bound to that same dict after the liveness
        # stage, so mirror the key for direct pre-liveness calls — and skip
        # the write entirely when the two names already alias one dict
        # (the old unconditional line was a silent self-assignment there).
        if self._liveness_stats is not self._context.liveness_stats:
            quality_stats = self._context.liveness_stats.get("quality")
            if quality_stats is not None:
                self._liveness_stats["quality"] = quality_stats
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
        combined_canon = _canonical_output_path(combined_output_file)
        for key, path in raw.items():
            list_type = normalize_list_type(key)
            if list_type == "mixed" or not path:
                continue
            path_str = str(path)
            if _canonical_output_path(path_str) == combined_canon:
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
            canon = _canonical_output_path(path_str)
            if canon in seen_paths:
                owner = next(
                    (
                        lt
                        for lt, p in result.items()
                        if _canonical_output_path(p) == canon
                    ),
                    "?",
                )
                logger.warning(
                    "split_output_files: path '%s' is already used by "
                    "list_type '%s' — ignoring duplicate for '%s' to "
                    "prevent overwriting. Fix: use a distinct output path.",
                    path_str,
                    owner,
                    list_type,
                )
                continue
            seen_paths.add(canon)
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
        if _canonical_output_path(path_str) == _canonical_output_path(
            combined_output_file
        ):
            logger.warning(
                "mix_output_file points to the combined output '%s' — ignoring.",
                combined_output_file,
            )
            return None

        split_paths = {
            _canonical_output_path(p) for p in (split_output_files or {}).values()
        }
        if _canonical_output_path(path_str) in split_paths:
            logger.warning(
                "mix_output_file path '%s' is already used by a split output — "
                "ignoring to prevent overwriting.",
                path_str,
            )
            return None

        return path_str

    def _write_empty_secondary_outputs(self, combined_output_file: str) -> list[str]:
        """Clear configured split and mix outputs on empty runs.

        Returns:
            Paths of the emptied location files, which the caller must publish
            too — they are not part of the statically configured output set.
        """
        split_output_files = self._split_output_files(combined_output_file)
        self._write_empty_split_outputs(combined_output_file)
        mix_output_file = self._mix_output_file(
            combined_output_file,
            split_output_files,
        )
        if mix_output_file:
            self._write_empty_output(mix_output_file)
        # Writing no countries empties every existing location file instead of
        # deleting it, so the published per-country lists are replaced as well.
        return self._write_location_outputs(
            [],
            self._configured_subscription_output_paths(combined_output_file),
        )

    def _configured_subscription_output_paths(
        self,
        combined_output_file: str,
    ) -> list[str]:
        """Return all subscription paths that should stay in sync on every run.

        Includes combined, mix, and split outputs. Location files are omitted
        here because they are not statically configured — the writer reports
        the ones it emptied.
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
        # Dedup by canonical path so "./output/x.txt" and "output/x.txt"
        # do not produce two publish targets for one file.
        seen: set[str] = set()
        unique: list[str] = []
        for p in paths:
            canon = _canonical_output_path(p)
            if canon in seen:
                continue
            seen.add(canon)
            unique.append(p)
        return unique

    def _min_publish_configs(self) -> int:
        """Floor on the number of configs that must survive before the run's

        subscription files are republished. Below this many, publishing would
        overwrite a working subscription with a near-empty one (typically after
        an infrastructure/validation failure), so the previously published
        subscription is kept instead. Mirrors the floor in ``_finish_empty_run``.
        """
        raw = self._section("publisher").get("min_publish_configs")
        value = Settings.as_int(raw, 10)
        if value < 0:
            logger.warning(
                "publisher.min_publish_configs=%r is negative; using default 10 "
                "instead of publishing empty subscriptions.",
                raw,
            )
            return 10
        return value

    async def _finish_empty_run(
        self,
        output_file: str,
        *,
        status: str,
        publish: bool,
    ) -> int:
        """Write empty subscription artifacts and optionally publish.

        Subscription artifacts become watermark-only placeholders on an empty
        run.  With ``publisher.min_publish_configs`` > 0 (default 10) those
        placeholders are written *locally* but are NOT published: the floor
        must live in code because the workflow's "<10" check runs in a later
        step, after publication — a network-failure run used to wipe the live
        subscription while CI could only mourn it.  Metadata (run summary,
        stats history, health history) still goes out so tooling sees the
        empty status; the previously published subscription stays untouched
        until a run with real content replaces it.
        """
        # Blocking file IO off the event loop (see _pipeline).
        await asyncio.to_thread(self._write_empty_output, output_file)
        # Reset the run stats BEFORE the location outputs are recorded: the
        # secondary-output writer reports every emptied location file into
        # _output_stats, and a reset after that (as it used to be) wiped the
        # location_* entries from the run summary of every empty run.
        self._output_stats = {}
        self._empty_output_files = set()
        location_files = await asyncio.to_thread(
            self._write_empty_secondary_outputs, output_file
        )

        # Keep run-summary outputs in sync with the empty files we just wrote.
        self._record_output_stats("combined", output_file, [])
        clash_output_file = self._writer._clash_output_file()
        if clash_output_file:
            await asyncio.to_thread(self._writer._write_empty_clash_output)
            self._record_output_stats("clash", clash_output_file, [])
        split_output_files = self._split_output_files(output_file)
        for list_type, split_file in split_output_files.items():
            self._record_output_stats(list_type, split_file, [])
        mix_output_file = self._mix_output_file(output_file, split_output_files)
        if mix_output_file:
            self._record_output_stats("mix", mix_output_file, [])

        summary_file = await asyncio.to_thread(self._write_run_summary, status)
        await asyncio.to_thread(self._write_health_history)
        await asyncio.to_thread(self._save_proxy_health_history)
        stats_files = await asyncio.to_thread(self._write_stats_history, status)
        if publish:
            subscription_paths = self._configured_subscription_output_paths(
                output_file,
            )
            subscription_paths.extend(location_files)
            if clash_output_file:
                subscription_paths.append(clash_output_file)
            publish_paths = list(subscription_paths)
            publish_paths.extend(stats_files)
            if summary_file:
                publish_paths.append(summary_file)
            # health-history.json stays local-only: see the note in _pipeline.

            # Single source of truth with _pipeline (negative → default 10).
            min_publish = self._min_publish_configs()
            min_publish = max(0, min_publish)
            if min_publish > 0:
                logger.warning(
                    "Empty run (%s): keeping the previously published "
                    "subscription files in the repository — %d watermark-only "
                    "placeholder(s) were written locally but must not wipe a "
                    "working subscription on what is usually an "
                    "infrastructure failure.",
                    status,
                    len(subscription_paths),
                )
                publish_paths = [
                    path for path in publish_paths if path not in subscription_paths
                ]

            # Record the outcome like the main path does: an empty run whose
            # publish failed leaves the previous, non-empty subscription live
            # in the repository, which is the one case that must never look green.
            self._publish_ok = await self._publish_files(
                publish_paths,
                combined_output_file=output_file,
            )
            if not self._publish_ok and summary_file:
                await asyncio.to_thread(
                    self._rewrite_summary_status, summary_file, "publish_failed"
                )
        return 0

    def _write_empty_split_outputs(self, combined_output_file: str) -> None:
        """Clear configured split outputs on empty runs."""
        for split_file in self._split_output_files(combined_output_file).values():
            self._write_empty_output(split_file)

    def _write_location_outputs(
        self,
        configs: list[Config],
        reserved_paths: Iterable[str] | None = None,
    ) -> list[str]:
        result = self._writer._write_location_outputs(configs, reserved_paths)
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
            if cfg.is_alive is not False
            and _safe_raw_link(cfg.raw_link)
            and getattr(cfg, "country", None)
        )
        # Count with the same predicate the writer applies (dead configs and
        # control-character links are skipped): a summary that reports more
        # configs than the file holds reads as a healthy run after a fail-open
        # validation.
        self._output_stats[name] = {
            "file": output_file,
            "count": sum(
                1
                for cfg in configs
                if cfg.is_alive is not False and _safe_raw_link(cfg.raw_link)
            ),
            "countries": dict(country_counts.most_common()),
        }

    def _degraded_reasons(self) -> list[str]:
        """One-line reasons a run's alive pool collapsed in some list.

        A full Xray sweep that leaves every candidate dead is almost always a
        probe-infrastructure failure (dead SOCKS proxies), not input that is
        100% dead — surface it in run-summary.json and Telegram instead of
        reporting a healthy "ok" run with an empty subscription.
        """
        reasons: list[str] = []
        lists = (self._liveness_stats or {}).get("lists") or {}
        if isinstance(lists, dict):
            for list_name, stats in lists.items():
                if not isinstance(stats, dict):
                    continue
                checked = int(stats.get("xray_checked") or 0)
                alive = int(stats.get("xray_alive") or 0)
                if checked >= 50 and alive == 0:
                    reasons.append(
                        f"{list_name}: 0 alive from {checked} Xray-checked configs",
                    )
                elif checked >= 100 and alive / checked < 0.02:
                    # A collapse to near-zero is the same probe-infrastructure
                    # signature as a collapse to zero: 1/100 alive reported a
                    # healthy "ok" run while the pool had died under it. The
                    # 2% floor mirrors source_bad_alive_rate.
                    reasons.append(
                        f"{list_name}: alive rate {alive}/{checked} "
                        f"({alive / checked:.1%}) below 2% — suspected "
                        "probe-infrastructure failure",
                    )
        return reasons

    def _write_run_summary(self, status: str) -> str | None:
        """Write machine-readable run metadata for Telegram and debugging.

        On success the path is also recorded in ``self._last_summary_path`` so
        callers can distinguish "this run wrote its summary" from "an older
        summary file happens to exist on disk".
        """
        self._last_summary_path = None
        output_file = self._status_output_file()
        if not output_file:
            logger.warning(
                "publisher.status_output_file is not configured — this run "
                "leaves no run summary, so the Telegram report and any "
                "operational tooling see nothing about it.",
            )
            return None

        # Never publish working SOCKS5 proxy URLs in the summary output.
        # Internal liveness stats keep the raw URLs for debugging only.
        validation = dict(self._liveness_stats)
        validation.pop("proxy_urls", None)
        degraded_reasons = self._degraded_reasons()
        payload: dict[str, Any] = {
            "status": status,
            "generated_at": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ",
                time.gmtime(),
            ),
            "outputs": self._output_stats,
            # Failed sources are invisible in ``outputs``: a dead source only
            # shows up as a smaller subscription, so record the fetch outcome.
            # Per-run snapshot (see _run_source_stats): reading the context
            # attribute here reported {} for every run — _prepare_run_state
            # had already cleared it by the time the summary was written.
            "sources": dict(self._run_source_stats),
            # Subscription slices withheld by the per-file publish floor, with
            # the counts that triggered the withholding.
            "publish_floor_applied": dict(self._publish_floor_applied),
            "validation": validation,
        }
        # One-glance health: a run whose alive pool collapsed in one list
        # while the pipeline still "works" used to look identical to a good
        # run in every machine-readable artifact.
        if degraded_reasons:
            payload["degraded"] = True
            payload["degraded_reasons"] = degraded_reasons
        try:
            path = resolve_safe_output_path(output_file)
        except ValueError:
            logger.exception("Unsafe run summary path %r rejected", output_file)
            return None
        try:
            # Atomic write: a crash mid-write must not leave a truncated
            # run-summary.json for CI and the Telegram reporter to read.
            write_text_atomic(
                path,
                json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
            )
        except Exception as exc:
            logger.warning("Could not write run summary %s: %s", output_file, exc)
            return None
        self._last_summary_path = output_file
        return output_file

    # --- stage 5: write ---

    def _write_stats_history(self, status: str) -> list[str]:
        """Append this run to the trend history and redraw the SVG badge.

        Both files are published with the subscriptions, so the badge in the
        README and the Telegram diff-alert survive run boundaries.
        """
        if not self._liveness_stats:
            # Early-fail runs (no sources / no configs / no countries) never
            # reached liveness; a zeros entry would dip the badge for a
            # fetch hiccup without saying anything about the proxies.
            return []
        try:
            from src.scheduler.stats_history import (
                DEFAULT_STATS_HISTORY_FILE,
                DEFAULT_TREND_SVG_FILE,
                append_run_stats,
                render_trend_svg,
                run_stats_entry,
            )

            # Live next to the run summary: the Telegram diff-alert reads
            # stats-history.json from Path(status_file).parent, so a custom
            # output directory must not leave the trend files behind in the
            # default output/ while the summary (and the alert) look elsewhere.
            history_file = DEFAULT_STATS_HISTORY_FILE
            svg_file = DEFAULT_TREND_SVG_FILE
            status_output = self._status_output_file()
            if status_output:
                parent = Path(status_output).parent
                history_file = str(parent / "stats-history.json")
                svg_file = str(parent / "alive-trend.svg")
            entry = run_stats_entry(self._liveness_stats, status)
            history, history_path = append_run_stats(entry, history_file)
            svg_path = render_trend_svg(history, svg_file)
            return [path for path in (history_path, svg_path) if path]
        except Exception as exc:
            logger.warning("Stats history write failed: %s", exc)
            return []

    def _write_output(self, configs: list[Config], output_file: str) -> int:
        """Write the subscription file via ``write_subscription``."""
        return self._writer._write_output(configs, output_file)

    def _write_empty_output(self, output_file: str) -> None:
        """Ensure the output file exists as a valid base64 subscription."""
        self._writer._write_empty_output(output_file)
        # Record it so the per-file publish floor can skip this empty slice
        # instead of overwriting a previously working published file.
        # Canonical key: normpath alone never equated "output\\x" and
        # "output/x" across spellings.
        self._empty_output_files.add(_canonical_output_path(output_file))

    def _rewrite_summary_status(self, output_file: str, status: str) -> None:
        """Overwrite the ``status`` field of an existing run summary file.

        Used after a publish failure: the summary was written with ``"ok"``
        before the publish result was known, and the local copy should not
        keep claiming success the repo copy is not entitled to.

        Blocking file IO — async callers must run this via
        ``await asyncio.to_thread(...)``.
        """
        try:
            path = resolve_safe_output_path(output_file)
        except ValueError:
            logger.exception("Unsafe run summary path %r rejected", output_file)
            return
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                payload["status"] = status
                write_text_atomic(
                    path,
                    json.dumps(
                        payload,
                        ensure_ascii=False,
                        indent=2,
                        sort_keys=True,
                    ),
                )
        except Exception as exc:
            logger.warning("Could not rewrite run summary %s: %s", output_file, exc)

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
        if (
            combined_output_file is not None
            and configured_combined_path
            and str(configured_combined_path) != combined_output_file
        ):
            logger.warning(
                "publisher.output_file %r only renames the combined "
                "subscription inside the repository — locally it is still "
                "written to %r (--output), and the repo copy of that path is "
                "never refreshed. Fix: run with --output %s or drop "
                "publisher.output_file.",
                str(configured_combined_path),
                combined_output_file,
                configured_combined_path,
            )

        # Per-file floor: a subscription slice (split/mix) that came out empty
        # must not overwrite a previously published, working file.  The combined
        # floor above already drops every subscription file when the *whole* run
        # is too small; this guards the opposite case, where the combined output
        # is fine but an individual slice is empty — a transient gap, not a
        # global degradation, so the last good slice is kept on the remote.
        # This is a sub-case of the combined publish floor, so it is also
        # disabled when min_publish_configs == 0 (the operator opt-out that
        # publishes everything, including empty slices, on purpose).
        if combined_output_file is not None and self._min_publish_configs() > 0:
            output_files = self._filter_empty_subscription_slices(
                output_files, combined_output_file
            )
            output_files = self._filter_below_floor_subscription_slices(
                output_files, combined_output_file
            )

        # A file written in the plain-text fallback format (write_subscription
        # crashed) must NOT be published as if it were the base64
        # subscription the repo promises — the fallback file is local-only
        # insurance, the published copy keeps the last good format.
        # The writer records RESOLVED absolute paths; the publish set holds
        # configured relative paths. Canonical form: resolve() both to a
        # common anchor so the filter actually matches (normpath alone could
        # never equate "output/x.txt" with "/abs/.../output/x.txt"). The
        # canonicalisation is extracted to a module-level sync helper —
        # ASYNC240 only fires inside async functions, and this is pure I/O
        # on run-local paths with no concurrent hazard.
        fallback_paths = {
            _canonical_output_path(p)
            for p in self._writer.context.output_stats.get("_fallback_paths", [])
        }
        if fallback_paths:
            logger.warning(
                "%d output file(s) fell back to plain-text format; excluded "
                "from publish (the repo keeps the last good format): %s",
                len(fallback_paths),
                sorted(fallback_paths),
            )
            output_files = [
                f
                for f in output_files
                if _canonical_output_path(f) not in fallback_paths
            ]

        targets = self._unique_publish_paths(output_files)
        if not targets:
            # "Nothing to publish" is a normal outcome (an empty run with the
            # publish floor active filters every file) — it returns True so it
            # is not confused with EXIT_PUBLISH_FAILED. It is logged so a
            # caller diagnosing a missing update can tell "skipped on purpose"
            # from "published".
            logger.info("Nothing to publish — every candidate was filtered out.")
            return True

        all_ok = True
        # One publisher (and therefore one HTTPS connection to the API) for the
        # whole batch: a fresh httpx.AsyncClient per file re-parses the CA
        # bundle and re-handshakes, which costs ~0.2s of blocked event loop per
        # output — over ten seconds for a run with per-country files.
        async with contextlib.AsyncExitStack() as stack:
            self._shared_publisher = await self._enter_shared_publisher(stack)
            try:
                for output_file in targets:
                    repo_path = self._repo_path_for(output_file)
                    if repo_path is None:
                        logger.error(
                            "Cannot derive a repo-relative path for %r "
                            "(absolute or outside the project); refusing to "
                            "publish it as a garbage commit path. Fix: run "
                            "with a relative --output.",
                            output_file,
                        )
                        all_ok = False
                        continue
                    try:
                        if not await self._publish(output_file, repo_path=repo_path):
                            all_ok = False
                    except GitHubPublishError:
                        # Deliberate batch abort (rate-limit beyond cap):
                        # remaining files are not attempted, but the caller
                        # must see False (→ publish_failed + exit 3), not a
                        # crash (exit 1).
                        logger.warning(
                            "Publish batch aborted by rate-limit cap; "
                            "%s not attempted further.",
                            output_file,
                        )
                        all_ok = False
                        break
            finally:
                self._shared_publisher = None
        return all_ok

    def _repo_path_for(self, output_file: str) -> str | None:
        """Return the repository path for a local output file.

        The publisher commits under the same path the file was written to, so
        a relative ``--output``/settings path maps 1:1. An ABSOLUTE local path
        (``C:\\...\\subscription-DE.txt``) must never become the commit path —
        the old code took the local path verbatim and committed garbage like
        ``C:/Users/...`` while the real subscription went stale. Absolute
        paths are mapped back relative to the project root when possible and
        rejected otherwise.
        """
        candidate = output_file.replace("\\", "/")
        if candidate.startswith("/"):
            try:
                candidate = str(
                    Path(candidate)
                    .resolve()
                    .relative_to(
                        Path(resolve_safe_output_path(".")).resolve(),
                    ),
                )
            except (ValueError, OSError):
                return None
        elif len(candidate) > 1 and candidate[1] == ":":
            # Windows drive-letter path: resolve and strip the project root.
            try:
                candidate = str(
                    Path(output_file)
                    .resolve()
                    .relative_to(
                        Path(resolve_safe_output_path(".")).resolve(),
                    ),
                )
            except (ValueError, OSError):
                return None
        if (
            not candidate
            or candidate.startswith(("..", "/"))
            or Path(candidate).is_absolute()
        ):
            return None
        # The Contents API path is always forward-slashed.
        return candidate.replace("\\", "/")

    @staticmethod
    def _is_empty_output_file(path: str) -> bool:
        """Return True when *path* exists and holds no content (an empty slice)."""
        try:
            # Resolve like the writer (project root, not CWD): a 0-byte check
            # against CWD misses the file when running outside the repo and
            # the empty slice then publishes over a working subscription.
            resolved: Path
            try:
                resolved = resolve_safe_output_path(path)
            except ValueError:
                resolved = Path(path)
            return resolved.exists() and resolved.stat().st_size == 0
        except OSError:
            return False

    def _filter_empty_subscription_slices(
        self,
        output_files: list[str],
        combined_output_file: str,
    ) -> list[str]:
        """Drop empty subscription slices so they don't overwrite a working file.

        The combined floor already drops every subscription file when the whole
        run is too small; this guards the opposite case, where the combined
        output is fine but an individual slice (split/mix) is empty — a transient
        gap.  Such an empty slice must not publish over a previously working
        published file, so it is skipped.
        """
        sub_slices = {
            _canonical_output_path(p)
            for p in self._configured_subscription_output_paths(combined_output_file)
        }
        sub_slices.discard(_canonical_output_path(combined_output_file))
        if not sub_slices:
            return output_files
        filtered: list[str] = []
        for f in output_files:
            norm = _canonical_output_path(f)
            # An empty slice was written as a watermark placeholder (non-zero
            # bytes), so key off the recorded empty set, with a 0-byte check as
            # a secondary safety net.
            is_empty = norm in self._empty_output_files or self._is_empty_output_file(f)
            if norm in sub_slices and is_empty:
                logger.warning(
                    "Skipping publish of empty subscription slice %s "
                    "(combined floor passed) to avoid overwriting a "
                    "working published file.",
                    f,
                )
                continue
            filtered.append(f)
        return filtered

    def _filter_below_floor_subscription_slices(
        self,
        output_files: list[str],
        combined_output_file: str,
    ) -> list[str]:
        """Drop subscription slices holding fewer than min_publish_configs.

        The combined floor guards the whole run, and the empty-slice filter
        above guards transient zero-config gaps; this guards the remaining
        hole, where a slice came out with 1..N-1 configs (a near-dead list, a
        drained country) and still published over a previously working file.
        Every drop is recorded in ``_publish_floor_applied`` and surfaced in
        run-summary.json — the floor used to act invisibly.
        """
        min_publish = self._min_publish_configs()
        if min_publish <= 0:
            return output_files
        # Config counts per output path, as recorded by _record_output_stats:
        # configured slices live under their own names, per-country location
        # files under "location_<xx>".
        counts: dict[str, int] = {}
        floored_paths: set[str] = set()
        for stat_key, entry in (self._output_stats or {}).items():
            if not isinstance(entry, dict):
                continue
            stat_file = entry.get("file")
            if not stat_file or "count" not in entry:
                continue
            norm = _canonical_output_path(str(stat_file))
            try:
                counts[norm] = int(entry["count"])
            except (TypeError, ValueError):
                continue
            if stat_key.startswith("location_") or "location" in str(stat_file):
                floored_paths.add(norm)
            elif stat_key == "clash":
                # The YAML twin is a per-file floor subject too: configs
                # inexpressible in Mihomo shrink it below the base64 twin's
                # count, and a near-empty YAML must not overwrite a working
                # published one.
                floored_paths.add(norm)
        combined_norm = _canonical_output_path(combined_output_file)
        floored_paths.update(
            p
            for p in (
                _canonical_output_path(path)
                for path in self._configured_subscription_output_paths(
                    combined_output_file
                )
            )
            if p and p != combined_norm
        )
        if not floored_paths:
            return output_files
        filtered: list[str] = []
        for f in output_files:
            norm = _canonical_output_path(f)
            count = counts.get(norm)
            if norm in floored_paths and count is not None and 0 < count < min_publish:
                self._publish_floor_applied[str(f)] = count
                logger.warning(
                    "Skipping publish of %s: %d config(s) below the per-file "
                    "floor (min_publish_configs=%d); the last good file stays "
                    "published.",
                    f,
                    count,
                    min_publish,
                )
                continue
            filtered.append(f)
        return filtered

    @staticmethod
    def _unique_publish_paths(output_files: list[str]) -> list[str]:
        """Drop duplicate output paths, ignoring separator/case differences.

        Location files are built with :class:`pathlib.Path` (``output\\x.txt``
        on Windows) while configured outputs keep the ``output/x.txt`` spelling
        from settings, so plain string dedup let the same file be committed
        twice — two Contents API round trips racing on one repo path.
        Uses the same canonical form as the empty-slice and fallback filters.
        """
        seen: set[str] = set()
        unique: list[str] = []
        for output_file in output_files:
            key = _canonical_output_path(output_file)
            if key in seen:
                continue
            seen.add(key)
            unique.append(output_file)
        return unique

    @staticmethod
    def _publish_owner_repo(pcfg: dict[str, Any]) -> tuple[str, str]:
        """Resolve the ``(owner, repo)`` publish target.

        ``publisher.owner``/``publisher.repo`` win; the GITHUB_OWNER +
        GITHUB_REPO env pair comes next (that is what CI sets). The final
        fallback is ``GITHUB_REPOSITORY`` — always exported on Actions
        runners, unlike the ``github.event`` payload, which carries no
        ``repository`` on schedule (the main trigger) and used to leave
        every scheduled publish with an empty repo and exit 3. Deliberately
        NO hardcoded default slug here: publishing must never silently
        target a different repository than the one configured.
        """
        owner = str(pcfg.get("owner") or os.environ.get("GITHUB_OWNER") or "")
        repo = str(pcfg.get("repo") or os.environ.get("GITHUB_REPO") or "")
        if owner and repo:
            return owner, repo
        repository = (os.environ.get("GITHUB_REPOSITORY") or "").strip().strip("/")
        if "/" in repository:
            slug_owner, _, slug_repo = repository.partition("/")
            return owner or slug_owner, repo or slug_repo
        return owner, repo

    async def _enter_shared_publisher(
        self,
        stack: contextlib.AsyncExitStack,
    ) -> Any | None:
        """Open one ``GitHubPublisher`` for a whole publish batch, if possible.

        Args:
            stack: Exit stack that owns the publisher for the batch.

        Returns:
            The entered publisher, or ``None`` when publishing is not
            configured — :meth:`_publish` then reports the exact reason per
            file, exactly as it did before.
        """
        pcfg = self._section("publisher")
        owner, repo = self._publish_owner_repo(pcfg)
        if not self.github_token or not owner or not repo:
            return None
        branch = pcfg.get("branch") or os.environ.get("GITHUB_BRANCH") or "main"
        try:
            from src.publisher.github import GitHubPublisher

            return await stack.enter_async_context(
                GitHubPublisher(
                    token=self.github_token,
                    owner=str(owner),
                    repo=str(repo),
                    branch=str(branch),
                ),
            )
        except ValueError:
            # SSRF-guard rejection (bad api_base) is a config error, not a
            # transient publish failure — fail closed, do not downgrade to
            # per-file attempts.
            raise
        except Exception:
            logger.exception("Could not open a shared GitHub publisher")
            return None

    async def _publish(self, output_file: str, repo_path: str | None = None) -> bool:
        """Publish the output file to a GitHub repo via ``GitHubPublisher``.
        Returns True on success, False on failure/skip."""
        if not self.github_token:
            logger.warning("Publish requested but GITHUB_TOKEN is not set — skipping.")
            return False

        pcfg = self._section("publisher")
        owner, repo = self._publish_owner_repo(pcfg)
        branch = pcfg.get("branch") or os.environ.get("GITHUB_BRANCH") or "main"
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
        # Path-safety first, repo-path derivation second: an unsafe local
        # path must fail with the "unsafe path" error, not the derivation one.
        if repo_path is None:
            repo_path = self._repo_path_for(
                str(pcfg.get("output_file") or output_file),
            )
            if repo_path is None:
                logger.error(
                    "Cannot derive a repo-relative path for %r; refusing to "
                    "publish it as a garbage commit path.",
                    output_file,
                )
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

        ok = False
        try:
            async with contextlib.AsyncExitStack() as stack:
                # _publish_files opens one publisher for the whole batch; a
                # standalone call still gets its own.
                publisher: Any = self._shared_publisher
                if publisher is None:
                    publisher = await stack.enter_async_context(
                        GitHubPublisher(
                            token=self.github_token,
                            owner=owner,
                            repo=repo,
                            branch=branch,
                        ),
                    )
                ok = bool(
                    await publisher.publish_file(repo_path, content, commit_message),
                )
        except GitHubPublishError:
            # The publisher raises this only when it deliberately aborts
            # (e.g. the rate-limit reset beyond the wait cap — "aborting
            # publish"). Swallowing it made every remaining file in the batch
            # issue GET+PUT pairs against an exhausted limit. Aborting the
            # batch is the point of the exception.
            raise
        except ValueError:
            # SSRF-guard / config error — fail closed, do not downgrade to
            # a plain publish failure.
            raise
        except Exception:
            logger.exception("Publish failed")
            return False
        if not ok:
            logger.error("Publish completed but reported failure for %s.", repo_path)
        return ok
