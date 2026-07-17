"""Output-writing stage: subscriptions, splits, locations, and run summary."""

from __future__ import annotations

import json
import logging
from collections import Counter
from pathlib import Path
from typing import Any

from src.parsers.base import Config
from src.scheduler.context import PipelineContext, PipelineState
from src.scheduler.stages.aggregate import Aggregator
from src.scheduler.stages.base import PipelineStage
from src.utils.paths import resolve_safe_output_path, validate_safe_output_path

logger = logging.getLogger(__name__)


class OutputWriter(PipelineStage):
    """Writes subscription files, split files, location files, and the run summary."""

    def __init__(self, context: PipelineContext) -> None:
        self.context = context
        self.settings = context.settings
        self.aggregator = Aggregator(context)

    async def run(
        self,
        state: PipelineState,
        context: PipelineContext | None = None,
    ) -> PipelineState:
        """Write all configured outputs from the aggregated and split configs."""
        output_files = self._write_outputs(
            state.aggregated,
            state.split_configs,
            state.summary_file,
        )
        state.output_files = output_files
        return state

    def _publisher_section(self) -> dict[str, Any]:
        return self.settings.section("publisher")

    def _location_output_config(self) -> tuple[bool, str, int]:
        pcfg = self._publisher_section()
        enabled = self.settings.as_bool(pcfg.get("location_outputs_enabled"), True)
        output_dir = str(pcfg.get("location_output_dir") or "output/locations")
        limit = self.settings.as_int(pcfg.get("location_output_limit"), 50, minimum=0)
        return enabled, output_dir, limit

    @staticmethod
    def _location_output_filename(country: str) -> str:
        code = "".join(ch for ch in country.upper() if ch.isalnum())
        return f"subscription-{code or 'XX'}.txt"

    def _clear_location_outputs(self) -> None:
        enabled, output_dir, _limit = self._location_output_config()
        if not enabled:
            return
        try:
            root = resolve_safe_output_path(output_dir)
        except ValueError as exc:
            logger.warning(
                "Unsafe location output dir %r rejected: %s",
                output_dir,
                exc,
            )
            return
        if not root.exists():
            return
        for path in root.glob("subscription-*.txt"):
            try:
                path.unlink()
            except OSError as exc:
                logger.warning(
                    "Failed to remove stale location output %s: %s",
                    path,
                    exc,
                )

    def _build_location_outputs(
        self,
        configs: list[Config],
        per_location_limit: int,
    ) -> dict[str, list[Config]]:
        groups: dict[str, list[Config]] = {}
        for cfg in configs:
            if not cfg.raw_link or not getattr(cfg, "country", None):
                continue
            country = str(cfg.country).upper()
            groups.setdefault(country, []).append(cfg)
        result: dict[str, list[Config]] = {}
        for country, country_configs in sorted(groups.items()):
            result[country] = self.aggregator._country_balanced_limit(
                country_configs,
                per_location_limit,
            )
        return result

    def _write_location_outputs(self, configs: list[Config]) -> list[str]:
        enabled, output_dir, limit = self._location_output_config()
        if not enabled:
            return []
        self._clear_location_outputs()
        outputs = self._build_location_outputs(configs, limit)
        output_files: list[str] = []
        for country, country_configs in outputs.items():
            output_file = str(
                Path(output_dir) / self._location_output_filename(country),
            )
            count = self._write_output(country_configs, output_file)
            self._record_output_stats(
                f"location_{country.lower()}",
                output_file,
                country_configs,
            )
            output_files.append(output_file)
            logger.info(
                "Wrote %d %s location configs to %s.",
                count,
                country,
                output_file,
            )
        return output_files

    def _write_outputs(
        self,
        aggregated: list[Config],
        splits: dict[str, list[Config]],
        summary_file: str | None = None,
    ) -> list[str]:
        pcfg = self._publisher_section()
        combined_output_file = str(pcfg.get("output_file") or "output/subscription.txt")
        mix_output_file = str(
            pcfg.get("mix_output_file") or "output/subscription-mix.txt",
        )
        split_output_files = pcfg.get("split_output_files") or {}

        output_files: list[str] = [combined_output_file]
        count = self._write_output(aggregated, combined_output_file)
        logger.info("Wrote %d configs to %s.", count, combined_output_file)

        mix_configs = self._build_mix(aggregated, splits, pcfg)
        self._write_output(mix_configs, mix_output_file)
        output_files.append(mix_output_file)

        split_files = self._write_split_outputs(splits, split_output_files)
        output_files.extend(split_files)

        location_files = self._write_location_outputs(aggregated)
        output_files.extend(location_files)

        self._write_run_summary("success", summary_file)
        return output_files

    def _write_empty_outputs(self, summary_file: str | None = None) -> list[str]:
        pcfg = self._publisher_section()
        combined_output_file = str(pcfg.get("output_file") or "output/subscription.txt")
        mix_output_file = str(
            pcfg.get("mix_output_file") or "output/subscription-mix.txt",
        )
        split_output_files = pcfg.get("split_output_files") or {}

        output_files = [combined_output_file, mix_output_file]
        self._write_empty_output(combined_output_file)
        self._write_empty_output(mix_output_file)
        self._write_empty_split_outputs(split_output_files)
        output_files.extend(str(path) for path in split_output_files.values())
        self._write_run_summary("empty_sources", summary_file)
        return output_files

    @staticmethod
    def _build_mix(
        aggregated: list[Config],
        splits: dict[str, list[Config]],
        pcfg: dict[str, Any],
    ) -> list[Config]:
        blacklist = list(splits.get("blacklist", []))
        whitelist = list(splits.get("whitelist", []))
        mix_black = pcfg.get("mix_blacklist_count", 100)
        mix_white = pcfg.get("mix_whitelist_count", 100)
        if isinstance(mix_black, int) and mix_black > 0:
            blacklist = blacklist[:mix_black]
        if isinstance(mix_white, int) and mix_white > 0:
            whitelist = whitelist[:mix_white]

        mixed: list[Config] = []
        black_iter = iter(blacklist)
        white_iter = iter(whitelist)
        while True:
            added = False
            try:
                mixed.append(next(black_iter))
                added = True
            except StopIteration:
                pass
            try:
                mixed.append(next(white_iter))
                added = True
            except StopIteration:
                pass
            if not added:
                break
        return mixed

    def _write_output(self, configs: list[Config], output_file: str) -> int:
        try:
            safe_path = resolve_safe_output_path(output_file)
        except ValueError:
            logger.exception("Unsafe output path %r rejected", output_file)
            return 0
        try:
            from src.aggregator.output import write_subscription
        except (ImportError, AttributeError):
            logger.exception(
                "Cannot import write_subscription — writing plain fallback.",
            )
            return self._write_plain_fallback(configs, str(safe_path))
        try:
            count = write_subscription(configs, str(safe_path))
        except Exception:
            logger.exception("write_subscription failed — plain fallback.")
            return self._write_plain_fallback(configs, str(safe_path))
        return int(count) if count else 0

    def _write_empty_output(self, output_file: str) -> None:
        if not validate_safe_output_path(output_file):
            return
        try:
            self._write_output([], output_file)
        except Exception as exc:
            logger.warning("Could not write empty output %s: %s", output_file, exc)

    @staticmethod
    def _write_plain_fallback(configs: list[Config], output_file: str) -> int:
        try:
            path = Path(output_file)
            path.parent.mkdir(parents=True, exist_ok=True)
            lines = [c.raw_link for c in configs if c.raw_link]
            with path.open("w", encoding="utf-8") as fh:
                fh.write("\n".join(lines))
                if lines:
                    fh.write("\n")
            return len(lines)
        except Exception:
            logger.exception("Plain fallback write failed for %s", output_file)
            return 0

    def _write_split_outputs(
        self,
        splits: dict[str, list[Config]],
        split_output_files: dict[str, str],
    ) -> list[str]:
        output_files: list[str] = []
        for list_key, output_file in split_output_files.items():
            configs = splits.get(list_key, [])
            count = self._write_output(configs, output_file)
            logger.info("Wrote %d %s configs to %s.", count, list_key, output_file)
            output_files.append(output_file)
        return output_files

    def _write_empty_split_outputs(self, split_output_files: dict[str, str]) -> None:
        for output_file in split_output_files.values():
            self._write_empty_output(output_file)

    def _record_output_stats(
        self,
        name: str,
        output_file: str,
        configs: list[Config],
    ) -> None:
        country_counts = Counter(
            str(cfg.country).upper()
            for cfg in configs
            if cfg.raw_link and getattr(cfg, "country", None)
        )
        self.context.output_stats[name] = {
            "file": output_file,
            "count": sum(1 for cfg in configs if cfg.raw_link),
            "countries": dict(country_counts.most_common()),
        }

    def _status_output_file(self) -> str | None:
        pcfg = self._publisher_section()
        raw = pcfg.get("status_output_file")
        if not raw:
            return None
        return str(raw)

    def _write_run_summary(
        self,
        status: str,
        output_file: str | None = None,
    ) -> str | None:
        output_file = output_file or self._status_output_file()
        if not output_file:
            return None
        validation = dict(self.context.liveness_stats)
        validation.pop("proxy_urls", None)
        payload = {
            "status": status,
            "outputs": self.context.output_stats,
            "validation": validation,
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
