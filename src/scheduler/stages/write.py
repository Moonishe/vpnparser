"""Output-writing stage: subscriptions, splits, locations, and run summary."""

from __future__ import annotations

import json
import logging
from collections import Counter
from collections.abc import Iterable
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

    @staticmethod
    def _location_root(output_dir: str) -> Path | None:
        """Resolve the location output dir stale per-country files live in.

        Args:
            output_dir: Configured location output directory.

        Returns:
            The resolved directory, or ``None`` when the path is unsafe.
        """
        try:
            return resolve_safe_output_path(output_dir)
        except ValueError as exc:
            logger.warning(
                "Unsafe location output dir %r rejected: %s",
                output_dir,
                exc,
            )
            return None

    @classmethod
    def _removable_location_root(cls, output_dir: str) -> Path | None:
        """Resolve the location output dir that stale files may be deleted from.

        ``resolve_safe_output_path`` only *warns* for absolute paths outside the
        project, which is fine for writing but not for unlinking: an absolute
        ``location_output_dir`` would let the cleanup remove unrelated files.
        Deletion therefore requires the directory to stay inside the project
        root; outside it the stale files are only overwritten with an empty
        subscription, which is exactly what writing there already does.

        Args:
            output_dir: Configured location output directory.

        Returns:
            The resolved directory, or ``None`` when nothing may be unlinked.
        """
        root = cls._location_root(output_dir)
        if root is None:
            return None
        # "." resolves to the project root the same helper anchors on.
        base = resolve_safe_output_path(".", strict=True)
        if root != base and base not in root.parents:
            logger.warning(
                "Location output dir %r is outside the project root %s — "
                "refusing to remove stale files there.",
                output_dir,
                base,
            )
            return None
        return root

    def _reserved_output_paths(self, extra: Iterable[str] | None = None) -> set[Path]:
        """Resolve the output paths the location cleanup must never touch.

        ``subscription-blacklist.txt``, ``subscription-whitelist.txt`` and
        ``subscription-mix.txt`` all match the ``subscription-*.txt`` cleanup
        mask, so pointing ``location_output_dir`` at the directory that already
        holds them made the cleanup delete the freshly written split/mix files
        and publish empty placeholders in their place — while the run summary
        still reported the counts written a moment earlier.

        Args:
            extra: Additional paths the caller knows about, e.g. the combined
                output file, which comes from ``--output`` rather than settings.

        Returns:
            Resolved paths that must survive the cleanup.
        """
        pcfg = self._publisher_section()
        candidates: list[str] = [str(path) for path in (extra or []) if path]
        for key in ("output_file", "mix_output_file"):
            value = pcfg.get(key)
            if value:
                candidates.append(str(value))
        splits = pcfg.get("split_output_files")
        if isinstance(splits, dict):
            candidates.extend(str(value) for value in splits.values() if value)

        reserved: set[Path] = set()
        for candidate in candidates:
            try:
                reserved.add(resolve_safe_output_path(candidate, strict=True))
            except ValueError:
                # An unsafe path is never written either, so nothing to protect.
                continue
        return reserved

    def _clear_location_outputs(
        self,
        reserved_paths: Iterable[str] | None = None,
    ) -> list[str]:
        """Remove stale per-country subscription files and report their paths.

        The caller is expected to leave an empty subscription behind for every
        returned path: a published location file is only replaced when the same
        path is written again, so a country that merely disappears locally would
        keep serving the previous run's configs from the repository forever.

        Args:
            reserved_paths: Output paths that belong to another stage and must
                not be cleared even when they sit in the location directory.

        Returns:
            Paths (relative to the configured output dir) of the stale files.
        """
        enabled, output_dir, _limit = self._location_output_config()
        if not enabled:
            return []
        root = self._location_root(output_dir)
        if root is None or not root.exists():
            return []
        removable_root = self._removable_location_root(output_dir)
        reserved = self._reserved_output_paths(reserved_paths)
        stale: list[str] = []
        for path in sorted(root.glob("subscription-*.txt")):
            # Symlinks may point anywhere, so only plain files inside the
            # resolved root are touched.
            if path.is_symlink() or not path.is_file():
                continue
            if path.resolve().parent != root:
                continue
            if path.resolve() in reserved:
                logger.warning(
                    "location_output_dir %r also holds the subscription output "
                    "%s — keeping it. Fix: give the location outputs their own "
                    "directory.",
                    output_dir,
                    path.name,
                )
                continue
            stale.append(str(Path(output_dir) / path.name))
            if removable_root is None:
                continue
            try:
                path.unlink()
            except OSError as exc:
                logger.warning(
                    "Failed to remove stale location output %s: %s",
                    path,
                    exc,
                )
        return stale

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

    def _write_location_outputs(
        self,
        configs: list[Config],
        reserved_paths: Iterable[str] | None = None,
    ) -> list[str]:
        """Write one subscription per country and retire the vanished ones.

        Args:
            configs: Configs to split by country.
            reserved_paths: Output paths owned by another stage that must not be
                retired even when they live in the location directory.

        Returns:
            Paths of every location file to publish: the ones written this run
            plus the empty placeholders left for countries that disappeared.
        """
        enabled, output_dir, limit = self._location_output_config()
        if not enabled:
            return []
        stale_files = self._clear_location_outputs(reserved_paths)
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
        for output_file in stale_files:
            if output_file in output_files:
                continue
            # Empty, not missing: the placeholder is what replaces the stale
            # copy already published for a country that is gone.
            self._write_empty_output(output_file)
            # Retired files are rewritten and published like any other output,
            # so they belong in the run summary too — without this an empty run
            # reports no location outputs at all while replacing every one.
            self._record_output_stats(
                f"location_{self._location_country_key(output_file)}",
                output_file,
                [],
            )
            output_files.append(output_file)
            logger.info("Retired location output %s (now empty).", output_file)
        return output_files

    @staticmethod
    def _location_country_key(output_file: str) -> str:
        """Return the lowercase country key encoded in a location file name.

        Args:
            output_file: Path of a ``subscription-<code>.txt`` location file.

        Returns:
            The country code in lower case, matching the key
            :meth:`_write_location_outputs` uses for freshly written files.
        """
        stem = Path(output_file).stem
        _, _, code = stem.partition("-")
        return (code or stem).lower()

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
