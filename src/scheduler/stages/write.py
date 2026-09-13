"""Output-writing helpers used by the runner (subscriptions, splits, locations).

The runner composes the write stage itself (order, publish floor, summary
shape): the generic ``run(state)`` form and the second, diverging output
assembly it used to carry (hardcoded mix path, its own summary payload)
were dead code and have been removed.
"""

from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from src.aggregator.output import _safe_raw_link
from src.parsers.base import Config
from src.scheduler.context import PipelineContext
from src.scheduler.stages.aggregate import Aggregator
from src.scheduler.stages.base import PipelineStage
from src.utils.paths import (
    resolve_safe_output_path,
    validate_safe_output_path,
    write_text_atomic,
)


def _is_countable(cfg: Config) -> bool:
    """Same predicate the writer applies: alive (or unjudged) + safe link."""
    return cfg.is_alive is not False and _safe_raw_link(cfg.raw_link) is not None


logger = logging.getLogger(__name__)


class OutputWriter(PipelineStage):
    """Writes subscription files, split files, and location files on demand."""

    def __init__(self, context: PipelineContext) -> None:
        self.context = context
        self.settings = context.settings
        self.aggregator = Aggregator(context)

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
            # Forward slashes: Path gives backslashes on Windows, which leak
            # into run-summary.json and break cross-platform tooling.
            output_file = str(
                Path(output_dir) / self._location_output_filename(country),
            ).replace("\\", "/")
            count = self._write_output(country_configs, output_file)
            self.context.output_stats[f"location_{country.lower()}"] = {
                "file": output_file,
                "count": sum(1 for cfg in country_configs if _is_countable(cfg)),
                "countries": dict(
                    Counter(
                        str(cfg.country).upper()
                        for cfg in country_configs
                        if _is_countable(cfg) and getattr(cfg, "country", None)
                    ).most_common(),
                ),
            }
            output_files.append(output_file)
            logger.info(
                "Wrote %d %s location configs to %s.",
                count,
                country,
                output_file,
            )
        written = {p.replace("\\", "/") for p in output_files}
        for stale in stale_files:
            # Forward slashes like the freshly written entries above, so the
            # membership check cannot miss on separator spelling.
            output_file = stale.replace("\\", "/")
            if output_file in written:
                continue
            # Empty, not missing: the placeholder is what replaces the stale
            # copy already published for a country that is gone.
            self._write_empty_output(output_file)
            # Retired files are rewritten and published like any other output,
            # so they belong in the run summary too — without this an empty run
            # reports no location outputs at all while replacing every one.
            self.context.output_stats[
                f"location_{self._location_country_key(output_file)}"
            ] = {
                "file": output_file,
                "count": 0,
                "countries": {},
            }
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

    def _clash_output_file(self) -> str | None:
        """Configured Clash YAML path, or ``None`` when the twin is off."""
        pcfg = self._publisher_section()
        return str(pcfg.get("clash_output_file") or "") or None

    def _write_clash_output(self, configs: list[Config]) -> str | None:
        """Write the Mihomo YAML twin of the combined subscription."""
        clash_output_file = self._clash_output_file()
        if not clash_output_file:
            return None
        try:
            safe_path = resolve_safe_output_path(clash_output_file)
        except ValueError:
            logger.exception("Unsafe Clash output path %r rejected", clash_output_file)
            return None
        write_failed = False
        try:
            from src.aggregator.clash import write_clash_subscription

            count = write_clash_subscription(configs, str(safe_path))
        except Exception:
            # An unwritten file would keep serving the previous run's
            # proxies from the repository forever — empty it instead.
            logger.exception("Clash subscription write failed.")
            self._write_empty_clash_output()
            count = 0
            write_failed = True
        if not write_failed:
            # A failure already logged its exception above; "Wrote 0 proxies"
            # right after it read like a success line for a broken run.
            logger.info("Wrote %d proxies to %s.", count, clash_output_file)
        # Same shape the other outputs get via _record_output_stats: an empty
        # run's clash entry used to differ from a success run's (count source
        # and countries), making run-summary comparisons asymmetric.
        # Countries are counted over exactly the set the YAML writer keeps
        # (alive + raw link + expressible): counting dead or inexpressible
        # (shadowtls, bad network, reality w/o pbk, tuic v4) configs inflated
        # the sum past the file's count.
        from src.aggregator.clash import config_to_clash_proxy

        country_counts = Counter(
            str(cfg.country).upper()
            for cfg in configs
            if cfg.raw_link
            and cfg.is_alive is not False
            and config_to_clash_proxy(cfg, set()) is not None
            and getattr(cfg, "country", None)
        )
        self.context.output_stats["clash"] = {
            "file": clash_output_file,
            "count": count,
            "countries": dict(country_counts.most_common()),
        }
        if write_failed:
            # A failed write leaves a `proxies: []` placeholder behind; handing
            # that path to the publisher would overwrite a working published
            # Clash twin with an empty one, so the caller is told there is
            # nothing to publish this run.
            return None
        return clash_output_file

    def _write_empty_clash_output(self) -> None:
        """Leave an empty (but valid) YAML document behind on empty runs."""
        pcfg = self._publisher_section()
        clash_output_file = str(pcfg.get("clash_output_file") or "")
        if not clash_output_file:
            return
        try:
            write_text_atomic(clash_output_file, "proxies: []\n")
        except (OSError, ValueError) as exc:
            logger.warning(
                "Could not write empty Clash output %s: %s",
                clash_output_file,
                exc,
            )

    def _write_output(self, configs: list[Config], output_file: str) -> int:
        try:
            safe_path = resolve_safe_output_path(output_file)
        except ValueError:
            logger.exception("Unsafe output path %r rejected", output_file)
            return 0
        return self._write_output_safe(configs, str(safe_path))

    def _write_output_safe(self, configs: list[Config], safe_path: str) -> int:
        try:
            from src.aggregator.output import write_subscription
        except (ImportError, AttributeError):
            logger.exception(
                "Cannot import write_subscription — writing plain fallback.",
            )
            count = self._write_plain_fallback(configs, safe_path)
            self._mark_fallback(safe_path)
            return count
        try:
            count = write_subscription(configs, str(safe_path))
        except Exception:
            # A plain-links file is NOT the format the repository promises
            # (base64). It is better than no local file, but it must never be
            # published as if it were the real subscription — the runner
            # filters these paths out of the publish set (see
            # _fallback_paths).
            logger.exception("write_subscription failed — plain fallback.")
            count = self._write_plain_fallback(configs, safe_path)
            self._mark_fallback(safe_path)
            return count
        return int(count) if count else 0

    def _mark_fallback(self, safe_path: str) -> None:
        """Record a path written in the fallback format (never publish it).

        The path is stored as the RESOLVED absolute form: the runner filters
        publish candidates via ``_canonical_output_path`` and relative
        configured paths (``output/subscription.txt``) must match it.
        """
        from pathlib import Path as _Path

        self.context.output_stats.setdefault("_fallback_paths", []).append(
            str(_Path(safe_path).resolve()),
        )

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
            lines = [c.raw_link for c in configs if c.raw_link]
            text = "\n".join(lines)
            if lines:
                text += "\n"
            # Atomic write so a crash mid-write cannot publish a broken file.
            write_text_atomic(output_file, text, encoding="utf-8")
            return len(lines)
        except Exception:
            logger.exception("Plain fallback write failed for %s", output_file)
            return 0
