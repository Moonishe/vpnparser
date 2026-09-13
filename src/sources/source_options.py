"""Per-source option parsing for :mod:`src.sources.manager`.

Pure plumbing shared by every source type: reading typed knobs
(``timeout``/``attempts``/``max_files``/...) out of a ``sources.json`` entry,
deriving fetch overrides from them, and applying include/exclude file filters.
Kept free of I/O and of any patchable module state so the manager can delegate
to it without changing what its tests monkeypatch.
"""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any

from src.validators.country_filter import normalize_country_code

#: Fallbacks for the per-source ``timeout``/``attempts`` knobs. A url-list index
#: is fetched once per run and losing it costs the whole source, so it keeps the
#: retry-heavy default; each URL listed *inside* one is one of hundreds, where a
#: retry is rarely worth three times the wall clock.
DEFAULT_FETCH_TIMEOUT = 30.0
DEFAULT_FETCH_ATTEMPTS = 3
DEFAULT_LISTED_URL_ATTEMPTS = 1


def _source_default_country(source: dict[str, Any]) -> str | None:
    raw = source.get("default_country")
    # Only a supported 2-letter ISO code counts: anything else would be
    # stamped onto Config.country and leak into location files and filter
    # verdicts (see src.validators.country_filter.normalize_country_code).
    return normalize_country_code(raw)


def _int_source_value(
    source: dict[str, Any],
    key: str,
    default: int,
    *,
    minimum: int = 1,
    maximum: int | None = None,
) -> int:
    """Read an integer source setting with configurable bounds.

    Booleans are explicitly rejected — bool is a subclass of int in Python
    (int(True) == 1), so without this guard ``max_files: false`` would
    silently become 1. Pass minimum=0 to allow 0 as a sentinel (unlimited).
    ``maximum`` caps crawl-bombs from config (e.g. max_files: 1000000).
    """
    raw = source.get(key, default)
    if isinstance(raw, bool):
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    value = max(minimum, value)
    if maximum is not None:
        value = min(maximum, value)
    return value


def _fetch_timeout(source: dict[str, Any]) -> float:
    """Return the per-request ``timeout`` configured for *source*.

    Applies to every URL the source pulls — a url-list index just as much
    as the URLs listed in it. Clamped to 2..60s so a config typo cannot
    park one fetch for an hour (budget is timeout*4).
    """
    return _float_source_value(
        source, "timeout", DEFAULT_FETCH_TIMEOUT, minimum=2.0, maximum=60.0
    )


def _direct_fetch_overrides(source: dict[str, Any]) -> dict[str, Any]:
    """Return the ``timeout``/``attempts`` overrides declared by *source*.

    Both knobs are documented per source and used to be read for the URLs
    *listed inside* a url-list only: the index itself, and every ``url``
    source, silently kept the built-in 30s/3-attempt defaults, so a mirror
    capped at ``timeout: 10`` could still hold the job for minutes.

    Only keys the source actually sets are returned, leaving the direct
    fetcher as the single place its own defaults live.
    """
    overrides: dict[str, Any] = {}
    if "timeout" in source:
        overrides["timeout"] = _fetch_timeout(source)
    if "attempts" in source:
        overrides["attempts"] = _int_source_value(
            source,
            "attempts",
            DEFAULT_FETCH_ATTEMPTS,
            maximum=10,
        )
    return overrides


def _float_source_value(
    source: dict[str, Any],
    key: str,
    default: float,
    *,
    minimum: float | None = None,
    maximum: float | None = None,
) -> float:
    """Read a float source setting, rejecting booleans/non-finite."""
    import math

    raw = source.get(key, default)
    if isinstance(raw, bool):
        return default
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return default
    if not math.isfinite(value):
        return default
    if minimum is not None:
        value = max(minimum, value)
    if maximum is not None:
        value = min(maximum, value)
    return value


def _filter_files(
    source: dict[str, Any],
    files: list[tuple[str, str]],
) -> list[tuple[str, str]]:
    """Apply optional include_files/exclude_files filters to raw sources.

    Non-list values (str, int, None) are silently ignored — only actual
    lists are iterated.  ``None`` items inside a list are skipped so they
    cannot become the literal string ``"none"`` and accidentally filter
    out every file.

    Filter entries are normalized identically to filenames (backslashes
    converted to forward slashes, leading/trailing slashes stripped,
    lowercased) so that ``"/keep.txt"`` or ``"dir\\\\file.txt"`` in the
    config match the corresponding file.
    """

    def _norm(value: object) -> str:
        return str(value).strip().replace("\\", "/").strip("/").lower()

    def _to_filter_set(key: str) -> set[str]:
        raw = source.get(key)
        if not isinstance(raw, list):
            return set()
        return {_norm(item) for item in raw if item is not None and str(item).strip()}

    include = _to_filter_set("include_files")
    exclude = _to_filter_set("exclude_files")
    if not include and not exclude:
        return files

    filtered: list[tuple[str, str]] = []
    for filename, content in files:
        key = _norm(filename)
        basename = PurePosixPath(key).name
        match_keys = {key, basename}
        if include and not (include & match_keys):
            continue
        if exclude & match_keys:
            continue
        filtered.append((filename, content))
    return filtered
