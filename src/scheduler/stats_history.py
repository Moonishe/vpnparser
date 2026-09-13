"""Run-over-run statistics: the trend file behind the README badge.

One JSON entry per run (alive counts per list, proxy pool size), appended to
a capped history that is published with the subscriptions, plus an SVG
sparkline rendered from it. The Telegram reporter reads the same file to
diff the current run against the previous one.
"""

from __future__ import annotations

import contextlib
import json
import logging
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from src.utils.paths import resolve_safe_output_path, write_text_atomic

logger = logging.getLogger(__name__)

DEFAULT_STATS_HISTORY_FILE = "output/stats-history.json"
DEFAULT_TREND_SVG_FILE = "output/alive-trend.svg"
#: Two weeks of hourly runs; older entries are dropped on append.
DEFAULT_HISTORY_LIMIT = 336

#: (list name, line color) pairs drawn in the sparkline, in order.
_TREND_SERIES = (("blacklist", "#5b8def"), ("whitelist", "#3fbf6f"))


def load_stats_history(path: str = DEFAULT_STATS_HISTORY_FILE) -> list[dict[str, Any]]:
    """Return the stored entries; anything unreadable counts as no history."""
    try:
        target = resolve_safe_output_path(path)
    except ValueError as exc:
        logger.warning("Unsafe stats history path %r: %s", path, exc)
        return []
    if not target.exists():
        return []
    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError) as exc:
        # UnicodeDecodeError (a ValueError) must be caught explicitly: one
        # corrupted byte used to raise past this loader forever — the file
        # survives in the Actions cache and every later run silently
        # stopped appending. Returning [] here also self-heals: the next
        # append overwrites the corrupt file with a fresh history.
        logger.warning("Cannot read stats history %s: %s", path, exc)
        return []
    if not isinstance(raw, list):
        return []
    return [entry for entry in raw if isinstance(entry, dict)]


def run_stats_entry(
    liveness_stats: dict[str, Any],
    status: str,
    *,
    now: int | None = None,
) -> dict[str, Any]:
    """Build one history entry out of the liveness stage statistics."""

    def _num(value: Any) -> int:
        try:
            return int(value or 0)
        except (TypeError, ValueError, OverflowError):
            try:
                return int(float(value))
            except (TypeError, ValueError, OverflowError):
                return 0

    lists_raw = liveness_stats.get("lists")
    lists: dict[str, dict[str, int]] = {}
    if isinstance(lists_raw, dict):
        for list_type, item in lists_raw.items():
            if not isinstance(item, dict):
                continue
            # xray stays the canonical alive/checked pair (badge + legacy
            # readers), but TCP/TLS-only runs never set xray_* — without
            # their own counters the trend history recorded zeros and the
            # Telegram diff-alert cried collapse on healthy runs.
            lists[str(list_type)] = {
                "alive": _num(item.get("xray_alive")),
                "checked": _num(item.get("xray_checked")),
                "tcp_alive": _num(item.get("tcp_alive")),
                "tcp_checked": _num(item.get("tcp_checked")),
                "tls_alive": _num(item.get("tls_alive")),
                "tls_checked": _num(item.get("tls_checked")),
            }
    return {
        "ts": _num(now if now is not None else time.time()),
        "status": str(status),
        "proxy_count": _num(liveness_stats.get("proxy_count")),
        "proxy_networks": _num(liveness_stats.get("proxy_networks")),
        "lists": lists,
    }


@contextlib.contextmanager
def _history_file_lock(target: Path) -> Iterator[None]:
    """Deprecated alias for :func:`src.utils.paths.history_file_lock`.

    The implementation moved there so the health-history writer shares the
    same cross-process exclusion; kept as an alias for compatibility.
    """
    from src.utils.paths import history_file_lock

    with history_file_lock(target):
        yield


def append_run_stats(
    entry: dict[str, Any],
    path: str = DEFAULT_STATS_HISTORY_FILE,
    *,
    limit: int = DEFAULT_HISTORY_LIMIT,
) -> tuple[list[dict[str, Any]], str | None]:
    """Append *entry* to the history file (atomic write).

    The load-append-write sequence runs under a best-effort cross-process
    lock so two overlapping runs cannot lose each other's entries.

    Returns the full (capped) history and the written path — ``None`` for the
    path when the write failed, so the caller does not publish a ghost file.
    """
    try:
        target = resolve_safe_output_path(path)
    except Exception as exc:
        logger.warning("Cannot write stats history %s: %s", path, exc)
        return [entry], None
    with _history_file_lock(target):
        history = load_stats_history(path)
        history.append(entry)
        if limit > 0 and len(history) > limit:
            history = history[-limit:]
        try:
            write_text_atomic(
                target,
                json.dumps(history, ensure_ascii=False, indent=1),
            )
        except Exception as exc:
            logger.warning("Cannot write stats history %s: %s", path, exc)
            return history, None
        return history, path


def _series_points(
    history: list[dict[str, Any]],
    key: str,
    *,
    points: int,
) -> list[int]:
    values: list[int] = []
    for entry in history[-points:]:
        lists = entry.get("lists")
        item = lists.get(key, {}) if isinstance(lists, dict) else {}
        if not isinstance(item, dict):
            values.append(0)
            continue
        try:
            values.append(int(item.get("alive") or 0))
        except (TypeError, ValueError, OverflowError):
            try:
                raw_alive: Any = item.get("alive")
                values.append(int(float(raw_alive)))
            except (TypeError, ValueError, OverflowError):
                values.append(0)
    return values


def render_trend_svg(
    history: list[dict[str, Any]],
    path: str = DEFAULT_TREND_SVG_FILE,
    *,
    points: int = 120,
    width: int = 640,
    height: int = 120,
) -> str | None:
    """Render the alive-count sparkline; returns the path or ``None``."""
    rows = history[-points:]
    if not rows:
        return None
    all_series = {
        key: _series_points(history, key, points=points)
        for key, _color in _TREND_SERIES
    }
    max_alive = max((v for vals in all_series.values() for v in vals), default=0)
    top = max(max_alive, 1)
    pad_x, pad_y = 4.0, 18.0
    plot_w = float(width - 2 * pad_x)
    plot_h = float(height - 2 * pad_y)
    step = plot_w / max(1, len(rows) - 1)

    def _coords(values: list[int]) -> str:
        pts = []
        for index, value in enumerate(values):
            x = pad_x + index * step
            y = pad_y + plot_h * (1.0 - value / top)
            pts.append(f"{x:.1f},{y:.1f}")
        return " ".join(pts)

    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" '
        f'height="{height}" viewBox="0 0 {width} {height}" '
        f'role="img" aria-label="Alive configs trend">',
        f'<rect width="{width}" height="{height}" fill="#0d1117"/>',
    ]
    labels: list[str] = []
    offset = 8
    for key, color in _TREND_SERIES:
        values = all_series.get(key)
        if not values:
            continue
        lines.append(
            f'<polyline fill="none" stroke="{color}" stroke-width="2" '
            f'points="{_coords(values)}"/>'
        )
        current = values[-1]
        labels.append(
            f'<text x="{offset}" y="12" fill="{color}" font-size="10" '
            f'font-family="monospace">{key}: {current}</text>'
        )
        offset += 8 + 10 * (len(key) + len(str(current)) + 2)
    lines.extend(labels)
    lines.append(
        f'<text x="{width - 4}" y="12" fill="#8b949e" font-size="10" '
        f'text-anchor="end" font-family="monospace">max {max_alive}</text>'
    )
    lines.append("</svg>")
    try:
        target = resolve_safe_output_path(path)
        write_text_atomic(target, "\n".join(lines))
    except Exception as exc:
        logger.warning("Cannot write trend SVG %s: %s", path, exc)
        return None
    return path
