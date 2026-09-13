"""Proxy health tracking for the SOCKS5 proxy pool.

Keeps a lightweight history of which proxies succeeded/failed and how fast
they were, so the pipeline can prefer recently-working proxies and ban
consistently dead ones across runs.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from src.utils.net import redact_proxy_url

logger = logging.getLogger(__name__)

_COUNTER_FIELDS = ("attempts", "successes", "consecutive_failures")

#: How long a proxy nobody probed successfully or unsuccessfully is remembered.
#: The file is rewritten (and committed) on every run, so without an upper
#: bound it keeps every proxy the upstream lists ever rotated through.
_DEFAULT_RETENTION_SECONDS = 86400.0

#: Default latency/recent-results window, mirrored by _sanitize_records for
#: legacy-key migration merges (the instance window is not known there).
_DEFAULT_WINDOW = 5


def _as_count(value: Any) -> int | None:
    """Return *value* as a non-negative int, or None when it is not one."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    count = int(value)
    return count if count >= 0 else None


def _sanitize_entry(raw: Any) -> dict[str, Any] | None:
    """Return a well-typed history entry, or None when *raw* is unusable.

    The history file is rewritten on every run and read back on the next one,
    so a truncated or hand-edited file must not reach :meth:`record` or
    :meth:`rank` — an ``int`` where a dict is expected used to raise deep inside
    the proxy pool, where the error is swallowed and the pool silently empties.
    """
    if not isinstance(raw, dict):
        return None

    entry: dict[str, Any] = {}
    for field in _COUNTER_FIELDS:
        count = _as_count(raw.get(field, 0))
        if count is None:
            return None
        entry[field] = count

    latencies = raw.get("latency_ms", [])
    if not isinstance(latencies, list):
        return None
    entry["latency_ms"] = [
        float(value)
        for value in latencies
        if not isinstance(value, bool) and isinstance(value, int | float) and value > 0
    ]

    recent_results = raw.get("recent_results", [])
    if not isinstance(recent_results, list):
        return None
    entry["recent_results"] = [
        bool(value) for value in recent_results if isinstance(value, bool)
    ]

    last_seen = raw.get("last_seen")
    if last_seen is None:
        # Legacy records predate the last_seen field. Substituting 0.0 made
        # prune() — which save() always runs — drop them on the very next
        # write, silently destroying the accumulated ban/latency stats.
        # "Seen just now" buys the record one retention window to earn a
        # fresher last_seen from a real probe.
        last_seen = time.time()
    elif isinstance(last_seen, bool) or not isinstance(last_seen, int | float):
        return None
    entry["last_seen"] = float(last_seen)

    banned_until = raw.get("banned_until", 0.0)
    if isinstance(banned_until, bool) or not isinstance(banned_until, int | float):
        return None
    entry["banned_until"] = float(banned_until)
    return entry


def _sanitize_records(
    data: dict[Any, Any], window: int = 5
) -> dict[str, dict[str, Any]]:
    """Keep only well-formed ``proxy_url -> entry`` pairs, warning about drops.

    Keys are migrated to the credential-free form: files written by pre-0.2.0
    versions (or restored from an old cache) carried raw
    ``socks5://user:pass@host`` keys, and without re-keying here the loaded
    records would re-persist that credential-at-rest on every save — plus
    fork the history, since new probes land under the redacted key.

    ``window`` caps the migrated latency/recent lists: ``load()`` passes the
    configured ``latency_window`` so a wide window is not silently truncated
    to the default on every restart.
    """
    cap = max(1, window)
    records: dict[str, dict[str, Any]] = {}
    dropped: list[str] = []
    migrated = 0
    for key, raw in data.items():
        entry = _sanitize_entry(raw) if isinstance(key, str) and key.strip() else None
        if entry is None:
            dropped.append(str(key))
            continue
        new_key = ProxyHealthHistory._key(key)
        if new_key != key:
            migrated += 1
            existing = records.get(new_key)
            if existing is not None:
                # A redacted twin already loaded (or an earlier migration of
                # the same host:port): merge so no evidence is lost.
                existing["attempts"] += entry["attempts"]
                existing["successes"] += entry["successes"]
                existing["latency_ms"] = (existing["latency_ms"] + entry["latency_ms"])[
                    -cap:
                ]
                existing["recent_results"] = (
                    existing["recent_results"] + entry["recent_results"]
                )[-cap:]
                existing["consecutive_failures"] = max(
                    int(existing.get("consecutive_failures") or 0),
                    int(entry.get("consecutive_failures") or 0),
                )
                existing["banned_until"] = max(
                    float(existing["banned_until"] or 0.0),
                    float(entry["banned_until"] or 0.0),
                )
                existing["last_seen"] = max(
                    float(existing["last_seen"] or 0.0),
                    float(entry["last_seen"] or 0.0),
                )
                continue
        records[new_key] = entry
    if dropped:
        logger.warning(
            "Dropped %d malformed proxy health record(s): %s",
            len(dropped),
            ", ".join(repr(redact_proxy_url(key)) for key in dropped[:5]),
        )
    if migrated:
        logger.info(
            "Migrated %d proxy health record(s) to credential-free keys.",
            migrated,
        )
    return records


def _masked_key(url: str) -> str:
    """Redact *url* for use as a record key, including scheme-less forms.

    ``redact_proxy_url``'s userinfo rule anchors on an authority (``//...@``),
    so a bare credential string (``user:pass@host``) would pass through
    unmasked and land in the persisted key on disk.
    """
    if "://" not in url and "@" in url:
        return redact_proxy_url("//" + url)
    return redact_proxy_url(url)


class ProxyHealthHistory:
    """In-memory proxy health history with JSON persistence.



    Records are keyed by a CREDENTIAL-FREE URL (``scheme://host:port``): the
    history is persisted to ``output/proxy-health-history.json`` on every
    run, and raw keys carried ``user:pass@`` — a credential-at-rest in a file
    that lives on every dev/runner disk. Two free-list proxies that differ
    only in credentials share a record, which is fine for health scoring:
    liveness is a property of the host:port pair, not the account.
    """

    def __init__(
        self,
        records: dict[str, dict[str, Any]] | None = None,
        *,
        window: int = 5,
        ban_after_consecutive_failures: int = 3,
        max_latency_ms: float = 8000.0,
        ban_seconds: float = 3600.0,
    ) -> None:
        self.records: dict[str, dict[str, Any]] = records or {}
        self.window = max(1, window)
        self.ban_after_consecutive_failures = max(1, ban_after_consecutive_failures)
        self.max_latency_ms = max(1.0, max_latency_ms)
        # A proxy ban is time-boxed, not permanent: the counter alone excluded
        # a proxy hit by one transient network event until its whole record
        # aged out of retention (24h), with no success path in between. After
        # ``ban_seconds`` the proxy re-enters the pool and a passing probe
        # resets the counter. 0 disables banning entirely.
        self.ban_seconds = max(0.0, float(ban_seconds))

    @staticmethod
    def _key(proxy_url: str) -> str:
        """Credential-free, stable record key: ``scheme://host:port``.

        The previous key was the redacted URL, which still *contained* the
        userinfo: one proxy spelled ``socks5://user:pass@h:p`` and the same
        proxy spelled ``socks5://h:p`` produced two forked histories
        (``socks5://***@h:p`` vs ``socks5://h:p``), splitting consecutive
        failure counters and bans. The health of a proxy is the health of its
        dial target, so the key is the dial target itself. Unparseable or
        host-less input falls back to the masked URL rather than raising.
        """
        try:
            parts = urlsplit(proxy_url.strip())
            host = (parts.hostname or "").strip()
            port = parts.port
        except ValueError:
            return _masked_key(proxy_url.strip())
        if not host or port is None:
            return _masked_key(proxy_url.strip())
        host_text = f"[{host}]" if ":" in host else host
        return f"{(parts.scheme or 'socks5').lower()}://{host_text}:{port}"

    @classmethod
    def load(cls, path: str | Path, **kwargs: Any) -> ProxyHealthHistory:
        from src.utils.paths import resolve_safe_output_path

        try:
            target = resolve_safe_output_path(path)
        except ValueError as exc:
            logger.warning("Unsafe proxy health path %r: %s", path, exc)
            return cls(**kwargs)
        if not target.exists():
            return cls(**kwargs)
        try:
            with target.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
            if not isinstance(data, dict):
                return cls(**kwargs)
            try:
                window = max(1, int(kwargs.get("window", _DEFAULT_WINDOW)))
            except (TypeError, ValueError):
                window = _DEFAULT_WINDOW
            return cls(_sanitize_records(data, window), **kwargs)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning(
                "Failed to load proxy health history from %s: %s",
                target,
                exc,
            )
            return cls(**kwargs)

    def save(self, path: str | Path) -> None:
        """Write the history to *path*, forgetting proxies nobody saw lately.

        Pruning belongs here because this is the only moment the whole history
        is touched: the file is rewritten and published on every run, and
        nothing else ever dropped an entry, so it grew monotonically with every
        proxy the free lists rotated through. Everything probed during this run
        has a fresh ``last_seen`` and survives.

        The write is atomic (temp file + ``os.replace``), mirroring
        ``HealthHistory.save``: a crash mid-write would otherwise truncate the
        file and lose the accumulated history.
        """
        self.prune()
        from src.utils.paths import resolve_safe_output_path, write_text_atomic

        try:
            target = resolve_safe_output_path(path)
        except ValueError as exc:
            logger.warning("Unsafe proxy health path %r: %s", path, exc)
            return
        try:
            # Atomic write (temp file + os.replace), mirroring
            # HealthHistory.save: a crash mid-write would otherwise truncate the
            # file and lose the accumulated history.
            write_text_atomic(
                target,
                json.dumps(self.records, indent=2, ensure_ascii=False),
            )
        except OSError as exc:
            logger.warning("Failed to save proxy health history to %s: %s", target, exc)

    def record(
        self,
        proxy_url: str,
        success: bool,
        latency_ms: float | None = None,
    ) -> None:
        if not proxy_url or not proxy_url.strip():
            return
        key = self._key(proxy_url)
        if not key:
            # Whitespace-only input would create a "" record that
            # _sanitize_records drops on the next load — never store it.
            return
        entry = self.records.setdefault(
            key,
            {
                "attempts": 0,
                "successes": 0,
                "consecutive_failures": 0,
                "latency_ms": [],
                "recent_results": [],
                "last_seen": 0.0,
                "banned_until": 0.0,
            },
        )
        entry["attempts"] += 1
        entry["last_seen"] = time.time()
        if success:
            entry["successes"] += 1
            entry["consecutive_failures"] = 0
            entry["banned_until"] = 0.0
        else:
            entry["consecutive_failures"] += 1
            if (
                self.ban_seconds > 0
                and entry["consecutive_failures"] >= self.ban_after_consecutive_failures
            ):
                entry["banned_until"] = time.time() + self.ban_seconds
        if latency_ms is not None and latency_ms > 0:
            entry["latency_ms"].append(latency_ms)
            entry["latency_ms"] = entry["latency_ms"][-self.window :]
        # Windowed success/failure trail for ranking: the lifetime rate let a
        # proxy's ancient good streak outrank its recent death spiral.
        entry["recent_results"] = [*entry.get("recent_results", []), success][
            -self.window :
        ]

    def is_banned(self, proxy_url: str) -> bool:
        key = self._key(proxy_url)
        entry = self.records.get(key)
        if not entry:
            return False
        if (
            int(entry.get("consecutive_failures", 0))
            < self.ban_after_consecutive_failures
        ):
            return False
        # The counter alone is not the ban — it only marks the proxy as
        # ban-worthy.  The deadline decides: records predating the deadline
        # field (``banned_until`` missing/0) count as expired, so a proxy
        # banned under the old scheme is re-probed instead of frozen out
        # until retention forgets it a day later.
        return time.time() < float(entry.get("banned_until") or 0.0)

    def _avg_latency(self, proxy_url: str) -> float:
        entry = self.records.get(self._key(proxy_url))
        if not entry:
            return float("inf")
        latencies = entry.get("latency_ms", [])
        if not latencies:
            return float("inf")
        total = float(sum(latencies))
        return total / len(latencies)

    def average_latency(self, proxy_url: str) -> float | None:
        """Return the proxy's mean latency in ms, or ``None`` without history."""
        avg = self._avg_latency(proxy_url)
        return None if avg == float("inf") else avg

    def _success_rate(self, entry: dict[str, Any]) -> float:
        """Success rate over the recent window, falling back to lifetime.

        A windowed rate exists from the moment any record() lands; records
        persisted before the field existed (or hand-trimmed files) fall back
        to the lifetime successes/attempts so ranking never regresses.
        """
        recent = [bool(v) for v in entry.get("recent_results", [])]
        if recent:
            return sum(1.0 for v in recent if v) / len(recent)
        attempts = max(1, int(entry.get("attempts", 0)))
        return int(entry.get("successes", 0)) / attempts

    def _score(self, proxy_url: str) -> float:
        entry = self.records.get(self._key(proxy_url))
        if not entry:
            return 0.5
        success_rate = self._success_rate(entry)
        avg_latency = self._avg_latency(proxy_url)
        if avg_latency == float("inf") or avg_latency > self.max_latency_ms:
            latency_penalty = 0.0
        else:
            latency_penalty = 1.0 - (avg_latency / self.max_latency_ms)
        return (0.7 * success_rate) + (0.3 * latency_penalty)

    def rank(
        self,
        proxies: list[str],
        *,
        drop_banned: bool = True,
        drop_slow: bool = True,
    ) -> list[str]:
        result: list[str] = []
        for proxy in proxies:
            key = self._key(proxy)
            if not key:
                continue
            if drop_banned and self.is_banned(key):
                logger.debug(
                    "Proxy %s is banned by health history.", redact_proxy_url(key)
                )
                continue
            # ``inf`` means "recorded, but never measured": record() appends a
            # latency only on success, so a proxy that has only ever failed has
            # a record with an empty latency list. Treating that as "too slow"
            # dropped it on every later run until retention forgot it a day
            # later — far stronger than the time-boxed ban this class
            # implements, and it also denied the proxy any chance to earn a
            # latency sample. _score() already reads ``inf`` as "no data".
            avg_latency = self._avg_latency(key)
            if (
                drop_slow
                and avg_latency != float("inf")
                and avg_latency > self.max_latency_ms
            ):
                logger.debug(
                    "Proxy %s is too slow by health history.",
                    redact_proxy_url(key),
                )
                continue
            result.append(proxy.strip())
        result.sort(key=lambda p: self._score(p), reverse=True)
        return result

    def prune(self, max_age_seconds: float = _DEFAULT_RETENTION_SECONDS) -> None:
        """Drop every record older than *max_age_seconds*.

        Age alone decides. Single-attempt records used to be exempt, which kept
        exactly the entries with the least information (a proxy seen once and
        never again) forever — 623 of the 1423 records in the shipped history
        file — so the history never actually stopped growing.
        """
        cutoff = time.time() - max_age_seconds
        self.records = {
            key: value
            for key, value in self.records.items()
            if float(value.get("last_seen", 0.0)) > cutoff
        }

    def to_dict(self) -> dict[str, dict[str, Any]]:
        return dict(self.records)
