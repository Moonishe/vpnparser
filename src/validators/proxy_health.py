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

logger = logging.getLogger(__name__)


class ProxyHealthHistory:
    """In-memory proxy health history with JSON persistence."""

    def __init__(
        self,
        records: dict[str, dict[str, Any]] | None = None,
        *,
        window: int = 5,
        ban_after_consecutive_failures: int = 3,
        max_latency_ms: float = 8000.0,
    ) -> None:
        self.records: dict[str, dict[str, Any]] = records or {}
        self.window = max(1, window)
        self.ban_after_consecutive_failures = max(1, ban_after_consecutive_failures)
        self.max_latency_ms = max(1.0, max_latency_ms)

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
            return cls(data, **kwargs)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning(
                "Failed to load proxy health history from %s: %s", target, exc
            )
            return cls(**kwargs)

    def save(self, path: str | Path) -> None:
        from src.utils.paths import resolve_safe_output_path

        try:
            target = resolve_safe_output_path(path)
        except ValueError as exc:
            logger.warning("Unsafe proxy health path %r: %s", path, exc)
            return
        try:
            if target.parent and not target.parent.exists():
                target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("w", encoding="utf-8") as fh:
                json.dump(self.records, fh, indent=2, ensure_ascii=False)
        except OSError as exc:
            logger.warning("Failed to save proxy health history to %s: %s", target, exc)

    def record(
        self,
        proxy_url: str,
        success: bool,
        latency_ms: float | None = None,
    ) -> None:
        if not proxy_url:
            return
        key = proxy_url.strip()
        entry = self.records.setdefault(
            key,
            {
                "attempts": 0,
                "successes": 0,
                "consecutive_failures": 0,
                "latency_ms": [],
                "last_seen": 0.0,
            },
        )
        entry["attempts"] += 1
        entry["last_seen"] = time.time()
        if success:
            entry["successes"] += 1
            entry["consecutive_failures"] = 0
        else:
            entry["consecutive_failures"] += 1
        if latency_ms is not None and latency_ms > 0:
            entry["latency_ms"].append(latency_ms)
            entry["latency_ms"] = entry["latency_ms"][-self.window :]

    def is_banned(self, proxy_url: str) -> bool:
        key = proxy_url.strip()
        entry = self.records.get(key)
        if not entry:
            return False
        return (
            int(entry.get("consecutive_failures", 0))
            >= self.ban_after_consecutive_failures
        )

    def _avg_latency(self, proxy_url: str) -> float:
        entry = self.records.get(proxy_url.strip())
        if not entry:
            return float("inf")
        latencies = entry.get("latency_ms", [])
        if not latencies:
            return float("inf")
        return sum(latencies) / len(latencies)

    def _has_history(self, proxy_url: str) -> bool:
        return proxy_url.strip() in self.records

    def _score(self, proxy_url: str) -> float:
        entry = self.records.get(proxy_url.strip())
        if not entry:
            return 0.5
        attempts = max(1, int(entry.get("attempts", 0)))
        successes = int(entry.get("successes", 0))
        success_rate = successes / attempts
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
            key = proxy.strip()
            if not key:
                continue
            if drop_banned and self.is_banned(key):
                logger.debug("Proxy %s is banned by health history.", key)
                continue
            if (
                drop_slow
                and self._has_history(key)
                and self._avg_latency(key) > self.max_latency_ms
            ):
                logger.debug("Proxy %s is too slow by health history.", key)
                continue
            result.append(key)
        result.sort(key=lambda p: self._score(p), reverse=True)
        return result

    def prune(self, max_age_seconds: float = 86400.0) -> None:
        now = time.time()
        cutoff = now - max_age_seconds
        self.records = {
            key: value
            for key, value in self.records.items()
            if value.get("last_seen", 0) > cutoff or value.get("attempts", 0) < 2
        }

    def to_dict(self) -> dict[str, dict[str, Any]]:
        return dict(self.records)
