"""Persistent health history for configs and sources."""

from __future__ import annotations

import contextlib
import json
import logging
import os
import tempfile
from typing import Any

from src.parsers.base import Config
from src.scheduler.settings import Settings
from src.utils.paths import resolve_safe_output_path

logger = logging.getLogger(__name__)


class HealthHistory:
    """Loads, updates, and persists config/source health records."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._cache: dict[str, Any] | None = None

    def _cfg(self) -> dict[str, Any]:
        raw = self.settings.section("quality")
        return raw if isinstance(raw, dict) else {}

    def _file(self) -> str | None:
        raw = self._cfg().get("health_history_file", "output/health-history.json")
        return str(raw) if raw else None

    def is_enabled(self) -> bool:
        return self.settings.as_bool(self._cfg().get("health_history_enabled"), True)

    def source_health_enabled(self) -> bool:
        return self.settings.as_bool(self._cfg().get("source_health_enabled"), True)

    def load(self) -> dict[str, Any]:
        if self._cache is not None:
            return self._cache
        path = self._file()
        if not path:
            self._cache = {"configs": {}, "sources": {}}
            return self._cache
        try:
            safe_path = resolve_safe_output_path(path)
            data = json.loads(safe_path.read_text(encoding="utf-8"))
        except Exception:
            data = {}
        if not isinstance(data, dict):
            data = {}
        data.setdefault("configs", {})
        data.setdefault("sources", {})
        self._cache = data
        return data

    def save(self) -> str | None:
        path = self._file()
        if not path or self._cache is None:
            return None
        payload = dict(self._cache)
        payload["updated_at"] = int(__import__("time").time())
        try:
            target = resolve_safe_output_path(path)
            target.parent.mkdir(parents=True, exist_ok=True)
            # Atomic write — write to temp file then rename.
            fd, tmp = tempfile.mkstemp(dir=target.parent, suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(payload, f, ensure_ascii=False, indent=2, sort_keys=True)
                os.replace(tmp, str(target))
            except Exception:
                with contextlib.suppress(Exception):
                    os.unlink(tmp)
                raise
        except Exception as exc:
            logger.warning("Could not write health history %s: %s", path, exc)
            return None
        return path

    @staticmethod
    def config_key(cfg: Config) -> str:
        raw = cfg.raw_link or "|".join(
            [
                str(cfg.protocol),
                str(cfg.address),
                str(cfg.port),
                str(cfg.uuid_or_password),
                str(cfg.network),
                str(cfg.security),
            ],
        )
        hashed = (
            __import__("hashlib")
            .sha256(
                raw.encode("utf-8", errors="ignore"),
            )
            .hexdigest()
        )
        return hashed

    def is_banned(self, cfg: Config, *, now: int | None = None) -> bool:
        if not self.is_enabled():
            return False
        now = now if now is not None else int(__import__("time").time())
        history = self.load()
        record = history.get("configs", {}).get(self.config_key(cfg), {})
        if int(record.get("banned_until") or 0) > now:
            cfg.quality_block_reason = "health_ban"
            return True
        source = str(getattr(cfg, "source_name", "?") or "?")
        source_record = history.get("sources", {}).get(source, {})
        if int(source_record.get("banned_until") or 0) > now:
            cfg.quality_block_reason = "source_ban"
            return True
        return False

    def update(self, checked_configs: list[Config]) -> None:
        if not self.is_enabled():
            return
        history = self.load()
        records = history.setdefault("configs", {})
        now = int(__import__("time").time())
        max_recent = self.settings.as_int(
            self._cfg().get("health_recent_window"),
            5,
            minimum=1,
        )
        fail_threshold = self.settings.as_int(
            self._cfg().get("ban_after_consecutive_failures"),
            2,
            minimum=1,
        )
        cooldown_seconds = int(
            self.settings.as_float(
                self._cfg().get("ban_cooldown_hours"),
                12.0,
                minimum=0.1,
            )
            * 3600,
        )
        for cfg in checked_configs:
            key = self.config_key(cfg)
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
            cfg.health_record = record

    def source_run_stats(
        self,
        checked_configs: list[Config],
    ) -> dict[str, dict[str, int]]:
        stats: dict[str, dict[str, int]] = {}
        for cfg in checked_configs:
            source = str(getattr(cfg, "source_name", "?") or "?")
            item = stats.setdefault(source, {"checked": 0, "alive": 0})
            item["checked"] += 1
            if getattr(cfg, "is_alive", False):
                item["alive"] += 1
        return stats

    def update_sources(
        self,
        checked_configs: list[Config],
        list_stats: dict[str, Any],
    ) -> None:
        qcfg = self._cfg()
        source_stats = self.source_run_stats(checked_configs)
        list_stats["sources"] = source_stats
        if not self.source_health_enabled():
            return
        min_checked = self.settings.as_int(
            qcfg.get("source_min_checked"),
            50,
            minimum=1,
        )
        bad_rate = self.settings.as_float(
            qcfg.get("source_bad_alive_rate"),
            0.02,
            minimum=0.0,
        )
        bad_runs = self.settings.as_int(
            qcfg.get("source_bad_runs_to_ban"),
            2,
            minimum=1,
        )
        cooldown_seconds = int(
            self.settings.as_float(
                qcfg.get("source_ban_cooldown_hours"),
                12.0,
                minimum=0.1,
            )
            * 3600,
        )
        now = int(__import__("time").time())
        history = self.load().setdefault("sources", {})
        for source, stats in source_stats.items():
            checked = int(stats["checked"])
            alive = int(stats["alive"])
            rate = alive / checked if checked else 0.0
            record = history.setdefault(
                source,
                {"runs": 0, "bad_runs": 0, "banned_until": 0},
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

    def score(self, cfg: Config) -> float:
        qcfg = self._cfg()
        score = 60.0 if getattr(cfg, "is_alive", False) else 0.0
        record = self.load().get("configs", {}).get(self.config_key(cfg), {})
        recent = list(record.get("recent") or [])
        if sum(1 for item in recent[-3:] if item) >= 2:
            score += 20.0
        if cfg.latency_ms is not None:
            max_latency = self.settings.as_float(
                qcfg.get("max_latency_ms"),
                10000.0,
                minimum=1.0,
            )
            if cfg.latency_ms <= max_latency:
                score += max(0.0, 10.0 * (1.0 - (float(cfg.latency_ms) / max_latency)))
        if getattr(cfg, "country", None):
            score += 5.0
        source = str(getattr(cfg, "source_name", "?") or "?")
        source_record = self.load().get("sources", {}).get(source, {})
        source_rate = float(source_record.get("last_alive_rate") or 0.0)
        if source_rate >= self.settings.as_float(
            qcfg.get("source_good_alive_rate"),
            0.2,
            minimum=0.0,
        ):
            score += 5.0
        proxy_checks = int(getattr(cfg, "xray_proxy_checks", 0) or 0)
        proxy_successes = int(getattr(cfg, "xray_proxy_successes", 0) or 0)
        if proxy_checks:
            score += min(5.0, 5.0 * (proxy_successes / proxy_checks))
        return score
