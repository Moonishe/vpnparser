"""Quality filtering stage: slow config dropping, source/config bans."""

from __future__ import annotations

import logging
from typing import Any

from src.parsers.base import Config
from src.scheduler.context import PipelineContext, PipelineState
from src.scheduler.health_history import HealthHistory
from src.scheduler.stages.base import PipelineStage

logger = logging.getLogger(__name__)


class QualityFilter(PipelineStage):
    """Apply quality filters and health/source bans to validated configs."""

    def __init__(
        self,
        context: PipelineContext,
        health: HealthHistory | None = None,
    ) -> None:
        self.context = context
        self.settings = context.settings
        self.health = health or HealthHistory(self.settings)

    async def run(
        self,
        state: PipelineState,
        context: PipelineContext | None = None,
    ) -> PipelineState:
        state.validated = self.apply(state.validated)
        return state

    def apply(
        self,
        configs_by_list: dict[str, list[Config]],
    ) -> dict[str, list[Config]]:
        qcfg = self.settings.section("quality")
        max_latency = self.settings.as_float(
            qcfg.get("max_latency_ms"),
            10000.0,
            minimum=1.0,
        )
        drop_slow = self.settings.as_bool(qcfg.get("drop_slow_configs"), True)
        min_alive_to_skip_slow_drop = self.settings.as_int(
            qcfg.get("min_alive_to_skip_slow_drop"),
            1,
            minimum=0,
        )
        result: dict[str, list[Config]] = {}
        quality_stats: dict[str, Any] = {
            "drop_slow": drop_slow,
            "max_latency_ms": max_latency,
            "min_alive_to_skip_slow_drop": min_alive_to_skip_slow_drop,
        }
        for list_type, configs in configs_by_list.items():
            fast: list[Config] = []
            slow: list[Config] = []
            for cfg in configs:
                if (
                    drop_slow
                    and cfg.latency_ms is not None
                    and cfg.latency_ms > max_latency
                ):
                    slow.append(cfg)
                else:
                    fast.append(cfg)
            kept = fast
            slow_dropped = len(slow)
            if fast and not slow:
                for cfg in fast:
                    cfg.quality_score = self.health.score(cfg)
            elif len(fast) < min_alive_to_skip_slow_drop and slow:
                for cfg in fast + slow:
                    cfg.quality_score = self.health.score(cfg)
                kept = fast + slow
                slow_dropped = 0
                quality_stats.setdefault("slow_preserved", {})[list_type] = len(slow)
            else:
                for cfg in fast:
                    cfg.quality_score = self.health.score(cfg)
            kept.sort(
                key=lambda cfg: (
                    -float(getattr(cfg, "quality_score", 0) or 0),
                    cfg.latency_ms is None,
                    float(cfg.latency_ms if cfg.latency_ms is not None else 10**9),
                ),
            )
            if kept:
                result[list_type] = kept
            quality_stats[list_type] = {
                "input": len(configs),
                "kept": len(kept),
                "slow_dropped": slow_dropped,
                "avg_score": (
                    sum(float(getattr(cfg, "quality_score", 0) or 0) for cfg in kept)
                    / len(kept)
                    if kept
                    else 0
                ),
            }
        self.context.liveness_stats["quality"] = quality_stats
        return result

    def is_banned(self, cfg: Config) -> bool:
        return self.health.is_banned(cfg)
