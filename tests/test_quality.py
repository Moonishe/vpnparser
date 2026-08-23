"""Tests for the QualityFilter stage — quality score filtering, slow config dropping."""

from __future__ import annotations

import asyncio
from pathlib import Path

from src.scheduler.context import PipelineState
from src.scheduler.runner import PipelineRunner

# ---------------------------------------------------------------------------
# run (async)  —  lines 33-34
# ---------------------------------------------------------------------------


def test_run_method_applies_quality_and_returns_state(tmp_path: Path) -> None:
    """Async run() should call self.apply() on state.validated and return state."""
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        "quality:\n  drop_slow_configs: false\n",
        encoding="utf-8",
    )
    runner = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    state = PipelineState(validated={"list_a": []})
    result = asyncio.run(runner._quality.run(state))
    assert result is state
    # Empty list is dropped by apply() — the key won't appear; verify state
    # was returned and apply() was called (non-empty lists pass through).
    runner2 = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    from src.parsers.base import Config

    cfg = Config("vless", "a.example", 443, "id", country="DE")
    state2 = PipelineState(validated={"list_b": [cfg]})
    result2 = asyncio.run(runner2._quality.run(state2))
    assert "list_b" in result2.validated


# ---------------------------------------------------------------------------
# Stability gate (min_consecutive_passes)
# ---------------------------------------------------------------------------


def _stability_runner(tmp_path: Path, quality_yaml: str) -> PipelineRunner:
    settings = tmp_path / "settings.yaml"
    settings.write_text(quality_yaml, encoding="utf-8")
    return PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )


def _cfg(address: str, latency_ms: float = 50.0):
    from src.parsers.base import Config

    return Config(
        "vless",
        address,
        443,
        f"id-{address}",
        country="DE",
        latency_ms=latency_ms,
        is_alive=True,
    )


def test_stability_gate_drops_one_shot_configs(tmp_path: Path) -> None:
    runner = _stability_runner(
        tmp_path,
        "quality:\n"
        "  health_history_enabled: true\n"
        "  health_history_file: placeholder.json\n"
        "  min_consecutive_passes: 2\n"
        "  stability_min_alive: 3\n",
    )
    configs = [_cfg(f"h{i}.example") for i in range(6)]
    # Three configs with a two-run streak, three first-timers.
    for cfg in configs[:3]:
        runner._quality.health.update([cfg])
        runner._quality.health.update([cfg])
    for cfg in configs[3:]:
        runner._quality.health.update([cfg])

    result = runner._quality.apply({"blacklist": configs})
    kept = result["blacklist"]
    assert {cfg.address for cfg in kept} == {f"h{i}.example" for i in range(3)}
    stats = runner._context.liveness_stats["quality"]
    assert stats["blacklist"]["stability_dropped"] == 3
    dropped = [cfg for cfg in configs if cfg.address not in {c.address for c in kept}]
    assert all(cfg.quality_block_reason == "stability" for cfg in dropped)


def test_stability_gate_relaxed_below_floor(tmp_path: Path) -> None:
    runner = _stability_runner(
        tmp_path,
        "quality:\n"
        "  health_history_enabled: true\n"
        "  min_consecutive_passes: 2\n"
        "  stability_min_alive: 10\n",
    )
    configs = [_cfg(f"h{i}.example") for i in range(4)]
    for cfg in configs[:2]:
        runner._quality.health.update([cfg])
        runner._quality.health.update([cfg])
    for cfg in configs[2:]:
        runner._quality.health.update([cfg])

    result = runner._quality.apply({"blacklist": configs})
    # Only 2 stable configs — below the floor of 10 — so everything stays.
    assert len(result["blacklist"]) == 4
    stats = runner._context.liveness_stats["quality"]
    assert stats["stability_relaxed"]["blacklist"] == 2
    assert stats["blacklist"]["stability_dropped"] == 0


def test_stability_gate_disabled_at_one(tmp_path: Path) -> None:
    runner = _stability_runner(
        tmp_path,
        "quality:\n  health_history_enabled: true\n  min_consecutive_passes: 1\n",
    )
    configs = [_cfg(f"h{i}.example") for i in range(3)]
    for cfg in configs:
        runner._quality.health.update([cfg])
    result = runner._quality.apply({"blacklist": configs})
    assert len(result["blacklist"]) == 3


# ---------------------------------------------------------------------------
# Slow-config dropping (min_alive_to_skip_slow_drop)
# ---------------------------------------------------------------------------


def test_zero_min_alive_keeps_fully_slow_list(tmp_path: Path) -> None:
    """min_alive_to_skip_slow_drop: 0 = never drop slow configs."""
    runner = _stability_runner(
        tmp_path,
        "quality:\n  max_latency_ms: 100\n  min_alive_to_skip_slow_drop: 0\n",
    )
    configs = [_cfg(f"h{i}.example", latency_ms=500.0) for i in range(3)]
    result = runner._quality.apply({"blacklist": configs})
    # Every config is slow and fast is empty — with 0 the slow ones stay.
    assert len(result["blacklist"]) == 3
    stats = runner._context.liveness_stats["quality"]
    assert stats["blacklist"]["slow_dropped"] == 0
    assert stats["slow_preserved"]["blacklist"] == 3


def test_positive_min_alive_still_drops_slow(tmp_path: Path) -> None:
    runner = _stability_runner(
        tmp_path,
        "quality:\n  max_latency_ms: 100\n  min_alive_to_skip_slow_drop: 1\n",
    )
    fast = _cfg("fast.example", latency_ms=50.0)
    slow = [_cfg(f"slow{i}.example", latency_ms=500.0) for i in range(2)]
    result = runner._quality.apply({"blacklist": [fast, *slow]})
    assert [cfg.address for cfg in result["blacklist"]] == ["fast.example"]
    stats = runner._context.liveness_stats["quality"]
    assert stats["blacklist"]["slow_dropped"] == 2
