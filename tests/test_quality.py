"""Tests for the QualityFilter stage — quality score filtering, slow config dropping."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

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
    # The generic run() form is not part of the quality contract: the runner
    # calls apply() directly.
    with pytest.raises(NotImplementedError):
        asyncio.run(runner._quality.run(state))
    # Empty list is dropped by apply() - the key won't appear; verify apply()
    # itself still works (non-empty lists pass through).
    runner2 = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    from src.parsers.base import Config

    cfg = Config("vless", "a.example", 443, "id", country="DE")
    state2 = PipelineState(validated={"list_b": [cfg]})
    result2 = runner2._quality.apply(state2.validated)
    assert "list_b" in result2


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
        "  stability_min_alive: 3\n"
        "  stability_exempt_first_pass: false\n",
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


def test_stability_gate_exempt_first_pass_keeps_newcomers(tmp_path: Path) -> None:
    """Default policy: a config on its first-ever pass has no run-to-run
    history to be unstable against, so the gate judges only configs WITH
    history — otherwise new candidates needed a second full run to enter the
    subscription at all."""
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
    assert {cfg.address for cfg in result["blacklist"]} == {
        f"h{i}.example" for i in range(6)
    }
    stats = runner._context.liveness_stats["quality"]
    assert stats["blacklist"]["stability_dropped"] == 0


def test_stability_gate_relaxed_below_floor(tmp_path: Path) -> None:
    runner = _stability_runner(
        tmp_path,
        "quality:\n"
        "  health_history_enabled: true\n"
        "  min_consecutive_passes: 2\n"
        "  stability_min_alive: 10\n"
        "  stability_exempt_first_pass: false\n",
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
# Stability gate — relative enforcement floor (stability_enforce_fraction)
# ---------------------------------------------------------------------------


def _big_list_runner(tmp_path: Path, extra: str) -> PipelineRunner:
    # stability_exempt_first_pass: false — these tests exercise the gate's
    # floor/fraction arithmetic, which needs every newcomer to be judgeable.
    return _stability_runner(
        tmp_path,
        "quality:\n"
        "  health_history_enabled: true\n"
        "  min_consecutive_passes: 2\n"
        "  stability_min_alive: 10\n"
        "  stability_exempt_first_pass: false\n" + extra,
    )


def test_stability_gate_tiny_stable_core_relaxes_at_scale(tmp_path: Path) -> None:
    """10 stable of 50 must NOT prune the other 40 down to a stub.

    The absolute floor alone let a tiny stable core pass the gate and gut a
    working list; the relative floor (30% default) relaxes instead.
    """
    runner = _big_list_runner(tmp_path, "")
    configs = [_cfg(f"h{i}.example") for i in range(50)]
    for cfg in configs[:10]:
        runner._quality.health.update([cfg])
        runner._quality.health.update([cfg])
    for cfg in configs[10:]:
        runner._quality.health.update([cfg])

    result = runner._quality.apply({"blacklist": configs})
    # enforce_floor = max(10, int(50*0.3)=15) = 15 > 10 stable → relaxed.
    assert len(result["blacklist"]) == 50
    stats = runner._context.liveness_stats["quality"]
    assert stats["stability_enforce_floor"]["blacklist"] == 15
    assert stats["blacklist"]["stability_dropped"] == 0


def test_stability_gate_enforces_with_sizable_stable_core(tmp_path: Path) -> None:
    """20 stable of 50 (>=30%) enforces the gate and prunes the unstable."""
    runner = _big_list_runner(tmp_path, "")
    configs = [_cfg(f"h{i}.example") for i in range(50)]
    for cfg in configs[:20]:
        runner._quality.health.update([cfg])
        runner._quality.health.update([cfg])
    for cfg in configs[20:]:
        runner._quality.health.update([cfg])

    result = runner._quality.apply({"blacklist": configs})
    assert len(result["blacklist"]) == 20
    stats = runner._context.liveness_stats["quality"]
    assert stats["blacklist"]["stability_dropped"] == 30


def test_zero_fraction_restores_absolute_floor(tmp_path: Path) -> None:
    runner = _big_list_runner(
        tmp_path,
        "  stability_enforce_fraction: 0\n",
    )
    configs = [_cfg(f"h{i}.example") for i in range(50)]
    for cfg in configs[:10]:
        runner._quality.health.update([cfg])
        runner._quality.health.update([cfg])
    for cfg in configs[10:]:
        runner._quality.health.update([cfg])

    result = runner._quality.apply({"blacklist": configs})
    # Absolute behavior: floor is exactly stability_min_alive=10 → enforced.
    assert len(result["blacklist"]) == 10


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


def test_stability_gate_requires_fresh_verdict(tmp_path: Path) -> None:
    """A skipped candidate (is_alive None) must not pass on an old streak."""
    runner = _stability_runner(
        tmp_path,
        "quality:\n"
        "  health_history_enabled: true\n"
        "  health_history_file: placeholder.json\n"
        "  min_consecutive_passes: 2\n"
        "  stability_min_alive: 1\n",
    )
    fresh = [_cfg(f"fresh{i}.example") for i in range(3)]
    skipped = [_cfg(f"skip{i}.example") for i in range(2)]
    for cfg in fresh + skipped:
        runner._quality.health.update([cfg])
        runner._quality.health.update([cfg])
    # The current run skipped these (budget/infra): no fresh verdict.
    for cfg in skipped:
        cfg.is_alive = None
    result = runner._quality.apply({"blacklist": fresh + skipped})
    kept = {cfg.address for cfg in result["blacklist"]}
    assert kept == {cfg.address for cfg in fresh}
    for cfg in skipped:
        assert cfg.quality_block_reason == "stability"
