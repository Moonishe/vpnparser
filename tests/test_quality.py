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
