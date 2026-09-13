"""Tests for src/scheduler/stages/base.py — PipelineStage interface."""

from __future__ import annotations

import pytest

from src.scheduler.context import PipelineState
from src.scheduler.stages.base import PipelineStage


async def test_default_run_raises_not_implemented() -> None:
    """A stage dispatched through run() without an override is a wiring bug.

    The base body raises instead of silently returning None: a None would
    surface much later as an AttributeError on the returned state.
    """

    class _BareStage(PipelineStage):
        pass

    with pytest.raises(NotImplementedError, match="_BareStage does not implement run"):
        await _BareStage().run(PipelineState())
