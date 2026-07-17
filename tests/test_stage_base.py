"""Tests for src/scheduler/stages/base.py — PipelineStage interface."""

from __future__ import annotations

import pytest

from src.scheduler.context import PipelineContext, PipelineState
from src.scheduler.settings import Settings
from src.scheduler.stages.base import PipelineStage


class _ConcreteStage(PipelineStage):
    """Minimal concrete subclass that delegates to the parent ``run``."""

    async def run(
        self,
        state: PipelineState,
        context: PipelineContext | None = None,
    ) -> PipelineState:
        return await super().run(state, context=context)


async def test_abstract_run_body_executes() -> None:
    """Cover the ``...`` body of PipelineStage.run via super().run().

    The abstract method body is ``...`` (Ellipsis) on line 26 of base.py.
    Calling it through ``super()`` from a concrete subclass executes that
    line and implicitly returns ``None`` because there is no explicit
    ``return`` statement.
    """
    state = PipelineState()
    stage = _ConcreteStage()
    result = await stage.run(state)
    # The abstract body (``...``) has no return, so the coroutine returns None.
    assert result is None
