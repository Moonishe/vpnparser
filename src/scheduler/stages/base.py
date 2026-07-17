"""Base pipeline stage interface."""

from __future__ import annotations

from abc import ABC, abstractmethod

from src.scheduler.context import PipelineContext, PipelineState


class PipelineStage(ABC):
    """A single stage of the pipeline.

    Concrete stages may accept ``run(state, context)`` or the older
    ``run(state)`` form. Callers that go through the stage interface always
    pass both arguments; older code paths that call ``state``-only methods
    continue to work because ``context`` is optional here.
    """

    @abstractmethod
    async def run(
        self,
        state: PipelineState,
        context: PipelineContext | None = None,
    ) -> PipelineState:
        """Execute the stage and return the updated state."""
        ...
