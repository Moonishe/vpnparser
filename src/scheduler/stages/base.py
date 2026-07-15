"""Base pipeline stage interface."""

from __future__ import annotations

from abc import ABC, abstractmethod

from src.scheduler.context import PipelineContext, PipelineState


class PipelineStage(ABC):
    """A single stage of the pipeline."""

    @abstractmethod
    async def run(self, state: PipelineState, context: PipelineContext) -> PipelineState:
        """Execute the stage and return the updated state."""
        ...
