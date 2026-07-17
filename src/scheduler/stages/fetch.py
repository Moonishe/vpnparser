"""Source-fetching stage."""

from __future__ import annotations

import logging

from src.scheduler.context import PipelineContext, PipelineState
from src.scheduler.stages.base import PipelineStage
from src.sources.manager import SourceManager

logger = logging.getLogger(__name__)


class SourceFetcher(PipelineStage):
    """Fetch all configured source files concurrently."""

    async def run(
        self, state: PipelineState, context: PipelineContext | None = None
    ) -> PipelineState:
        assert context is not None  # runner always supplies context
        manager = SourceManager(
            sources_file=context.sources_path,
            settings_file=context.settings_path or "config/settings.yaml",
            github_token=context.github_token,
        )
        async with manager:
            results = await manager.fetch_all()
        state.sources = list(results) if results else []
        logger.info("Fetched %d source results.", len(state.sources))
        return state
