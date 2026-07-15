"""Source-fetching stage."""

from __future__ import annotations

import logging
from typing import Any

from src.scheduler.context import PipelineContext, PipelineState
from src.scheduler.stages.base import PipelineStage
from src.sources.manager import SourceManager

logger = logging.getLogger(__name__)


class SourceFetcher(PipelineStage):
    """Fetch all configured source files concurrently."""

    async def run(self, state: PipelineState, context: PipelineContext) -> PipelineState:
        manager = SourceManager(
            sources_file=context.sources_path,
            settings_file="config/settings.yaml",
            github_token=context.github_token,
        )
        async with manager:
            results = await manager.fetch_all()
        state.sources = list(results) if results else []
        logger.info("Fetched %d source results.", len(state.sources))
        return state