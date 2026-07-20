"""Publisher stage."""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any

from src.scheduler.context import PipelineContext, PipelineState
from src.scheduler.stages.base import PipelineStage

logger = logging.getLogger(__name__)


class Publisher(PipelineStage):
    """Publish output files to a GitHub repo via the Contents API."""

    def __init__(self, context: PipelineContext) -> None:
        self.context = context

    async def run(
        self,
        state: PipelineState,
        context: PipelineContext | None = None,
    ) -> PipelineState:
        assert context is not None  # runner always supplies context
        if not context.github_token:
            logger.warning("Publish requested but GITHUB_TOKEN is not set — skipping.")
            return state

        pcfg = context.settings.section("publisher")
        owner = pcfg.get("owner") or os.environ.get("GITHUB_OWNER")
        repo = pcfg.get("repo") or os.environ.get("GITHUB_REPO")
        branch = pcfg.get("branch") or os.environ.get("GITHUB_BRANCH") or "main"
        commit_tpl = pcfg.get("commit_message", "auto-update configs [{timestamp}]")
        configured_combined_path = pcfg.get("output_file")

        if not owner or not repo:
            logger.warning(
                "Publish requested but GitHub owner/repo not configured — skipping.",
            )
            return state

        try:
            from src.publisher.github import GitHubPublisher
        except ImportError:
            logger.exception("Cannot import GitHubPublisher — skipping publish.")
            return state

        commit_message = commit_tpl.replace(
            "{timestamp}",
            time.strftime("%Y-%m-%d %H:%M:%S"),
        )

        async with GitHubPublisher(
            token=context.github_token,
            owner=owner,
            repo=repo,
            branch=branch,
        ) as publisher:
            all_ok = True
            for output_file in dict.fromkeys(state.output_files):
                repo_path = output_file
                if (
                    configured_combined_path
                    and output_file == state.output_files[0]
                    and output_file == configured_combined_path
                ):
                    repo_path = str(configured_combined_path)
                ok = await self._publish_file(
                    publisher,
                    output_file,
                    repo_path,
                    commit_message,
                )
                if not ok:
                    all_ok = False

        state.published = all_ok
        return state

    @staticmethod
    async def _publish_file(
        publisher: Any,
        output_file: str,
        repo_path: str,
        commit_message: str,
    ) -> bool:
        try:
            from src.utils.paths import resolve_safe_output_path

            safe_path = resolve_safe_output_path(output_file)
        except ValueError:
            logger.exception("Unsafe output file %r rejected for publish", output_file)
            return False
        try:
            content = await asyncio.to_thread(safe_path.read_text, encoding="utf-8")
        except FileNotFoundError:
            logger.exception(
                "Cannot publish: output file %s does not exist.",
                output_file,
            )
            return False
        except Exception:
            logger.exception("Cannot read output file %s for publish", output_file)
            return False

        try:
            ok = await publisher.publish_file(repo_path, content, commit_message)
            if not ok:
                logger.error(
                    "Publish completed but reported failure for %s.",
                    repo_path,
                )
            return bool(ok)
        except Exception:
            logger.exception("Publish failed for %s", repo_path)
            return False
