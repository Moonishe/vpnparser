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

    async def run(
        self,
        state: PipelineState,
        context: PipelineContext | None = None,
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
        context.source_stats = self._report_failures(state.sources)
        return state

    @staticmethod
    def _report_failures(results: list[Any]) -> dict[str, Any]:
        """Log every failed source and summarise the fetch for the run summary.

        ``SourceResult.error`` used to be read nowhere: a source answering 404
        counted as a fetched result, the subscription built from it silently
        became empty, and the run still finished with status ``ok`` and no
        warning anywhere.

        The published error text is sanitised: ``SourceResult.error`` embeds
        attacker-influenced URLs (a hostile redirect Location header, a
        hostile index URL). The raw text stays in the log; the summary
        carries a printable-ASCII-only, line-stripped version so a crafted
        URL cannot inject prose into the committed run-summary.json.

        Args:
            results: Whatever ``SourceManager.fetch_all()`` returned.

        Returns:
            Counts plus the per-source error messages, ready to be embedded in
            ``run-summary.json``.
        """
        errors: list[dict[str, str]] = []
        for result in results:
            error = getattr(result, "error", None)
            if not error:
                continue
            name = str(getattr(result, "source_name", None) or "<unnamed>")
            raw = str(error)
            # Printable ASCII single-line only: source-influenced URLs and
            # redirect targets cannot inject newlines or non-ASCII prose
            # into the committed run-summary.json. Full detail stays in logs.
            lines = raw.splitlines()
            first = lines[0] if lines else ""
            safe = "".join(ch if 0x20 <= ord(ch) < 0x7F else "?" for ch in first)[:300]
            errors.append({"source": name, "error": safe})
            logger.warning("Source %r produced no configs: %s", name, error)
        logger.info(
            "Fetched %d source results (%d ok, %d failed).",
            len(results),
            len(results) - len(errors),
            len(errors),
        )
        return {
            "total": len(results),
            "ok": len(results) - len(errors),
            "failed": len(errors),
            "errors": errors,
        }
