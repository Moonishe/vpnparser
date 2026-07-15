"""Link-parsing stage."""

from __future__ import annotations

import logging
from typing import Any

from src.parsers import PARSER_BY_SCHEME
from src.parsers.base import Config, find_all_links, is_garbage_config
from src.parsers.llm_fallback import should_use_llm
from src.parsers.subscription import SubscriptionParser
from src.scheduler.context import PipelineContext, PipelineState
from src.scheduler.settings import Settings
from src.scheduler.stages.base import PipelineStage
from src.sources.list_types import normalize_list_type

logger = logging.getLogger(__name__)


class LinkParser(PipelineStage):
    """Parse raw source text into ``Config`` objects grouped by list type."""

    def __init__(self, context: PipelineContext) -> None:
        self.context = context
        self.settings = context.settings

    async def run(self, state: PipelineState, context: PipelineContext) -> PipelineState:
        parsed: dict[str, list[Config]] = {}
        total = 0
        for source_result in state.sources:
            if not source_result.content:
                continue
            label = normalize_list_type(getattr(source_result, "list_type", None))
            configs = self._parse_source_text(
                source_result.content,
                default_country=getattr(source_result, "default_country", None),
            )
            parsed.setdefault(label, []).extend(configs)
            total += len(configs)

        state.parsed = parsed
        logger.info("Parsed %d configs total across %d list group(s).", total, len(parsed))
        return state

    def _parse_source_text(
        self, text: str, default_country: str | None = None
    ) -> list[Config]:
        """Extract links from source text and parse them into Config objects."""
        min_text_length = self.settings.as_int(
            self.settings.section("llm").get("min_text_length"), 100, minimum=0
        )
        raw_links = find_all_links(text)

        if not raw_links and should_use_llm(text, raw_links, min_text_length):
            raw_links = self._llm_extract_links(text) or []

        configs: list[Config] = []
        for link in raw_links:
            config = self._parse_link(link)
            if config is None:
                continue
            if default_country and not config.country:
                config.country = default_country
            if not is_garbage_config(config):
                configs.append(config)
        return configs

    def _llm_extract_links(self, text: str) -> list[str]:
        """Attempt LLM fallback extraction and log the result."""
        from src.parsers.llm_fallback import LLMFallbackParser

        llm_cfg = self.settings.section("llm")
        if not self.settings.as_bool(llm_cfg.get("enabled"), False):
            return []

        api_key = self.context.settings.get("llm_api_key_env")
        if api_key:
            api_key = __import__("os").environ.get(api_key)
        parser = LLMFallbackParser(
            provider=str(llm_cfg.get("provider") or "groq"),
            model=str(llm_cfg.get("model") or "llama-3.1-8b-instant"),
            api_key=api_key,
        )
        try:
            import asyncio
            links = asyncio.run(parser.extract_links(text))
        except Exception as exc:
            logger.warning("LLM fallback extraction failed: %s", exc)
            return []
        logger.info("LLM fallback extracted %d links.", len(links))
        return links

    @staticmethod
    def _parse_link(link: str) -> Config | None:
        """Parse a single link using the scheme dispatch table or subscription decoder."""
        stripped = link.strip()
        if not stripped:
            return None

        lower = stripped.lower()
        if lower.startswith("vmess://"):
            try:
                return SubscriptionParser().parse(stripped)
            except Exception:
                return None

        scheme = lower.split("://", 1)[0] if "://" in lower else ""
        parser = PARSER_BY_SCHEME.get(scheme)
        if parser is None:
            return None
        try:
            return parser.parse(stripped)
        except Exception:
            return None
