"""Link-parsing stage."""

from __future__ import annotations

import logging
import os
from typing import Any

from src.parsers import PARSER_BY_SCHEME
from src.parsers.base import Config, find_all_links
from src.parsers.llm_fallback import LLMFallbackParser, should_use_llm
from src.parsers.subscription import SubscriptionParser
from src.scheduler.context import PipelineContext, PipelineState
from src.scheduler.stages.base import PipelineStage
from src.sources.list_types import normalize_list_type

logger = logging.getLogger(__name__)


def _result_files(result: Any) -> list[tuple[str, str]]:
    """Extract ``[(filename, content), ...]`` from a SourceResult."""
    files: Any = None
    if hasattr(result, "files"):
        files = result.files
    elif isinstance(result, dict):
        files = result.get("files")
    elif isinstance(result, list):
        files = result
    if not files:
        return []
    if isinstance(files, list):
        normalized: list[tuple[str, str]] = []
        for item in files:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                normalized.append((str(item[0]), str(item[1])))
            elif isinstance(item, dict):
                name = item.get("name") or item.get("filename")
                content = item.get("content")
                if name is not None and content is not None:
                    normalized.append((str(name), str(content)))
        return normalized
    return []


def _result_name(result: Any) -> str:
    """Best-effort source name for logging."""
    for attr in ("name", "source_name"):
        if hasattr(result, attr):
            val = getattr(result, attr)
            if val:
                return str(val)
    if isinstance(result, dict):
        for key in ("name", "source_name"):
            val = result.get(key)
            if val:
                return str(val)
    return "unknown"


def _result_default_country(result: Any) -> str | None:
    """Best-effort default country hint carried by a source result."""
    raw: Any = None
    if hasattr(result, "default_country"):
        raw = result.default_country
    elif isinstance(result, dict):
        raw = result.get("default_country")
    if raw is None or raw == "":
        return None
    return str(raw).upper()


class LinkParser(PipelineStage):
    """Parse raw source text into ``Config`` objects grouped by list type."""

    def __init__(self, context: PipelineContext) -> None:
        self.context = context
        self.settings = context.settings

    async def run(
        self,
        state: PipelineState,
        context: PipelineContext | None = None,
    ) -> PipelineState:
        grouped = await self.parse_all_by_list(state.sources)
        state.parsed = grouped
        total = sum(len(cfgs) for cfgs in grouped.values())
        logger.info(
            "Parsed %d configs total across %d list group(s).",
            total,
            len(grouped),
        )
        return state

    async def parse_all_by_list(self, results: list[Any]) -> dict[str, list[Config]]:
        """Parse all source results grouped by normalized list type."""
        grouped: dict[str, list[Config]] = {}
        sub_parser = SubscriptionParser()

        for result in results:
            list_type = normalize_list_type(getattr(result, "list_type", "mixed"))
            files = _result_files(result)
            source_name = _result_name(result)

            for filename, content in files:
                if not content or not content.strip():
                    continue

                links = await self.extract_links(
                    sub_parser,
                    content,
                    filename,
                    source_name,
                )
                if not links:
                    logger.debug("No links found in %s (%s).", filename, source_name)
                    continue

                parsed_here = 0
                bucket = grouped.setdefault(list_type, [])
                for link in links:
                    cfg = self.parse_one_link(link)
                    if cfg is not None:
                        source_default_country = _result_default_country(result)
                        if source_default_country:
                            cfg.source_default_country = source_default_country
                        cfg.source_name = source_name
                        cfg.source_file = filename
                        bucket.append(cfg)
                        parsed_here += 1
                logger.debug(
                    "Parsed %d/%d links from %s (%s, %s).",
                    parsed_here,
                    len(links),
                    filename,
                    source_name,
                    list_type,
                )

        # Optional GeoIP enrichment for configs without a detected country.
        vcfg = self.settings.section("validator")
        if self.settings.as_bool(vcfg.get("geoip_enabled"), False):
            all_configs = [cfg for bucket in grouped.values() for cfg in bucket]
            to_enrich = [cfg for cfg in all_configs if cfg.country is None]
            if to_enrich:
                try:
                    from src.validators.geoip import enrich_configs_geoip

                    api_url = str(
                        vcfg.get("geoip_api_url", "http://ip-api.com/json/{ip}"),
                    )
                    await enrich_configs_geoip(to_enrich, api_url=api_url)
                    enriched = sum(1 for cfg in to_enrich if cfg.country is not None)
                    logger.info(
                        "GeoIP enriched %d/%d configs.",
                        enriched,
                        len(to_enrich),
                    )
                except Exception as exc:
                    logger.warning("GeoIP enrichment failed: %s", exc)

        return grouped

    async def extract_links(
        self,
        sub_parser: SubscriptionParser,
        content: str,
        filename: str,
        source_name: str,
    ) -> list[str]:
        """Extract proxy links from a content blob."""
        try:
            is_sub = sub_parser.is_subscription(content)
        except Exception as exc:
            logger.debug(
                "is_subscription raised for %s (%s): %s — treating as raw.",
                filename,
                source_name,
                exc,
            )
            is_sub = False

        if is_sub:
            try:
                links = sub_parser.parse_subscription(content) or []
                logger.debug(
                    "Subscription blob %s (%s) -> %d links.",
                    filename,
                    source_name,
                    len(links),
                )
                return [ln for ln in links if isinstance(ln, str) and ln]
            except Exception as exc:
                logger.warning(
                    "SubscriptionParser.parse_subscription failed for %s (%s): %s — falling back to find_all_links.",  # noqa: E501
                    filename,
                    source_name,
                    exc,
                )

        links = find_all_links(content)

        if not links:
            links = await self.llm_fallback(content, filename, source_name)

        return links

    async def llm_fallback(
        self,
        content: str,
        filename: str,
        source_name: str,
    ) -> list[str]:
        """Try LLM extraction when regex found 0 links."""
        lcfg = self.settings.section("llm")
        if not self.settings.as_bool(lcfg.get("enabled"), False):
            return []

        api_key_env = lcfg.get("api_key_env", "LLM_API_KEY")
        api_key = os.environ.get(api_key_env, "")
        if not api_key:
            logger.debug("LLM fallback skipped: no API key in env %s", api_key_env)
            return []

        provider = lcfg.get("provider", "gemini")
        model = lcfg.get("model", "gemini-2.0-flash")
        min_text_length = self.settings.as_int(
            lcfg.get("min_text_length"),
            100,
            minimum=0,
        )

        if not should_use_llm(content, [], min_text_length=min_text_length):
            return []

        logger.info(
            "Trying LLM fallback for %s (%s) — regex found 0 links in %d chars.",
            filename,
            source_name,
            len(content),
        )

        try:
            llm = LLMFallbackParser(provider=provider, model=model, api_key=api_key)
            links = await llm.extract_links(content)
        except Exception as exc:
            logger.warning(
                "LLM fallback failed for %s (%s): %s",
                filename,
                source_name,
                exc,
            )
            return []

        if links:
            logger.info(
                "LLM fallback extracted %d links from %s (%s).",
                len(links),
                filename,
                source_name,
            )
        return links

    @staticmethod
    def parse_one_link(link: str) -> Config | None:
        """Parse a single link via O(1) scheme dispatch."""
        low = link.strip().lower()
        idx = low.find("://")
        if idx < 0:
            return None
        parser = PARSER_BY_SCHEME.get(low[:idx])
        if parser is None:
            return None
        try:
            return parser.parse(link)
        except Exception as exc:
            logger.debug("Parser %s raised on link: %s", type(parser).__name__, exc)
            return None
