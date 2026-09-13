"""Link-parsing stage."""

from __future__ import annotations

import contextlib
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
from src.validators.country_filter import (
    detect_country,
    normalize_country_code,
    remark_names_unsupported_country,
)

logger = logging.getLogger(__name__)


def _link_has_parser(link: str) -> bool:
    """Return ``True`` when a parser exists for the link's scheme.

    ``find_all_links`` extracts every known scheme — including ones with no
    parser (``wireguard://``) — so "extracted" and "parseable" differ, and
    the LLM-fallback decision must use the latter.
    """
    low = link.strip().lower()
    idx = low.find("://")
    return idx >= 0 and low[:idx] in PARSER_BY_SCHEME


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


def _geoip_priority(cfg: Config) -> int:
    """Sort key spending the capped API budget where it can keep servers.

    Configs whose remark already stamps an unsupported ISO code ("NO-01")
    are dropped by the country filter after a lookup anyway, so they sort
    last. Stable sort keeps parse order within each group; the free offline
    enrichment still covers everyone.
    """
    return 1 if remark_names_unsupported_country(getattr(cfg, "remark", None)) else 0


def _result_default_country(result: Any) -> str | None:
    """Best-effort default country hint carried by a source result.

    Only a supported 2-letter ISO code survives (mirrors
    ``SourceManager._source_default_country``): an unvalidated hint would
    otherwise be stamped onto ``Config.country`` when remark-based detection
    fails, producing bogus location files and filter verdicts.
    """
    raw: Any = None
    if hasattr(result, "default_country"):
        raw = result.default_country
    elif isinstance(result, dict):
        raw = result.get("default_country")
    return normalize_country_code(None if raw is None else str(raw))


class LinkParser(PipelineStage):
    """Parse raw source text into ``Config`` objects grouped by list type."""

    def __init__(self, context: PipelineContext) -> None:
        self.context = context
        self.settings = context.settings
        #: One LLM fallback instance (and HTTP client) per parse stage; see
        #: the lazy construction in _llm_fallback.
        self._llm_parser: Any | None = None
        self._llm_calls_made = 0
        #: Per-source call counter for the LLM budget (source_name -> calls).
        self._llm_calls_per_source: dict[str, int] = {}

    async def aclose(self) -> None:
        """Release the shared LLM client, if one was created."""
        parser = self._llm_parser
        self._llm_parser = None
        if parser is None:
            return
        closer = getattr(parser, "aclose", None)
        if closer is None:
            return
        with contextlib.suppress(Exception):
            await closer()

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
                # Cap the per-file link count: a 12 MB hostile source carrying
                # 400k links materialised ~350 MB of Config objects (each is a
                # 36-field dataclass) — an OOM on a small runner and minutes of
                # garbage-filter churn. Legit sources rarely exceed a few
                # thousand links per file; the cap only bites on adversarial
                # input and the truncation is logged loudly.
                max_links = self.settings.as_int(
                    self.settings.section("sources").get("max_links_per_file"),
                    20000,
                    minimum=1,
                )
                truncated = False
                for link in links:
                    if parsed_here >= max_links:
                        truncated = True
                        break
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
                if truncated:
                    logger.warning(
                        "Source %s (%s): link cap %d reached — %d links "
                        "truncated. Raise sources.max_links_per_file to raise.",
                        source_name,
                        filename,
                        max_links,
                        len(links) - parsed_here,
                    )

        # Optional GeoIP enrichment for configs without a detected country.
        vcfg = self.settings.section("validator")
        if self.settings.as_bool(vcfg.get("geoip_enabled"), False):
            all_configs = [cfg for bucket in grouped.values() for cfg in bucket]
            to_enrich = [cfg for cfg in all_configs if self._needs_geoip(cfg)]
            if len(to_enrich) > 1:
                # Spend the capped API budget where it can keep servers:
                # configs whose remark already stamps an unsupported ISO
                # code ("NO-01") are dropped by the country filter after
                # the lookup anyway, so they go last. Stable sort keeps
                # parse order within each group; offline enrichment (free)
                # still covers everyone.
                to_enrich.sort(key=_geoip_priority)
            mmdb_file = str(vcfg.get("geoip_mmdb_file") or "")
            offline_path = (
                await self._ensure_offline_geoip(vcfg, mmdb_file) if mmdb_file else None
            )
            if offline_path:
                try:
                    from src.validators.geoip import enrich_configs_geoip_offline

                    await enrich_configs_geoip_offline(to_enrich, offline_path)
                    enriched = sum(1 for cfg in to_enrich if cfg.country is not None)
                    logger.info(
                        "GeoIP (offline) enriched %d/%d configs.",
                        enriched,
                        len(to_enrich),
                    )
                except Exception as exc:
                    logger.warning("Offline GeoIP enrichment failed: %s", exc)
            elif to_enrich:
                # ip-api.com allows 45 req/min, so enrichment is throttled and
                # its duration grows linearly with the number of distinct
                # addresses. Cap the batch instead of letting a large parse
                # stall the run for hours; skipped configs simply keep
                # country=None. This is only the fallback for runs without a
                # usable offline database.
                rpm = self.settings.as_float(
                    vcfg.get("geoip_requests_per_minute"),
                    40.0,
                    minimum=1.0,
                )
                max_lookups = self.settings.as_int(
                    vcfg.get("geoip_max_lookups"),
                    300,
                    minimum=1,
                )
                # enrich_configs_geoip() groups configs by resolved address and
                # spends one request per group, so the cap must count addresses:
                # capping configs would drop whole servers without saving a
                # single request.
                addresses = list(dict.fromkeys(cfg.address for cfg in to_enrich))
                if len(addresses) > max_lookups:
                    logger.warning(
                        "GeoIP: %d addresses need a country but the per-run cap "
                        "is %d (%.0f req/min); enriching the first %d, skipping "
                        "%d.",
                        len(addresses),
                        max_lookups,
                        rpm,
                        max_lookups,
                        len(addresses) - max_lookups,
                    )
                    kept = set(addresses[:max_lookups])
                    to_enrich = [cfg for cfg in to_enrich if cfg.address in kept]
                if to_enrich:
                    try:
                        from src.validators.geoip import enrich_configs_geoip

                        api_url = str(
                            # The free ip-api.com tier does NOT serve https:
                            # its https endpoint answers 403 for every request,
                            # so an https default silently killed API-based
                            # enrichment while still burning the rate limit.
                            # The url carries only the IP, and the SSRF gate
                            # in geoip.py accepts http and https alike.
                            vcfg.get("geoip_api_url", "http://ip-api.com/json/{ip}"),
                        )
                        await enrich_configs_geoip(
                            to_enrich,
                            api_url=api_url,
                            requests_per_minute=rpm,
                        )
                        enriched = sum(
                            1 for cfg in to_enrich if cfg.country is not None
                        )
                        logger.info(
                            "GeoIP enriched %d/%d configs.",
                            enriched,
                            len(to_enrich),
                        )
                    except Exception as exc:
                        logger.warning("GeoIP enrichment failed: %s", exc)

        return grouped

    async def _ensure_offline_geoip(
        self, vcfg: dict[str, Any], mmdb_file: str
    ) -> str | None:
        """Return the resolved database path when an offline mmdb is ready.

        Downloads the pinned artifact once when it is missing; failures fall
        back to the (capped) API enrichment instead of failing the parse.
        """
        try:
            from src.validators.geoip import ensure_geoip_database

            return await ensure_geoip_database(
                path=mmdb_file,
                url=str(vcfg.get("geoip_mmdb_url") or ""),
                sha256=str(vcfg.get("geoip_mmdb_sha256") or "") or None,
            )
        except Exception as exc:
            logger.warning("Offline GeoIP database unavailable: %s", exc)
            return None

    @staticmethod
    def _needs_geoip(cfg: Config) -> bool:
        """Return ``True`` when only a GeoIP lookup can give this config a country.

        No parser ever sets ``Config.country``, so testing ``country is None``
        here selected *every* parsed config and the ``geoip_max_lookups`` budget
        was spent on the first N addresses in parse order — usually servers
        whose remark already names the country. The same detection the country
        filter runs later (:func:`detect_country` plus the source's
        ``default_country``) therefore decides who actually needs a lookup.

        The detected code is assigned to ``cfg.country`` before returning:
        computing it and discarding it made the country filter re-run the
        identical (regex-heavy) detection over the whole corpus a second
        time, and ``filter_countries`` already skips configs whose country
        is set.

        Args:
            cfg: Freshly parsed config.

        Returns:
            ``True`` when no free source of a country code is available.
        """
        if cfg.country is not None or getattr(cfg, "source_default_country", None):
            return False
        detected = detect_country(
            cfg.remark,
            getattr(cfg, "address", None),
            getattr(cfg, "sni", None),
            getattr(cfg, "host", None),
        )
        if detected is not None:
            cfg.country = detected
            return False
        return True

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

        if not any(_link_has_parser(link) for link in links):
            # Nothing the regex route can parse: an empty file, or only
            # unsupported schemes (wireguard:// is extracted but has no
            # parser). The LLM still gets its chance — without this, one
            # wireguard link in a file silently disabled the fallback for
            # the unparseable text around it. The original links are kept:
            # the LLM validator uses the same parsers, so a wireguard-only
            # file still yields nothing instead of hiding the skip.
            links = links + await self.llm_fallback(
                content, filename, source_name, regex_links=links
            )

        return links

    async def llm_fallback(
        self,
        content: str,
        filename: str,
        source_name: str,
        regex_links: list[str] | None = None,
    ) -> list[str]:
        """Try LLM extraction when regex found 0 parseable links."""
        lcfg = self.settings.section("llm")
        if not self.settings.as_bool(lcfg.get("enabled"), False):
            return []

        api_key_env = lcfg.get("api_key_env", "LLM_API_KEY")
        api_key = os.environ.get(api_key_env, "")
        if not api_key:
            logger.debug("LLM fallback skipped: no API key in env %s", api_key_env)
            return []

        max_calls = self.settings.as_int(lcfg.get("max_calls_per_run"), 50, minimum=0)
        if max_calls <= 0:
            logger.debug("LLM fallback disabled: max_calls_per_run is 0")
            return []
        if self._llm_calls_made >= max_calls:
            # Without a ceiling, 50 unparsable files x 20 sources sent hundreds
            # of 100k-char prompts (x3 retries) per run — paid API calls with
            # no bound.
            logger.warning(
                "LLM fallback budget exhausted (%d calls); skipping %s.",
                max_calls,
                filename,
            )
            return []
        # Per-source cap: one hostile source publishing 50 link-free files
        # would otherwise burn the ENTIRE run budget, starving legitimate
        # messy sources that arrive later.
        max_per_source = self.settings.as_int(
            lcfg.get("max_calls_per_source"), 10, minimum=0
        )
        source_key = source_name or "<unnamed>"
        if max_per_source > 0 and self._llm_calls_per_source.get(source_key, 0) >= (
            max_per_source
        ):
            logger.warning(
                "LLM fallback per-source budget exhausted (%d calls for %s); "
                "skipping %s.",
                max_per_source,
                source_key,
                filename,
            )
            return []

        provider = lcfg.get("provider", "gemini")
        model = lcfg.get("model", "gemini-2.0-flash")
        min_text_length = self.settings.as_int(
            lcfg.get("min_text_length"),
            100,
            minimum=0,
        )

        if not should_use_llm(
            content,
            [ln for ln in (regex_links or []) if _link_has_parser(ln)],
            min_text_length=min_text_length,
        ):
            return []
        # Charge budgets only for real attempts: short files below
        # min_text_length used to burn per-source quota without one API call.
        try:
            calls_before = int(getattr(self._llm_parser, "http_attempts", 0) or 0)
        except (TypeError, ValueError):
            calls_before = 0

        logger.info(
            "Trying LLM fallback for %s (%s) — regex found 0 links in %d chars.",
            filename,
            source_name,
            len(content),
        )

        try:
            # ONE parser (and therefore one HTTP client and one SSRF check)
            # per parse stage, not one per file: a fresh instance reset the
            # api_base verification and re-opened a connection every time.
            if self._llm_parser is None:
                self._llm_parser = LLMFallbackParser(
                    provider=provider,
                    model=model,
                    api_key=api_key,
                )
            links = await self._llm_parser.extract_links(content)
            # Charge paid HTTP attempts, not files: one budget unit used to
            # cover up to _MAX_RETRIES paid calls on 429/5xx, so a few
            # flaky files burned the whole run budget. extract_links adds
            # nothing on pre-HTTP failures — those stay a single unit.
            try:
                spent = int(getattr(self._llm_parser, "http_attempts", 0) or 0)
                spent -= calls_before
            except (TypeError, ValueError):
                spent = 1
            spent = max(1, spent)
            self._llm_calls_made += spent
            self._llm_calls_per_source[source_key] = (
                self._llm_calls_per_source.get(source_key, 0) + spent
            )
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
            logger.warning(
                "No parser for scheme %r — link skipped (wireguard and other "
                "unsupported schemes are found by find_all_links but have no parser).",
                low[:idx],
            )
            return None
        try:
            return parser.parse(link)
        except Exception as exc:
            logger.debug("Parser %s raised on link: %s", type(parser).__name__, exc)
            return None
