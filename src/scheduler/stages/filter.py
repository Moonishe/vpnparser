"""Filter stages: garbage removal, country filter, dedup, and preprocessing."""

from __future__ import annotations

import logging
import random

from src.parsers.base import Config, is_garbage_config
from src.scheduler.context import PipelineContext, PipelineState
from src.scheduler.stages.base import PipelineStage
from src.sources.list_types import normalize_list_type
from src.validators.country_filter import detect_country, filter_by_country

logger = logging.getLogger(__name__)


class GarbageFilter(PipelineStage):
    """Remove placeholder/template configs."""

    def __init__(self, context: PipelineContext) -> None:
        self.context = context

    async def run(
        self,
        state: PipelineState,
        context: PipelineContext | None = None,
    ) -> PipelineState:
        filtered: dict[str, list[Config]] = {}
        for label, configs in state.parsed.items():
            clean, count = self.filter_garbage(configs)
            if count:
                logger.info(
                    "Filtered %d garbage/placeholder configs for %s.",
                    count,
                    label,
                )
            filtered[label] = clean
        state.parsed = filtered
        return state

    @staticmethod
    def filter_garbage(configs: list[Config]) -> tuple[list[Config], int]:
        """Remove placeholder/template configs (UUID, SERVER_IP, example.com)."""
        clean: list[Config] = []
        garbage = 0
        for cfg in configs:
            if is_garbage_config(cfg):
                garbage += 1
                logger.debug(
                    "Garbage filtered: %s://%s:%d (%s)",
                    cfg.protocol,
                    cfg.address,
                    cfg.port,
                    (cfg.remark or "")[:50],
                )
            else:
                clean.append(cfg)
        return clean, garbage


class CountryFilter(PipelineStage):
    """Detect country and filter to allowed countries."""

    def __init__(self, context: PipelineContext) -> None:
        self.context = context
        self.settings = context.settings

    async def run(
        self,
        state: PipelineState,
        context: PipelineContext | None = None,
    ) -> PipelineState:
        filtered: dict[str, list[Config]] = {}
        for label, configs in state.parsed.items():
            filtered[label] = self.filter_countries(configs, list_type=label)
        state.parsed = filtered
        return state

    def filter_countries(
        self,
        configs: list[Config],
        *,
        list_type: str = "mixed",
    ) -> list[Config]:
        """Filter configs by allowed countries."""
        vcfg = self.settings.section("validator")
        allowed = vcfg.get("allowed_countries", [])
        by_list = vcfg.get("allowed_countries_by_list", {})
        if isinstance(by_list, dict):
            specific = by_list.get(normalize_list_type(list_type))
            if specific is not None:
                allowed = specific
        if isinstance(allowed, str):
            allowed = [allowed]

        for cfg in configs:
            if cfg.country is None:
                cfg.country = detect_country(
                    cfg.remark,
                    getattr(cfg, "address", None),
                    getattr(cfg, "sni", None),
                    getattr(cfg, "host", None),
                )
            if cfg.country is None:
                default_country = getattr(cfg, "source_default_country", None)
                if default_country:
                    cfg.country = str(default_country).upper()

        if not allowed:
            logger.info("No country filter configured — keeping all configs.")
            for cfg in configs:
                if cfg.country is None:
                    cfg.country = detect_country(
                        cfg.remark,
                        getattr(cfg, "address", None),
                        getattr(cfg, "sni", None),
                        getattr(cfg, "host", None),
                    )
            return configs

        allowed_list = [str(c).upper() for c in allowed]
        logger.info("Filtering %s to allowed countries: %s", list_type, allowed_list)
        return filter_by_country(configs, allowed_list)


class DedupFilter(PipelineStage):
    """Deduplicate configs by (address, port)."""

    async def run(
        self,
        state: PipelineState,
        context: PipelineContext | None = None,
    ) -> PipelineState:
        deduped: dict[str, list[Config]] = {}
        for label, configs in state.parsed.items():
            deduped[label] = self.dedup_only(configs)
            logger.info("%s after dedup: %d configs.", label, len(deduped[label]))
        state.parsed = deduped
        return state

    @staticmethod
    def dedup_only(configs: list[Config]) -> list[Config]:
        """Deduplicate configs by (address, port)."""
        try:
            from src.aggregator.merger import deduplicate
        except (ImportError, AttributeError):
            logger.exception("Cannot import deduplicate — skipping dedup.")
            return configs
        try:
            return deduplicate(configs)
        except Exception:
            logger.exception("deduplicate failed — passing through.")
            return configs


class Sampler(PipelineStage):
    """Sample configs to a per-list maximum."""

    def __init__(self, context: PipelineContext) -> None:
        self.context = context
        self.settings = context.settings

    async def run(
        self,
        state: PipelineState,
        context: PipelineContext | None = None,
    ) -> PipelineState:
        vcfg = self.settings.section("validator")
        max_to_process = self.settings.as_int(
            vcfg.get("max_configs_to_validate"),
            20000,
            minimum=0,
        )
        sampled: dict[str, list[Config]] = {}
        for label, configs in state.parsed.items():
            if max_to_process > 0 and len(configs) > max_to_process:
                logger.info(
                    "Sampling %d configs from %d for %s processing.",
                    max_to_process,
                    len(configs),
                    label,
                )
                sampled[label] = random.sample(configs, max_to_process)
            else:
                sampled[label] = configs
        state.parsed = sampled
        return state


class PreprocessFilter(PipelineStage):
    """Combined preprocess: garbage -> sample -> dedup -> country filter."""

    def __init__(self, context: PipelineContext) -> None:
        self.context = context
        self.settings = context.settings
        self.garbage = GarbageFilter(context)
        self.sampler = Sampler(context)
        self.dedup = DedupFilter()
        self.country = CountryFilter(context)

    async def run(
        self,
        state: PipelineState,
        context: PipelineContext | None = None,
    ) -> PipelineState:
        preprocessed: dict[str, list[Config]] = {}
        for label, configs in state.parsed.items():
            preprocessed[label] = self.preprocess(configs, label=label)
        state.preprocessed = preprocessed
        return state

    def preprocess(self, configs: list[Config], *, label: str) -> list[Config]:
        """Preprocess configs: garbage -> sample -> dedup -> country filter."""
        if not configs:
            return []
        configs, _ = self.garbage.filter_garbage(configs)
        if not configs:
            return []
        max_to_process = self.settings.as_int(
            self.settings.section("validator").get("max_configs_to_validate"),
            20000,
            minimum=0,
        )
        if max_to_process > 0 and len(configs) > max_to_process:
            logger.info(
                "Sampling %d configs from %d for %s processing.",
                max_to_process,
                len(configs),
                label,
            )
            configs = random.sample(configs, max_to_process)
        configs = self.dedup.dedup_only(configs)
        logger.info("%s after dedup: %d configs.", label, len(configs))
        configs = self.country.filter_countries(configs, list_type=label)
        logger.info("%s after country filter: %d configs.", label, len(configs))
        return configs
