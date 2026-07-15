"""Aggregation stage: sorting, country balancing, whitelist mix, and limiting."""

from __future__ import annotations

import logging
from typing import Any

from src.parsers.base import Config
from src.scheduler.context import PipelineContext, PipelineState
from src.scheduler.settings import Settings
from src.scheduler.stages.base import PipelineStage
from src.scheduler.stages.filter import DedupFilter
from src.sources.list_types import normalize_list_type

logger = logging.getLogger(__name__)


class Aggregator(PipelineStage):
    """Sort, dedup (cross-list), and limit configs into the final combined output."""

    def __init__(self, context: PipelineContext) -> None:
        self.context = context
        self.settings = context.settings

    async def run(self, state: PipelineState) -> PipelineState:
        """Aggregate preprocessed lists into a single combined list."""
        max_total = self._max_configs()
        combined: list[Config] = []
        for configs in state.preprocessed.values():
            combined.extend(configs)
        all_live = self._dedup_only(combined)
        state.aggregated = self._country_balanced_limit(all_live, max_total)
        return state

    def _max_configs(self) -> int:
        return self.settings.as_int(
            self.settings.section("aggregator").get("max_configs_in_output"), 500, minimum=0
        )

    @staticmethod
    def _dedup_only(configs: list[Config]) -> list[Config]:
        return DedupFilter.dedup_only(configs)

    def _sort_and_limit(self, configs: list[Config]) -> list[Config]:
        """Sort and limit configs (dedup already done)."""
        max_configs = self._max_configs()
        try:
            return self._country_balanced_limit(configs, max_configs)
        except Exception as exc:
            logger.error("sort_and_limit failed: %s — passing through.", exc)
            return configs[:max_configs]

    def _country_balanced_limit(
        self, configs: list[Config], max_total: int
    ) -> list[Config]:
        """Limit configs by taking one server per country in repeated rounds."""
        if max_total <= 0 or not configs:
            return []

        acfg = self.settings.section("aggregator")
        sort_by = str(acfg.get("sort_by", "country"))
        try:
            max_per_country = int(acfg.get("max_per_country", 0))
        except (TypeError, ValueError):
            max_per_country = 0

        try:
            from src.aggregator.merger import sort_configs
        except (ImportError, AttributeError) as exc:
            logger.error("Cannot import sort_configs: %s — skipping sort.", exc)
            sorted_configs = list(configs)
        else:
            sorted_configs = sort_configs(
                [cfg for cfg in configs if cfg.country is not None],
                sort_by=sort_by,
            )

        groups: dict[str, list[Config]] = {}
        for cfg in sorted_configs:
            if cfg.country is None:
                continue
            country = str(cfg.country).upper()
            bucket = groups.setdefault(country, [])
            if max_per_country > 0 and len(bucket) >= max_per_country:
                continue
            bucket.append(cfg)

        for bucket in groups.values():
            bucket.sort(
                key=lambda cfg: (
                    -float(getattr(cfg, "quality_score", 0) or 0),
                    cfg.latency_ms is None,
                    float(cfg.latency_ms if cfg.latency_ms is not None else 10**9),
                )
            )

        countries = sorted(groups)
        result: list[Config] = []
        indexes = {country: 0 for country in countries}
        while len(result) < max_total:
            progressed = False
            for country in countries:
                index = indexes[country]
                bucket = groups[country]
                if index >= len(bucket):
                    continue
                result.append(bucket[index])
                indexes[country] = index + 1
                progressed = True
                if len(result) >= max_total:
                    break
            if not progressed:
                break

        return result

    def _whitelist_balance(self, configs: list[Config], max_total: int) -> list[Config]:
        """Build whitelist output: mostly RU servers plus EU fallback servers."""
        vcfg = self.settings.section("validator")
        try:
            ru_ratio = float(vcfg.get("whitelist_ru_ratio", 0.8))
        except (TypeError, ValueError):
            ru_ratio = 0.8
        ru_ratio = min(1.0, max(0.0, ru_ratio))
        eu_raw = vcfg.get("whitelist_eu_countries", ["DE", "FI", "NL", "FR"])
        if isinstance(eu_raw, str):
            eu_raw = [eu_raw]
        eu_countries = {str(code).upper() for code in eu_raw}

        ru = [c for c in configs if c.country == "RU"]
        eu = [c for c in configs if c.country in eu_countries]

        ru_target = int(max_total * ru_ratio)
        eu_target = max_total - ru_target

        ru_sorted = self._country_balanced_limit(ru, max_total)
        eu_sorted = self._country_balanced_limit(eu, max_total)

        ru_result = ru_sorted[:ru_target]
        eu_result = eu_sorted[:eu_target]

        shortfall = max_total - len(ru_result) - len(eu_result)
        if shortfall > 0:
            if len(ru_result) < ru_target and len(eu_sorted) > len(eu_result):
                extra = eu_sorted[len(eu_result) : len(eu_result) + shortfall]
                eu_result.extend(extra)
            elif len(eu_result) < eu_target and len(ru_sorted) > len(ru_result):
                extra = ru_sorted[len(ru_result) : len(ru_result) + shortfall]
                ru_result.extend(extra)

        result = ru_result + eu_result
        logger.info(
            "Whitelist balance: %d RU + %d EU = %d total.",
            len(ru_result),
            len(eu_result),
            len(result),
        )
        return result

    def _build_mixed_output(
        self, preprocessed_by_list: dict[str, list[Config]], max_total: int
    ) -> list[Config]:
        """Build a strict 50/50 blacklist + whitelist mix from live configs."""
        if max_total <= 0:
            return []

        blacklist_target = max_total // 2
        whitelist_target = max_total - blacklist_target
        used_keys: set[Any] = set()

        blacklist_candidates = self._sort_and_limit(
            preprocessed_by_list.get("blacklist", [])
        )
        blacklist_part = self._take_unique_configs(
            blacklist_candidates, blacklist_target, used_keys
        )

        whitelist_source = [
            cfg
            for cfg in preprocessed_by_list.get("whitelist", [])
            if cfg.dedup_key not in used_keys
        ]
        whitelist_candidates = self._whitelist_balance(whitelist_source, whitelist_target)
        whitelist_part = self._take_unique_configs(
            whitelist_candidates, whitelist_target, used_keys
        )

        if len(blacklist_part) < blacklist_target:
            logger.warning(
                "Mix output short on blacklist configs: %d/%d.",
                len(blacklist_part),
                blacklist_target,
            )
        if len(whitelist_part) < whitelist_target:
            logger.warning(
                "Mix output short on whitelist configs: %d/%d.",
                len(whitelist_part),
                whitelist_target,
            )

        result = blacklist_part + whitelist_part
        logger.info(
            "Mix output: %d blacklist + %d whitelist = %d total.",
            len(blacklist_part),
            len(whitelist_part),
            len(result),
        )
        return result

    @staticmethod
    def _take_unique_configs(
        configs: list[Config], target: int, used_keys: set[Any]
    ) -> list[Config]:
        """Take up to target configs, skipping keys already used by another list."""
        if target <= 0:
            return []

        selected: list[Config] = []
        for cfg in configs:
            key = cfg.dedup_key
            if key in used_keys:
                continue
            selected.append(cfg)
            used_keys.add(key)
            if len(selected) >= target:
                break
        return selected

    def process_configs(
        self, configs: list[Config], *, label: str, preprocessor: Any
    ) -> list[Config]:
        """Run configs through preprocess -> sort -> limit."""
        configs = preprocessor.preprocess(configs, label=label)
        if not configs:
            return []
        configs = self._sort_and_limit(configs)
        logger.info("%s after aggregation: %d configs.", label, len(configs))
        return configs