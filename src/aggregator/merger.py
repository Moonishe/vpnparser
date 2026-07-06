"""Deduplication and sorting for aggregated VPN configs.

Pipeline: dedup → sort → limit per country → limit total.
Used by the aggregator to produce a clean, prioritized config list for output.
"""

from __future__ import annotations

import math
from collections import defaultdict

from src.parsers.base import Config


def _latency_sort_key(config: Config) -> tuple[int, float]:
    """Sort key for latency: (is_none_flag, latency_value).

    None latency sorts last (is_none=1); real latency sorts first (is_none=0)
    in ascending order. math.inf guarantees None stays last even when all
    real latencies are large.
    """
    if config.latency_ms is None:
        return (1, math.inf)
    return (0, float(config.latency_ms))


def deduplicate(configs: list[Config]) -> list[Config]:
    """Remove duplicate configs by dedup_key.

    dedup_key is (address, port) — one server = one config, regardless of
    protocol/uuid. When duplicates are found, keep the one with the lowest
    latency_ms. latency_ms=None counts as infinity (worst), so a config with
    a real latency always wins over one without.

    Preserves first-seen insertion order for the surviving config of each key.
    Returns an empty list for empty input.
    """
    if not configs:
        return []

    seen: dict[tuple, Config] = {}
    order: list[tuple] = []

    for config in configs:
        key = config.dedup_key
        if key not in seen:
            seen[key] = config
            order.append(key)
        else:
            existing = seen[key]
            existing_lat = (
                existing.latency_ms if existing.latency_ms is not None else math.inf
            )
            new_lat = config.latency_ms if config.latency_ms is not None else math.inf
            if new_lat < existing_lat:
                seen[key] = config

    return [seen[key] for key in order]


def sort_configs(configs: list[Config], sort_by: str = "latency") -> list[Config]:
    """Sort configs by latency (ascending) or by country then latency.

    sort_by="latency": sort by latency_ms ascending; None latency goes last.
    sort_by="country": sort by country alphabetically (None/unknown last),
        then by latency within each country.

    Unknown sort_by values return a shallow copy of the input unchanged.
    Returns an empty list for empty input.
    """
    if not configs:
        return []

    if sort_by == "latency":
        return sorted(configs, key=_latency_sort_key)

    if sort_by == "country":

        def country_key(config: Config) -> tuple[int, str, int, float]:
            # None country sorts last (is_none=1); named countries first.
            is_none = 1 if config.country is None else 0
            country_name = config.country or ""
            lat_key = _latency_sort_key(config)
            return (is_none, country_name, lat_key[0], lat_key[1])

        return sorted(configs, key=country_key)

    return list(configs)


def limit_per_country(configs: list[Config], max_per_country: int = 0) -> list[Config]:
    """Limit configs per country. 0 = unlimited.

    Counts configs per country and keeps only the first max_per_country
    from each country, preserving the existing sort order within each
    country. Configs with country=None are counted under the None bucket.

    Returns a shallow copy of the input when max_per_country <= 0 or input
    is empty.
    """
    if max_per_country <= 0 or not configs:
        return list(configs)

    counts: dict[str | None, int] = defaultdict(int)
    result: list[Config] = []

    for config in configs:
        if counts[config.country] < max_per_country:
            result.append(config)
            counts[config.country] += 1

    return result


def merge_and_filter(
    configs: list[Config],
    max_total: int = 500,
    sort_by: str = "latency",
    max_per_country: int = 50,
) -> list[Config]:
    """Full pipeline: dedup → sort → limit per country → limit total.

    1. deduplicate by dedup_key (keep lowest latency)
    2. sort by sort_by ("latency" or "country")
    3. limit per country (only if max_per_country > 0)
    4. limit total to max_total (only if max_total > 0, take first N)

    The defaults below are generic library defaults, NOT the deployed
    values. The pipeline runner reads ``config/settings.yaml`` and passes
    the real values explicitly (``max_configs_in_output``, ``sort_by``,
    ``max_per_country``). As of settings.yaml the deploy values are
    max_total=75, sort_by="country", max_per_country=50; only
    ``max_per_country`` happens to coincide with the default below.
    Returns an empty list for empty input.
    """
    deduped = deduplicate(configs)
    sorted_configs = sort_configs(deduped, sort_by=sort_by)
    limited = limit_per_country(sorted_configs, max_per_country=max_per_country)

    if max_total > 0 and len(limited) > max_total:
        limited = limited[:max_total]

    return limited
