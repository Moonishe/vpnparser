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
    real latencies are large. NaN is treated like None: ``nan < nan`` is
    False, so a NaN latency would otherwise make dedup comparisons and
    sorted() order undefined.
    """
    latency = config.latency_ms
    # Non-float junk (e.g. a stray str from hand-built configs) must sort
    # last like None instead of raising TypeError out of math.isnan/float.
    if not isinstance(latency, (int, float)) or math.isnan(latency):
        return (1, math.inf)
    return (0, float(latency))


def _dedup_rank(config: Config) -> tuple[int, int, float]:
    """Preference key among duplicates: prefer a live config, then low latency.

    ``is_alive is False`` sorts last regardless of latency. A config that
    passed TCP and then failed TLS/Xray keeps the latency the TCP probe
    measured, so ranking on latency alone let a *dead* duplicate evict its
    live twin — and the writers skip dead configs, so the server then
    disappeared from every output. ``None`` (never checked) ranks with the
    live ones, matching ``write_subscription``, which only drops explicit
    ``False``.
    """
    is_dead = 1 if config.is_alive is False else 0
    none_flag, latency = _latency_sort_key(config)
    return (is_dead, none_flag, latency)


def deduplicate(configs: list[Config]) -> list[Config]:
    """Remove duplicate configs by dedup_key.

    dedup_key is (protocol, address, port, cred_hash); the credential hash
    covers the user credential, REALITY public key, shadowsocks method and
    security scheme, so two configs sharing protocol/address/port but carrying
    different credentials survive as distinct configs (collapsing them would
    silently drop working accounts on the same node).

    When duplicates are found, keep the best one by :func:`_dedup_rank`: a
    config not marked dead always beats one that is, and among equals the
    lowest latency_ms wins (``None``/NaN counts as infinity, i.e. worst).

    Preserves first-seen insertion order for the surviving config of each key.
    Returns an empty list for empty input.
    """
    if not configs:
        return []

    seen: dict[tuple[str, str, int, str], Config] = {}
    order: list[tuple[str, str, int, str]] = []

    for config in configs:
        if config is None:
            continue
        try:
            key = config.dedup_key
        except Exception:
            key = (
                str(getattr(config, "protocol", "") or "").lower(),
                str(getattr(config, "address", "") or "").strip().lower(),
                0,
                repr(config),
            )
        if key not in seen:
            seen[key] = config
            order.append(key)
        elif _dedup_rank(config) < _dedup_rank(seen[key]):
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
    # Like deduplicate: stray None entries never crash the sort.
    configs = [c for c in configs if c is not None]
    if not configs:
        return []

    if sort_by == "latency":
        return sorted(configs, key=_latency_sort_key)

    if sort_by == "country":

        def country_key(config: Config) -> tuple[int, str, int, float]:
            # None country sorts last (is_none=1); named countries first.
            is_none = 1 if config.country is None else 0
            # Non-str junk would poison sorted() with mixed-type comparison.
            country_name = str(config.country or "")
            lat_key = _latency_sort_key(config)
            return (is_none, country_name, lat_key[0], lat_key[1])

        return sorted(configs, key=country_key)

    return list(configs)


def limit_per_country(configs: list[Config], max_per_country: int = 0) -> list[Config]:
    """Limit configs per country. 0 = unlimited.

    Counts configs per country and keeps only the first max_per_country
    from each country, preserving the existing sort order within each
    country. Configs with country=None are counted under the None bucket.

    The bucket key is case-insensitive (uppercased): the pipeline normalises
    countries upstream, but library callers can pass raw ``"de"``/``"DE"``,
    and treating those as two buckets gave each a full quota.

    Returns a shallow copy of the input when max_per_country <= 0 or input
    is empty.
    """
    if not configs:
        return []
    # Like deduplicate/sort: stray None entries are skipped, not counted.
    clean = [c for c in configs if c is not None]
    if max_per_country <= 0:
        return list(clean)
    if not clean:
        return []

    counts: dict[str | None, int] = defaultdict(int)
    result: list[Config] = []

    for config in clean:
        bucket = (config.country or "").upper() or None
        if counts[bucket] < max_per_country:
            result.append(config)
            counts[bucket] += 1

    return result


def merge_and_filter(
    configs: list[Config],
    max_total: int = 500,
    sort_by: str = "latency",
    max_per_country: int = 50,
) -> list[Config]:
    """Full pipeline: dedup → sort → limit per country → limit total.

    1. deduplicate by dedup_key (prefer live over dead, then lowest latency)
    2. sort by sort_by ("latency" or "country")
    3. limit per country (only if max_per_country > 0)
    4. limit total to max_total (only if max_total > 0, take first N)

    The defaults below are generic library defaults, NOT the deployed
    values. The pipeline runner reads ``config/settings.yaml`` and passes
    the real values explicitly (``max_configs_in_output``, ``sort_by``,
    ``max_per_country``).
    Returns an empty list for empty input.
    """
    deduped = deduplicate(configs)
    sorted_configs = sort_configs(deduped, sort_by=sort_by)
    limited = limit_per_country(sorted_configs, max_per_country=max_per_country)

    if max_total > 0 and len(limited) > max_total:
        limited = limited[:max_total]

    return limited
