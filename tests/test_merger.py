"""Tests for src/aggregator/merger.py — dedup, sort, limit, merge_and_filter."""

from __future__ import annotations

import pytest

from src.aggregator.merger import (
    _latency_sort_key,
    deduplicate,
    limit_per_country,
    merge_and_filter,
    sort_configs,
)
from src.parsers.base import Config


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_config(
    address: str = "host.example",
    port: int = 443,
    uuid: str = "11111111-1111-4111-8111-111111111111",
    country: str | None = "DE",
    latency_ms: float | None = 50.0,
    protocol: str = "vless",
) -> Config:
    return Config(
        protocol=protocol,
        address=address,
        port=port,
        uuid_or_password=uuid,
        country=country,
        latency_ms=latency_ms,
    )


# ---------------------------------------------------------------------------
# _latency_sort_key
# ---------------------------------------------------------------------------


def test_latency_sort_key_none() -> None:
    cfg = make_config(latency_ms=None)
    key = _latency_sort_key(cfg)
    assert key == (1, float("inf"))


def test_latency_sort_key_real() -> None:
    cfg = make_config(latency_ms=25.5)
    key = _latency_sort_key(cfg)
    assert key == (0, 25.5)


def test_latency_sort_key_integer_cast() -> None:
    cfg = make_config(latency_ms=10.0)
    key = _latency_sort_key(cfg)
    assert key == (0, 10.0)


# ---------------------------------------------------------------------------
# deduplicate
# ---------------------------------------------------------------------------


def test_deduplicate_empty() -> None:
    assert deduplicate([]) == []


def test_deduplicate_all_unique() -> None:
    a = make_config(address="a.com", latency_ms=10.0)
    b = make_config(address="b.com", latency_ms=20.0)
    result = deduplicate([a, b])
    assert result == [a, b]


def test_deduplicate_keeps_lower_latency() -> None:
    """Same (address, port) — keep the one with lowest latency."""
    high = make_config(address="same.com", uuid="id-high", latency_ms=100.0)
    low = make_config(address="same.com", uuid="id-low", latency_ms=10.0)
    result = deduplicate([high, low])
    assert len(result) == 1
    assert result[0].uuid_or_password == "id-low"


def test_deduplicate_keeps_first_when_latency_equal() -> None:
    """Same (address, port), same latency — keep first seen."""
    a = make_config(address="same.com", uuid="id-a", latency_ms=50.0)
    b = make_config(address="same.com", uuid="id-b", latency_ms=50.0)
    result = deduplicate([a, b])
    assert len(result) == 1
    assert result[0].uuid_or_password == "id-a"


def test_deduplicate_none_latency_replaced_by_real() -> None:
    """Config with None latency is replaced by one with real latency."""
    none_lat = make_config(address="host.com", uuid="id-none", latency_ms=None)
    real_lat = make_config(address="host.com", uuid="id-real", latency_ms=30.0)
    result = deduplicate([none_lat, real_lat])
    assert len(result) == 1
    assert result[0].uuid_or_password == "id-real"


def test_deduplicate_real_not_replaced_by_none() -> None:
    """Config with real latency is NOT replaced by one with None latency."""
    none_lat = make_config(address="host.com", uuid="id-none", latency_ms=None)
    real_lat = make_config(address="host.com", uuid="id-real", latency_ms=30.0)
    result = deduplicate([real_lat, none_lat])
    assert len(result) == 1
    assert result[0].uuid_or_password == "id-real"


def test_deduplicate_preserves_order() -> None:
    """First occurrence of each unique key determines order."""
    a = make_config(address="a.com", uuid="id-a", latency_ms=10.0)
    b = make_config(address="b.com", uuid="id-b", latency_ms=20.0)
    c = make_config(address="c.com", uuid="id-c", latency_ms=30.0)
    result = deduplicate([c, a, b])
    assert [cfg.uuid_or_password for cfg in result] == ["id-c", "id-a", "id-b"]


# ---------------------------------------------------------------------------
# sort_configs
# ---------------------------------------------------------------------------


def test_sort_configs_empty() -> None:
    assert sort_configs([]) == []


def test_sort_configs_by_latency() -> None:
    a = make_config(address="a.com", uuid="id-a", latency_ms=100.0)
    b = make_config(address="b.com", uuid="id-b", latency_ms=10.0)
    c = make_config(address="c.com", uuid="id-c", latency_ms=None)
    result = sort_configs([a, b, c], sort_by="latency")
    assert result == [b, a, c]


def test_sort_configs_by_country() -> None:
    ru = make_config(address="ru.com", uuid="id-ru", country="RU", latency_ms=5.0)
    de = make_config(address="de.com", uuid="id-de", country="DE", latency_ms=50.0)
    us = make_config(address="us.com", uuid="id-us", country="US", latency_ms=100.0)
    result = sort_configs([us, ru, de], sort_by="country")
    assert [c.country for c in result] == ["DE", "RU", "US"]


def test_sort_configs_by_country_none_last() -> None:
    de = make_config(address="de.com", uuid="id-de", country="DE", latency_ms=50.0)
    none_cfg = make_config(
        address="none.com", uuid="id-none", country=None, latency_ms=10.0
    )
    result = sort_configs([none_cfg, de], sort_by="country")
    assert result == [de, none_cfg]


def test_sort_configs_by_country_latency_subsort() -> None:
    """Within each country, configs are sorted by latency."""
    de_fast = make_config(address="f.de.com", uuid="id-f", country="DE", latency_ms=5.0)
    de_slow = make_config(
        address="s.de.com", uuid="id-s", country="DE", latency_ms=50.0
    )
    us_fast = make_config(
        address="f.us.com", uuid="id-uf", country="US", latency_ms=1.0
    )
    result = sort_configs([de_slow, us_fast, de_fast], sort_by="country")
    assert result == [de_fast, de_slow, us_fast]


def test_sort_configs_unknown_sort_by() -> None:
    a = make_config(address="b.com", uuid="id-b", latency_ms=10.0)
    b = make_config(address="a.com", uuid="id-a", latency_ms=5.0)
    configs = [a, b]
    result = sort_configs(configs, sort_by="unknown")
    # Shallow copy with same order
    assert result == configs
    assert result is not configs


# ---------------------------------------------------------------------------
# limit_per_country
# ---------------------------------------------------------------------------


def test_limit_per_country_no_limit() -> None:
    configs = [make_config(address="a.com", country="DE")]
    result = limit_per_country(configs, max_per_country=0)
    assert result == configs


def test_limit_per_country_empty() -> None:
    assert limit_per_country([], max_per_country=5) == []


def test_limit_per_country_caps_per_country() -> None:
    de_configs = [
        make_config(address=f"de-{i}.com", uuid=f"id-{i}", country="DE")
        for i in range(5)
    ]
    us_configs = [
        make_config(address=f"us-{i}.com", uuid=f"id-us-{i}", country="US")
        for i in range(3)
    ]
    all_configs = de_configs + us_configs
    result = limit_per_country(all_configs, max_per_country=2)
    assert len(result) == 4  # 2 DE + 2 US
    assert [c.address for c in result] == [
        "de-0.com",
        "de-1.com",
        "us-0.com",
        "us-1.com",
    ]


def test_limit_per_country_none_country() -> None:
    configs = [
        make_config(address="a.com", uuid="id-a", country=None),
        make_config(address="b.com", uuid="id-b", country=None),
        make_config(address="c.com", uuid="id-c", country=None),
    ]
    result = limit_per_country(configs, max_per_country=2)
    assert len(result) == 2


def test_limit_per_country_negative_is_unlimited() -> None:
    configs = [make_config(address="a.com", country="DE")]
    result = limit_per_country(configs, max_per_country=-1)
    assert result == configs


# ---------------------------------------------------------------------------
# merge_and_filter (full pipeline)
# ---------------------------------------------------------------------------


def test_merge_and_filter_empty() -> None:
    assert merge_and_filter([]) == []


def test_merge_and_filter_dedup_sort_limit() -> None:
    """Full pipeline: dedup by host, sort by latency, cap total."""
    configs = [
        make_config(address="same.com", uuid="id-1", country="DE", latency_ms=100.0),
        make_config(address="same.com", uuid="id-2", country="DE", latency_ms=10.0),
        make_config(address="us.com", uuid="id-us", country="US", latency_ms=50.0),
    ]
    result = merge_and_filter(configs, max_total=2)
    assert len(result) == 2
    # After dedup: id-2 (lower latency), id-us. After sort: id-2 (10), id-us (50). Cap at 2.
    assert result[0].uuid_or_password == "id-2"
    assert result[1].uuid_or_password == "id-us"


def test_merge_and_filter_sort_by_country() -> None:
    configs = [
        make_config(address="ru.com", uuid="id-ru", country="RU", latency_ms=5.0),
        make_config(address="de.com", uuid="id-de", country="DE", latency_ms=50.0),
    ]
    result = merge_and_filter(configs, sort_by="country", max_total=5)
    assert [c.country for c in result] == ["DE", "RU"]


def test_merge_and_filter_max_total_cap() -> None:
    configs = [
        make_config(address=f"h{i}.com", uuid=f"id{i}", country="DE") for i in range(10)
    ]
    result = merge_and_filter(configs, max_total=3)
    assert len(result) == 3


def test_merge_and_filter_max_total_zero_is_unlimited() -> None:
    configs = [
        make_config(address=f"h{i}.com", uuid=f"id{i}", country="DE") for i in range(10)
    ]
    result = merge_and_filter(configs, max_total=0)
    assert len(result) == 10


def test_merge_and_filter_per_country_cap() -> None:
    configs = [
        make_config(address=f"h{i}.com", uuid=f"id{i}", country="DE") for i in range(10)
    ]
    result = merge_and_filter(configs, max_total=50, max_per_country=3)
    assert len(result) == 3


def test_merge_and_filter_per_country_with_mixed_countries() -> None:
    configs = [
        make_config(address=f"de-{i}.com", uuid=f"id-de-{i}", country="DE")
        for i in range(5)
    ] + [
        make_config(address=f"us-{i}.com", uuid=f"id-us-{i}", country="US")
        for i in range(5)
    ]
    result = merge_and_filter(configs, max_total=50, max_per_country=2)
    assert len(result) == 4  # 2 DE + 2 US
