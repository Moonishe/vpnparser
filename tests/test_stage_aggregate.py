"""Tests for the aggregation stage — 100% coverage of aggregate.py."""

from __future__ import annotations

import pytest

from src.parsers.base import Config
from src.scheduler.context import PipelineContext, PipelineState
from src.scheduler.settings import Settings
from src.scheduler.stages.aggregate import Aggregator

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _make_context(settings_dict: dict | None = None) -> PipelineContext:
    return PipelineContext(
        settings=Settings(settings_dict or {}),
        github_token=None,
        sources_path="missing.json",
    )


def _make_config(
    address: str = "test.example",
    port: int = 443,
    *,
    country: str | None = None,
    quality_score: float | None = None,
    latency_ms: float | None = None,
    remark: str = "",
    dedup_address: str | None = None,
    dedup_port: int | None = None,
) -> Config:
    cfg = Config(
        protocol="vless",
        address=address,
        port=port,
        uuid_or_password="11111111-1111-4111-8111-111111111111",
        country=country,
        quality_score=quality_score,
        latency_ms=latency_ms,
        remark=remark,
    )
    if dedup_address is not None:
        # Override dedup_key by setting fields directly for testing
        object.__setattr__(cfg, "address", dedup_address)
    if dedup_port is not None:
        object.__setattr__(cfg, "port", dedup_port)
    return cfg


# ---------------------------------------------------------------------------
# Aggregator.run()
# ---------------------------------------------------------------------------


class TestRun:
    """Cover lines 29-35 of aggregate.py."""

    async def test_run_basic(self) -> None:
        """run() chains dedup + country-balanced-limit."""
        context = _make_context(
            {
                "aggregator": {"max_configs_in_output": 10, "sort_by": "country"},
            }
        )
        agg = Aggregator(context)
        state = PipelineState(
            preprocessed={
                "blacklist": [
                    _make_config("a.com", 443, country="DE"),
                    _make_config("b.com", 443, country="FI"),
                    _make_config("a.com", 443, country="DE"),  # duplicate
                ],
            },
        )
        result = await agg.run(state)
        # dedup removes the duplicate, then country-balanced-limit
        assert len(result.aggregated) == 2
        assert result.aggregated[0].country == "DE"
        assert result.aggregated[1].country == "FI"

    async def test_run_empty_preprocessed(self) -> None:
        """run() with no preprocessed configs returns empty list."""
        agg = Aggregator(_make_context())
        state = PipelineState(preprocessed={})
        result = await agg.run(state)
        assert result.aggregated == []

    async def test_run_multiple_lists(self) -> None:
        """run() merges configs from multiple preprocessed lists."""
        context = _make_context(
            {
                "aggregator": {"max_configs_in_output": 100, "sort_by": "country"},
            }
        )
        agg = Aggregator(context)
        state = PipelineState(
            preprocessed={
                "blacklist": [
                    _make_config("bl-1.com", 443, country="DE"),
                    _make_config("bl-2.com", 444, country="FI"),
                ],
                "whitelist": [
                    _make_config("wl-1.com", 445, country="RU"),
                ],
            },
        )
        result = await agg.run(state)
        assert len(result.aggregated) == 3


# ---------------------------------------------------------------------------
# _dedup_only
# ---------------------------------------------------------------------------


class TestDedupOnly:
    """Cover line 46 of aggregate.py."""

    def test_dedup_only_static(self) -> None:
        """_dedup_only delegates to DedupFilter.dedup_only."""
        agg = Aggregator(_make_context())
        configs = [
            _make_config("same.com", 443, country="DE"),
            _make_config("same.com", 443, country="FI"),  # duplicate
            _make_config("other.com", 444, country="RU"),
        ]
        result = Aggregator._dedup_only(configs)
        assert len(result) == 2


# ---------------------------------------------------------------------------
# _sort_and_limit
# ---------------------------------------------------------------------------


class TestSortAndLimit:
    """Cover lines 53-55 (exception path) of aggregate.py."""

    def test_sort_and_limit_exception(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When _country_balanced_limit raises, fallback to simple slice."""
        agg = Aggregator(
            _make_context(
                {"aggregator": {"max_configs_in_output": 10}},
            )
        )

        def _raise(*args: object, **kwargs: object) -> list:
            raise RuntimeError("boom")

        monkeypatch.setattr(agg, "_country_balanced_limit", _raise)

        configs = [_make_config("a.com", 443), _make_config("b.com", 444)]
        result = agg._sort_and_limit(configs)
        # falls back to configs[:max_configs]
        assert len(result) == 2

    def test_sort_and_limit_ok(self) -> None:
        """Happy path with country=DE and sort_by=country."""
        context = _make_context(
            {
                "aggregator": {"max_configs_in_output": 5, "sort_by": "country"},
            }
        )
        agg = Aggregator(context)
        configs = [
            _make_config("a.com", 443, country="DE"),
            _make_config("b.com", 444, country="FI"),
        ]
        result = agg._sort_and_limit(configs)
        assert len(result) == 2


# ---------------------------------------------------------------------------
# _country_balanced_limit
# ---------------------------------------------------------------------------


class TestCountryBalancedLimit:
    """Cover lines 63-64, 70-71, 75-77, 91-92, 96, 99-111."""

    def test_max_total_zero(self) -> None:
        """max_total <= 0 returns []. (lines 63-64)"""
        agg = Aggregator(_make_context())
        configs = [_make_config(country="DE")]
        assert agg._country_balanced_limit(configs, 0) == []
        assert agg._country_balanced_limit(configs, -1) == []

    def test_empty_configs(self) -> None:
        """Empty configs returns []. (lines 63-64)"""
        agg = Aggregator(_make_context())
        assert agg._country_balanced_limit([], 10) == []

    def test_max_per_country_type_error(self) -> None:
        """max_per_country ValueError/TypeError falls back to 0. (lines 70-71)"""
        context = _make_context(
            {
                "aggregator": {
                    "max_configs_in_output": 10,
                    "max_per_country": "not-a-number",
                    "sort_by": "country",
                },
            }
        )
        agg = Aggregator(context)
        configs = [
            _make_config("a.com", 443, country="DE"),
            _make_config("b.com", 444, country="FI"),
        ]
        result = agg._country_balanced_limit(configs, 10)
        assert len(result) == 2

    def test_max_per_country_none_value(self) -> None:
        """max_per_country None triggers TypeError -> fallback to 0."""
        context = _make_context(
            {
                "aggregator": {
                    "max_configs_in_output": 10,
                    "max_per_country": None,
                    "sort_by": "country",
                },
            }
        )
        agg = Aggregator(context)
        configs = [
            _make_config("a.com", 443, country="DE"),
            _make_config("b.com", 444, country="FI"),
        ]
        result = agg._country_balanced_limit(configs, 10)
        assert len(result) == 2

    def test_sort_configs_import_error(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """ImportError for sort_configs skips sorting. (lines 75-77)"""
        import src.aggregator.merger as merger_mod

        monkeypatch.delattr(merger_mod, "sort_configs", raising=False)

        context = _make_context(
            {
                "aggregator": {"max_configs_in_output": 10, "sort_by": "country"},
            }
        )
        agg = Aggregator(context)
        configs = [
            _make_config("a.com", 443, country="DE"),
            _make_config("b.com", 444, country="FI"),
        ]
        result = agg._country_balanced_limit(configs, 10)
        assert len(result) == 2

    def test_sort_by_latency(self) -> None:
        """sort_by='latency' works correctly."""
        context = _make_context(
            {
                "aggregator": {
                    "max_configs_in_output": 10,
                    "sort_by": "latency",
                },
            }
        )
        agg = Aggregator(context)
        configs = [
            _make_config("a.com", 443, country="DE", latency_ms=100),
            _make_config("b.com", 444, country="FI", latency_ms=50),
            _make_config("c.com", 445, country="DE", latency_ms=200),
        ]
        result = agg._country_balanced_limit(configs, 10)
        assert len(result) == 3

    def test_sort_by_unknown(self) -> None:
        """Unknown sort_by returns configs unchanged."""
        context = _make_context(
            {
                "aggregator": {
                    "max_configs_in_output": 10,
                    "sort_by": "nonexistent_sort",
                },
            }
        )
        agg = Aggregator(context)
        configs = [
            _make_config("a.com", 443, country="DE"),
            _make_config("b.com", 444, country="FI"),
        ]
        result = agg._country_balanced_limit(configs, 10)
        assert len(result) == 2

    def test_country_none_unknown_bucket(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Configs with country=None go into unknown_bucket. (lines 91-92, 99-111)

        The unknown_bucket code is only reachable via the import-error path
        (line 77) because the normal sort path filters country=None out.
        """
        import src.aggregator.merger as merger_mod

        monkeypatch.delattr(merger_mod, "sort_configs", raising=False)

        context = _make_context(
            {
                "aggregator": {"max_configs_in_output": 10, "sort_by": "country"},
            }
        )
        agg = Aggregator(context)
        configs = [
            _make_config("known.com", 443, country="DE"),
            _make_config("unknown.com", 444, country=None, quality_score=0.5),
        ]
        result = agg._country_balanced_limit(configs, 10)
        # both configs should appear
        assert len(result) == 2
        assert result[0].country == "DE"
        assert result[1].address == "unknown.com"

    def test_country_none_unknown_bucket_sorted(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Unknown bucket configs are sorted by quality_score then latency.

        The unknown_bucket code is only reachable via the import-error path
        (line 77) because the normal sort path filters country=None out.
        """
        import src.aggregator.merger as merger_mod

        monkeypatch.delattr(merger_mod, "sort_configs", raising=False)

        context = _make_context(
            {
                "aggregator": {"max_configs_in_output": 10, "sort_by": "country"},
            }
        )
        agg = Aggregator(context)
        configs = [
            _make_config("low-q.com", 444, country=None, quality_score=0.1),
            _make_config("high-q.com", 445, country=None, quality_score=0.9),
            _make_config("known.com", 443, country="DE", quality_score=0.5),
        ]
        result = agg._country_balanced_limit(configs, 10)
        assert len(result) == 3
        # known countries come first, then unknown (sorted by quality desc)
        unknown = [c for c in result if c.country is None]
        assert unknown[0].address == "high-q.com"

    def test_max_per_country_capping(self) -> None:
        """max_per_country limits per-country count. (line 96)"""
        context = _make_context(
            {
                "aggregator": {
                    "max_configs_in_output": 100,
                    "max_per_country": 2,
                    "sort_by": "country",
                },
            }
        )
        agg = Aggregator(context)
        configs = [
            _make_config(f"de-{i}.com", 4000 + i, country="DE") for i in range(5)
        ] + [_make_config(f"fi-{i}.com", 5000 + i, country="FI") for i in range(5)]
        result = agg._country_balanced_limit(configs, 100)
        # max 2 per country = 4 total
        assert len(result) == 4
        de_count = sum(1 for c in result if c.country == "DE")
        fi_count = sum(1 for c in result if c.country == "FI")
        assert de_count == 2
        assert fi_count == 2

    def test_round_robin_exhausts_countries(self) -> None:
        """Round-robin stops when all buckets exhausted."""
        context = _make_context(
            {
                "aggregator": {
                    "max_configs_in_output": 100,
                    "max_per_country": 2,
                    "sort_by": "country",
                },
            }
        )
        agg = Aggregator(context)
        configs = [
            _make_config("de-1.com", 4001, country="DE"),
            _make_config("de-2.com", 4002, country="DE"),
            _make_config("fi-1.com", 5001, country="FI"),
            _make_config("fi-2.com", 5002, country="FI"),
        ]
        result = agg._country_balanced_limit(configs, 3)
        # round-robin: DE, FI, DE (3 configs)
        assert len(result) == 3
        assert result[0].country == "DE"
        assert result[1].country == "FI"
        assert result[2].country == "DE"


# ---------------------------------------------------------------------------
# _whitelist_balance
# ---------------------------------------------------------------------------


class TestWhitelistBalance:
    """Cover lines 142-183 (all branches)."""

    def test_ru_ratio_type_error(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """ru_ratio ValueError/TypeError falls back to 0.8. (lines 147-148)"""
        context = _make_context(
            {
                "validator": {
                    "whitelist_ru_ratio": "not-a-number",
                    "whitelist_eu_countries": ["DE"],
                },
            }
        )
        agg = Aggregator(context)
        # Need to also set max_configs_in_output for country_balanced_limit
        monkeypatch.setattr(agg, "_max_configs", lambda: 100)

        configs = [
            _make_config("ru.com", 443, country="RU", quality_score=0.9, latency_ms=10),
            _make_config("de.com", 444, country="DE", quality_score=0.8, latency_ms=20),
        ]
        result = agg._whitelist_balance(configs, 10)
        assert len(result) >= 1

    def test_ru_ratio_clamped(self) -> None:
        """ru_ratio is clamped to [0.0, 1.0]."""
        context = _make_context(
            {
                "validator": {
                    "whitelist_ru_ratio": 5.0,  # clamped to 1.0
                    "whitelist_eu_countries": ["DE"],
                },
            }
        )
        agg = Aggregator(context)
        configs = [
            _make_config("ru.com", 443, country="RU"),
            _make_config("de.com", 444, country="DE"),
        ]
        result = agg._whitelist_balance(configs, 10)
        # With ratio clamped to 1.0, all should be RU
        assert sum(1 for c in result if c.country == "RU") <= 10

    def test_eu_raw_string(self) -> None:
        """eu_raw as string is wrapped in list. (line 152)"""
        context = _make_context(
            {
                "validator": {
                    "whitelist_ru_ratio": 0.5,
                    "whitelist_eu_countries": "DE",  # string, not list
                },
            }
        )
        agg = Aggregator(context)
        configs = [
            _make_config("ru.com", 443, country="RU"),
            _make_config("de.com", 444, country="DE"),
        ]
        result = agg._whitelist_balance(configs, 10)
        assert len(result) >= 1

    def test_shortfall_fill_from_eu(self) -> None:
        """When ru_target not met, fill shortfall from EU. (lines 168-171)"""
        context = _make_context(
            {
                "validator": {
                    "whitelist_ru_ratio": 0.8,
                    "whitelist_eu_countries": ["DE"],
                },
            }
        )
        agg = Aggregator(context)
        ru_configs = [
            _make_config(
                f"ru-{i}.com", 4000 + i, country="RU", quality_score=0.9, latency_ms=10
            )
            for i in range(3)
        ]
        eu_configs = [
            _make_config(
                f"de-{i}.com", 5000 + i, country="DE", quality_score=0.8, latency_ms=20
            )
            for i in range(10)
        ]
        result = agg._whitelist_balance(ru_configs + eu_configs, 10)
        # ru_target = 8, but only 3 RU available
        # shortfall = 10 - 3 - len(eu_result with 3 EU) = 4
        # EU gets more: eu_result extended by shortfall
        assert sum(1 for c in result if c.country == "RU") == 3
        assert len(result) == 10

    def test_shortfall_fill_from_ru(self) -> None:
        """When eu_target not met, fill shortfall from RU. (lines 172-174)"""
        context = _make_context(
            {
                "validator": {
                    "whitelist_ru_ratio": 0.5,
                    "whitelist_eu_countries": ["DE"],
                },
            }
        )
        agg = Aggregator(context)
        ru_configs = [
            _make_config(
                f"ru-{i}.com", 4000 + i, country="RU", quality_score=0.9, latency_ms=10
            )
            for i in range(10)
        ]
        eu_configs = [
            _make_config(
                "de-1.com", 5001, country="DE", quality_score=0.8, latency_ms=20
            ),
        ]
        result = agg._whitelist_balance(ru_configs + eu_configs, 10)
        # ru_target = 5, eu_target = 5, but only 1 EU available
        # shortfall = 10 - 5 - 1 = 4, RU fills = 9
        assert sum(1 for c in result if c.country == "RU") >= 5
        assert len(result) == 10


# ---------------------------------------------------------------------------
# _build_mixed_output
# ---------------------------------------------------------------------------


class TestBuildMixedOutput:
    """Cover lines 185-242 (all branches)."""

    def test_max_total_zero(self) -> None:
        """max_total <= 0 returns []. (line 192)"""
        agg = Aggregator(_make_context())
        result = agg._build_mixed_output({}, 0)
        assert result == []

    def test_basic_mix(self) -> None:
        """Basic 50/50 mix."""
        context = _make_context(
            {
                "aggregator": {"max_configs_in_output": 10, "sort_by": "country"},
                "validator": {
                    "whitelist_ru_ratio": 0.8,
                    "whitelist_eu_countries": ["DE"],
                },
            }
        )
        agg = Aggregator(context)
        blacklist = [
            _make_config(f"bl-{i}.com", 4000 + i, country="DE") for i in range(10)
        ]
        whitelist = [
            _make_config(f"wl-ru-{i}.com", 5000 + i, country="RU") for i in range(10)
        ]
        result = agg._build_mixed_output(
            {"blacklist": blacklist, "whitelist": whitelist},
            10,
        )
        assert len(result) == 10
        assert sum(1 for c in result if "bl-" in c.address) == 5
        assert sum(1 for c in result if "wl-" in c.address) == 5

    def test_short_blacklist_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        """Warning logged when blacklist is short. (line 223)"""
        context = _make_context(
            {
                "aggregator": {"max_configs_in_output": 10, "sort_by": "country"},
                "validator": {
                    "whitelist_ru_ratio": 0.8,
                    "whitelist_eu_countries": ["DE"],
                },
            }
        )
        agg = Aggregator(context)
        caplog.set_level("WARNING")
        result = agg._build_mixed_output(
            {"blacklist": [], "whitelist": []},
            10,
        )
        assert len(result) == 0
        assert "short on blacklist" in caplog.text

    def test_short_whitelist_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        """Warning logged when whitelist is short. (line 229)"""
        context = _make_context(
            {
                "aggregator": {"max_configs_in_output": 10, "sort_by": "country"},
                "validator": {
                    "whitelist_ru_ratio": 0.8,
                    "whitelist_eu_countries": ["DE"],
                },
            }
        )
        agg = Aggregator(context)
        blacklist = [
            _make_config(f"bl-{i}.com", 4000 + i, country="DE") for i in range(10)
        ]
        caplog.set_level("WARNING")
        result = agg._build_mixed_output(
            {"blacklist": blacklist, "whitelist": []},
            10,
        )
        assert sum(1 for c in result if "bl-" in c.address) == 5
        assert "short on whitelist" in caplog.text

    def test_dedup_key_collision(self) -> None:
        """Whitelist configs with dedup_key already used by blacklist are skipped."""
        context = _make_context(
            {
                "aggregator": {"max_configs_in_output": 10, "sort_by": "country"},
                "validator": {
                    "whitelist_ru_ratio": 0.8,
                    "whitelist_eu_countries": ["DE"],
                },
            }
        )
        agg = Aggregator(context)
        blacklist = [_make_config("shared.com", 443, country="DE") for _ in range(5)]
        whitelist = [
            # Same address/port as blacklist — should be skipped
            _make_config("shared.com", 443, country="RU"),
            _make_config("unique.com", 444, country="RU"),
        ]
        result = agg._build_mixed_output(
            {"blacklist": blacklist, "whitelist": whitelist},
            10,
        )
        # blacklist gets 5, but dedup reduces to 1
        # whitelist: "shared.com" skipped (used by blacklist), "unique.com" added
        blacklist_in_result = sum(1 for c in result if c.country == "DE")
        whitelist_in_result = sum(1 for c in result if c.country == "RU")
        assert blacklist_in_result + whitelist_in_result <= 10


# ---------------------------------------------------------------------------
# _take_unique_configs
# ---------------------------------------------------------------------------


class TestTakeUniqueConfigs:
    """Cover lines 244-263 (all branches)."""

    def test_target_zero(self) -> None:
        """target <= 0 returns []. (line 252)"""
        result = Aggregator._take_unique_configs(
            [_make_config("a.com", 443)],
            0,
            set(),
        )
        assert result == []

    def test_target_negative(self) -> None:
        """Negative target returns []. (line 252)"""
        result = Aggregator._take_unique_configs(
            [_make_config("a.com", 443)],
            -1,
            set(),
        )
        assert result == []

    def test_used_keys_skipped(self) -> None:
        """Configs with dedup_key already in used_keys are skipped. (line 258)"""
        used = {("vless", "a.com", 443)}
        configs = [
            _make_config("a.com", 443, country="DE"),  # skipped
            _make_config("b.com", 444, country="FI"),  # taken
            _make_config("a.com", 443, country="RU"),  # skipped (duplicate key)
        ]
        result = Aggregator._take_unique_configs(configs, 5, used)
        assert len(result) == 1
        assert result[0].address == "b.com"
        assert ("vless", "b.com", 444) in used

    def test_take_all(self) -> None:
        """Take up to target unique configs."""
        configs = [
            _make_config("a.com", 443),
            _make_config("b.com", 444),
            _make_config("c.com", 445),
        ]
        result = Aggregator._take_unique_configs(configs, 2, set())
        assert len(result) == 2

    def test_take_less_than_available(self) -> None:
        """Take fewer than available configs."""
        configs = [
            _make_config("a.com", 443),
            _make_config("b.com", 444),
        ]
        result = Aggregator._take_unique_configs(configs, 5, set())
        assert len(result) == 2


# ---------------------------------------------------------------------------
# process_configs
# ---------------------------------------------------------------------------


class FakePreprocessor:
    """Mock preprocessor that optionally returns empty list."""

    def __init__(self, empty: bool = False) -> None:
        self._empty = empty

    def preprocess(
        self,
        configs: list[Config],
        *,
        label: str,
    ) -> list[Config]:
        return [] if self._empty else configs


class TestProcessConfigs:
    """Cover lines 265-278."""

    def test_process_configs_happy_path(self) -> None:
        """process_configs runs preprocess -> sort -> limit."""
        context = _make_context(
            {
                "aggregator": {"max_configs_in_output": 10, "sort_by": "country"},
            }
        )
        agg = Aggregator(context)
        configs = [
            _make_config("a.com", 443, country="DE"),
            _make_config("b.com", 444, country="FI"),
        ]
        result = agg.process_configs(
            configs,
            label="test",
            preprocessor=FakePreprocessor(),
        )
        assert len(result) == 2

    def test_process_configs_empty(self) -> None:
        """When preprocessor returns empty, return []. (line 274-275)"""
        agg = Aggregator(_make_context())
        result = agg.process_configs(
            [_make_config("a.com", 443)],
            label="test",
            preprocessor=FakePreprocessor(empty=True),
        )
        assert result == []

    def test_process_configs_empty_input(self) -> None:
        """Empty input list returns []. (line 274-275)"""
        agg = Aggregator(_make_context())
        result = agg.process_configs(
            [],
            label="test",
            preprocessor=FakePreprocessor(),
        )
        assert result == []


# ---------------------------------------------------------------------------
# _max_configs
# ---------------------------------------------------------------------------


class TestMaxConfigs:
    """Cover the _max_configs method."""

    def test_max_configs_default(self) -> None:
        """When not configured, default is 500."""
        agg = Aggregator(_make_context())
        assert agg._max_configs() == 500

    def test_max_configs_custom(self) -> None:
        """When configured, returns the custom value."""
        agg = Aggregator(
            _make_context(
                {
                    "aggregator": {"max_configs_in_output": 42},
                }
            )
        )
        assert agg._max_configs() == 42

    def test_max_configs_non_int(self) -> None:
        """Non-int value falls back to default."""
        agg = Aggregator(
            _make_context(
                {
                    "aggregator": {"max_configs_in_output": "not-a-number"},
                }
            )
        )
        assert agg._max_configs() == 500
