"""Tests for the filter stages — 100% coverage of filter.py."""

from __future__ import annotations

import pytest

from src.parsers.base import Config
from src.scheduler.context import PipelineContext, PipelineState
from src.scheduler.settings import Settings
from src.scheduler.stages.filter import (
    CountryFilter,
    DedupFilter,
    GarbageFilter,
    PreprocessFilter,
)

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
    remark: str = "",
    quality_score: float | None = None,
    latency_ms: float | None = None,
) -> Config:
    return Config(
        protocol="vless",
        address=address,
        port=port,
        uuid_or_password="11111111-1111-4111-8111-111111111111",
        country=country,
        remark=remark,
        quality_score=quality_score,
        latency_ms=latency_ms,
    )


# ---------------------------------------------------------------------------
# GarbageFilter
# ---------------------------------------------------------------------------


class TestGarbageFilterRun:
    """The runner calls filter_garbage directly; run() is not implemented."""

    async def test_default_run_raises_not_implemented(self) -> None:
        gf = GarbageFilter(_make_context())
        with pytest.raises(NotImplementedError):
            await gf.run(PipelineState(parsed={}))

    def test_filters_garbage(self) -> None:
        """filter_garbage removes garbage configs."""
        gf = GarbageFilter(_make_context())
        clean, count = gf.filter_garbage(
            [
                _make_config("real.server", 443, remark="DE-01"),
                Config(
                    "vless",
                    "placeholder.test",
                    443,
                    "11111111-1111-4111-8111-111111111111",
                    remark="nope",
                    sni="SERVER_IP",  # triggers garbage detection
                ),
            ],
        )
        assert count == 1
        assert len(clean) == 1
        assert clean[0].address == "real.server"


class TestFilterGarbage:
    """Cover lines 48-49 (debug logging) + general cases."""

    def test_garbage_counted_and_logged(self, caplog: pytest.LogCaptureFixture) -> None:
        """filter_garbage logs garbage count at debug level. (lines 48-49)"""
        caplog.set_level("DEBUG")
        configs = [
            Config(
                "vless",
                "example.com",
                443,
                "11111111-1111-4111-8111-111111111111",
                remark="buy vpn .ru",
            ),
        ]
        clean, count = GarbageFilter.filter_garbage(configs)
        assert count == 1
        assert clean == []
        assert "Garbage filtered" in caplog.text

    def test_filter_garbage_all_clean(self) -> None:
        """All configs clean -> no garbage."""
        configs = [_make_config("real.com", 443)]
        clean, count = GarbageFilter.filter_garbage(configs)
        assert count == 0
        assert len(clean) == 1

    def test_filter_garbage_mixed(self) -> None:
        """Mix of clean and garbage configs."""
        configs = [
            _make_config("real.com", 443),
            Config(
                "vless",
                "example.com",
                443,
                "11111111-1111-4111-8111-111111111111",
                remark="t.me/ad",
            ),
            _make_config("real-2.com", 444),
        ]
        clean, count = GarbageFilter.filter_garbage(configs)
        assert count == 1
        assert len(clean) == 2

    def test_filter_garbage_empty(self) -> None:
        """Empty input -> 0 garbage, empty list."""
        clean, count = GarbageFilter.filter_garbage([])
        assert count == 0
        assert clean == []


# ---------------------------------------------------------------------------
# CountryFilter
# ---------------------------------------------------------------------------


class TestCountryFilterRun:
    """The runner calls filter_countries directly; run() is not implemented."""

    async def test_default_run_raises_not_implemented(self) -> None:
        cf = CountryFilter(_make_context())
        with pytest.raises(NotImplementedError):
            await cf.run(PipelineState(parsed={}))

    def test_filters_by_allowed_countries(self) -> None:
        cf = CountryFilter(
            _make_context(
                {
                    "validator": {
                        "allowed_countries": ["DE"],
                    },
                }
            )
        )
        configs = [
            _make_config("de.com", 443, country="DE"),
            _make_config("ru.com", 444, country="RU"),
        ]
        result = cf.filter_countries(configs, list_type="blacklist")
        assert len(result) == 1
        assert result[0].country == "DE"

    def test_detect_retry_for_unknown_country(self) -> None:
        """Configs with country=None get detect_country retry."""
        cf = CountryFilter(
            _make_context(
                {
                    "validator": {"allowed_countries": ["DE"]},
                }
            )
        )
        configs = [_make_config("de.com", 443, country=None, remark="DE-01")]
        result = cf.filter_countries(configs)
        assert len(result) == 1
        assert result[0].country == "DE"


class TestFilterCountries:
    """Cover lines 78-122 (all branches)."""

    def test_allowed_string(self) -> None:
        """allowed_countries as string is wrapped in list. (line 93)"""
        cf = CountryFilter(
            _make_context(
                {
                    "validator": {"allowed_countries": "DE"},
                }
            )
        )
        configs = [
            _make_config("de.com", 443, country="DE"),
            _make_config("ru.com", 444, country="RU"),
        ]
        result = cf.filter_countries(configs, list_type="mixed")
        assert len(result) == 1
        assert result[0].country == "DE"

    def test_allowed_by_list_specific(self) -> None:
        """allowed_countries_by_list overrides global allowed."""
        cf = CountryFilter(
            _make_context(
                {
                    "validator": {
                        "allowed_countries": ["DE", "FI"],
                        "allowed_countries_by_list": {
                            "whitelist": ["RU"],
                        },
                    },
                }
            )
        )
        configs = [
            _make_config("ru.com", 443, country="RU"),
            _make_config("de.com", 444, country="DE"),
        ]
        # whitelist uses per-list setting -> only RU
        result = cf.filter_countries(configs, list_type="whitelist")
        assert len(result) == 1
        assert result[0].country == "RU"

    def test_no_allowed_keeps_all_and_detects(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """No country filter configured -> keep all, detect countries. (line 112)"""
        cf = CountryFilter(_make_context())
        caplog.set_level("INFO")
        configs = [
            _make_config("de.com", 443, country=None, remark="DE-01"),
        ]
        result = cf.filter_countries(configs)
        assert len(result) == 1
        assert result[0].country is not None
        assert "No country filter configured" in caplog.text

    def test_allowed_by_list_not_dict(self) -> None:
        """allowed_countries_by_list as non-dict is ignored."""
        cf = CountryFilter(
            _make_context(
                {
                    "validator": {
                        "allowed_countries": ["DE"],
                        "allowed_countries_by_list": "not-a-dict",
                    },
                }
            )
        )
        configs = [
            _make_config("de.com", 443, country="DE"),
            _make_config("ru.com", 444, country="RU"),
        ]
        result = cf.filter_countries(configs, list_type="blacklist")
        assert len(result) == 1

    def test_allowed_by_list_none_value(self) -> None:
        """allowed_countries_by_list entry with None value is skipped."""
        cf = CountryFilter(
            _make_context(
                {
                    "validator": {
                        "allowed_countries": ["DE"],
                        "allowed_countries_by_list": {"blacklist": None},
                    },
                }
            )
        )
        configs = [
            _make_config("de.com", 443, country="DE"),
            _make_config("ru.com", 444, country="RU"),
        ]
        # None means no specific override -> use global ["DE"]
        result = cf.filter_countries(configs, list_type="blacklist")
        assert len(result) == 1

    def test_source_default_country_used(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """source_default_country is used when detect_country returns None."""
        cf = CountryFilter(
            _make_context(
                {
                    "validator": {"allowed_countries": ["RU"]},
                }
            )
        )
        cfg = _make_config("unknown.example", 443, country=None, remark="NODETECT")
        cfg.source_default_country = "RU"
        result = cf.filter_countries([cfg], list_type="blacklist")
        assert len(result) == 1
        assert result[0].country == "RU"

    def test_unsupported_source_default_country_ignored(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A default_country outside the supported ISO set is not stamped.

        Otherwise a bogus hint (e.g. ``"XX"``) would land in Config.country and
        produce garbage location files and filter verdicts.
        """
        cf = CountryFilter(
            _make_context(
                {
                    "validator": {"allowed_countries": ["RU"]},
                }
            )
        )
        cfg = _make_config("unknown.example", 443, country=None, remark="NODETECT")
        cfg.source_default_country = "XX"
        result = cf.filter_countries([cfg], list_type="blacklist")
        assert result == []


# ---------------------------------------------------------------------------
# DedupFilter
# ---------------------------------------------------------------------------


class TestDedupFilterRun:
    """The runner calls dedup_only directly; run() is not implemented."""

    async def test_default_run_raises_not_implemented(self) -> None:
        df = DedupFilter()
        with pytest.raises(NotImplementedError):
            await df.run(PipelineState(parsed={}))


class TestDedupOnly:
    """Cover lines 141-152 (all branches)."""

    def test_dedup_import_error(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """ImportError for deduplicate skips dedup. (lines 145-147)"""
        import src.aggregator.merger as merger_mod

        monkeypatch.delattr(merger_mod, "deduplicate", raising=False)

        configs = [
            _make_config("a.com", 443),
            _make_config("a.com", 443),  # duplicate (kept because import fails)
        ]
        result = DedupFilter.dedup_only(configs)
        # dedup skipped -> all configs returned as-is
        assert len(result) == 2

    def test_dedup_exception(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """deduplicate raises Exception -> passthrough. (lines 150-152)"""
        import src.aggregator.merger as merger_mod

        def _raise(*args: object, **kwargs: object) -> list:
            raise RuntimeError("dedup boom")

        monkeypatch.setattr(merger_mod, "deduplicate", _raise)

        configs = [
            _make_config("a.com", 443),
            _make_config("b.com", 444),
        ]
        result = DedupFilter.dedup_only(configs)
        assert len(result) == 2

    def test_dedup_happy_path(self) -> None:
        """Normal dedup removes duplicates."""
        configs = [
            _make_config("a.com", 443),
            _make_config("a.com", 443),  # duplicate
            _make_config("b.com", 444),
        ]
        result = DedupFilter.dedup_only(configs)
        assert len(result) == 2

    def test_dedup_empty(self) -> None:
        """Empty input -> empty output."""
        result = DedupFilter.dedup_only([])
        assert result == []


# ---------------------------------------------------------------------------
# PreprocessFilter
# ---------------------------------------------------------------------------


class TestPreprocessFilterRun:
    """run() preprocesses every parsed list into state.preprocessed."""

    async def test_run_preprocesses_each_parsed_list(self) -> None:
        pf = PreprocessFilter(
            _make_context({"validator": {"allowed_countries": ["DE"]}})
        )
        de = _make_config("de.com", 443, country="DE")
        ru = _make_config("ru.com", 444, country="RU")
        state = PipelineState(parsed={"blacklist": [de, ru]})
        result = await pf.run(state)

        assert result is state
        assert state.preprocessed["blacklist"] == [de]
        assert all(cfg.country == "DE" for cfg in state.preprocessed["blacklist"])


class TestPreprocess:
    """Cover lines 211-235 (all branches)."""

    def test_empty_configs(self) -> None:
        """Empty input returns []. (line 213-214)"""
        pf = PreprocessFilter(_make_context())
        assert pf.preprocess([], label="test") == []

    def test_all_garbage(self) -> None:
        """All configs are garbage -> return []. (line 216-217)"""
        pf = PreprocessFilter(_make_context())
        configs = [
            Config(
                "vless",
                "example.com",
                443,
                "11111111-1111-4111-8111-111111111111",
                remark="join t.me/channel",
            ),
        ]
        assert pf.preprocess(configs, label="test") == []

    def test_sampling_triggered(self) -> None:
        """Sampling happens when configs exceed max_to_process. (lines 224-230)"""
        pf = PreprocessFilter(
            _make_context(
                {
                    "validator": {"max_configs_to_validate": 2},
                }
            )
        )
        configs = [_make_config(f"host-{i}.com", 4000 + i) for i in range(10)]
        result = pf.preprocess(configs, label="test")
        assert len(result) <= 2  # sampled then filtered

    def test_full_pipeline(self) -> None:
        """Full preprocess pipeline: garbage -> sample -> dedup -> country filter."""
        pf = PreprocessFilter(
            _make_context(
                {
                    "validator": {
                        "allowed_countries": ["DE", "RU"],
                    },
                }
            )
        )
        configs = [
            _make_config("de.com", 443, country="DE"),
            _make_config("ru.com", 444, country="RU"),
            Config(
                "vless",
                "example.com",
                445,
                "11111111-1111-4111-8111-111111111111",
                remark="ad .com",  # garbage
            ),
        ]
        result = pf.preprocess(configs, label="test")
        assert len(result) == 2

    def test_dedup_during_preprocess(self) -> None:
        """Dedup removes duplicates during preprocess."""
        pf = PreprocessFilter(
            _make_context(
                {
                    "validator": {"allowed_countries": ["DE"]},
                }
            )
        )
        configs = [
            _make_config("de.com", 443, country="DE"),
            _make_config("de.com", 443, country="DE"),  # duplicate
        ]
        result = pf.preprocess(configs, label="test")
        assert len(result) == 1
