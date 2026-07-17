"""Tests for src/scheduler/stages/parse.py — 100% coverage of LinkParser."""

from __future__ import annotations

import logging
import os
import types
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.parsers.base import Config, find_all_links
from src.scheduler.context import PipelineContext, PipelineState
from src.scheduler.settings import Settings
from src.scheduler.stages.parse import (
    LinkParser,
    _result_default_country,
    _result_files,
    _result_name,
)

# Standard test UUID
_UUID = "11111111-1111-4111-8111-111111111111"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_context(settings_dict: dict | None = None) -> PipelineContext:
    return PipelineContext(
        settings=Settings(settings_dict or {}),
        github_token=None,
        sources_path="missing.json",
    )


def _ns(**kwargs: object) -> types.SimpleNamespace:
    """Shorthand for creating SimpleNamespace with arbitrary attrs."""
    return types.SimpleNamespace(**kwargs)


def _vless(host: str, port: int = 443, remark: str = "") -> str:
    frag = f"#{remark}" if remark else ""
    return f"vless://{_UUID}@{host}:{port}{frag}"


# ===========================================================================
# _result_files
# ===========================================================================


class TestResultFiles:
    """100% coverage of _result_files — lines 20-42."""

    def test_object_with_files_attr(self) -> None:
        """Has ``.files`` attribute — extracts from it."""
        obj = _ns(files=[("a.txt", "hello")])
        assert _result_files(obj) == [("a.txt", "hello")]

    def test_dict_with_files_key(self) -> None:
        """dict with ``files`` key — extracts from it."""
        obj: dict = {"files": [("b.txt", "world")]}
        assert _result_files(obj) == [("b.txt", "world")]

    def test_dict_without_files_key(self) -> None:
        """dict without ``files`` key — returns empty."""
        obj: dict = {"name": "foo"}
        assert _result_files(obj) == []

    def test_list_input(self) -> None:
        """list passed directly — returned as-is."""
        assert _result_files([("c.txt", "!")]) == [("c.txt", "!")]

    def test_none_input(self) -> None:
        """None — returns empty."""
        assert _result_files(None) == []

    def test_empty_list(self) -> None:
        """Empty list — returns empty."""
        assert _result_files([]) == []

    def test_list_of_dict_items(self) -> None:
        """list of dicts with name/filename + content keys."""
        items = [
            {"name": "x.txt", "content": "aaa"},
            {"filename": "y.txt", "content": "bbb"},
        ]
        result = _result_files(items)
        assert result == [("x.txt", "aaa"), ("y.txt", "bbb")]

    def test_list_of_dict_missing_keys(self) -> None:
        """list of dicts missing required keys — skipped."""
        items = [{"name": "x.txt"}]  # no "content"
        result = _result_files(items)
        assert result == []

    def test_list_of_mixed_items(self) -> None:
        """list of tuples shorter than 2 — skipped."""
        items: list = [("only-name",)]
        result = _result_files(items)
        assert result == []

    def test_non_list_iterable_returns_empty(self) -> None:
        """Non-iterable/strangely-typed — returns empty."""
        assert _result_files(42) == []

    def test_truthy_non_list_files_returns_empty(self) -> None:
        """Object with .files that is truthy but not a list -> empty. (line 42)"""
        obj = _ns(files="this is a string, not a list")
        assert _result_files(obj) == []

    def test_list_item_tuple_longer_than_2(self) -> None:
        """Tuple with more than 2 elements — first two used."""
        items = [("a.txt", "content", "extra")]
        assert _result_files(items) == [("a.txt", "content")]

    def test_list_item_dict_name_takes_precedence(self) -> None:
        """Dict with both name and filename — name wins."""
        items = [{"name": "primary", "filename": "secondary", "content": "data"}]
        assert _result_files(items) == [("primary", "data")]


# ===========================================================================
# _result_name
# ===========================================================================


class TestResultName:
    """100% coverage of _result_name — lines 45-57."""

    def test_object_with_name(self) -> None:
        """Object with .name attr."""
        assert _result_name(_ns(name="my-source")) == "my-source"

    def test_object_with_source_name(self) -> None:
        """Object with .source_name attr (fallback)."""
        assert _result_name(_ns(source_name="fallback")) == "fallback"

    def test_object_both_empty(self) -> None:
        """Object with empty .name and .source_name — unknown."""
        assert _result_name(_ns(name="", source_name="")) == "unknown"

    def test_dict_with_name_key(self) -> None:
        """dict with 'name' key."""
        assert _result_name({"name": "dict-src"}) == "dict-src"

    def test_dict_with_source_name_key(self) -> None:
        """dict with 'source_name' key (fallback)."""
        assert _result_name({"source_name": "dict-fallback"}) == "dict-fallback"

    def test_dict_missing_keys(self) -> None:
        """dict with neither key — unknown."""
        assert _result_name({"foo": "bar"}) == "unknown"

    def test_unknown_type(self) -> None:
        """int — unknown."""
        assert _result_name(42) == "unknown"


# ===========================================================================
# _result_default_country
# ===========================================================================


class TestResultDefaultCountry:
    """100% coverage of _result_default_country — lines 60-69."""

    def test_object_with_default_country(self) -> None:
        """Object with .default_country."""
        assert _result_default_country(_ns(default_country="DE")) == "DE"

    def test_object_country_none(self) -> None:
        """Object with .default_country=None returns None."""
        assert _result_default_country(_ns(default_country=None)) is None

    def test_object_country_empty_string(self) -> None:
        """Object with .default_country='' returns None."""
        assert _result_default_country(_ns(default_country="")) is None

    def test_dict_with_default_country(self) -> None:
        """dict with 'default_country' key."""
        assert _result_default_country({"default_country": "RU"}) == "RU"

    def test_dict_missing_key(self) -> None:
        """dict without 'default_country'."""
        assert _result_default_country({"name": "x"}) is None

    def test_no_attr(self) -> None:
        """Plain object without attr."""
        assert _result_default_country(_ns(foo="bar")) is None

    def test_lowercase_gets_uppercased(self) -> None:
        """Returns uppercased version."""
        assert _result_default_country(_ns(default_country="us")) == "US"


# ===========================================================================
# LinkParser.run()
# ===========================================================================


class TestLinkParserRun:
    """Cover lines 79-92."""

    async def test_run_returns_state_with_parsed(self) -> None:
        """Happy path: parses sources and populates state.parsed."""
        lp = LinkParser(_make_context())
        result = await lp.run(
            PipelineState(
                sources=[
                    _ns(
                        list_type="blacklist",
                        files=[("sub.txt", _vless("x.com"))],
                        name="src1",
                    ),
                ],
            ),
        )
        assert "blacklist" in result.parsed
        assert len(result.parsed["blacklist"]) == 1
        assert result.parsed["blacklist"][0].address == "x.com"

    async def test_run_empty_sources(self) -> None:
        """No sources -> empty parsed."""
        lp = LinkParser(_make_context())
        result = await lp.run(PipelineState(sources=[]))
        assert result.parsed == {}


# ===========================================================================
# LinkParser.parse_all_by_list()
# ===========================================================================


class TestParseAllByList:
    """Cover parse_all_by_list — lines 94-161."""

    async def test_multiple_list_types(self) -> None:
        """Configs grouped by normalized list type."""
        lp = LinkParser(_make_context())
        black = _ns(
            list_type="blacklist",
            files=[("b.txt", _vless("b.example"))],
            name="black-src",
        )
        white = _ns(
            list_type="whitelist",
            files=[("w.txt", "trojan://pass@w.example:443")],
            name="white-src",
        )
        grouped = await lp.parse_all_by_list([black, white])
        assert set(grouped.keys()) == {"blacklist", "whitelist"}
        assert grouped["blacklist"][0].address == "b.example"
        assert grouped["whitelist"][0].address == "w.example"

    async def test_empty_content_skipped(self) -> None:
        """File with empty/whitespace content -> skipped."""
        lp = LinkParser(_make_context())
        result = _ns(
            list_type="mixed",
            files=[
                ("empty.txt", ""),
                ("spaces.txt", "   "),
                ("valid.txt", _vless("x.com")),
            ],
            name="src",
        )
        grouped = await lp.parse_all_by_list([result])
        assert len(grouped.get("mixed", [])) == 1

    async def test_no_links_found(self) -> None:
        """File with no extractable links -> skipped (debug log)."""
        lp = LinkParser(_make_context())
        result = _ns(
            list_type="mixed",
            files=[("nope.txt", "just some random text without links")],
            name="src",
        )
        grouped = await lp.parse_all_by_list([result])
        assert grouped == {}

    async def test_source_default_country_applied(self) -> None:
        """Source default_country is set on parsed configs."""
        lp = LinkParser(_make_context())
        result = _ns(
            list_type="blacklist",
            files=[("c.txt", _vless("c.example"))],
            name="src",
            default_country="RU",
        )
        grouped = await lp.parse_all_by_list([result])
        cfg = grouped["blacklist"][0]
        assert cfg.source_default_country == "RU"

    async def test_parse_one_link_returns_none(self) -> None:
        """parse_one_link returning None (bad link) -> not added."""
        lp = LinkParser(_make_context())
        result = _ns(
            list_type="mixed",
            files=[("bad.txt", "notaproxy://bad")],
            name="src",
        )
        grouped = await lp.parse_all_by_list([result])
        assert grouped == {}

    async def test_geoip_enriched(self) -> None:
        """GeoIP enrichment runs when enabled."""
        ctx = _make_context({"validator": {"geoip_enabled": True}})
        lp = LinkParser(ctx)

        async def fake_enrich(configs, api_url="http://ip-api.com/json/{ip}"):
            for c in configs:
                c.country = "DE"

        # Patch at the source module so lazy import picks it up
        with patch(
            "src.validators.geoip.enrich_configs_geoip",
            side_effect=fake_enrich,
        ):
            result = _ns(
                list_type="blacklist",
                files=[("g.txt", _vless("g.example", remark="TEST"))],
                name="src",
            )
            grouped = await lp.parse_all_by_list([result])
        assert grouped["blacklist"][0].country == "DE"

    async def test_geoip_enrichment_fails_gracefully(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """GeoIP exception is caught and logged as warning."""
        caplog.set_level(logging.WARNING)
        ctx = _make_context({"validator": {"geoip_enabled": True}})
        lp = LinkParser(ctx)

        with patch(
            "src.validators.geoip.enrich_configs_geoip",
            side_effect=RuntimeError("API down"),
        ):
            result = _ns(
                list_type="blacklist",
                files=[("g.txt", _vless("g.example"))],
                name="src",
            )
            grouped = await lp.parse_all_by_list([result])
        assert len(grouped["blacklist"]) == 1
        assert "GeoIP enrichment failed" in caplog.text

    async def test_geoip_disabled(self) -> None:
        """GeoIP enrichment does not run when disabled."""
        ctx = _make_context({"validator": {"geoip_enabled": False}})
        lp = LinkParser(ctx)
        result = _ns(
            list_type="blacklist",
            files=[("g.txt", _vless("g.example"))],
            name="src",
        )
        grouped = await lp.parse_all_by_list([result])
        assert grouped["blacklist"][0].country is None

    async def test_geoip_to_enrich_empty(self) -> None:
        """No configs to enrich — GeoIP not called when all already have country."""
        ctx = _make_context({"validator": {"geoip_enabled": True}})
        lp = LinkParser(ctx)

        result = _ns(
            list_type="whitelist",
            files=[("g.txt", _vless("g.example"))],
            name="src",
        )
        # Patch parse_one_link to return configs with country already set
        original = LinkParser.parse_one_link

        def patched_parse(link: str) -> Config | None:
            cfg = original(link)
            if cfg is not None:
                cfg.country = "DE"
            return cfg

        with patch.object(LinkParser, "parse_one_link", side_effect=patched_parse):
            grouped = await lp.parse_all_by_list([result])
        assert grouped["whitelist"][0].country == "DE"


# ===========================================================================
# LinkParser.extract_links()
# ===========================================================================


class TestExtractLinks:
    """Cover extract_links — lines 163-205."""

    async def test_subscription_extracts_links(self) -> None:
        """Subscription blob parsed by SubscriptionParser."""
        import base64

        from src.parsers.subscription import SubscriptionParser

        lp = LinkParser(_make_context())
        links = [
            _vless("x.com", remark="DE-01"),
            "trojan://pass@y.com:443",
        ]
        blob = base64.b64encode("\n".join(links).encode()).decode()
        result = await lp.extract_links(SubscriptionParser(), blob, "sub.txt", "src")
        assert len(result) == 2

    async def test_subscription_is_subscription_raises(self) -> None:
        """is_subscription raises -> treated as raw, links found."""
        lp = LinkParser(_make_context())
        sub_parser = MagicMock()
        sub_parser.is_subscription.side_effect = ValueError("boom")

        result = await lp.extract_links(sub_parser, _vless("x.com"), "f.txt", "src")
        assert len(result) == 1

    async def test_subscription_parse_falls_back(self) -> None:
        """parse_subscription raises -> falls back to find_all_links."""
        lp = LinkParser(_make_context())
        sub_parser = MagicMock()
        sub_parser.is_subscription.return_value = True
        sub_parser.parse_subscription.side_effect = RuntimeError("parse fail")

        result = await lp.extract_links(
            sub_parser,
            f"{_vless('x.com')}\ntrojan://pass@y.com:443",
            "f.txt",
            "src",
        )
        assert len(result) == 2

    async def test_not_a_subscription_falls_to_find_all_links(self) -> None:
        """Plain text -> find_all_links."""
        lp = LinkParser(_make_context())
        sub_parser = MagicMock()
        sub_parser.is_subscription.return_value = False

        result = await lp.extract_links(sub_parser, _vless("x.com"), "f.txt", "src")
        assert result == [_vless("x.com")]

    async def test_no_links_triggers_llm_fallback(self) -> None:
        """0 links from regex -> llm_fallback is tried."""
        lp = LinkParser(_make_context())
        sub_parser = MagicMock()
        sub_parser.is_subscription.return_value = False

        with patch.object(
            lp, "llm_fallback", new=AsyncMock(return_value=[_vless("x.com")])
        ):
            result = await lp.extract_links(
                sub_parser, "some long text without proxy links", "f.txt", "src"
            )
        assert result == [_vless("x.com")]

    async def test_subscription_filtered_non_string(self) -> None:
        """Non-string items in subscription result filtered out."""
        import base64

        from src.parsers.subscription import SubscriptionParser

        lp = LinkParser(_make_context())
        links = [_vless("x.com"), "trojan://pass@y.com:443"]
        blob = base64.b64encode("\n".join(links).encode()).decode()
        result = await lp.extract_links(SubscriptionParser(), blob, "sub.txt", "src")
        assert len(result) == 2
        assert all(isinstance(ln, str) for ln in result)


# ===========================================================================
# LinkParser.llm_fallback()
# ===========================================================================


class TestLlmFallback:
    """Cover llm_fallback — lines 207-261."""

    async def test_llm_disabled(self) -> None:
        """LLM not enabled in settings -> []."""
        lp = LinkParser(_make_context())
        result = await lp.llm_fallback("some text", "f.txt", "src")
        assert result == []

    async def test_no_api_key(self) -> None:
        """LLM enabled but no API key in env -> []."""
        ctx = _make_context({"llm": {"enabled": True}})
        lp = LinkParser(ctx)
        os.environ.pop("LLM_API_KEY", None)
        result = await lp.llm_fallback("some text", "f.txt", "src")
        assert result == []

    async def test_text_too_short(self) -> None:
        """Text below min_text_length -> []."""
        ctx = _make_context({"llm": {"enabled": True}})
        lp = LinkParser(ctx)
        os.environ["LLM_API_KEY"] = "test-key"
        result = await lp.llm_fallback("short", "f.txt", "src")
        assert result == []

    async def test_should_use_llm_false(self) -> None:
        """should_use_llm returns False -> []."""
        ctx = _make_context({"llm": {"enabled": True}})
        lp = LinkParser(ctx)
        os.environ["LLM_API_KEY"] = "test-key"
        with patch("src.scheduler.stages.parse.should_use_llm", return_value=False):
            result = await lp.llm_fallback("x" * 200, "f.txt", "src")
        assert result == []

    async def test_llm_extract_success(self) -> None:
        """LLM extract returns links."""
        ctx = _make_context({"llm": {"enabled": True}})
        lp = LinkParser(ctx)
        os.environ["LLM_API_KEY"] = "test-key"
        fake_llm = MagicMock()
        fake_llm.extract_links = AsyncMock(return_value=[_vless("x.com")])
        with patch(
            "src.scheduler.stages.parse.LLMFallbackParser",
            return_value=fake_llm,
        ):
            with patch(
                "src.scheduler.stages.parse.should_use_llm",
                return_value=True,
            ):
                result = await lp.llm_fallback("x" * 200, "f.txt", "src")
        assert result == [_vless("x.com")]

    async def test_llm_extract_exception(self) -> None:
        """LLM extract raises exception -> []."""
        ctx = _make_context({"llm": {"enabled": True}})
        lp = LinkParser(ctx)
        os.environ["LLM_API_KEY"] = "test-key"
        fake_llm = MagicMock()
        fake_llm.extract_links = AsyncMock(side_effect=RuntimeError("API error"))
        with patch(
            "src.scheduler.stages.parse.LLMFallbackParser",
            return_value=fake_llm,
        ):
            with patch(
                "src.scheduler.stages.parse.should_use_llm",
                return_value=True,
            ):
                result = await lp.llm_fallback("x" * 200, "f.txt", "src")
        assert result == []

    async def test_custom_api_key_env(self) -> None:
        """Uses custom api_key_env setting."""
        ctx = _make_context({"llm": {"enabled": True, "api_key_env": "MY_KEY"}})
        lp = LinkParser(ctx)
        os.environ["MY_KEY"] = "custom-key"
        result = await lp.llm_fallback("short", "f.txt", "src")
        assert result == []


# ===========================================================================
# LinkParser.parse_one_link()
# ===========================================================================


class TestParseOneLink:
    """Cover parse_one_link — lines 263-277."""

    def test_valid_vless(self) -> None:
        """Valid vless link -> Config."""
        cfg = LinkParser.parse_one_link(_vless("x.com"))
        assert cfg is not None
        assert cfg.protocol == "vless"
        assert cfg.address == "x.com"

    def test_valid_trojan(self) -> None:
        """Valid trojan link -> Config."""
        cfg = LinkParser.parse_one_link("trojan://pass@x.com:443")
        assert cfg is not None
        assert cfg.protocol == "trojan"

    def test_no_scheme_separator(self) -> None:
        """No :// found -> None."""
        assert LinkParser.parse_one_link("just-text") is None

    def test_unknown_scheme(self) -> None:
        """Unknown scheme -> None."""
        assert LinkParser.parse_one_link("unknown://x") is None

    def test_parser_exception(self) -> None:
        """Parser raises -> None."""
        from src.parsers import PARSER_BY_SCHEME

        original = PARSER_BY_SCHEME["vmess"]
        parser_mock = MagicMock()
        parser_mock.parse.side_effect = ValueError("bad data")
        PARSER_BY_SCHEME["vmess"] = parser_mock
        try:
            result = LinkParser.parse_one_link("vmess://bad")
            assert result is None
        finally:
            PARSER_BY_SCHEME["vmess"] = original

    def test_empty_link(self) -> None:
        """Empty string -> None."""
        assert LinkParser.parse_one_link("") is None

    def test_whitespace_link(self) -> None:
        """Whitespace string -> None."""
        assert LinkParser.parse_one_link("   ") is None


# ===========================================================================
# Integration: LinkParser full pipeline
# ===========================================================================


class TestLinkParserIntegration:
    """End-to-end flow through LinkParser.run()."""

    async def test_full_pipeline_with_mixed_sources(self) -> None:
        """Multiple source results with different list types."""
        lp = LinkParser(_make_context())
        sources = [
            _ns(
                list_type="blacklist",
                files=[
                    ("bl1.txt", _vless("bl1.example", remark="DE-01")),
                    ("bl2.txt", "trojan://pass@bl2.example:443"),
                ],
                name="black-src",
            ),
            _ns(
                list_type="whitelist",
                files=[("wl.txt", _vless("wl.example", remark="FI-01"))],
                name="white-src",
            ),
            _ns(
                list_type="mixed",
                files=[("mx.txt", "ss://YWVzLTI1Ni1nY206cGFzcw@mx.example:8388")],
                name="mixed-src",
            ),
        ]
        state = await lp.run(PipelineState(sources=sources))
        assert "blacklist" in state.parsed
        assert "whitelist" in state.parsed
        assert "mixed" in state.parsed
        assert len(state.parsed["blacklist"]) == 2
        assert len(state.parsed["whitelist"]) == 1
        assert len(state.parsed["mixed"]) == 1

    async def test_invalid_list_type_falls_to_mixed(self) -> None:
        """Unknown list_type -> mixed group."""
        lp = LinkParser(_make_context())
        result = _ns(
            list_type="invalid-type",
            files=[("f.txt", _vless("x.com"))],
            name="src",
        )
        grouped = await lp.parse_all_by_list([result])
        assert "mixed" in grouped
        assert len(grouped["mixed"]) == 1
