"""Tests for src/parsers/llm_fallback.py — LLM fallback parser.

Uses inline _FakeResp / _FakeAsyncClient and monkeypatch to avoid real HTTP
calls.  All tests are async (asyncio_mode=auto).
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from src.parsers.llm_fallback import (
    _MAX_INPUT_CHARS,
    LLMFallbackParser,
    should_use_llm,
)

# ---------------------------------------------------------------------------
# should_use_llm
# ---------------------------------------------------------------------------


def test_should_use_llm_true_when_no_regex_results_and_text_long_enough() -> None:
    assert should_use_llm("a" * 100, regex_results=[]) is True


def test_should_use_llm_false_when_regex_found_results() -> None:
    assert should_use_llm("a" * 100, regex_results=["vmess://abc"]) is False


def test_should_use_llm_false_when_text_too_short() -> None:
    assert should_use_llm("short", regex_results=[]) is False


def test_should_use_llm_respects_min_text_length() -> None:
    assert should_use_llm("a" * 50, regex_results=[], min_text_length=50) is True
    assert should_use_llm("a" * 49, regex_results=[], min_text_length=50) is False


def test_should_use_llm_strips_whitespace_for_length() -> None:
    # Only non-whitespace chars count: 50 spaces + 50 'a's -> strip gives 50
    text = (" " * 50) + ("a" * 50)
    assert should_use_llm(text, regex_results=[], min_text_length=100) is False
    assert should_use_llm("a" * 100, regex_results=[], min_text_length=100) is True


# ---------------------------------------------------------------------------
# extract_links — empty / boundary input
# ---------------------------------------------------------------------------


async def test_extract_links_returns_empty_on_empty_input() -> None:
    parser = LLMFallbackParser(api_key="test-key")
    assert await parser.extract_links("") == []
    assert await parser.extract_links("   ") == []


async def test_extract_limits_input_to_max_chars(monkeypatch) -> None:
    """Input text is truncated to _MAX_INPUT_CHARS before being sent."""
    called_with: list[str] = []

    async def fake_call_api(self, body: dict[str, Any]) -> str:
        called_with.append(body["messages"][1]["content"])
        return "vmess://abc\nvless://def\n"

    monkeypatch.setattr(LLMFallbackParser, "_call_api", fake_call_api)

    long_text = "x" * (_MAX_INPUT_CHARS + 5000)
    parser = LLMFallbackParser(api_key="test-key")
    result = await parser.extract_links(long_text)

    assert len(called_with) == 1
    # The text inside <data> tags should be truncated
    data_content = called_with[0]
    # The text inside <data> tags was truncated
    assert len(data_content) < (_MAX_INPUT_CHARS + 5000)


# ---------------------------------------------------------------------------
# extract_links — successful LLM response parsing
# ---------------------------------------------------------------------------


async def test_extract_links_parses_successful_llm_response(monkeypatch) -> None:
    """Happy path: LLM returns raw proxy links, they get validated."""

    async def fake_call_api(self, body: dict[str, Any]) -> str:
        return (
            "vmess://eyJ2IjoiMiIsInBzIjoiREUtMDEiLCJhZGQiOiJkZS5leGFtcGxlLmNvbSIsInBvcnQiOiA0NDMsICJpZCI6ICIxMTExMTExMS0xMTExLTQxMTEtODExMS0xMTExMTExMTExMTEifQ==\n"
            "trojan://secret@example.com:443\n"
            "vless://11111111-1111-4111-8111-111111111111@example.com:443\n"
        )

    monkeypatch.setattr(LLMFallbackParser, "_call_api", fake_call_api)

    parser = LLMFallbackParser(api_key="test-key")
    result = await parser.extract_links("some long messy text with proxy data")

    assert len(result) >= 1
    # All returned links should be valid proxy links
    for link in result:
        assert link.startswith(("vmess://", "vless://", "trojan://"))


async def test_extract_links_filters_hallucinated_urls(monkeypatch) -> None:
    """Non-proxy URLs returned by the LLM should be filtered out."""

    async def fake_call_api(self, body: dict[str, Any]) -> str:
        return (
            "vmess://eyJ2IjoiMiIsInBzIjoiREUtMDEiLCJhZGQiOiJkZS5leGFtcGxlLmNvbSIsInBvcnQiOiA0NDMsICJpZCI6ICIxMTExMTExMS0xMTExLTQxMTEtODExMS0xMTExMTExMTExMTEifQ==\n"
            "https://example.com\n"
            "not-a-link\n"
        )

    monkeypatch.setattr(LLMFallbackParser, "_call_api", fake_call_api)

    parser = LLMFallbackParser(api_key="test-key")
    result = await parser.extract_links("some text")

    assert len(result) == 1
    assert result[0].startswith("vmess://")


async def test_extract_links_deduplicates(monkeypatch) -> None:
    """Duplicate links from the LLM response should be deduplicated."""

    async def fake_call_api(self, body: dict[str, Any]) -> str:
        link = "vmess://eyJ2IjoiMiIsInBzIjoiREUtMDEiLCJhZGQiOiJkZS5leGFtcGxlLmNvbSIsInBvcnQiOiA0NDMsICJpZCI6ICIxMTExMTExMS0xMTExLTQxMTEtODExMS0xMTExMTExMTExMTEifQ=="
        return f"{link}\n{link}\n"

    monkeypatch.setattr(LLMFallbackParser, "_call_api", fake_call_api)

    parser = LLMFallbackParser(api_key="test-key")
    result = await parser.extract_links("some text")

    assert len(result) == 1


# ---------------------------------------------------------------------------
# _call_api — mock httpx directly
# ---------------------------------------------------------------------------


class _FakeResp:
    """Simulates httpx.Response for _call_api tests."""

    def __init__(
        self,
        status_code: int = 200,
        json_data: object | None = None,
        text: str = "",
    ) -> None:
        self.status_code = status_code
        self._json = json_data
        self.text = text

    def json(self) -> object:
        if self._json is None:
            raise ValueError("no json")
        return self._json


class _FakeAsyncClient:
    """Replaces httpx.AsyncClient used inside LLMFallbackParser._call_api."""

    def __init__(self, resp: _FakeResp) -> None:
        self._resp = resp

    async def __aenter__(self) -> _FakeAsyncClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    async def post(self, url: str, **kwargs: object) -> _FakeResp:
        return self._resp


def _patch_llm_httpx(monkeypatch, resp: _FakeResp) -> None:
    """Replace httpx.AsyncClient used by LLMFallbackParser._call_api."""
    monkeypatch.setattr(
        "src.parsers.llm_fallback.httpx.AsyncClient",
        lambda *a, **kw: _FakeAsyncClient(resp),
    )


async def test_call_api_successful_response(monkeypatch) -> None:
    """200 with valid JSON choices[0].message.content returns the content."""
    payload = {"choices": [{"message": {"content": "vmess://abc\ntrojan://def\n"}}]}
    _patch_llm_httpx(monkeypatch, _FakeResp(200, json_data=payload))

    parser = LLMFallbackParser(api_key="test-key")
    body = parser._build_chat_request("system", "user data", max_tokens=100)
    result = await parser._call_api(body)

    assert result == "vmess://abc\ntrojan://def\n"


async def test_call_api_handles_keyerror_in_response(monkeypatch) -> None:
    """Missing 'choices' key should be caught and return ''."""
    payload = {"choices": [{"message": {}}]}  # missing 'content'
    _patch_llm_httpx(monkeypatch, _FakeResp(200, json_data=payload))

    parser = LLMFallbackParser(api_key="test-key")
    result = await parser._call_api(parser._build_chat_request("s", "u"))

    assert result == ""


async def test_call_api_handles_missing_choices(monkeypatch) -> None:
    """Response with no 'choices' key should return ''."""
    payload: dict[str, list[Any]] = {}
    _patch_llm_httpx(monkeypatch, _FakeResp(200, json_data=payload))

    parser = LLMFallbackParser(api_key="test-key")
    result = await parser._call_api(parser._build_chat_request("s", "u"))

    assert result == ""


async def test_call_api_handles_valueerror_non_json(monkeypatch) -> None:
    """Non-JSON response body should be caught and return ''."""
    _patch_llm_httpx(monkeypatch, _FakeResp(200, json_data=None))

    parser = LLMFallbackParser(api_key="test-key")
    result = await parser._call_api(parser._build_chat_request("s", "u"))

    assert result == ""


async def test_call_api_handles_401_auth_error(monkeypatch) -> None:
    """401 should return '' immediately without retry."""
    _patch_llm_httpx(monkeypatch, _FakeResp(401, text="Unauthorized"))

    parser = LLMFallbackParser(api_key="test-key")
    result = await parser._call_api(parser._build_chat_request("s", "u"))

    assert result == ""


async def test_call_api_handles_429_rate_limit_then_succeeds(monkeypatch) -> None:
    """429 should retry; a subsequent success should return the content."""
    call_count: list[int] = [0]

    class _FakeClientRetry:
        async def __aenter__(self) -> _FakeClientRetry:
            return self

        async def __aexit__(self, *exc: object) -> None:
            return None

        async def post(self, url: str, **kwargs: object) -> _FakeResp:
            call_count[0] += 1
            if call_count[0] == 1:
                return _FakeResp(429, text="rate limited")
            payload = {"choices": [{"message": {"content": "vmess://success\n"}}]}
            return _FakeResp(200, json_data=payload)

    monkeypatch.setattr(
        "src.parsers.llm_fallback.httpx.AsyncClient",
        lambda *a, **kw: _FakeClientRetry(),
    )

    async def fake_sleep(_seconds: float) -> None:
        pass

    monkeypatch.setattr("src.parsers.llm_fallback.asyncio.sleep", fake_sleep)

    parser = LLMFallbackParser(api_key="test-key")
    result = await parser._call_api(parser._build_chat_request("s", "u"))

    assert result == "vmess://success\n"
    assert call_count[0] == 2


async def test_call_api_no_api_key_returns_empty(monkeypatch) -> None:
    """Without an API key, _call_api returns '' immediately."""
    parser = LLMFallbackParser(api_key="")
    result = await parser._call_api({"model": "test"})

    assert result == ""


async def test_call_api_retries_on_server_error(monkeypatch) -> None:
    """5xx errors should be retried, then return '' after exhausting retries."""
    call_count: list[int] = [0]

    class _FakeClient5xx:
        async def __aenter__(self) -> _FakeClient5xx:
            return self

        async def __aexit__(self, *exc: object) -> None:
            return None

        async def post(self, url: str, **kwargs: object) -> _FakeResp:
            call_count[0] += 1
            return _FakeResp(503, text="Service Unavailable")

    monkeypatch.setattr(
        "src.parsers.llm_fallback.httpx.AsyncClient",
        lambda *a, **kw: _FakeClient5xx(),
    )

    sleeps: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    monkeypatch.setattr("src.parsers.llm_fallback.asyncio.sleep", fake_sleep)

    parser = LLMFallbackParser(api_key="test-key")
    result = await parser._call_api(parser._build_chat_request("s", "u"))

    assert result == ""
    assert call_count[0] == 3  # _MAX_RETRIES
    assert len(sleeps) == 2  # exponential backoff: 1, 2


async def test_call_api_handles_timeout(monkeypatch) -> None:
    """Timeout should retry then return '' after exhausting retries."""
    call_count: list[int] = [0]

    class _FakeClientTimeout:
        async def __aenter__(self) -> _FakeClientTimeout:
            return self

        async def __aexit__(self, *exc: object) -> None:
            return None

        async def post(self, url: str, **kwargs: object) -> _FakeResp:
            call_count[0] += 1
            raise httpx.TimeoutException("timeout")

    monkeypatch.setattr(
        "src.parsers.llm_fallback.httpx.AsyncClient",
        lambda *a, **kw: _FakeClientTimeout(),
    )

    sleeps: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    monkeypatch.setattr("src.parsers.llm_fallback.asyncio.sleep", fake_sleep)

    parser = LLMFallbackParser(api_key="test-key")
    result = await parser._call_api(parser._build_chat_request("s", "u"))

    assert result == ""
    assert call_count[0] == 3
    assert len(sleeps) == 2


# ---------------------------------------------------------------------------
# normalize_remark
# ---------------------------------------------------------------------------


async def test_normalize_remark_strips_backticks(monkeypatch) -> None:
    """LLM response with backticks should be cleaned."""

    async def fake_call_api(self, body: dict[str, Any]) -> str:
        return "`US-01`"

    monkeypatch.setattr(LLMFallbackParser, "_call_api", fake_call_api)

    parser = LLMFallbackParser(api_key="test-key")
    result = await parser.normalize_remark("🇺🇸 USA-01 | 1.2x | Reality | @vpnseller")

    assert result == "US-01"


async def test_normalize_remark_returns_original_on_empty_api(monkeypatch) -> None:
    async def fake_call_api(self, body: dict[str, Any]) -> str:
        return ""

    monkeypatch.setattr(LLMFallbackParser, "_call_api", fake_call_api)

    parser = LLMFallbackParser(api_key="test-key")
    result = await parser.normalize_remark("US-01")

    assert result == "US-01"


async def test_normalize_remark_empty_input() -> None:
    parser = LLMFallbackParser(api_key="test-key")
    assert await parser.normalize_remark("") == ""
    assert await parser.normalize_remark("   ") == "   "


# ---------------------------------------------------------------------------
# categorize
# ---------------------------------------------------------------------------


async def test_categorize_returns_standard_on_unexpected_response(monkeypatch) -> None:
    async def fake_call_api(self, body: dict[str, Any]) -> str:
        return "unknown_category"

    monkeypatch.setattr(LLMFallbackParser, "_call_api", fake_call_api)

    parser = LLMFallbackParser(api_key="test-key")
    result = await parser.categorize("some remark")

    assert result == "standard"


async def test_categorize_returns_valid_category(monkeypatch) -> None:
    async def fake_call_api(self, body: dict[str, Any]) -> str:
        return "gaming"

    monkeypatch.setattr(LLMFallbackParser, "_call_api", fake_call_api)

    parser = LLMFallbackParser(api_key="test-key")
    result = await parser.categorize("game-server-01")

    assert result == "gaming"


async def test_categorize_returns_standard_on_empty_api(monkeypatch) -> None:
    async def fake_call_api(self, body: dict[str, Any]) -> str:
        return ""

    monkeypatch.setattr(LLMFallbackParser, "_call_api", fake_call_api)

    parser = LLMFallbackParser(api_key="test-key")
    result = await parser.categorize("some server")

    assert result == "standard"


# ---------------------------------------------------------------------------
# _build_chat_request
# ---------------------------------------------------------------------------


def test_build_chat_request_structure() -> None:
    parser = LLMFallbackParser(api_key="test-key", model="test-model", max_tokens=500)
    body = parser._build_chat_request("sys prompt", "user msg", max_tokens=100)

    assert body["model"] == "test-model"
    assert body["messages"][0]["role"] == "system"
    assert body["messages"][0]["content"] == "sys prompt"
    assert body["messages"][1]["role"] == "user"
    assert body["messages"][1]["content"] == "user msg"
    assert body["temperature"] == 0.1
    assert body["max_tokens"] == 100


def test_build_chat_request_uses_default_max_tokens() -> None:
    parser = LLMFallbackParser(api_key="test-key", max_tokens=500)
    body = parser._build_chat_request("sys", "user")

    assert body["max_tokens"] == 500


# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------


def test_parser_init_uses_provider_url_map() -> None:
    parser = LLMFallbackParser(provider="groq", api_key="k")
    assert "api.groq.com" in parser.api_base

    parser2 = LLMFallbackParser(provider="openrouter", api_key="k")
    assert "openrouter.ai" in parser2.api_base


def test_parser_init_falls_back_to_groq_for_unknown_provider() -> None:
    parser = LLMFallbackParser(provider="unknown", api_key="k")
    assert "api.groq.com" in parser.api_base


def test_parser_init_custom_api_base_overrides_provider() -> None:
    parser = LLMFallbackParser(
        provider="groq", api_key="k", api_base="https://custom.example.com/v1"
    )
    assert parser.api_base == "https://custom.example.com/v1"


# ---------------------------------------------------------------------------
# extract_links — empty API response (lines 182-183)
# ---------------------------------------------------------------------------


async def test_extract_links_returns_empty_on_empty_api_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When _call_api returns empty string, extract_links returns []."""

    async def fake_call_api(
        self: object,
        body: dict[str, object],
    ) -> str:
        return ""

    monkeypatch.setattr(LLMFallbackParser, "_call_api", fake_call_api)

    parser = LLMFallbackParser(api_key="test-key")
    result = await parser.extract_links("some long text worth processing")
    assert result == []


# ---------------------------------------------------------------------------
# extract_links — skip empty/backtick lines (line 189)
# ---------------------------------------------------------------------------


async def test_extract_links_skips_empty_and_backtick_lines(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Empty lines, whitespace-only lines, and standalone backticks are skipped."""

    async def fake_call_api(
        self: object,
        body: dict[str, object],
    ) -> str:
        return (
            "vmess://eyJ2IjoiMiIsInBzIjoiREUtMDEiLCJhZGQiOiJkZS5leGFtcGxlLmNvbSIsInBvcnQiOiA0NDMsICJpZCI6ICIxMTExMTExMS0xMTExLTQxMTEtODExMS0xMTExMTExMTExMTEifQ==\n"
            "\n"
            "   \n"
            "```\n"
            "vless://11111111-1111-4111-8111-111111111111@example.com:443\n"
        )

    monkeypatch.setattr(LLMFallbackParser, "_call_api", fake_call_api)

    parser = LLMFallbackParser(api_key="test-key")
    result = await parser.extract_links("some text")
    # Two valid links should be found, empty/backtick lines skipped
    assert len(result) == 2
    assert result[0].startswith("vmess://")
    assert result[1].startswith("vless://")


# ---------------------------------------------------------------------------
# _call_api — openrouter sets referer header  (lines 346-347)
# ---------------------------------------------------------------------------


async def test_call_api_openrouter_sets_referer_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """openrouter provider should set HTTP-Referer and X-Title headers."""
    captured_headers: dict[str, str] = {}

    class _FakeClientCaptureHeaders:
        async def __aenter__(self) -> _FakeClientCaptureHeaders:
            return self

        async def __aexit__(self, *exc: object) -> None:
            return None

        async def post(
            self,
            url: str,
            **kwargs: object,
        ) -> _FakeResp:
            captured_headers.clear()
            captured_headers.update(
                kwargs.get("headers", {}),  # type: ignore[arg-type]
            )
            payload = {"choices": [{"message": {"content": "result"}}]}
            return _FakeResp(200, json_data=payload)

    monkeypatch.setattr(
        "src.parsers.llm_fallback.httpx.AsyncClient",
        lambda *a, **kw: _FakeClientCaptureHeaders(),
    )

    parser = LLMFallbackParser(provider="openrouter", api_key="test-key")
    result = await parser._call_api(parser._build_chat_request("s", "u"))

    assert result == "result"
    assert (
        captured_headers.get("HTTP-Referer") == "https://github.com/vpn-config-parser"
    )
    assert captured_headers.get("X-Title") == "vpn-config-parser"


# ---------------------------------------------------------------------------
# _call_api — httpx.HTTPError (lines 366-368)
# ---------------------------------------------------------------------------


async def test_call_api_handles_generic_http_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Generic httpx.HTTPError should retry then return ''."""
    call_count: list[int] = [0]

    class _FakeClientHTTPError:
        async def __aenter__(self) -> _FakeClientHTTPError:
            return self

        async def __aexit__(self, *exc: object) -> None:
            return None

        async def post(
            self,
            url: str,
            **kwargs: object,
        ) -> _FakeResp:
            call_count[0] += 1
            raise httpx.HTTPError("connection error")

    monkeypatch.setattr(
        "src.parsers.llm_fallback.httpx.AsyncClient",
        lambda *a, **kw: _FakeClientHTTPError(),
    )

    sleeps: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    monkeypatch.setattr("src.parsers.llm_fallback.asyncio.sleep", fake_sleep)

    parser = LLMFallbackParser(api_key="test-key")
    result = await parser._call_api(parser._build_chat_request("s", "u"))

    assert result == ""
    assert call_count[0] == 3
    assert len(sleeps) == 2  # exponential backoff


# ---------------------------------------------------------------------------
# _call_api — 4xx client error (lines 399-404)
# ---------------------------------------------------------------------------


async def test_call_api_handles_400_client_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """400 client error should return '' immediately without retry."""
    call_count: list[int] = [0]

    class _FakeClient400:
        async def __aenter__(self) -> _FakeClient400:
            return self

        async def __aexit__(self, *exc: object) -> None:
            return None

        async def post(
            self,
            url: str,
            **kwargs: object,
        ) -> _FakeResp:
            call_count[0] += 1
            return _FakeResp(400, text="Bad Request")

    monkeypatch.setattr(
        "src.parsers.llm_fallback.httpx.AsyncClient",
        lambda *a, **kw: _FakeClient400(),
    )

    parser = LLMFallbackParser(api_key="test-key")
    result = await parser._call_api(parser._build_chat_request("s", "u"))

    assert result == ""
    assert call_count[0] == 1  # no retry
