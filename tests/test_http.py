"""Tests for the shared HTTP body-reading helper (src.utils.http)."""

from __future__ import annotations

from collections.abc import AsyncIterator

from src.utils.http import read_limited_text


class _FakeResponse:
    """Minimal streaming response: chunked body plus a fixed encoding."""

    def __init__(self, chunks: list[bytes], encoding: str | None) -> None:
        self._chunks = chunks
        self.encoding = encoding

    async def aiter_bytes(self) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            yield chunk


async def test_read_limited_text_decodes_within_budget() -> None:
    response = _FakeResponse([b"hel", b"lo"], encoding=None)
    assert await read_limited_text(response, max_bytes=100) == "hello"


async def test_read_limited_text_returns_none_over_budget() -> None:
    """The read stops as soon as the budget is crossed, not after the body."""
    response = _FakeResponse([b"abc", b"def"], encoding="utf-8")
    assert await read_limited_text(response, max_bytes=4) is None


async def test_read_limited_text_unknown_encoding_falls_back_to_utf8() -> None:
    """A bogus codec name from the response headers must not lose the body."""
    response = _FakeResponse(["héllo".encode()], encoding="not-a-codec")
    assert await read_limited_text(response, max_bytes=100) == "héllo"
