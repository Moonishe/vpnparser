"""Tests for src.sources.github — 100% coverage target."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import logging
import time as _time
from email.utils import formatdate
from unittest import mock

import httpx
import pytest

from src.sources.github import (
    _SERVER_ERROR_RETRY_DELAY,
    GitHubClient,
    GitHubRateLimitError,
    _clean_repo_path,
    _contents_url,
    _quote_path,
    _raw_url,
)

# ---------------------------------------------------------------------------
# Helper: a reusable FakeResponse / FakeClient pair
# ---------------------------------------------------------------------------


class _FakeResponse:
    """Simulates an httpx.Response."""

    def __init__(
        self,
        status_code: int = 200,
        *,
        json_data: object = None,
        text_data: str = "",
        headers: dict[str, str] | None = None,
        encoding: str = "utf-8",
    ):
        self.status_code = status_code
        self._json_data = json_data
        self.text = text_data
        self.headers = headers or {}
        self.encoding = encoding

    async def aiter_bytes(self, chunk_size: int = 4):
        """Yield the body in small chunks, as a streamed response would.

        Chunking matters: the reader enforces its byte budget per chunk, so a
        single-chunk fake would not exercise the early bail-out.
        """
        payload = self.text.encode(self.encoding or "utf-8")
        for start in range(0, len(payload), chunk_size):
            yield payload[start : start + chunk_size]

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                f"{self.status_code} error",
                request=mock.MagicMock(),
                response=self,
            )

    def json(self) -> object:
        return self._json_data


class _FakeClient:
    """Mimics httpx.AsyncClient for use as _get_client() return value."""

    def __init__(self, responses: list[_FakeResponse] | None = None):
        self._responses = iter(responses or [_FakeResponse(json_data={})])
        self._call_count = 0
        self._last_url = None
        self._last_params = None

    async def request(self, method: str, url: str, **kwargs) -> _FakeResponse:
        self._call_count += 1
        self._last_url = url
        self._last_params = kwargs.get("params")
        resp = next(self._responses)
        return resp


def _raw_client(handler, requested: list[str] | None = None):
    """Build an httpx.AsyncClient stand-in whose get()/stream() call *handler*.

    ``handler(url)`` returns the :class:`_FakeResponse` to serve, or raises to
    simulate a transport error. Raw downloads use ``stream()`` so the body is
    never buffered whole; ``get()`` stays for the JSON API paths.
    """

    class _StreamContext:
        def __init__(self, url):
            self._url = url

        async def __aenter__(self):
            return handler(self._url)

        async def __aexit__(self, *args):
            return None

    class _Client:
        def __init__(self, *args, **kwargs):
            self.kwargs = kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def get(self, url, **kwargs):
            if requested is not None:
                requested.append(url)
            return handler(url)

        def stream(self, method, url, **kwargs):
            if requested is not None:
                requested.append(url)
            return _StreamContext(url)

    return _Client


# ===================================================================
# _clean_repo_path / _quote_path / _contents_url / _raw_url
# ===================================================================


class TestPathHelpers:
    def test_clean_repo_path_normalizes(self) -> None:
        assert _clean_repo_path("  dir/subdir  ") == "dir/subdir"
        assert _clean_repo_path("") == ""
        assert _clean_repo_path(None) == ""
        assert _clean_repo_path("  ") == ""
        assert _clean_repo_path("a/b/c") == "a/b/c"
        assert _clean_repo_path("a\\b") == "a/b"

    def test_clean_repo_path_rejects_dotdots(self) -> None:
        with pytest.raises(ValueError, match="unsafe repository path"):
            _clean_repo_path("../secret")
        with pytest.raises(ValueError, match="unsafe repository path"):
            _clean_repo_path("a/../b")
        with pytest.raises(ValueError, match="unsafe repository path"):
            _clean_repo_path(".")

    def test_quote_path_encodes_special_chars(self) -> None:
        assert _quote_path("dir/file+name.txt") == "dir/file%2Bname.txt"
        assert _quote_path("") == ""
        assert _quote_path("simple.txt") == "simple.txt"
        assert _quote_path("a b/c d") == "a%20b/c%20d"

    def test_quote_path_rejects_unsafe(self) -> None:
        with pytest.raises(ValueError):
            _quote_path("../secret")

    def test_contents_url_basic(self) -> None:
        assert _contents_url("owner", "repo", "") == "/repos/owner/repo/contents"
        assert _contents_url("owner", "repo", "file.txt") == (
            "/repos/owner/repo/contents/file.txt"
        )

    def test_contents_url_special_chars(self) -> None:
        url = _contents_url("owner", "repo", "dir/file+name.txt")
        assert url == "/repos/owner/repo/contents/dir/file%2Bname.txt"
        assert "+" not in url  # must be encoded

    def test_contents_url_strips_whitespace(self) -> None:
        url = _contents_url("  owner ", " repo ", "  path ")
        assert url == "/repos/owner/repo/contents/path"

    def test_contents_url_rejects_unsafe_path(self) -> None:
        with pytest.raises(ValueError):
            _contents_url("owner", "repo", "../secret")

    def test_raw_url_basic(self) -> None:
        url = _raw_url("owner", "repo", "main", "file.txt")
        assert url == "https://raw.githubusercontent.com/owner/repo/main/file.txt"

    def test_raw_url_special_chars(self) -> None:
        url = _raw_url("owner", "repo", "main", "dir/f+name.txt")
        assert url == (
            "https://raw.githubusercontent.com/owner/repo/main/dir/f%2Bname.txt"
        )
        assert "+" not in url

    def test_raw_url_strips_whitespace(self) -> None:
        url = _raw_url("  Owner ", " Repo ", " Feat ", " sub/file.txt ")
        assert url.startswith("https://raw.githubusercontent.com/")

    def test_raw_url_keeps_branch_slash(self) -> None:
        """A branch named ``feature/test`` keeps its slash in the raw URL.

        The raw host does not decode %2F in the ref position, so a
        percent-encoded slash made every file of such a branch 404.
        """
        url = _raw_url("owner", "repo", "feature/test", "dir/file.txt")
        assert "/owner/repo/feature/test/dir/file.txt" in url
        assert "%2F" not in url


# ===================================================================
# GitHubClient — __init__ / _headers / lifecycle
# ===================================================================


class TestInitAndHeaders:
    def test_init_without_token(self) -> None:
        client = GitHubClient()
        assert client.token is None
        assert client.api_base == "https://api.github.com"
        assert client._client is None

    def test_init_with_token(self) -> None:
        client = GitHubClient(token="ghp_secret")
        assert client.token == "ghp_secret"

    def test_init_custom_api_base(self) -> None:
        client = GitHubClient(api_base="https://internal.github.com/")
        assert client.api_base == "https://internal.github.com"

    def test_init_timeout_and_concurrency(self) -> None:
        client = GitHubClient(timeout=15.0, max_concurrent_api=5)
        assert client._timeout == 15.0
        assert client._api_semaphore._value == 5

    def test_headers_without_token(self) -> None:
        client = GitHubClient()
        headers = client._headers()
        assert headers["User-Agent"] == "vpn-config-parser/1.0"
        assert "Authorization" not in headers

    def test_headers_with_token(self) -> None:
        client = GitHubClient(token="ghp_secret")
        headers = client._headers()
        assert headers["Authorization"] == "Bearer ghp_secret"

    def test_raw_headers_never_authorization(self) -> None:
        client = GitHubClient(token="ghp_secret")
        headers = client._raw_headers()
        assert "Authorization" not in headers
        assert headers["Accept"] == "text/plain,*/*"

    def test_get_client_lazy_creation(self, monkeypatch) -> None:
        async def _public(_url: str, *, timeout: float = 5.0) -> bool:
            return True

        monkeypatch.setattr("src.sources.github.is_safe_public_url", _public)
        client = GitHubClient()
        assert client._client is None

        c = asyncio.run(client._get_client())
        assert c is not None
        assert client._client is c
        # second call returns same instance
        assert asyncio.run(client._get_client()) is c

    def test_get_client_concurrent_safety(self, monkeypatch) -> None:
        async def _public(_url: str, *, timeout: float = 5.0) -> bool:
            return True

        monkeypatch.setattr("src.sources.github.is_safe_public_url", _public)
        client = GitHubClient()
        results = []

        async def get():
            c = await client._get_client()
            results.append(c)

        async def run():
            await asyncio.gather(get(), get(), get())

        asyncio.run(run())
        # All coros got the same client instance
        assert len(set(id(r) for r in results)) == 1

    def test_aclose(self, monkeypatch) -> None:
        async def _public(_url: str, *, timeout: float = 5.0) -> bool:
            return True

        monkeypatch.setattr("src.sources.github.is_safe_public_url", _public)
        client = GitHubClient()
        c = asyncio.run(client._get_client())
        assert client._client is c

        asyncio.run(client.aclose())
        assert client._client is None

    def test_aclose_idempotent(self) -> None:
        client = GitHubClient()
        # no client yet, must not crash
        asyncio.run(client.aclose())

    def test_async_context_manager(self, monkeypatch) -> None:
        async def _public(_url: str, *, timeout: float = 5.0) -> bool:
            return True

        monkeypatch.setattr("src.sources.github.is_safe_public_url", _public)

        async def test():
            async with GitHubClient() as client:
                assert client._client is not None
            # After exit, client is closed
            assert client._client is None

        asyncio.run(test())

    def test_request_calls_get_client(self, monkeypatch) -> None:
        client = GitHubClient()
        fake_resp = _FakeResponse(json_data={"name": "test"})
        fake_client = _FakeClient([fake_resp])

        async def fake_get_client():
            return fake_client

        monkeypatch.setattr(client, "_get_client", fake_get_client)

        result = asyncio.run(client._request("GET", "/repos/o/r/contents/f"))
        assert result == {"name": "test"}

    def test_get_client_rejects_non_https_api_base(self, monkeypatch) -> None:
        """http api_base must be rejected before any request is issued."""

        async def _public(_url: str, *, timeout: float = 5.0) -> bool:
            return True

        monkeypatch.setattr("src.sources.github.is_safe_public_url", _public)
        client = GitHubClient(api_base="http://example.com")
        with pytest.raises(ValueError, match="must use https"):
            asyncio.run(client._get_client())

    def test_get_client_rejects_non_public_api_base(self, monkeypatch) -> None:
        """An internal/loopback api_base must never receive the bearer token."""

        async def _unsafe(_url: str, *, timeout: float = 5.0) -> bool:
            return False

        monkeypatch.setattr("src.sources.github.is_safe_public_url", _unsafe)
        client = GitHubClient(api_base="https://127.0.0.1:8080")
        with pytest.raises(ValueError, match="non-public"):
            asyncio.run(client._get_client())

    def test_get_client_accepts_public_https_api_base(self, monkeypatch) -> None:
        """A verified public https api_base builds the client normally."""

        async def _public(_url: str, *, timeout: float = 5.0) -> bool:
            return True

        monkeypatch.setattr("src.sources.github.is_safe_public_url", _public)
        client = GitHubClient(api_base="https://api.github.com")
        c = asyncio.run(client._get_client())
        assert c is not None
        assert client._api_base_checked is True


# ===================================================================
# Helper: patch _get_client with an async factory
# ===================================================================


def _patch_get_client(client: GitHubClient, monkeypatch, fc: _FakeClient):
    async def fake_get_client():
        return fc

    monkeypatch.setattr(client, "_get_client", fake_get_client)


# ===================================================================
# GitHubClient._request — success paths
# ===================================================================


class TestRequestSuccess:
    def test_request_returns_json_dict(self, monkeypatch) -> None:
        client = GitHubClient()
        fc = _FakeClient([_FakeResponse(json_data={"key": "val"})])
        _patch_get_client(client, monkeypatch, fc)
        result = asyncio.run(client._request("GET", "/url"))
        assert result == {"key": "val"}

    def test_request_returns_json_list(self, monkeypatch) -> None:
        client = GitHubClient()
        fc = _FakeClient([_FakeResponse(json_data=[1, 2, 3])])
        _patch_get_client(client, monkeypatch, fc)
        result = asyncio.run(client._request("GET", "/url"))
        assert result == [1, 2, 3]

    def test_request_returns_raw_text(self, monkeypatch) -> None:
        client = GitHubClient()
        fc = _FakeClient([_FakeResponse(text_data="raw text")])
        _patch_get_client(client, monkeypatch, fc)
        result = asyncio.run(client._request("GET", "/url", parse_json=False))
        assert result == "raw text"

    def test_request_404_returns_empty_list(self, monkeypatch) -> None:
        client = GitHubClient()
        fc = _FakeClient([_FakeResponse(status_code=404)])
        _patch_get_client(client, monkeypatch, fc)
        result = asyncio.run(client._request("GET", "/url"))
        assert result == []

    def test_request_404_returns_empty_string(self, monkeypatch) -> None:
        client = GitHubClient()
        fc = _FakeClient([_FakeResponse(status_code=404)])
        _patch_get_client(client, monkeypatch, fc)
        result = asyncio.run(client._request("GET", "/url", parse_json=False))
        assert result == ""

    def test_request_raises_on_http_error(self, monkeypatch) -> None:
        client = GitHubClient()
        fc = _FakeClient([_FakeResponse(status_code=500)])
        _patch_get_client(client, monkeypatch, fc)
        with pytest.raises(httpx.HTTPStatusError):
            asyncio.run(client._request("GET", "/url"))


# ===================================================================
# GitHubClient._request — rate limit handling
# ===================================================================


class TestRequestRateLimit:
    def test_403_rate_limit_retry_success(self, monkeypatch) -> None:
        client = GitHubClient()
        reset_ts = str(int(_time.time()) + 10)
        fc = _FakeClient(
            [
                _FakeResponse(
                    status_code=403,
                    headers={
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": reset_ts,
                    },
                ),
                _FakeResponse(json_data={"ok": True}),
            ]
        )
        _patch_get_client(client, monkeypatch, fc)
        sleeps = []

        async def fake_sleep(secs):
            sleeps.append(secs)

        monkeypatch.setattr("src.sources.github.asyncio.sleep", fake_sleep)

        result = asyncio.run(client._request("GET", "/url"))
        assert result == {"ok": True}
        assert len(sleeps) == 1

    def test_403_retry_after_success(self, monkeypatch) -> None:
        client = GitHubClient()
        fc = _FakeClient(
            [
                _FakeResponse(status_code=403, headers={"Retry-After": "5"}),
                _FakeResponse(json_data={"ok": True}),
            ]
        )
        _patch_get_client(client, monkeypatch, fc)
        sleeps = []

        async def fake_sleep(secs):
            sleeps.append(secs)

        monkeypatch.setattr("src.sources.github.asyncio.sleep", fake_sleep)

        result = asyncio.run(client._request("GET", "/url"))
        assert result == {"ok": True}
        assert sleeps and 5.0 <= sleeps[0] <= 5.0 * 1.25

    def test_403_retry_after_invalid_default_wait(self, monkeypatch) -> None:
        """Invalid Retry-After falls back to _DEFAULT_RATELIMIT_WAIT."""
        client = GitHubClient()
        fc = _FakeClient(
            [
                _FakeResponse(status_code=403, headers={"Retry-After": "not-a-number"}),
                _FakeResponse(json_data={"ok": True}),
            ]
        )
        _patch_get_client(client, monkeypatch, fc)
        sleeps = []

        async def fake_sleep(secs):
            sleeps.append(secs)

        monkeypatch.setattr("src.sources.github.asyncio.sleep", fake_sleep)

        result = asyncio.run(client._request("GET", "/url"))
        assert result == {"ok": True}
        # default wait when retry-after is unparseable (plus up to 25% jitter)
        assert 60.0 <= sleeps[0] <= 60.0 * 1.25

    def test_403_rate_limit_exceeds_cap_raises(self, monkeypatch) -> None:
        """Wait > 300s raises GitHubRateLimitError."""
        client = GitHubClient()
        far_future = 9999999999
        fc = _FakeClient(
            [
                _FakeResponse(
                    status_code=403,
                    headers={
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": str(far_future),
                    },
                ),
            ]
        )
        _patch_get_client(client, monkeypatch, fc)

        with pytest.raises(GitHubRateLimitError, match=">300s cap"):
            asyncio.run(client._request("GET", "/url"))

    def test_403_after_retry_raises(self, monkeypatch) -> None:
        """Retry still gets 403 -> GitHubRateLimitError."""
        client = GitHubClient()
        fc = _FakeClient(
            [
                _FakeResponse(
                    status_code=403,
                    headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "0"},
                ),
                _FakeResponse(
                    status_code=403,
                    headers={"X-RateLimit-Remaining": "0"},
                ),
            ]
        )
        _patch_get_client(client, monkeypatch, fc)

        async def fake_sleep(_secs):
            pass

        monkeypatch.setattr("src.sources.github.asyncio.sleep", fake_sleep)

        with pytest.raises(GitHubRateLimitError, match="after retry"):
            asyncio.run(client._request("GET", "/url"))

    def test_429_retry_after_success(self, monkeypatch) -> None:
        """A 429 (secondary rate limit) with Retry-After is waited out."""
        client = GitHubClient()
        fc = _FakeClient(
            [
                _FakeResponse(status_code=429, headers={"Retry-After": "4"}),
                _FakeResponse(json_data={"ok": True}),
            ]
        )
        _patch_get_client(client, monkeypatch, fc)
        sleeps = []

        async def fake_sleep(secs):
            sleeps.append(secs)

        monkeypatch.setattr("src.sources.github.asyncio.sleep", fake_sleep)

        result = asyncio.run(client._request("GET", "/url"))
        assert result == {"ok": True}
        assert sleeps and 4.0 <= sleeps[0] <= 4.0 * 1.25

    def test_429_rate_limit_exceeds_cap_raises(self, monkeypatch) -> None:
        """A 429 whose wait exceeds the cap raises GitHubRateLimitError."""
        client = GitHubClient()
        fc = _FakeClient(
            [
                _FakeResponse(
                    status_code=429,
                    headers={"Retry-After": "999"},
                ),
            ]
        )
        _patch_get_client(client, monkeypatch, fc)

        with pytest.raises(GitHubRateLimitError, match=">300s cap"):
            asyncio.run(client._request("GET", "/url"))

    def test_429_after_retry_raises(self, monkeypatch) -> None:
        """Retry still gets 429 -> GitHubRateLimitError."""
        client = GitHubClient()
        fc = _FakeClient(
            [
                _FakeResponse(status_code=429, headers={"Retry-After": "1"}),
                _FakeResponse(status_code=429, headers={"Retry-After": "1"}),
            ]
        )
        _patch_get_client(client, monkeypatch, fc)

        async def fake_sleep(_secs):
            pass

        monkeypatch.setattr("src.sources.github.asyncio.sleep", fake_sleep)

        with pytest.raises(GitHubRateLimitError, match="after retry"):
            asyncio.run(client._request("GET", "/url"))

    def test_403_non_rate_limit_raises_http_error(self, monkeypatch) -> None:
        """403 without rate limit headers -> regular HTTP error."""
        client = GitHubClient()
        fc = _FakeClient([_FakeResponse(status_code=403, headers={})])
        _patch_get_client(client, monkeypatch, fc)

        with pytest.raises(httpx.HTTPStatusError):
            asyncio.run(client._request("GET", "/url"))


# ===================================================================
# list_repo_contents
# ===================================================================


class TestListRepoContents:
    def test_list_directory(self, monkeypatch) -> None:
        client = GitHubClient()
        fc = _FakeClient(
            [
                _FakeResponse(
                    json_data=[
                        {
                            "name": "file1.txt",
                            "path": "dir/file1.txt",
                            "download_url": "https://raw.githubusercontent.com/...",
                            "type": "file",
                        },
                        {
                            "name": "sub",
                            "path": "dir/sub",
                            "download_url": None,
                            "type": "dir",
                        },
                    ]
                ),
            ]
        )
        _patch_get_client(client, monkeypatch, fc)

        result = asyncio.run(client.list_repo_contents("owner", "repo", "dir"))
        assert len(result) == 2
        assert result[0]["name"] == "file1.txt"
        assert result[0]["type"] == "file"
        assert result[1]["type"] == "dir"

    def test_list_single_file_returns_single_item_list(self, monkeypatch) -> None:
        client = GitHubClient()
        fc = _FakeClient(
            [
                _FakeResponse(
                    json_data={
                        "name": "file.txt",
                        "path": "file.txt",
                        "download_url": "https://...",
                        "type": "file",
                    }
                ),
            ]
        )
        _patch_get_client(client, monkeypatch, fc)

        result = asyncio.run(client.list_repo_contents("owner", "repo", "file.txt"))
        assert len(result) == 1
        assert result[0]["name"] == "file.txt"

    def test_list_unexpected_response_type(self, monkeypatch) -> None:
        client = GitHubClient()
        fc = _FakeClient([_FakeResponse(json_data="unexpected string")])
        _patch_get_client(client, monkeypatch, fc)

        result = asyncio.run(client.list_repo_contents("owner", "repo", "dir"))
        assert result == []

    def test_list_404_returns_empty(self, monkeypatch) -> None:
        client = GitHubClient()
        fc = _FakeClient([_FakeResponse(status_code=404)])
        _patch_get_client(client, monkeypatch, fc)

        result = asyncio.run(client.list_repo_contents("owner", "repo", "dir"))
        assert result == []

    def test_list_skips_non_dict_entries(self, monkeypatch) -> None:
        client = GitHubClient()
        fc = _FakeClient(
            [
                _FakeResponse(
                    json_data=[
                        {"name": "good.txt", "path": "good.txt", "type": "file"},
                        "invalid entry",
                        None,
                        42,
                    ]
                ),
            ]
        )
        _patch_get_client(client, monkeypatch, fc)

        result = asyncio.run(client.list_repo_contents("owner", "repo", "dir"))
        assert len(result) == 1
        assert result[0]["name"] == "good.txt"

    def test_capped_listing_is_completed_via_tree(self, monkeypatch) -> None:
        """At the 1000-entry cap the listing is re-read through the Trees API.

        The Contents API has no pagination, so a directory at the cap is only
        fully visible via the recursive tree; without the fallback the files
        past the first 1000 would be silently dropped.
        """
        client = GitHubClient()
        capped = [
            {"name": f"f{i}.txt", "path": f"dir/f{i}.txt", "type": "file"}
            for i in range(1000)
        ]
        fc = _FakeClient(
            [
                _FakeResponse(json_data=capped),
                _FakeResponse(
                    json_data={
                        "sha": "abc",
                        "truncated": False,
                        "tree": [
                            {"path": "dir", "type": "tree"},
                            {"path": "dir/f0.txt", "type": "blob"},
                            {"path": "dir/sub", "type": "tree"},
                            # Deeper than one level: not a direct child.
                            {"path": "dir/sub/nested.txt", "type": "blob"},
                        ],
                    }
                ),
            ]
        )
        _patch_get_client(client, monkeypatch, fc)

        result = asyncio.run(client.list_repo_contents("owner", "repo", "dir"))
        assert {(e["name"], e["type"]) for e in result} == {
            ("f0.txt", "file"),
            ("sub", "dir"),
        }
        assert result[0]["download_url"] is None
        # The tree request must use recursive=1.
        assert fc._last_params == {"recursive": "1"}

    def test_capped_listing_keeps_contents_when_tree_fails(self, monkeypatch) -> None:
        """A failed tree read keeps the (possibly truncated) Contents listing."""
        client = GitHubClient()
        capped = [
            {"name": f"f{i}.txt", "path": f"dir/f{i}.txt", "type": "file"}
            for i in range(1000)
        ]
        fc = _FakeClient(
            [
                _FakeResponse(json_data=capped),
                _FakeResponse(status_code=500),
            ]
        )
        _patch_get_client(client, monkeypatch, fc)

        result = asyncio.run(client.list_repo_contents("owner", "repo", "dir"))
        assert len(result) == 1000


# ===================================================================
# _list_repo_tree
# ===================================================================


class TestListRepoTree:
    def test_returns_direct_children_mapped_to_contents_shape(
        self, monkeypatch
    ) -> None:
        client = GitHubClient()
        fc = _FakeClient(
            [
                _FakeResponse(
                    json_data={
                        "tree": [
                            {"path": "dir/a.txt", "type": "blob"},
                            {"path": "dir/sub", "type": "tree"},
                            {"path": "dir/sub/b.txt", "type": "blob"},
                            {"path": "other.txt", "type": "blob"},
                            "junk",
                        ]
                    }
                ),
            ]
        )
        _patch_get_client(client, monkeypatch, fc)

        result = asyncio.run(client._list_repo_tree("owner", "repo", "dir", "main"))
        assert result is not None
        assert {(e["name"], e["type"]) for e in result} == {
            ("a.txt", "file"),
            ("sub", "dir"),
        }
        assert all(e["download_url"] is None for e in result)

    def test_root_path_lists_top_level(self, monkeypatch) -> None:
        client = GitHubClient()
        fc = _FakeClient(
            [
                _FakeResponse(
                    json_data={
                        "tree": [
                            {"path": "a.txt", "type": "blob"},
                            {"path": "sub/b.txt", "type": "blob"},
                        ]
                    }
                ),
            ]
        )
        _patch_get_client(client, monkeypatch, fc)

        result = asyncio.run(client._list_repo_tree("owner", "repo", "", "main"))
        assert result is not None
        assert [e["name"] for e in result] == ["a.txt"]

    def test_request_failure_returns_none(self, monkeypatch) -> None:
        client = GitHubClient()
        fc = _FakeClient([_FakeResponse(status_code=500)])
        _patch_get_client(client, monkeypatch, fc)

        result = asyncio.run(client._list_repo_tree("owner", "repo", "dir", "main"))
        assert result is None

    def test_non_dict_payload_returns_none(self, monkeypatch) -> None:
        client = GitHubClient()
        fc = _FakeClient([_FakeResponse(json_data=[1, 2, 3])])
        _patch_get_client(client, monkeypatch, fc)

        result = asyncio.run(client._list_repo_tree("owner", "repo", "dir", "main"))
        assert result is None

    def test_tree_without_tree_key_returns_none(self, monkeypatch) -> None:
        client = GitHubClient()
        fc = _FakeClient([_FakeResponse(json_data={"truncated": False})])
        _patch_get_client(client, monkeypatch, fc)

        result = asyncio.run(client._list_repo_tree("owner", "repo", "dir", "main"))
        assert result is None

    def test_truncated_tree_is_rejected(self, monkeypatch, caplog) -> None:
        """A truncated tree returns None — the caller keeps its own listing.

        The truncated listing can be missing the requested directory entirely
        (the 1000-entry cap cuts wherever GitHub decides), so serving it
        replaced a known-good partial Contents listing with a *smaller* one
        and silently lost files.
        """
        caplog.set_level(logging.WARNING)
        client = GitHubClient()
        fc = _FakeClient(
            [
                _FakeResponse(
                    json_data={
                        "truncated": True,
                        "tree": [{"path": "f.txt", "type": "blob"}],
                    }
                ),
            ]
        )
        _patch_get_client(client, monkeypatch, fc)

        result = asyncio.run(client._list_repo_tree("owner", "repo", "", "main"))
        assert result is None
        assert "truncated" in caplog.text

    def test_capped_listing_falls_back_to_none_on_truncated_tree(
        self, monkeypatch
    ) -> None:
        """At the cap a truncated tree leaves the Contents listing in place."""
        client = GitHubClient()
        capped = [
            {"name": f"f{i}.txt", "path": f"dir/f{i}.txt", "type": "file"}
            for i in range(1000)
        ]
        fc = _FakeClient(
            [
                _FakeResponse(json_data=capped),
                _FakeResponse(
                    json_data={
                        "truncated": True,
                        "tree": [{"path": "dir/f0.txt", "type": "blob"}],
                    }
                ),
            ]
        )
        _patch_get_client(client, monkeypatch, fc)

        result = asyncio.run(client.list_repo_contents("owner", "repo", "dir"))
        # The (capped but known-good) Contents listing is kept as-is.
        assert len(result) == 1000

    def test_tree_skips_non_dict_entries(self, monkeypatch) -> None:
        """Junk entries in a tree payload are skipped, not mapped."""
        client = GitHubClient()

        async def fetch_with_junk(owner, repo, branch):
            # Bypasses _fetch_repo_tree's own non-dict filter, as a cached
            # future from a differently-filtered path could.
            return [{"path": "dir/a.txt", "type": "blob"}, "junk", None]

        monkeypatch.setattr(client, "_fetch_repo_tree", fetch_with_junk)

        result = asyncio.run(client._list_repo_tree("owner", "repo", "dir", "main"))
        assert [e["name"] for e in result] == ["a.txt"]

    def test_tree_result_is_cached(self, monkeypatch) -> None:
        """The whole-branch tree is fetched once, not once per directory."""
        client = GitHubClient()
        fc = _FakeClient(
            [
                _FakeResponse(
                    json_data={
                        "tree": [{"path": "dir/a.txt", "type": "blob"}],
                    }
                ),
            ]
        )
        _patch_get_client(client, monkeypatch, fc)

        first = asyncio.run(client._list_repo_tree("owner", "repo", "dir", "main"))
        second = asyncio.run(client._list_repo_tree("owner", "repo", "dir", "main"))
        assert first == second
        assert fc._call_count == 1

    def test_tree_failure_is_not_cached(self, monkeypatch) -> None:
        """A transient failure must not pin the repo to a permanent 'no tree'.

        The failure used to be cached alongside successes, so one rate-limit
        or network blip disabled the Trees fallback for the whole run.
        """
        client = GitHubClient()
        fc = _FakeClient(
            [
                _FakeResponse(status_code=500),
                _FakeResponse(
                    json_data={
                        "tree": [{"path": "dir/a.txt", "type": "blob"}],
                    }
                ),
            ]
        )
        _patch_get_client(client, monkeypatch, fc)

        first = asyncio.run(client._list_repo_tree("owner", "repo", "dir", "main"))
        assert first is None
        # The retry actually goes to the network again instead of a cached None.
        second = asyncio.run(client._list_repo_tree("owner", "repo", "dir", "main"))
        assert second is not None
        assert [e["name"] for e in second] == ["a.txt"]
        assert fc._call_count == 2

    def test_cancelled_tree_waiter_does_not_poison_cache(self, monkeypatch) -> None:
        """A cancelled waiter must evict the shared future it killed.

        Cancelling the task awaiting the shared future delivers the cancel to
        that future; if it stayed cached, every later caller of this repo
        would get CancelledError for the rest of the run.
        """
        client = GitHubClient()
        real_fetch = client._fetch_repo_tree

        async def scenario() -> None:
            started = asyncio.Event()

            async def slow_fetch(
                owner: str, repo: str, branch: str
            ) -> list[dict[str, object]] | None:
                started.set()
                await asyncio.sleep(3600)
                return None

            client._fetch_repo_tree = slow_fetch  # type: ignore[method-assign]
            first = asyncio.ensure_future(
                client._list_repo_tree("owner", "repo", "dir", "main")
            )
            await started.wait()
            first.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await first

            # Restore the real fetch: the retry below must hit it instead of
            # joining the cancelled future still parked in the cache.
            client._fetch_repo_tree = real_fetch  # type: ignore[method-assign]
            result = await client._list_repo_tree("owner", "repo", "dir", "main")

        asyncio.run(scenario())

    def test_concurrent_tree_requests_share_one_fetch(self, monkeypatch) -> None:
        """Parallel listings of the same repo must not duplicate the fetch.

        fetch_directory gathers subdirectories concurrently; without a shared
        in-flight future each of them would issue its own Trees API request,
        burning API budget on the same whole-branch tree.
        """
        client = GitHubClient()
        fc = _FakeClient(
            [
                _FakeResponse(
                    json_data={
                        "tree": [{"path": "dir/a.txt", "type": "blob"}],
                    }
                ),
            ]
        )
        _patch_get_client(client, monkeypatch, fc)

        async def _two_listings() -> tuple[object, object]:
            first = client._list_repo_tree("owner", "repo", "dir", "main")
            second = client._list_repo_tree("owner", "repo", "dir", "main")
            return await asyncio.gather(first, second)

        first, second = asyncio.run(_two_listings())
        assert first == second
        assert fc._call_count == 1

    def test_branch_with_slash_is_one_url_segment(self, monkeypatch) -> None:
        """A branch named ``feature/test`` is %-encoded, not split in the URL."""
        client = GitHubClient()
        fc = _FakeClient(
            [
                _FakeResponse(
                    json_data={
                        "tree": [{"path": "dir/a.txt", "type": "blob"}],
                    }
                ),
            ]
        )
        _patch_get_client(client, monkeypatch, fc)

        result = asyncio.run(
            client._list_repo_tree("owner", "repo", "dir", "feature/test")
        )
        assert result is not None
        assert isinstance(fc._last_url, str)
        assert "/git/trees/feature/test" not in fc._last_url
        assert "feature%2Ftest" in fc._last_url


# ===================================================================
# fetch_file
# ===================================================================


class TestFetchFile:
    def test_fetch_file_base64_success(self, monkeypatch) -> None:
        client = GitHubClient()
        content_b64 = base64.b64encode(b"hello world").decode("ascii")
        fc = _FakeClient(
            [
                _FakeResponse(
                    json_data={
                        "content": content_b64,
                        "encoding": "base64",
                        "name": "file.txt",
                    }
                ),
            ]
        )
        _patch_get_client(client, monkeypatch, fc)

        result = asyncio.run(client.fetch_file("owner", "repo", "file.txt"))
        assert result == "hello world"

    def test_fetch_file_no_content_uses_download_url(self, monkeypatch) -> None:
        client = GitHubClient()
        fc = _FakeClient(
            [
                _FakeResponse(
                    json_data={
                        "download_url": "https://raw.githubusercontent.com/o/r/main/f.txt",
                    }
                ),
            ]
        )
        _patch_get_client(client, monkeypatch, fc)

        async def fake_raw(url):
            return "from-raw"

        monkeypatch.setattr(client, "fetch_raw_file", fake_raw)

        result = asyncio.run(client.fetch_file("owner", "repo", "file.txt"))
        assert result == "from-raw"

    def test_fetch_file_base64_decode_failure_falls_back(self, monkeypatch) -> None:
        client = GitHubClient()
        fc = _FakeClient(
            [
                _FakeResponse(
                    json_data={
                        "content": "not-valid-base64!!!",
                        "encoding": "base64",
                        "download_url": "https://raw.githubusercontent.com/o/r/main/f.txt",
                    }
                ),
            ]
        )
        _patch_get_client(client, monkeypatch, fc)

        async def fake_raw(url):
            return "fallback-content"

        monkeypatch.setattr(client, "fetch_raw_file", fake_raw)

        result = asyncio.run(client.fetch_file("owner", "repo", "file.txt"))
        assert result == "fallback-content"

    def test_fetch_file_non_dict_response(self, monkeypatch) -> None:
        client = GitHubClient()
        fc = _FakeClient([_FakeResponse(json_data=["not", "a", "dict"])])
        _patch_get_client(client, monkeypatch, fc)

        result = asyncio.run(client.fetch_file("owner", "repo", "file.txt"))
        assert result == ""

    def test_fetch_file_empty_response(self, monkeypatch) -> None:
        client = GitHubClient()
        fc = _FakeClient([_FakeResponse(json_data={})])
        _patch_get_client(client, monkeypatch, fc)

        result = asyncio.run(client.fetch_file("owner", "repo", "file.txt"))
        assert result == ""

    def test_fetch_file_rate_limit_fallback(self, monkeypatch) -> None:
        client = GitHubClient()

        async def failing_request(*args, **kwargs):
            raise GitHubRateLimitError("limited")

        monkeypatch.setattr(client, "_request", failing_request)

        async def fake_raw(url):
            return "raw-content"

        monkeypatch.setattr(client, "fetch_raw_file", fake_raw)

        result = asyncio.run(client.fetch_file("owner", "repo", "dir/f.txt", "feature"))
        assert result == "raw-content"

    def test_fetch_file_rate_limit_fallback_failure_returns_empty(
        self, monkeypatch
    ) -> None:
        """A raw fallback still failing (429/5xx) returns '' instead of raising.

        fetch_file's contract is an empty string on failure — the Contents API
        being rate-limited must not crash the whole fetch stage.
        """
        client = GitHubClient()

        async def limited(*args, **kwargs):
            raise GitHubRateLimitError("limited")

        monkeypatch.setattr(client, "_request", limited)

        async def failing_raw(url):
            raise httpx.HTTPStatusError(
                "429 still failing after retries",
                request=mock.MagicMock(),
                response=mock.MagicMock(status_code=429),
            )

        monkeypatch.setattr(client, "fetch_raw_file", failing_raw)

        result = asyncio.run(client.fetch_file("owner", "repo", "dir/f.txt", "feature"))
        assert result == ""

    def test_fetch_file_404_returns_empty(self, monkeypatch) -> None:
        client = GitHubClient()
        fc = _FakeClient([_FakeResponse(status_code=404)])
        _patch_get_client(client, monkeypatch, fc)

        result = asyncio.run(client.fetch_file("owner", "repo", "missing.txt"))
        assert result == ""


# ===================================================================
# fetch_raw_file
# ===================================================================


class TestFetchRawFile:
    def test_rejects_untrusted_host(self) -> None:
        client = GitHubClient()
        result = asyncio.run(client.fetch_raw_file("https://evil.example.com/file.txt"))
        assert result == ""

    def test_rejection_log_masks_query_token(self, caplog) -> None:
        """A ``?token=`` download_url is logged redacted, never raw."""
        client = GitHubClient()
        secret_url = "https://evil.example.com/file.txt?token=ghp_ABCDEF0123456789"
        with caplog.at_level(logging.WARNING, logger="src.sources.github"):
            result = asyncio.run(client.fetch_raw_file(secret_url))
        assert result == ""
        logged = "\n".join(record.getMessage() for record in caplog.records)
        assert "ghp_ABCDEF0123456789" not in logged
        assert "token=***" in logged

    def test_rejects_http_scheme(self) -> None:
        client = GitHubClient()
        result = asyncio.run(
            client.fetch_raw_file("http://raw.githubusercontent.com/o/r/main/f.txt")
        )
        assert result == ""

    def test_404_returns_empty(self, monkeypatch) -> None:
        client = GitHubClient()
        monkeypatch.setattr(
            "src.sources.github.httpx.AsyncClient",
            _raw_client(lambda url: _FakeResponse(status_code=404)),
        )

        result = asyncio.run(
            client.fetch_raw_file(
                "https://raw.githubusercontent.com/o/r/main/missing.txt"
            )
        )
        assert result == ""

    def test_raw_redirect_is_refused(self, monkeypatch, caplog) -> None:
        """A redirect from the raw host is refused, never followed (SSRF).

        The destination is not re-validated against the trusted-host
        allow-list, so it could be any host.
        """
        caplog.set_level(logging.WARNING)
        client = GitHubClient()
        monkeypatch.setattr(
            "src.sources.github.httpx.AsyncClient",
            _raw_client(
                lambda url: _FakeResponse(
                    status_code=302,
                    headers={"Location": "https://evil.example.com/f.txt"},
                )
            ),
        )

        result = asyncio.run(
            client.fetch_raw_file("https://raw.githubusercontent.com/o/r/main/f.txt")
        )
        assert result == ""
        assert "refusing to follow" in caplog.text

    def test_retry_after_naive_http_date_is_parsed(self, monkeypatch) -> None:
        """A Retry-After HTTP-date without a timezone becomes a UTC delay.

        ``formatdate(usegmt=False)`` ends in ``-0000``, for which
        parsedate_to_datetime returns a naive datetime.
        """
        client = GitHubClient()
        attempt = {"count": 0}
        future = _time.time() + 20

        def throttled(url):
            attempt["count"] += 1
            if attempt["count"] == 1:
                return _FakeResponse(
                    status_code=429,
                    headers={"Retry-After": formatdate(timeval=future)},
                )
            return _FakeResponse(text_data="after date throttle")

        monkeypatch.setattr(
            "src.sources.github.httpx.AsyncClient",
            _raw_client(throttled),
        )

        slept: list[float] = []

        async def fake_sleep(secs):
            slept.append(secs)

        monkeypatch.setattr("src.sources.github.asyncio.sleep", fake_sleep)

        result = asyncio.run(
            client.fetch_raw_file("https://raw.githubusercontent.com/o/r/main/f.txt")
        )
        assert result == "after date throttle"
        assert attempt["count"] == 2
        # The parsed date delay (~20s) is used, not the 0.5s attempt backoff.
        assert 10 <= slept[0] <= 30

    def test_network_error_retry_then_empty(self, monkeypatch) -> None:
        client = GitHubClient()

        def always_fail(url):
            raise httpx.ConnectError("connection refused")

        monkeypatch.setattr(
            "src.sources.github.httpx.AsyncClient",
            _raw_client(always_fail),
        )

        async def fake_sleep(_secs):
            pass

        monkeypatch.setattr("src.sources.github.asyncio.sleep", fake_sleep)

        result = asyncio.run(
            client.fetch_raw_file("https://raw.githubusercontent.com/o/r/main/f.txt")
        )
        assert result == ""

    def test_read_timeout_returns_empty_after_retries(self, monkeypatch) -> None:
        """A wall-clock budget expiry inside fetch_raw_file is caught: bare
        TimeoutError is not an httpx.RequestError, so without its own handler
        it used to escape and fail the WHOLE source in the manager."""
        client = GitHubClient()

        class _HangingStream:
            async def __aenter__(self):
                raise TimeoutError("wall budget expired")

            async def __aexit__(self, *exc):
                return False

        class _HangingClient:
            def __init__(self) -> None:
                self.calls = 0

            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return None

            def stream(self, method, url, **kwargs):
                self.calls += 1
                return _HangingStream()

        hanging = _HangingClient()
        monkeypatch.setattr(
            "src.sources.github.httpx.AsyncClient",
            lambda *a, **kw: hanging,
        )

        async def fake_sleep(_secs):
            pass

        monkeypatch.setattr("src.sources.github.asyncio.sleep", fake_sleep)

        result = asyncio.run(
            client.fetch_raw_file("https://raw.githubusercontent.com/o/r/main/f.txt")
        )
        assert result == ""
        assert hanging.calls == 3  # _RAW_FETCH_ATTEMPTS

    def test_successful_raw_fetch(self, monkeypatch) -> None:
        client = GitHubClient()
        monkeypatch.setattr(
            "src.sources.github.httpx.AsyncClient",
            _raw_client(lambda url: _FakeResponse(text_data="raw content")),
        )

        result = asyncio.run(
            client.fetch_raw_file("https://raw.githubusercontent.com/o/r/main/f.txt")
        )
        assert result == "raw content"

    def test_retry_then_success(self, monkeypatch) -> None:
        client = GitHubClient()
        attempt = {"count": 0}

        def flaky(url):
            attempt["count"] += 1
            if attempt["count"] == 1:
                raise httpx.ConnectError("transient")
            return _FakeResponse(text_data="final content")

        monkeypatch.setattr(
            "src.sources.github.httpx.AsyncClient",
            _raw_client(flaky),
        )

        async def fake_sleep(_secs):
            pass

        monkeypatch.setattr("src.sources.github.asyncio.sleep", fake_sleep)

        result = asyncio.run(
            client.fetch_raw_file("https://raw.githubusercontent.com/o/r/main/f.txt")
        )
        assert result == "final content"
        assert attempt["count"] == 2

    def test_http_error_raises(self, monkeypatch) -> None:
        """A 5xx that survives every retry surfaces as HTTPStatusError."""
        client = GitHubClient()
        attempt = {"count": 0}

        def always_500(url):
            attempt["count"] += 1
            return _FakeResponse(status_code=500)

        monkeypatch.setattr(
            "src.sources.github.httpx.AsyncClient",
            _raw_client(always_500),
        )

        slept: list[float] = []

        async def fake_sleep(secs):
            slept.append(secs)

        monkeypatch.setattr("src.sources.github.asyncio.sleep", fake_sleep)

        with pytest.raises(httpx.HTTPStatusError):
            asyncio.run(
                client.fetch_raw_file(
                    "https://raw.githubusercontent.com/o/r/main/f.txt"
                )
            )
        assert attempt["count"] == 3
        assert len(slept) == 2

    def test_no_response_after_retries(self, monkeypatch) -> None:
        """If every attempt raises a transport error, return empty string."""
        client = GitHubClient()

        def always_fail(url):
            raise httpx.ConnectError("always fails")

        monkeypatch.setattr(
            "src.sources.github.httpx.AsyncClient",
            _raw_client(always_fail),
        )

        async def fake_sleep(_secs):
            pass

        monkeypatch.setattr("src.sources.github.asyncio.sleep", fake_sleep)

        result = asyncio.run(
            client.fetch_raw_file("https://raw.githubusercontent.com/o/r/main/f.txt")
        )
        assert result == ""

    # --- transient statuses are retried (regression) --------------------

    def test_rate_limited_429_is_retried(self, monkeypatch) -> None:
        """429 from the raw host is transient: retry instead of raising."""
        client = GitHubClient()
        attempt = {"count": 0}

        def throttled(url):
            attempt["count"] += 1
            if attempt["count"] == 1:
                return _FakeResponse(status_code=429, headers={"Retry-After": "2"})
            return _FakeResponse(text_data="after throttle")

        monkeypatch.setattr(
            "src.sources.github.httpx.AsyncClient",
            _raw_client(throttled),
        )

        slept: list[float] = []

        async def fake_sleep(secs):
            slept.append(secs)

        monkeypatch.setattr("src.sources.github.asyncio.sleep", fake_sleep)

        result = asyncio.run(
            client.fetch_raw_file("https://raw.githubusercontent.com/o/r/main/f.txt")
        )
        assert result == "after throttle"
        assert attempt["count"] == 2
        # Retry-After is honoured instead of the default backoff (plus up to
        # 25% jitter, like the API path).
        assert len(slept) == 1 and 2.0 <= slept[0] <= 2.0 * 1.25

    def test_retry_after_garbage_falls_back_to_backoff(self, monkeypatch) -> None:
        """An unparsable Retry-After uses the attempt backoff."""
        client = GitHubClient()
        attempt = {"count": 0}

        def throttled(url):
            attempt["count"] += 1
            if attempt["count"] == 1:
                return _FakeResponse(
                    status_code=503,
                    headers={"Retry-After": "later"},
                )
            return _FakeResponse(text_data="recovered")

        monkeypatch.setattr(
            "src.sources.github.httpx.AsyncClient",
            _raw_client(throttled),
        )

        slept: list[float] = []

        async def fake_sleep(secs):
            slept.append(secs)

        monkeypatch.setattr("src.sources.github.asyncio.sleep", fake_sleep)

        result = asyncio.run(
            client.fetch_raw_file("https://raw.githubusercontent.com/o/r/main/f.txt")
        )
        assert result == "recovered"
        assert len(slept) == 1 and 0.5 <= slept[0] <= 0.5 * 1.25

    def test_client_error_is_not_retried(self, monkeypatch) -> None:
        """403 is not transient: raise on the first attempt, without sleeping."""
        client = GitHubClient()
        attempt = {"count": 0}

        def forbidden(url):
            attempt["count"] += 1
            return _FakeResponse(status_code=403)

        monkeypatch.setattr(
            "src.sources.github.httpx.AsyncClient",
            _raw_client(forbidden),
        )

        slept: list[float] = []

        async def fake_sleep(secs):
            slept.append(secs)

        monkeypatch.setattr("src.sources.github.asyncio.sleep", fake_sleep)

        with pytest.raises(httpx.HTTPStatusError):
            asyncio.run(
                client.fetch_raw_file(
                    "https://raw.githubusercontent.com/o/r/main/f.txt"
                )
            )
        assert attempt["count"] == 1
        assert slept == []

    # --- body size cap (regression) -------------------------------------

    def test_oversized_body_is_discarded(self, monkeypatch, caplog) -> None:
        """A body past MAX_RAW_FILE_BYTES is dropped instead of parsed."""
        caplog.set_level("WARNING")
        client = GitHubClient()
        monkeypatch.setattr("src.sources.github.MAX_RAW_FILE_BYTES", 8)
        monkeypatch.setattr(
            "src.sources.github.httpx.AsyncClient",
            _raw_client(lambda url: _FakeResponse(text_data="1234567890123")),
        )

        result = asyncio.run(
            client.fetch_raw_file("https://raw.githubusercontent.com/o/r/main/big.txt")
        )
        assert result == ""
        assert "exceeded" in caplog.text

    def test_oversized_body_stops_reading_early(self, monkeypatch) -> None:
        """The stream is abandoned mid-body instead of buffered then measured."""
        client = GitHubClient()
        monkeypatch.setattr("src.sources.github.MAX_RAW_FILE_BYTES", 8)
        chunks_served = 0

        class _EndlessResponse(_FakeResponse):
            async def aiter_bytes(self, chunk_size: int = 4):
                nonlocal chunks_served
                for _ in range(1024):
                    chunks_served += 1
                    yield b"x" * chunk_size

        monkeypatch.setattr(
            "src.sources.github.httpx.AsyncClient",
            _raw_client(lambda url: _EndlessResponse()),
        )

        result = asyncio.run(
            client.fetch_raw_file("https://raw.githubusercontent.com/o/r/main/big.txt")
        )
        assert result == ""
        # 4 + 4 = 8 fits, the third chunk crosses the budget and ends the read.
        assert chunks_served == 3

    def test_body_at_limit_is_kept(self, monkeypatch) -> None:
        """A body exactly at the cap is still returned."""
        client = GitHubClient()
        monkeypatch.setattr("src.sources.github.MAX_RAW_FILE_BYTES", 10)
        monkeypatch.setattr(
            "src.sources.github.httpx.AsyncClient",
            _raw_client(lambda url: _FakeResponse(text_data="1234567890")),
        )

        result = asyncio.run(
            client.fetch_raw_file("https://raw.githubusercontent.com/o/r/main/f.txt")
        )
        assert result == "1234567890"


# ===================================================================
# fetch_directory
# ===================================================================


class TestFetchDirectory:
    def test_empty_directory(self, monkeypatch) -> None:
        client = GitHubClient()
        fc = _FakeClient([_FakeResponse(json_data=[])])
        _patch_get_client(client, monkeypatch, fc)

        result = asyncio.run(client.fetch_directory("owner", "repo", "empty"))
        assert result == []

    def test_max_depth_zero_returns_empty(self) -> None:
        client = GitHubClient()
        result = asyncio.run(
            client.fetch_directory("owner", "repo", "path", max_depth=0)
        )
        assert result == []

    def test_root_path_warning(self, monkeypatch) -> None:
        client = GitHubClient()
        fc = _FakeClient([_FakeResponse(json_data=[])])
        _patch_get_client(client, monkeypatch, fc)

        result = asyncio.run(client.fetch_directory("owner", "repo", ""))
        assert result == []

    def test_fetches_files_in_directory(self, monkeypatch) -> None:
        client = GitHubClient()
        fc = _FakeClient(
            [
                _FakeResponse(
                    json_data=[
                        {
                            "name": "a.txt",
                            "path": "dir/a.txt",
                            "download_url": "https://raw.githubusercontent.com/a.txt",
                            "type": "file",
                        },
                        {
                            "name": "b.txt",
                            "path": "dir/b.txt",
                            "download_url": "https://raw.githubusercontent.com/b.txt",
                            "type": "file",
                        },
                    ]
                ),
            ]
        )
        _patch_get_client(client, monkeypatch, fc)

        async def fake_raw(url):
            return (
                "content-a" if "a.txt" in url else "content-b" if "b.txt" in url else ""
            )

        monkeypatch.setattr(client, "fetch_raw_file", fake_raw)

        result = asyncio.run(client.fetch_directory("owner", "repo", "dir"))
        assert len(result) == 2
        assert ("dir/a.txt", "content-a") in result
        assert ("dir/b.txt", "content-b") in result

    def test_file_without_download_url_falls_back(self, monkeypatch) -> None:
        client = GitHubClient()
        fc = _FakeClient(
            [
                _FakeResponse(
                    json_data=[
                        {
                            "name": "nodl.txt",
                            "path": "dir/nodl.txt",
                            "download_url": None,
                            "type": "file",
                        },
                    ]
                ),
            ]
        )
        _patch_get_client(client, monkeypatch, fc)

        async def fake_fetch_file(*args, **kwargs):
            return "content-from-api"

        monkeypatch.setattr(client, "fetch_file", fake_fetch_file)

        result = asyncio.run(client.fetch_directory("owner", "repo", "dir"))
        assert result == [("dir/nodl.txt", "content-from-api")]

    def test_file_fetch_error_skipped(self, monkeypatch) -> None:
        client = GitHubClient()
        fc = _FakeClient(
            [
                _FakeResponse(
                    json_data=[
                        {
                            "name": "ok.txt",
                            "path": "dir/ok.txt",
                            "download_url": "https://raw.githubusercontent.com/ok.txt",
                            "type": "file",
                        },
                        {
                            "name": "bad.txt",
                            "path": "dir/bad.txt",
                            "download_url": "https://raw.githubusercontent.com/bad.txt",
                            "type": "file",
                        },
                    ]
                ),
            ]
        )
        _patch_get_client(client, monkeypatch, fc)

        async def fake_raw(url):
            if "bad.txt" in url:
                raise httpx.HTTPStatusError(
                    "bad", request=mock.MagicMock(), response=mock.MagicMock()
                )
            return "ok content"

        monkeypatch.setattr(client, "fetch_raw_file", fake_raw)

        result = asyncio.run(client.fetch_directory("owner", "repo", "dir"))
        assert result == [("dir/ok.txt", "ok content")]

    def test_max_files_cap(self, monkeypatch) -> None:
        client = GitHubClient()
        entries = [
            {
                "name": f"f{i}.txt",
                "path": f"f{i}.txt",
                "download_url": f"https://example.com/{i}",
                "type": "file",
            }
            for i in range(10)
        ]
        fc = _FakeClient([_FakeResponse(json_data=entries)])
        _patch_get_client(client, monkeypatch, fc)

        async def fake_raw(url):
            return "content"

        monkeypatch.setattr(client, "fetch_raw_file", fake_raw)

        result = asyncio.run(
            client.fetch_directory("owner", "repo", "dir", max_files=3)
        )
        assert len(result) == 3

    def test_subdirectory_recursion(self, monkeypatch) -> None:
        client = GitHubClient()
        list_root = _FakeResponse(
            json_data=[
                {
                    "name": "root.txt",
                    "path": "root.txt",
                    "download_url": "https://example.com/root",
                    "type": "file",
                },
                {
                    "name": "subdir",
                    "path": "subdir",
                    "download_url": None,
                    "type": "dir",
                },
            ]
        )
        list_sub = _FakeResponse(
            json_data=[
                {
                    "name": "sub_file.txt",
                    "path": "subdir/sub_file.txt",
                    "download_url": "https://example.com/sub",
                    "type": "file",
                },
            ]
        )
        fc = _FakeClient([list_root, list_sub])
        _patch_get_client(client, monkeypatch, fc)

        async def fake_raw(url):
            return "content"

        monkeypatch.setattr(client, "fetch_raw_file", fake_raw)

        result = asyncio.run(client.fetch_directory("owner", "repo", "", max_depth=2))
        assert len(result) == 2
        assert ("root.txt", "content") in result
        assert ("subdir/sub_file.txt", "content") in result

    def test_subdirectory_recursion_exception_handled(self, monkeypatch) -> None:
        client = GitHubClient()
        fc = _FakeClient(
            [
                _FakeResponse(
                    json_data=[
                        {
                            "name": "subdir",
                            "path": "subdir",
                            "download_url": None,
                            "type": "dir",
                        },
                    ]
                ),
            ]
        )
        _patch_get_client(client, monkeypatch, fc)

        original_fetch_directory = client.fetch_directory

        async def broken_recursion(*args, **kwargs):
            path_arg = args[2] if len(args) > 2 else ""
            if path_arg == "subdir" or "subdir" in str(path_arg):
                raise ValueError("recursion error")
            return await original_fetch_directory(*args, **kwargs)

        monkeypatch.setattr(client, "fetch_directory", broken_recursion)

        result = asyncio.run(client.fetch_directory("owner", "repo", ""))
        assert result == []

    def test_empty_file_results_not_included(self, monkeypatch) -> None:
        client = GitHubClient()
        fc = _FakeClient(
            [
                _FakeResponse(
                    json_data=[
                        {
                            "name": "empty.txt",
                            "path": "empty.txt",
                            "download_url": "https://example.com/empty",
                            "type": "file",
                        },
                        {
                            "name": "full.txt",
                            "path": "full.txt",
                            "download_url": "https://example.com/full",
                            "type": "file",
                        },
                    ]
                ),
            ]
        )
        _patch_get_client(client, monkeypatch, fc)

        async def fake_raw(url):
            return "full content" if "full" in url else ""

        monkeypatch.setattr(client, "fetch_raw_file", fake_raw)

        result = asyncio.run(client.fetch_directory("owner", "repo", "dir"))
        assert result == [("full.txt", "full content")]

    def test_budget_exhausted_with_dirs(self, monkeypatch) -> None:
        """max_files=0 skips the files *and* the subdirectories of a level."""
        client = GitHubClient()
        fc = _FakeClient(
            [
                _FakeResponse(
                    json_data=[
                        {
                            "name": "file.txt",
                            "path": "dir/file.txt",
                            "download_url": "https://example.com/file",
                            "type": "file",
                        },
                        {
                            "name": "subdir",
                            "path": "dir/subdir",
                            "download_url": None,
                            "type": "dir",
                        },
                    ]
                ),
            ]
        )
        _patch_get_client(client, monkeypatch, fc)

        result = asyncio.run(
            client.fetch_directory("owner", "repo", "dir", max_files=0)
        )
        assert result == []
        # Only the directory listing was requested — no file/subdir fetches.
        assert fc._call_count == 1

    def test_budget_exhausted_with_dirs_remaining(self, monkeypatch) -> None:
        """remaining_budget <= 0 with dir_entries still present (line 530-537).

        One file + one dir with max_files=1 → file consumes the budget,
        dir is skipped → elif at line 530 triggers.
        """
        client = GitHubClient()
        # Only one response needed: the top-level listing.
        fc = _FakeClient(
            [
                _FakeResponse(
                    json_data=[
                        {
                            "name": "file.txt",
                            "path": "file.txt",
                            "download_url": "https://example.com/file",
                            "type": "file",
                        },
                        {
                            "name": "subdir",
                            "path": "subdir",
                            "download_url": None,
                            "type": "dir",
                        },
                    ]
                ),
            ]
        )
        _patch_get_client(client, monkeypatch, fc)

        async def fake_raw(url):
            return "content"

        monkeypatch.setattr(client, "fetch_raw_file", fake_raw)

        result = asyncio.run(
            client.fetch_directory("owner", "repo", "dir", max_files=1)
        )
        assert result == [("file.txt", "content")]

    def test_subdir_budget_zero(self, monkeypatch) -> None:
        """sub_budget <= 0 inside _recurse_subdir (line 503-504).

        Two dirs + no files + max_files=1 → budgets = [1, 0].
        The second dir's _recurse_subdir returns [] immediately (sub_budget=0).
        The first dir's recursion needs a second response (empty listing).
        """
        client = GitHubClient()
        fc = _FakeClient(
            [
                # Response 1: top-level list → two dirs, no files
                _FakeResponse(
                    json_data=[
                        {"name": "d1", "path": "d1", "type": "dir"},
                        {"name": "d2", "path": "d2", "type": "dir"},
                    ]
                ),
                # Response 2: first subdir recursion → empty
                _FakeResponse(json_data=[]),
            ]
        )
        _patch_get_client(client, monkeypatch, fc)

        result = asyncio.run(
            client.fetch_directory("owner", "repo", "dir", max_files=1, max_depth=2)
        )
        assert result == []

    def test_file_without_download_url_fetch_file_raises(self, monkeypatch) -> None:
        """fetch_file raises exception for entry without download_url (lines 438-440)."""
        client = GitHubClient()
        fc = _FakeClient(
            [
                _FakeResponse(
                    json_data=[
                        {
                            "name": "broken.txt",
                            "path": "broken.txt",
                            "download_url": None,
                            "type": "file",
                        },
                    ]
                ),
            ]
        )
        _patch_get_client(client, monkeypatch, fc)

        async def broken_fetch_file(*args, **kwargs):
            raise ValueError("API error")

        monkeypatch.setattr(client, "fetch_file", broken_fetch_file)

        result = asyncio.run(client.fetch_directory("owner", "repo", "dir"))
        assert result == []


# ===================================================================
# fetch_raw_file — zero-attempt edge case
# ===================================================================


class TestFetchRawFileEdge:
    def test_fetch_raw_file_no_attempts(self, monkeypatch) -> None:
        """Patch _RAW_FETCH_ATTEMPTS to 0 so the loop never executes (lines 304-308)."""
        monkeypatch.setattr("src.sources.github._RAW_FETCH_ATTEMPTS", 0)
        client = GitHubClient()
        result = asyncio.run(
            client.fetch_raw_file("https://raw.githubusercontent.com/o/r/f")
        )
        assert result == ""


# ===================================================================
# Integration-style: _request with patched httpx.AsyncClient
# ===================================================================


class TestRequestIntegration:
    def test_request_with_real_client(self, monkeypatch) -> None:
        """Use a patched httpx.AsyncClient to test full request flow."""

        async def _public(_url: str, *, timeout: float = 5.0) -> bool:
            return True

        monkeypatch.setattr("src.sources.github.is_safe_public_url", _public)
        client = GitHubClient()

        class FakeHttpxClient:
            def __init__(self, *args, **kwargs):
                self.base_url = kwargs.get("base_url")
                self.headers = kwargs.get("headers", {})

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            async def request(self, method, url, **kwargs):
                return _FakeResponse(json_data={"method": method, "url": url})

        monkeypatch.setattr("src.sources.github.httpx.AsyncClient", FakeHttpxClient)

        result = asyncio.run(client._request("GET", "/repos/o/r/contents/f"))
        assert result == {"method": "GET", "url": "/repos/o/r/contents/f"}


class TestServerErrorRetry:
    """A transient 502/503/504 from the API is retried once with backoff."""

    def test_502_retried_then_succeeds(self, monkeypatch) -> None:
        client = GitHubClient()
        fc = _FakeClient(
            [
                _FakeResponse(status_code=502),
                _FakeResponse(json_data={"ok": True}),
            ]
        )
        _patch_get_client(client, monkeypatch, fc)
        sleeps: list[float] = []

        async def fake_sleep(secs):
            sleeps.append(secs)

        monkeypatch.setattr("src.sources.github.asyncio.sleep", fake_sleep)
        result = asyncio.run(client._request("GET", "/url"))
        assert result == {"ok": True}
        assert len(sleeps) == 1
        assert _SERVER_ERROR_RETRY_DELAY <= sleeps[0] <= _SERVER_ERROR_RETRY_DELAY + 1.0

    def test_502_on_every_attempt_raises(self, monkeypatch) -> None:
        """A 5xx that survives the retry surfaces as HTTPStatusError."""
        client = GitHubClient()
        fc = _FakeClient(
            [
                _FakeResponse(status_code=503),
                _FakeResponse(status_code=503),
            ]
        )
        _patch_get_client(client, monkeypatch, fc)
        with pytest.raises(httpx.HTTPStatusError):
            asyncio.run(client._request("GET", "/url"))

    def test_500_is_not_retried(self, monkeypatch) -> None:
        """Only the transient 502/503/504 set retries; a plain 500 raises."""
        client = GitHubClient()
        fc = _FakeClient(
            [
                _FakeResponse(status_code=500),
            ]
        )
        _patch_get_client(client, monkeypatch, fc)
        with pytest.raises(httpx.HTTPStatusError):
            asyncio.run(client._request("GET", "/url"))


class TestRawClientAuthIsolation:
    """Raw downloads must never carry the API bearer token.

    The raw client is a SEPARATE client on purpose: httpx merges client-level
    headers with per-request ones, so routing raw fetches through the API
    client would send ``Authorization: Bearer <token>`` to
    raw.githubusercontent.com.
    """

    def test_raw_request_carries_no_authorization(self, monkeypatch) -> None:
        client = GitHubClient(token="tok123")
        seen: dict[str, object] = {}

        class _RecordingResponse:
            status_code = 200

            def raise_for_status(self) -> None:
                return None

            async def aiter_bytes(self):
                yield b"content"

        class _RecordingCtx:
            async def __aenter__(self):
                return _RecordingResponse()

            async def __aexit__(self, *exc):
                return False

        class _RecordingRawClient:
            def stream(self, method: str, url: str, **kwargs):
                seen["headers"] = dict(kwargs.get("headers") or {})

                class _Resp:
                    status_code = 200

                    def raise_for_status(self) -> None:
                        return None

                    async def aiter_bytes(self):
                        yield b"content"

                class _StreamCtx:
                    async def __aenter__(self):
                        return _Resp()

                    async def __aexit__(self, *exc):
                        return False

                return _StreamCtx()

        recording = _RecordingRawClient()

        async def fake_get_raw():
            return recording

        monkeypatch.setattr(client, "_get_raw_client", fake_get_raw)

        async def _fake_read(response, *, max_bytes: int):
            return "content"

        monkeypatch.setattr(
            "src.sources.github.read_limited_text",
            _fake_read,
        )
        body = asyncio.run(
            client.fetch_raw_file("https://raw.githubusercontent.com/o/r/main/f.txt")
        )
        assert body == "content"
        headers = seen["headers"]
        assert isinstance(headers, dict)
        assert "Authorization" not in headers
        assert headers.get("User-Agent") == client.USER_AGENT

    def test_raw_client_is_reused_across_attempts(self, monkeypatch) -> None:
        """The raw client is created once, not per attempt/file."""
        client = GitHubClient()
        built: list[object] = []

        class _NoopClient:
            async def aclose(self) -> None:
                return None

        original = httpx.AsyncClient

        def counting_client(**kwargs):
            c = original(**kwargs)
            built.append(c)
            return c

        monkeypatch.setattr("src.sources.github.httpx.AsyncClient", counting_client)

        async def scenario():
            c1 = await client._get_raw_client()
            c2 = await client._get_raw_client()
            assert c1 is c2
            await client.aclose()
            c3 = await client._get_raw_client()
            assert c3 is not c1

        asyncio.run(scenario())
        assert len(built) == 2
