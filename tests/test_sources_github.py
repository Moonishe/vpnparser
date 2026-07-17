"""Tests for src.sources.github — 100% coverage target."""

from __future__ import annotations

import asyncio
import base64
import time as _time
from unittest import mock

import httpx
import pytest

from src.sources.github import (
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
    ):
        self.status_code = status_code
        self._json_data = json_data
        self.text = text_data
        self.headers = headers or {}

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

    def test_get_client_lazy_creation(self) -> None:
        client = GitHubClient()
        assert client._client is None

        c = asyncio.run(client._get_client())
        assert c is not None
        assert client._client is c
        # second call returns same instance
        assert asyncio.run(client._get_client()) is c

    def test_get_client_concurrent_safety(self) -> None:
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

    def test_aclose(self) -> None:
        client = GitHubClient()
        c = asyncio.run(client._get_client())
        assert client._client is c

        asyncio.run(client.aclose())
        assert client._client is None

    def test_aclose_idempotent(self) -> None:
        client = GitHubClient()
        # no client yet, must not crash
        asyncio.run(client.aclose())

    def test_async_context_manager(self) -> None:
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
        assert sleeps == [5.0]

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
        # default wait when retry-after is unparseable
        assert sleeps == [pytest.approx(60.0, abs=5)]

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

    def test_rejects_http_scheme(self) -> None:
        client = GitHubClient()
        result = asyncio.run(
            client.fetch_raw_file("http://raw.githubusercontent.com/o/r/main/f.txt")
        )
        assert result == ""

    def test_404_returns_empty(self, monkeypatch) -> None:
        client = GitHubClient()

        class RawClient404:
            def __init__(self, *args, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            async def get(self, *args, **kwargs):
                return _FakeResponse(status_code=404)

        monkeypatch.setattr("src.sources.github.httpx.AsyncClient", RawClient404)

        result = asyncio.run(
            client.fetch_raw_file(
                "https://raw.githubusercontent.com/o/r/main/missing.txt"
            )
        )
        assert result == ""

    def test_network_error_retry_then_empty(self, monkeypatch) -> None:
        client = GitHubClient()

        class FailingClient:
            def __init__(self, *args, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            async def get(self, *args, **kwargs):
                raise httpx.ConnectError("connection refused")

        monkeypatch.setattr("src.sources.github.httpx.AsyncClient", FailingClient)

        async def fake_sleep(_secs):
            pass

        monkeypatch.setattr("src.sources.github.asyncio.sleep", fake_sleep)

        result = asyncio.run(
            client.fetch_raw_file("https://raw.githubusercontent.com/o/r/main/f.txt")
        )
        assert result == ""

    def test_successful_raw_fetch(self, monkeypatch) -> None:
        client = GitHubClient()

        class RawClientOK:
            def __init__(self, *args, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            async def get(self, url, **kwargs):
                return _FakeResponse(text_data="raw content")

        monkeypatch.setattr("src.sources.github.httpx.AsyncClient", RawClientOK)

        result = asyncio.run(
            client.fetch_raw_file("https://raw.githubusercontent.com/o/r/main/f.txt")
        )
        assert result == "raw content"

    def test_retry_then_success(self, monkeypatch) -> None:
        client = GitHubClient()
        attempt = {"count": 0}

        class RetryClient:
            def __init__(self, *args, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            async def get(self, url, **kwargs):
                attempt["count"] += 1
                if attempt["count"] == 1:
                    raise httpx.ConnectError("transient")
                return _FakeResponse(text_data="final content")

        monkeypatch.setattr("src.sources.github.httpx.AsyncClient", RetryClient)

        async def fake_sleep(_secs):
            pass

        monkeypatch.setattr("src.sources.github.asyncio.sleep", fake_sleep)

        result = asyncio.run(
            client.fetch_raw_file("https://raw.githubusercontent.com/o/r/main/f.txt")
        )
        assert result == "final content"
        assert attempt["count"] == 2

    def test_http_error_raises(self, monkeypatch) -> None:
        client = GitHubClient()

        class Client500:
            def __init__(self, *args, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            async def get(self, url, **kwargs):
                return _FakeResponse(status_code=500)

        monkeypatch.setattr("src.sources.github.httpx.AsyncClient", Client500)

        with pytest.raises(httpx.HTTPStatusError):
            asyncio.run(
                client.fetch_raw_file(
                    "https://raw.githubusercontent.com/o/r/main/f.txt"
                )
            )

    def test_no_response_after_retries(self, monkeypatch) -> None:
        """If loop completes with no response set, return empty string."""
        client = GitHubClient()

        class AllFailClient:
            def __init__(self, *args, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            async def get(self, url, **kwargs):
                raise httpx.ConnectError("always fails")

        monkeypatch.setattr("src.sources.github.httpx.AsyncClient", AllFailClient)

        async def fake_sleep(_secs):
            pass

        monkeypatch.setattr("src.sources.github.asyncio.sleep", fake_sleep)

        result = asyncio.run(
            client.fetch_raw_file("https://raw.githubusercontent.com/o/r/main/f.txt")
        )
        assert result == ""


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

    def test_budget_exhausted_with_dirs(self) -> None:
        client = GitHubClient()
        result = asyncio.run(
            client.fetch_directory("owner", "repo", "dir", max_files=0)
        )
        assert result == []

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
