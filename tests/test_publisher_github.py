"""Tests for src/publisher/github.py — GitHub Contents API publisher.

Uses inline _FakeResp / _FakeAsyncClient classes and monkeypatch to avoid
real HTTP calls and asyncio.sleep.
"""

from __future__ import annotations

import asyncio
import base64
import time
from email.utils import formatdate
from typing import Any

import httpx
import pytest

from src.publisher.github import (
    GitHubPublishError,
    GitHubPublisher,
    _clean_repo_path,
    _contents_url,
)


# ---------------------------------------------------------------------------
# _clean_repo_path
# ---------------------------------------------------------------------------


def test_clean_repo_path_strips_slashes() -> None:
    assert _clean_repo_path(" /foo/bar/ ") == "foo/bar"
    assert _clean_repo_path("//baz//") == "baz"
    assert _clean_repo_path("a/b/c/") == "a/b/c"


def test_clean_repo_path_normalizes_backslashes() -> None:
    assert _clean_repo_path("foo\\bar") == "foo/bar"


def test_clean_repo_path_raises_on_empty() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        _clean_repo_path("")
    with pytest.raises(ValueError, match="must not be empty"):
        _clean_repo_path("   ")


def test_clean_repo_path_raises_on_unsafe_dotdot() -> None:
    with pytest.raises(ValueError, match="unsafe"):
        _clean_repo_path("../secret.txt")
    with pytest.raises(ValueError, match="unsafe"):
        _clean_repo_path("foo/./bar")


def test_clean_repo_path_collapses_multiple_parts() -> None:
    assert _clean_repo_path("a//b///c") == "a/b/c"


# ---------------------------------------------------------------------------
# _contents_url
# ---------------------------------------------------------------------------


def test_contents_url_quotes_owner_repo_path() -> None:
    assert _contents_url("My Owner", "My Repo", "dir/file.txt") == (
        "/repos/My%20Owner/My%20Repo/contents/dir/file.txt"
    )


def test_contents_url_encodes_special_chars() -> None:
    assert _contents_url("o", "r", "dir/file+name.txt") == (
        "/repos/o/r/contents/dir/file%2Bname.txt"
    )


def test_contents_url_raises_on_unsafe_path() -> None:
    with pytest.raises(ValueError, match="unsafe"):
        _contents_url("o", "r", "../bad.txt")


# ---------------------------------------------------------------------------
# GitHubPublisher.__init__
# ---------------------------------------------------------------------------


def test_publisher_init_valid_args() -> None:
    pub = GitHubPublisher(
        token="ghp_token",
        owner="my-owner",
        repo="my-repo",
        branch="develop",
        api_base="https://api.github.com/",
        timeout=15.0,
    )
    assert pub.token == "ghp_token"
    assert pub.owner == "my-owner"
    assert pub.repo == "my-repo"
    assert pub.branch == "develop"
    assert pub.api_base == "https://api.github.com"  # rstrip("/")
    assert pub._timeout == 15.0


def test_publisher_init_defaults() -> None:
    pub = GitHubPublisher(token="t", owner="o", repo="r")
    assert pub.branch == "main"
    assert pub.api_base == "https://api.github.com"
    assert pub._timeout == 30.0


def test_publisher_init_raises_on_missing_token() -> None:
    with pytest.raises(ValueError, match="GitHub token is required"):
        GitHubPublisher(token="", owner="o", repo="r")


def test_publisher_init_raises_on_missing_owner_or_repo() -> None:
    with pytest.raises(ValueError, match="GitHub owner and repo are required"):
        GitHubPublisher(token="t", owner="", repo="r")
    with pytest.raises(ValueError, match="GitHub owner and repo are required"):
        GitHubPublisher(token="t", owner="o", repo="")


# ---------------------------------------------------------------------------
# _is_rate_limited
# ---------------------------------------------------------------------------


def test_is_rate_limited_primary_ratelimit() -> None:
    resp = httpx.Response(403, headers={"X-RateLimit-Remaining": "0"})
    assert GitHubPublisher._is_rate_limited(resp) is True


def test_is_rate_limited_secondary_retry_after() -> None:
    resp = httpx.Response(403, headers={"Retry-After": "30"})
    assert GitHubPublisher._is_rate_limited(resp) is True


def test_is_rate_limited_no_headers() -> None:
    resp = httpx.Response(403, headers={})
    assert GitHubPublisher._is_rate_limited(resp) is False


def test_is_rate_limited_non_403_still_checks_headers() -> None:
    resp = httpx.Response(429, headers={"X-RateLimit-Remaining": "0"})
    assert GitHubPublisher._is_rate_limited(resp) is True


# ---------------------------------------------------------------------------
# _wait_for_rate_limit  (mocks asyncio.sleep)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "resp_headers, expected_lo, expected_hi",
    [
        ({"Retry-After": "15"}, 14, 16),
        ({}, 59, 61),  # default _DEFAULT_RATELIMIT_WAIT
    ],
)
async def test_wait_for_rate_limit_retry_after_and_default(
    monkeypatch, resp_headers: dict[str, str], expected_lo: float, expected_hi: float
) -> None:
    slept: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    fake_resp = type("FakeResp", (), {"status_code": 403, "headers": resp_headers})()

    pub = GitHubPublisher(token="t", owner="o", repo="r")
    await pub._wait_for_rate_limit(fake_resp)  # type: ignore[arg-type]

    assert len(slept) == 1
    assert expected_lo <= slept[0] <= expected_hi, (
        f"Expected sleep between {expected_lo} and {expected_hi}, got {slept[0]}"
    )


async def test_wait_for_rate_limit_reset_with_future_timestamp(monkeypatch) -> None:
    """X-RateLimit-Reset as a future epoch timestamp."""
    future_epoch = time.time() + 10  # 10 seconds from now
    slept: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    fake_resp = type(
        "FakeResp",
        (),
        {"status_code": 403, "headers": {"X-RateLimit-Reset": str(future_epoch)}},
    )()

    pub = GitHubPublisher(token="t", owner="o", repo="r")
    await pub._wait_for_rate_limit(fake_resp)  # type: ignore[arg-type]

    assert len(slept) == 1
    # Should be ~10 seconds (fudge factor of 2 for test execution time)
    assert 8 <= slept[0] <= 12


async def test_wait_for_rate_limit_cap_exceeded_raises(monkeypatch) -> None:
    fake_resp = type(
        "FakeResp",
        (),
        {"status_code": 403, "headers": {"X-RateLimit-Reset": "99999999999"}},
    )()

    pub = GitHubPublisher(token="t", owner="o", repo="r")
    with pytest.raises(GitHubPublishError, match="rate limit exhausted"):
        await pub._wait_for_rate_limit(fake_resp)  # type: ignore[arg-type]


async def test_wait_for_rate_limit_retry_after_date(monkeypatch) -> None:
    """Retry-After as an HTTP-date is parsed correctly."""
    future_ts = time.time() + 42
    future_date = formatdate(timeval=future_ts, usegmt=True)

    slept: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    fake_resp = type(
        "FakeResp", (), {"status_code": 403, "headers": {"Retry-After": future_date}}
    )()

    pub = GitHubPublisher(token="t", owner="o", repo="r")
    await pub._wait_for_rate_limit(fake_resp)  # type: ignore[arg-type]

    assert len(slept) == 1
    assert 35 <= slept[0] <= 50, f"Unexpected sleep duration: {slept[0]}"


# ---------------------------------------------------------------------------
# Helpers for publish_file tests
# ---------------------------------------------------------------------------


class _FakeResp:
    """Simulates httpx.Response for publish_file tests."""

    def __init__(
        self,
        status_code: int = 200,
        json_data: object | None = None,
        headers: dict[str, str] | None = None,
        text: str = "",
    ) -> None:
        self.status_code = status_code
        self._json = json_data
        self.headers = headers or {}
        self.text = text

    def json(self) -> object:
        if self._json is None:
            raise ValueError("no json")
        return self._json

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                f"HTTP {self.status_code}",
                request=None,  # type: ignore[arg-type]
                response=self,  # type: ignore[arg-type]
            )


def _make_publisher(monkeypatch, fake_client: Any) -> GitHubPublisher:
    """Create a GitHubPublisher whose _get_client returns *fake_client*.

    Also ensures the fake client is stored in ``self._client`` so that
    ``aclose()`` works properly.
    """

    async def fake_get_client(self) -> Any:  # noqa: ARG001
        self._client = fake_client  # type: ignore[attr-defined]
        return fake_client

    monkeypatch.setattr(GitHubPublisher, "_get_client", fake_get_client)
    return GitHubPublisher(token="t", owner="o", repo="r")


# ---------------------------------------------------------------------------
# publish_file: creation (201)
# ---------------------------------------------------------------------------


async def test_publish_file_creates_new_file(monkeypatch) -> None:
    """File that doesn't exist yet (404 on GET) -> PUT with no sha -> 201."""

    class _FakeClient:
        def __init__(self) -> None:
            self.get_calls: list[str] = []
            self.put_calls: list[tuple[str, dict[str, Any] | None]] = []

        async def __aenter__(self) -> _FakeClient:
            return self

        async def __aexit__(self, *exc: object) -> None:
            return None

        async def get(self, url: str, **kw: object) -> _FakeResp:
            self.get_calls.append(url)
            return _FakeResp(404)

        async def put(self, url: str, **kw: object) -> _FakeResp:
            body = kw.get("json")
            self.put_calls.append((url, body))  # type: ignore[arg-type]
            return _FakeResp(201, json_data={"content": {"sha": "newsha"}})

        async def aclose(self) -> None:
            return None

    fake = _FakeClient()
    pub = _make_publisher(monkeypatch, fake)

    result = await pub.publish_file("output/sub.txt", "hello world", "create test")

    assert result is True
    assert len(fake.get_calls) == 1
    assert len(fake.put_calls) == 1
    body = fake.put_calls[0][1]
    assert body is not None
    assert "sha" not in body  # creation has no sha


# ---------------------------------------------------------------------------
# publish_file: update (200)
# ---------------------------------------------------------------------------


async def test_publish_file_updates_existing_file(monkeypatch) -> None:
    """File exists (GET returns sha) -> PUT with sha -> 200."""

    class _FakeClient:
        def __init__(self) -> None:
            self.get_calls: list[str] = []
            self.put_calls: list[tuple[str, dict[str, Any] | None]] = []

        async def __aenter__(self) -> _FakeClient:
            return self

        async def __aexit__(self, *exc: object) -> None:
            return None

        async def get(self, url: str, **kw: object) -> _FakeResp:
            self.get_calls.append(url)
            return _FakeResp(200, json_data={"sha": "abc123"})

        async def put(self, url: str, **kw: object) -> _FakeResp:
            body = kw.get("json")
            self.put_calls.append((url, body))  # type: ignore[arg-type]
            return _FakeResp(200, json_data={"content": {"sha": "def456"}})

        async def aclose(self) -> None:
            return None

    fake = _FakeClient()
    pub = _make_publisher(monkeypatch, fake)

    result = await pub.publish_file("output/sub.txt", "updated content", "update test")

    assert result is True
    assert len(fake.put_calls) == 1
    body = fake.put_calls[0][1]
    assert body is not None
    assert body.get("sha") == "abc123"


# ---------------------------------------------------------------------------
# publish_file: 403 rate limit retry
# ---------------------------------------------------------------------------


async def test_publish_file_retries_on_403_rate_limit(monkeypatch) -> None:
    """First PUT returns 403 rate-limited, second succeeds."""
    slept: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    class _FakeClient:
        def __init__(self) -> None:
            self.put_count = 0

        async def __aenter__(self) -> _FakeClient:
            return self

        async def __aexit__(self, *exc: object) -> None:
            return None

        async def get(self, url: str, **kw: object) -> _FakeResp:
            return _FakeResp(200, json_data={"sha": "abc"})

        async def put(self, url: str, **kw: object) -> _FakeResp:
            self.put_count += 1
            if self.put_count == 1:
                return _FakeResp(
                    403,
                    headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1"},
                )
            return _FakeResp(201, json_data={"content": {"sha": "x"}})

        async def aclose(self) -> None:
            return None

    pub = _make_publisher(monkeypatch, _FakeClient())
    result = await pub.publish_file("f.txt", "data", "msg")

    assert result is True
    assert slept  # at least one sleep was issued


# ---------------------------------------------------------------------------
# publish_file: 409 conflict
# ---------------------------------------------------------------------------


async def test_publish_file_conflict_409(monkeypatch) -> None:
    """409 conflict should return False (recoverable failure)."""

    class _FakeClient:
        def __init__(self) -> None:
            self.put_calls: list[str] = []

        async def __aenter__(self) -> _FakeClient:
            return self

        async def __aexit__(self, *exc: object) -> None:
            return None

        async def get(self, url: str, **kw: object) -> _FakeResp:
            return _FakeResp(200, json_data={"sha": "abc"})

        async def put(self, url: str, **kw: object) -> _FakeResp:
            self.put_calls.append(url)
            return _FakeResp(409, text="Conflict")

        async def aclose(self) -> None:
            return None

    pub = _make_publisher(monkeypatch, _FakeClient())
    result = await pub.publish_file("f.txt", "data", "msg")

    assert result is False


# ---------------------------------------------------------------------------
# publish_file: 422 unprocessable
# ---------------------------------------------------------------------------


async def test_publish_file_unprocessable_422(monkeypatch) -> None:
    """422 should return False."""

    class _FakeClient:
        async def __aenter__(self) -> _FakeClient:
            return self

        async def __aexit__(self, *exc: object) -> None:
            return None

        async def get(self, url: str, **kw: object) -> _FakeResp:
            return _FakeResp(404)

        async def put(self, url: str, **kw: object) -> _FakeResp:
            return _FakeResp(422, json_data={"message": "invalid"})

        async def aclose(self) -> None:
            return None

    pub = _make_publisher(monkeypatch, _FakeClient())
    result = await pub.publish_file("f.txt", "data", "msg")

    assert result is False


# ---------------------------------------------------------------------------
# publish_file: network error on PUT
# ---------------------------------------------------------------------------


async def test_publish_file_network_error_on_put(monkeypatch) -> None:
    """httpx.RequestError on PUT should be caught and return False."""

    class _FakeClient:
        async def __aenter__(self) -> _FakeClient:
            return self

        async def __aexit__(self, *exc: object) -> None:
            return None

        async def get(self, url: str, **kw: object) -> _FakeResp:
            return _FakeResp(200, json_data={"sha": "abc123"})

        async def put(self, url: str, **kw: object) -> _FakeResp:
            raise httpx.ConnectError("connection refused")

        async def aclose(self) -> None:
            return None

    pub = _make_publisher(monkeypatch, _FakeClient())
    result = await pub.publish_file("f.txt", "data", "msg")

    assert result is False


# ---------------------------------------------------------------------------
# publish_file: encoding error
# ---------------------------------------------------------------------------


class _FailingStr(str):
    """String subclass that fails on encode()."""

    def encode(self, encoding: str = "utf-8", errors: str = "strict") -> bytes:
        raise UnicodeEncodeError("utf-8", self, 0, len(self), "mock encoding failure")


async def test_publish_file_encoding_error(monkeypatch) -> None:
    """When content.encode('utf-8') fails, publish_file returns False."""

    class _FakeClient:
        async def __aenter__(self) -> _FakeClient:
            return self

        async def __aexit__(self, *exc: object) -> None:
            return None

        async def get(self, url: str, **kw: object) -> _FakeResp:
            raise AssertionError("should not reach GET")

        async def put(self, url: str, **kw: object) -> _FakeResp:
            raise AssertionError("should not reach PUT")

        async def aclose(self) -> None:
            return None

    pub = _make_publisher(monkeypatch, _FakeClient())
    result = await pub.publish_file("f.txt", _FailingStr("data"), "msg")

    assert result is False


# ---------------------------------------------------------------------------
# publish_file: HTTPStatusError on GET sha
# ---------------------------------------------------------------------------


async def test_publish_file_http_status_error_on_get_sha(monkeypatch) -> None:
    """A non-404/non-403 HTTP error on GET should be caught and return False."""

    class _FakeClient:
        async def __aenter__(self) -> _FakeClient:
            return self

        async def __aexit__(self, *exc: object) -> None:
            return None

        async def get(self, url: str, **kw: object) -> _FakeResp:
            return _FakeResp(500, text="Server Error")

        async def put(self, url: str, **kw: object) -> _FakeResp:
            raise AssertionError("should not reach PUT")

        async def aclose(self) -> None:
            return None

    pub = _make_publisher(monkeypatch, _FakeClient())
    result = await pub.publish_file("f.txt", "data", "msg")

    assert result is False


# ---------------------------------------------------------------------------
# publish_file: GitHubPublishError propagates
# ---------------------------------------------------------------------------


async def test_publish_file_propagates_githubpublisherror(monkeypatch) -> None:
    """GitHubPublishError (cap exceeded in _get_file_sha) must propagate."""

    class _FakeClient:
        async def __aenter__(self) -> _FakeClient:
            return self

        async def __aexit__(self, *exc: object) -> None:
            return None

        async def get(self, url: str, **kw: object) -> _FakeResp:
            # Primary rate limit with a reset time far in the future -> cap exceeds
            return _FakeResp(
                403,
                headers={
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": "99999999999",
                },
            )

        async def put(self, url: str, **kw: object) -> _FakeResp:
            raise AssertionError("should not reach PUT")

        async def aclose(self) -> None:
            return None

    pub = _make_publisher(monkeypatch, _FakeClient())
    with pytest.raises(GitHubPublishError):
        await pub.publish_file("f.txt", "data", "msg")


# ---------------------------------------------------------------------------
# async context manager
# ---------------------------------------------------------------------------


async def test_publisher_async_context_manager(monkeypatch) -> None:
    closed = False

    class FakeClient:
        async def __aenter__(self) -> FakeClient:
            return self

        async def __aexit__(self, *exc: object) -> None:
            return None

        async def aclose(self) -> None:
            nonlocal closed
            closed = True

    async def fake_get_client(self: Any) -> FakeClient:  # noqa: ARG001
        self._client = FakeClient()  # type: ignore[attr-defined]
        return self._client

    monkeypatch.setattr(GitHubPublisher, "_get_client", fake_get_client)

    async with GitHubPublisher(token="t", owner="o", repo="r") as pub:
        assert pub.owner == "o"

    assert closed


# ---------------------------------------------------------------------------
# _headers
# ---------------------------------------------------------------------------


def test_headers_returns_dict() -> None:
    """_headers() returns the expected dict with auth and version headers."""
    pub = GitHubPublisher(token="test-token", owner="o", repo="r")
    headers = pub._headers()
    assert headers["User-Agent"] == GitHubPublisher.USER_AGENT
    assert headers["Authorization"] == "Bearer test-token"
    assert headers["X-GitHub-Api-Version"] == "2022-11-28"
    assert "application/vnd.github+json" in headers["Accept"]


# ---------------------------------------------------------------------------
# _get_client (real, not monkeypatched)
# ---------------------------------------------------------------------------


async def test_get_client_double_check_locking() -> None:
    """_get_client creates the client on first call and reuses it on subsequent calls.

    Covers both branches of the double-checked locking pattern.
    """
    pub = GitHubPublisher(
        token="t",
        owner="o",
        repo="r",
        api_base="http://localhost:0",  # safe — no real requests made
    )
    # First call: client is None → enters lock → creates client (lines 106-114).
    client1 = await pub._get_client()
    assert client1 is not None
    assert pub._client is client1

    # Second call: client already exists → returns immediately (lines 104-105).
    client2 = await pub._get_client()
    assert client2 is client1

    await pub.aclose()
    assert pub._client is None


# ---------------------------------------------------------------------------
# _get_file_sha: rate-limited 403 then 404
# ---------------------------------------------------------------------------


async def test_get_file_sha_rate_limit_then_404(monkeypatch) -> None:
    """Rate-limited 403 on GET, then 404 on retry -> None (file missing)."""
    slept: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    class _FakeClient:
        def __init__(self) -> None:
            self.get_count = 0

        async def __aenter__(self) -> _FakeClient:
            return self

        async def __aexit__(self, *exc: object) -> None:
            return None

        async def get(self, url: str, **kw: object) -> _FakeResp:
            self.get_count += 1
            if self.get_count == 1:
                return _FakeResp(
                    403,
                    headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1"},
                )
            return _FakeResp(404)

        async def aclose(self) -> None:
            return None

    pub = _make_publisher(monkeypatch, _FakeClient())
    sha = await pub._get_file_sha("f.txt")
    assert sha is None
    assert len(slept) == 1  # waited once for rate limit
    assert _FakeClient().get_count == 0  # just a type hint, ignore


# ---------------------------------------------------------------------------
# _get_file_sha: 409 conflict
# ---------------------------------------------------------------------------


async def test_get_file_sha_409_conflict(monkeypatch) -> None:
    """409 on GET -> treated as file missing, returns None."""

    class _FakeClient:
        async def __aenter__(self) -> _FakeClient:
            return self

        async def __aexit__(self, *exc: object) -> None:
            return None

        async def get(self, url: str, **kw: object) -> _FakeResp:
            return _FakeResp(409)

        async def aclose(self) -> None:
            return None

    pub = _make_publisher(monkeypatch, _FakeClient())
    sha = await pub._get_file_sha("f.txt")
    assert sha is None


# ---------------------------------------------------------------------------
# _get_file_sha: unexpected response shape
# ---------------------------------------------------------------------------


async def test_get_file_sha_unexpected_response(monkeypatch) -> None:
    """Non-dict JSON / dict missing 'sha' key -> returns None."""

    class _FakeClient:
        def __init__(self) -> None:
            self.call = 0

        async def __aenter__(self) -> _FakeClient:
            return self

        async def __aexit__(self, *exc: object) -> None:
            return None

        async def get(self, url: str, **kw: object) -> _FakeResp:
            self.call += 1
            if self.call == 1:
                return _FakeResp(200, json_data=["not", "a", "dict"])
            return _FakeResp(200, json_data={"sha": None})  # sha not a str

        async def aclose(self) -> None:
            return None

    pub = _make_publisher(monkeypatch, _FakeClient())
    sha1 = await pub._get_file_sha("f1.txt")
    assert sha1 is None
    sha2 = await pub._get_file_sha("f2.txt")
    assert sha2 is None


# ---------------------------------------------------------------------------
# _wait_for_rate_limit: unparseable Retry-After date
# ---------------------------------------------------------------------------


async def test_wait_for_rate_limit_invalid_retry_after_date(monkeypatch) -> None:
    """Retry-After with a value that is neither a number nor an HTTP-date
    falls back to _DEFAULT_RATELIMIT_WAIT (~60s)."""
    slept: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    fake_resp = type(
        "FakeResp",
        (),
        {"status_code": 403, "headers": {"Retry-After": "garbage-value"}},
    )()

    pub = GitHubPublisher(token="t", owner="o", repo="r")
    await pub._wait_for_rate_limit(fake_resp)  # type: ignore[arg-type]

    assert len(slept) == 1
    assert 59 <= slept[0] <= 61


# ---------------------------------------------------------------------------
# publish_file: unexpected exception in _get_file_sha
# ---------------------------------------------------------------------------


async def test_publish_file_unexpected_error_on_get_sha(monkeypatch) -> None:
    """A generic Exception (not HTTPStatusError / GitHubPublishError) from
    _get_file_sha is caught and returns False."""

    class _FakeClient:
        async def __aenter__(self) -> _FakeClient:
            return self

        async def __aexit__(self, *exc: object) -> None:
            return None

        async def get(self, url: str, **kw: object) -> _FakeResp:
            raise RuntimeError("unexpected internal failure")

        async def put(self, url: str, **kw: object) -> _FakeResp:
            raise AssertionError("should not reach PUT")

        async def aclose(self) -> None:
            return None

    pub = _make_publisher(monkeypatch, _FakeClient())
    result = await pub.publish_file("f.txt", "data", "msg")
    assert result is False


# ---------------------------------------------------------------------------
# publish_file: network error on PUT after rate-limit retry
# ---------------------------------------------------------------------------


async def test_publish_file_network_error_on_rate_limit_retry(monkeypatch) -> None:
    """First PUT is rate-limited. Retry PUT raises RequestError -> False."""
    slept: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    class _FakeClient:
        def __init__(self) -> None:
            self.put_count = 0

        async def __aenter__(self) -> _FakeClient:
            return self

        async def __aexit__(self, *exc: object) -> None:
            return None

        async def get(self, url: str, **kw: object) -> _FakeResp:
            return _FakeResp(200, json_data={"sha": "abc"})

        async def put(self, url: str, **kw: object) -> _FakeResp:
            self.put_count += 1
            if self.put_count == 1:
                return _FakeResp(
                    403,
                    headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1"},
                )
            raise httpx.ConnectError("connection refused on retry")

        async def aclose(self) -> None:
            return None

    pub = _make_publisher(monkeypatch, _FakeClient())
    result = await pub.publish_file("f.txt", "data", "msg")
    assert result is False
    assert len(slept) == 1


# ---------------------------------------------------------------------------
# publish_file: 422 with non-JSON body
# ---------------------------------------------------------------------------


async def test_publish_file_422_invalid_json(monkeypatch) -> None:
    """422 where response.json() raises -> falls back to response.text."""

    class _FakeClient:
        async def __aenter__(self) -> _FakeClient:
            return self

        async def __aexit__(self, *exc: object) -> None:
            return None

        async def get(self, url: str, **kw: object) -> _FakeResp:
            return _FakeResp(404)

        async def put(self, url: str, **kw: object) -> _FakeResp:
            # No json_data -> _FakeResp.json() raises ValueError
            return _FakeResp(422, text="raw error text")

        async def aclose(self) -> None:
            return None

    pub = _make_publisher(monkeypatch, _FakeClient())
    result = await pub.publish_file("f.txt", "data", "msg")
    assert result is False


# ---------------------------------------------------------------------------
# publish_file: unexpected HTTP status (not explicitly handled)
# ---------------------------------------------------------------------------


async def test_publish_file_unexpected_status_code(monkeypatch) -> None:
    """Unexpected HTTP status (401) on PUT triggers raise_for_status -> False."""

    class _FakeClient:
        async def __aenter__(self) -> _FakeClient:
            return self

        async def __aexit__(self, *exc: object) -> None:
            return None

        async def get(self, url: str, **kw: object) -> _FakeResp:
            return _FakeResp(200, json_data={"sha": "abc"})

        async def put(self, url: str, **kw: object) -> _FakeResp:
            return _FakeResp(401, text="Unauthorized")

        async def aclose(self) -> None:
            return None

    pub = _make_publisher(monkeypatch, _FakeClient())
    result = await pub.publish_file("f.txt", "data", "msg")
    assert result is False


async def test_publish_file_2xx_non_200_201(monkeypatch) -> None:
    """A 2xx response that is not 200/201 (e.g. 202) reaches the final
    ``return False`` after ``raise_for_status()`` (line 317)."""

    class _FakeClient:
        async def __aenter__(self) -> _FakeClient:
            return self

        async def __aexit__(self, *exc: object) -> None:
            return None

        async def get(self, url: str, **kw: object) -> _FakeResp:
            return _FakeResp(200, json_data={"sha": "abc"})

        async def put(self, url: str, **kw: object) -> _FakeResp:
            return _FakeResp(202, json_data={"status": "accepted"})

        async def aclose(self) -> None:
            return None

    pub = _make_publisher(monkeypatch, _FakeClient())
    result = await pub.publish_file("f.txt", "data", "msg")
    assert result is False
