"""Reproduction tests for bugs found in src/sources/github.py.

Each test demonstrates a concrete defect BEFORE the fix. Run with:
    python -m pytest tests/test_github_debug_repro.py -q
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from src.sources.github import GitHubClient


# ---------------------------------------------------------------------------
# Bug 1: max_files budget inconsistency.
# Current level decrements budget by *attempts* (len(files_to_fetch)) while
# subdir recursion decrements by *successes* (len(sub)).  When files at the
# current level fail (empty content), budget is consumed for nothing and the
# global "files fetched" cap is miscounted.
# ---------------------------------------------------------------------------
def test_budget_counts_attempts_not_successes() -> None:
    client = GitHubClient()

    # Root listing: 3 "files" (no download_url → fetch_file fallback) + 1 subdir.
    root_listing = [
        {"name": "f1.txt", "path": "f1.txt", "download_url": None, "type": "file"},
        {"name": "f2.txt", "path": "f2.txt", "download_url": None, "type": "file"},
        {"name": "f3.txt", "path": "f3.txt", "download_url": None, "type": "file"},
        {"name": "sub", "path": "sub", "download_url": None, "type": "dir"},
    ]
    sub_listing = [
        {"name": "s1.txt", "path": "sub/s1.txt", "download_url": None, "type": "file"},
        {"name": "s2.txt", "path": "sub/s2.txt", "download_url": None, "type": "file"},
    ]

    call_log: list[str] = []

    async def fake_list(owner, repo, path, branch="main"):
        call_log.append(f"list:{path}")
        return root_listing if path == "" or path == "root" else sub_listing

    async def fake_fetch_file(owner, repo, path, branch="main"):
        # Root files return EMPTY (simulate 404/empty); subdir files return data.
        if path.startswith("sub/"):
            return f"DATA:{path}"
        return ""

    monkeypatch_list = fake_list
    monkeypatch_ff = fake_fetch_file

    client.list_repo_contents = monkeypatch_list  # type: ignore[method-assign]
    client.fetch_file = monkeypatch_ff  # type: ignore[method-assign]
    client.fetch_raw_file = lambda *a, **k: asyncio.sleep(0, result="")  # type: ignore[method-assign]

    # max_files=3: 3 root files "attempted" (all empty). With attempt-counting,
    # budget hits 0 and the subdir is never recursed → 0 files total.
    # With success-counting, root contributes 0 successes, so the subdir (2
    # files) should still be fetched → 2 files total.
    results = asyncio.run(
        client.fetch_directory("o", "r", "root", "main", max_depth=2, max_files=3)
    )

    # The subdir recursion should still happen because no real files were fetched.
    assert any("sub" in (p or "") for p, _ in results), (
        f"subdir files lost due to attempt-counting budget bug: {results!r}; "
        f"calls={call_log!r}"
    )


# ---------------------------------------------------------------------------
# Bug 2: fetch_directory recursion uses entry.get("path", entry.get("name", ""))
# which returns None when the "path" key EXISTS with value None.  The recursive
# call then does None.strip("/") → AttributeError, silently skipping the subdir.
# ---------------------------------------------------------------------------
def test_recursion_handles_none_path() -> None:
    client = GitHubClient()

    root_listing = [
        {"name": "sub", "path": None, "download_url": None, "type": "dir"},
    ]

    async def fake_list(owner, repo, path, branch="main"):
        if path in ("", "root"):
            return root_listing
        # If we get here, recursion used a real path (the name fallback).
        return [
            {
                "name": "x.txt",
                "path": f"{path}/x.txt",
                "download_url": None,
                "type": "file",
            }
        ]

    async def fake_fetch_file(owner, repo, path, branch="main"):
        return f"DATA:{path}"

    client.list_repo_contents = fake_list  # type: ignore[method-assign]
    client.fetch_file = fake_fetch_file  # type: ignore[method-assign]

    results = asyncio.run(
        client.fetch_directory("o", "r", "root", "main", max_depth=2, max_files=10)
    )
    # The subdir (name="sub") should have been recursed-into via the name
    # fallback, yielding x.txt.  Before the fix, path=None crashed recursion.
    assert len(results) == 1, f"None-path subdir was silently skipped: {results!r}"
    assert results[0][0].endswith("x.txt")


# ---------------------------------------------------------------------------
# Bug 3: rate-limit handling ignores the Retry-After header (secondary rate
# limit).  A 403 with Retry-After but X-RateLimit-Remaining != "0" is NOT
# treated as a rate limit and surfaces as HTTPStatusError / silent data loss.
# ---------------------------------------------------------------------------
def test_secondary_rate_limit_via_retry_after(monkeypatch) -> None:
    client = GitHubClient()
    attempts = {"n": 0}

    class FakeResponse:
        def __init__(self, status: int, headers: dict):
            self.status_code = status
            self.headers = headers

        def raise_for_status(self):
            if self.status_code >= 400:
                raise httpx.HTTPStatusError(
                    "err",
                    request=httpx.Request("GET", "http://x"),
                    response=self,  # type: ignore[arg-type]
                )

        def json(self):
            return {}

    class FakeClient:
        async def request(self, *a, **kw):
            attempts["n"] += 1
            if attempts["n"] == 1:
                # Secondary rate limit: 403 + Retry-After, but remaining=100.
                return FakeResponse(
                    403, {"X-RateLimit-Remaining": "100", "Retry-After": "2"}
                )
            return FakeResponse(200, {})

    async def fake_get_client():
        return FakeClient()

    async def fake_sleep(s):
        return None

    monkeypatch.setattr(client, "_get_client", fake_get_client)
    monkeypatch.setattr("src.sources.github.asyncio.sleep", fake_sleep)

    # Should NOT raise: the secondary rate limit should be waited out.
    data = asyncio.run(client._request("GET", "/repos/o/r/contents/file.txt"))
    assert data == {}
    assert attempts["n"] == 2, (
        f"expected a retry after Retry-After wait, got {attempts['n']} calls"
    )


# ---------------------------------------------------------------------------
# Bug 4 (regression): subdirectory recursion was sequential despite the
# docstring claiming concurrency.  Verify two subdirs are now recursed in
# parallel by observing overlapping list_repo_contents calls.
# ---------------------------------------------------------------------------
def test_subdir_recursion_is_concurrent() -> None:
    client = GitHubClient()
    in_flight = {"n": 0}
    overlap = {"detected": False}

    async def fake_list(owner, repo, path, branch="main"):
        if path in ("", "root"):
            return [
                {"name": "a", "path": "a", "download_url": None, "type": "dir"},
                {"name": "b", "path": "b", "download_url": None, "type": "dir"},
            ]
        in_flight["n"] += 1
        if in_flight["n"] >= 2:
            overlap["detected"] = True
        await asyncio.sleep(0.05)  # simulated latency so concurrency is observable
        in_flight["n"] -= 1
        return [
            {
                "name": "x.txt",
                "path": f"{path}/x.txt",
                "download_url": None,
                "type": "file",
            }
        ]

    async def fake_fetch_file(owner, repo, path, branch="main"):
        return f"DATA:{path}"

    client.list_repo_contents = fake_list  # type: ignore[method-assign]
    client.fetch_file = fake_fetch_file  # type: ignore[method-assign]

    asyncio.run(
        client.fetch_directory("o", "r", "root", "main", max_depth=2, max_files=10)
    )
    assert overlap["detected"], (
        "subdirectory recursions ran sequentially, not concurrently"
    )


# ---------------------------------------------------------------------------
# Bug 5 (regression): _api_semaphore only bounded _fetch_one_file, so
# list_repo_contents (and direct fetch_file / fetch_raw_file calls) escaped
# the concurrency cap.  Verify _request now acquires the semaphore by
# checking that with max_concurrent_api=1 two _request calls are serialized.
# ---------------------------------------------------------------------------
def test_request_is_bounded_by_semaphore(monkeypatch) -> None:
    client = GitHubClient(max_concurrent_api=1)
    in_flight = {"n": 0, "max": 0}

    class FakeResponse:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            return {"ok": True}

    class FakeClient:
        async def request(self, *a, **kw):
            in_flight["n"] += 1
            in_flight["max"] = max(in_flight["max"], in_flight["n"])
            await asyncio.sleep(0.03)
            in_flight["n"] -= 1
            return FakeResponse()

    async def fake_get_client():
        return FakeClient()

    monkeypatch.setattr(client, "_get_client", fake_get_client)

    async def two_concurrent_requests():
        await asyncio.gather(
            client._request("GET", "/u1"),
            client._request("GET", "/u2"),
        )

    asyncio.run(two_concurrent_requests())
    assert in_flight["max"] == 1, (
        f"semaphore did not serialize _request calls (max concurrent="
        f"{in_flight['max']}); the cap must be centralized in _request"
    )


# ---------------------------------------------------------------------------
# Regression: token (Bearer) must NEVER appear in headers for raw URLs.
# This was the original leak (shared client used _headers() for raw GET);
# the fix uses a standalone client + _raw_headers().  Lock it in.
# ---------------------------------------------------------------------------
def test_raw_url_never_carries_token(monkeypatch) -> None:
    client = GitHubClient(token="ghp_secret")
    captured: dict = {}

    class FakeResponse:
        status_code = 200
        text = "raw"

        def raise_for_status(self):
            return None

    class FakeRawClient:
        def __init__(self, *a, **kw):
            captured["init_headers"] = kw.get("headers")

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return None

        async def get(self, url, headers=None):
            captured["get_headers"] = headers
            return FakeResponse()

    monkeypatch.setattr("src.sources.github.httpx.AsyncClient", FakeRawClient)

    out = asyncio.run(
        client.fetch_raw_file("https://raw.githubusercontent.com/o/r/main/f.txt")
    )
    assert out == "raw"
    assert "Authorization" not in (captured.get("init_headers") or {})
    assert "Authorization" not in (captured.get("get_headers") or {})
    # And the shared client's default headers must not leak into raw fetches.
    assert "Bearer" not in str(captured)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
