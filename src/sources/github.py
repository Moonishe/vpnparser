"""Async GitHub API client for fetching files from repos.

Wraps the GitHub Contents API (https://docs.github.com/rest/repos/contents).
Handles authentication, rate limits, and 404s gracefully.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# Seconds to wait when primary rate limit is exhausted (fallback, normally
# derived from X-RateLimit-Reset header).
_DEFAULT_RATELIMIT_WAIT = 60.0


class GitHubRateLimitError(Exception):
    """Raised when the GitHub API rate limit is exhausted and cannot be waited out."""


class GitHubClient:
    """Async client for the GitHub Contents API.

    Lifecycle:
        Prefer using ``async with GitHubClient(...) as client:`` to ensure the
        underlying ``httpx.AsyncClient`` is closed. If used without ``async with``,
        call ``await client.aclose()`` when done (a lazily-created client will
        then be cleaned up).
    """

    USER_AGENT = "vpn-config-parser/1.0"

    # Default cap on concurrent API requests.  Prevents triggering GitHub's
    # secondary rate limit (which fires on too many simultaneous requests,
    # even when the primary hourly quota is fine).
    DEFAULT_MAX_CONCURRENT_API = 10

    def __init__(
        self,
        token: str | None = None,
        api_base: str = "https://api.github.com",
        timeout: float = 30.0,
        max_concurrent_api: int = DEFAULT_MAX_CONCURRENT_API,
    ) -> None:
        self.token = token
        self.api_base = api_base.rstrip("/")
        self._client: httpx.AsyncClient | None = None
        self._timeout = timeout
        # Lock to avoid creating multiple clients on concurrent first calls.
        self._lock = asyncio.Lock()
        # Semaphore to bound concurrent HTTP requests across all operations
        # (file fetches, directory listings).  Prevents overwhelming the API
        # when fetch_directory recurses into a large repo tree.
        self._api_semaphore = asyncio.Semaphore(max(1, max_concurrent_api))

    # --- client lifecycle ---

    def _headers(self) -> dict[str, str]:
        headers = {
            "User-Agent": self.USER_AGENT,
            "Accept": "application/vnd.github+json",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is not None:
            return self._client
        async with self._lock:
            if self._client is None:
                self._client = httpx.AsyncClient(
                    base_url=self.api_base,
                    headers=self._headers(),
                    timeout=self._timeout,
                    follow_redirects=True,
                )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> GitHubClient:
        await self._get_client()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    # --- low-level request helper ---

    async def _request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str] | None = None,
        parse_json: bool = True,
    ) -> Any:
        """Perform an HTTP request with rate-limit / 404 handling.

        Returns:
            - Parsed JSON (dict or list) when ``parse_json=True``
            - Raw text (str) when ``parse_json=False``
            - Empty list ``[]`` or empty string ``""`` for 404s (depending on parse_json)

        Raises:
            GitHubRateLimitError: if rate limited and wait time exceeds a sane bound.
            httpx.HTTPStatusError: for other non-2xx statuses.
        """
        client = await self._get_client()
        response = await client.request(method, url, params=params)

        # --- rate limit handling ---
        if response.status_code == 403:
            remaining = response.headers.get("X-RateLimit-Remaining")
            if remaining == "0":
                reset = response.headers.get("X-RateLimit-Reset")
                wait = _DEFAULT_RATELIMIT_WAIT
                if reset:
                    try:
                        # X-RateLimit-Reset is a unix timestamp (UTC, in seconds).
                        wait = max(1.0, float(reset) - time.time())
                    except (TypeError, ValueError):
                        pass
                # Cap the wait so we never block forever in a pipeline.
                if wait > 300:
                    raise GitHubRateLimitError(
                        f"GitHub rate limit exhausted; reset in {wait:.0f}s (>300s cap)."
                    )
                logger.warning(
                    "GitHub rate limit hit; sleeping %.1fs before retrying %s",
                    wait,
                    url,
                )
                await asyncio.sleep(wait)
                response = await client.request(method, url, params=params)

        # --- 404: not found → graceful empty result ---
        if response.status_code == 404:
            logger.debug("GitHub 404 for %s?%s", url, params)
            return [] if parse_json else ""

        response.raise_for_status()

        if parse_json:
            return response.json()
        return response.text

    # --- public API ---

    async def list_repo_contents(
        self,
        owner: str,
        repo: str,
        path: str,
        branch: str = "main",
    ) -> list[dict]:
        """List files in a repo directory.

        Returns a list of dicts with keys: ``name``, ``path``, ``download_url``,
        ``type`` (``"file"`` or ``"dir"``). Returns an empty list on 404.
        """
        path = path.strip("/")
        url = f"/repos/{owner}/{repo}/contents/{path}"
        data = await self._request("GET", url, params={"ref": branch}, parse_json=True)
        if isinstance(data, dict):
            # Single file returned (path points to a file, not a dir).
            data = [data]
        if not isinstance(data, list):
            logger.warning("Unexpected GitHub contents response for %s: %r", url, data)
            return []
        result: list[dict] = []
        for entry in data:
            if not isinstance(entry, dict):
                continue
            result.append(
                {
                    "name": entry.get("name", ""),
                    "path": entry.get("path", ""),
                    "download_url": entry.get("download_url"),
                    "type": entry.get("type", "file"),
                }
            )
        return result

    async def fetch_raw_file(self, download_url: str) -> str:
        """Fetch raw file content from a ``download_url``.

        Returns empty string on 404.
        """
        # download_url points to raw.githubusercontent.com, not the API base,
        # so use a standalone request (no base_url).
        client = await self._get_client()
        response = await client.get(download_url, headers=self._headers())
        if response.status_code == 404:
            logger.debug("404 fetching raw file %s", download_url)
            return ""
        response.raise_for_status()
        return response.text

    async def fetch_file(
        self,
        owner: str,
        repo: str,
        path: str,
        branch: str = "main",
    ) -> str:
        """Fetch a single file's content.

        Uses the Contents API: response includes ``content`` (base64) and/or
        ``download_url``. Falls back to ``download_url`` if ``content`` is missing
        (e.g. large files). Returns empty string on 404.
        """
        path = path.strip("/")
        url = f"/repos/{owner}/{repo}/contents/{path}"
        data = await self._request("GET", url, params={"ref": branch}, parse_json=True)
        if not isinstance(data, dict):
            logger.warning("Unexpected GitHub file response for %s: %r", url, data)
            return ""
        # Preferred: base64-encoded content payload.
        content_b64 = data.get("content")
        encoding = data.get("encoding", "base64")
        if content_b64 and encoding == "base64":
            try:
                return base64.b64decode(content_b64).decode("utf-8", errors="replace")
            except Exception as exc:
                logger.warning("Failed to decode base64 content for %s: %s", url, exc)
        # Fallback: fetch via download_url (e.g. files > 1 MB).
        download_url = data.get("download_url")
        if download_url:
            return await self.fetch_raw_file(download_url)
        return ""

    async def fetch_directory(
        self,
        owner: str,
        repo: str,
        path: str,
        branch: str = "main",
        max_depth: int = 3,
        max_files: int = 200,
    ) -> list[tuple[str, str]]:
        """Fetch all files in a directory, recursing into subdirectories.

        Recursion is bounded by ``max_depth`` (default 3) to prevent
        exhausting the API rate limit on very large repository trees.
        ``max_files`` (default 200) caps the total number of files fetched
        across the entire recursion — once reached, remaining entries are
        skipped with a warning.  This prevents a root-level fetch on a
        large repo from making hundreds of API calls.

        Files at each directory level and subdirectory recursions are
        fetched **concurrently** (bounded by the client's internal
        semaphore) rather than sequentially, dramatically reducing wall
        time for repos with many files.

        Returns a list of ``(filename, content)`` tuples. Files in
        subdirectories are flattened to just their basename. Empty list on
        404 or empty dir.
        """
        # Warn on potentially expensive root-level fetches.
        if not path.strip("/") and max_depth > 1:
            logger.warning(
                "fetch_directory on root of %s/%s with max_depth=%d — "
                "this may make many API calls. Consider reducing max_depth "
                "or specifying a subdirectory path.",
                owner,
                repo,
                max_depth,
            )

        if max_depth <= 0:
            logger.debug(
                "max_depth reached for %s/%s/%s — skipping.", owner, repo, path
            )
            return []

        entries = await self.list_repo_contents(owner, repo, path, branch)
        results: list[tuple[str, str]] = []

        # Separate files and directories for concurrent processing.
        file_entries: list[dict] = []
        dir_entries: list[dict] = []
        for entry in entries:
            etype = entry.get("type", "file")
            if etype == "file":
                file_entries.append(entry)
            elif etype == "dir":
                dir_entries.append(entry)

        # --- Concurrent file fetches at this level ---
        async def _fetch_one_file(entry: dict) -> tuple[str, str] | None:
            name = entry.get("name", "")
            download_url = entry.get("download_url")
            if not download_url:
                # Fallback to Contents API fetch_file (handles base64 payload).
                try:
                    async with self._api_semaphore:
                        content = await self.fetch_file(
                            owner, repo, entry.get("path", name), branch
                        )
                except Exception as exc:
                    logger.warning("Failed to fetch %s: %s", name, exc)
                    return None
            else:
                try:
                    async with self._api_semaphore:
                        content = await self.fetch_raw_file(download_url)
                except Exception as exc:
                    logger.warning("Failed to fetch raw %s: %s", download_url, exc)
                    return None
            if content:
                return (name, content)
            return None

        # Respect max_files: only fetch up to the remaining budget.
        remaining_budget = max_files
        if remaining_budget <= 0:
            logger.warning(
                "max_files budget exhausted in %s/%s/%s — skipping %d files.",
                owner,
                repo,
                path,
                len(file_entries),
            )
        else:
            files_to_fetch = file_entries[:remaining_budget]
            skipped = len(file_entries) - len(files_to_fetch)
            if skipped > 0:
                logger.warning(
                    "max_files cap reached in %s/%s/%s — skipping %d of %d files.",
                    owner,
                    repo,
                    path,
                    skipped,
                    len(file_entries),
                )
            file_results = await asyncio.gather(
                *(_fetch_one_file(e) for e in files_to_fetch)
            )
            for item in file_results:
                if item is not None:
                    results.append(item)
            remaining_budget -= len(files_to_fetch)

        # --- Concurrent subdirectory recursion ---
        if remaining_budget > 0 and dir_entries:
            subdir_tasks = [
                self.fetch_directory(
                    owner,
                    repo,
                    entry.get("path", entry.get("name", "")),
                    branch,
                    max_depth=max_depth - 1,
                    max_files=remaining_budget,
                )
                for entry in dir_entries
            ]
            subdir_results = await asyncio.gather(*subdir_tasks, return_exceptions=True)
            for sub in subdir_results:
                if isinstance(sub, BaseException):
                    logger.warning("Subdirectory recursion failed: %s", sub)
                    continue
                # Track how many files the sub-fetch consumed.
                results.extend(sub)
                remaining_budget -= len(sub)
        elif remaining_budget <= 0 and dir_entries:
            logger.warning(
                "max_files budget exhausted — skipping %d subdirectories in %s/%s/%s.",
                len(dir_entries),
                owner,
                repo,
                path,
            )

        return results
