"""Async GitHub API client for fetching files from repos.

Wraps the GitHub Contents API (https://docs.github.com/rest/repos/contents).
Handles authentication, rate limits, and 404s gracefully.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import logging
import time
from typing import Any
from urllib.parse import quote, urlparse

import httpx

logger = logging.getLogger(__name__)

# Seconds to wait when primary rate limit is exhausted (fallback, normally
# derived from X-RateLimit-Reset header).
_DEFAULT_RATELIMIT_WAIT = 60.0
_TRUSTED_RAW_HOSTS = {"raw.githubusercontent.com"}
_RAW_FETCH_ATTEMPTS = 3


def _clean_repo_path(path: str) -> str:
    """Normalize and validate a GitHub repository path."""
    path = (path or "").strip().replace("\\", "/").strip("/")
    if not path:
        return ""
    parts = [part for part in path.split("/") if part]
    if any(part in (".", "..") for part in parts):
        raise ValueError(f"unsafe repository path: {path!r}")
    return "/".join(parts)


def _quote_path(path: str) -> str:
    """URL-quote a repository path while preserving separators."""
    clean = _clean_repo_path(path)
    return "/".join(quote(part, safe="") for part in clean.split("/")) if clean else ""


def _contents_url(owner: str, repo: str, path: str) -> str:
    """Build a safe GitHub Contents API URL path."""
    owner_q = quote(str(owner).strip(), safe="")
    repo_q = quote(str(repo).strip(), safe="")
    path_q = _quote_path(path)
    suffix = f"/{path_q}" if path_q else ""
    return f"/repos/{owner_q}/{repo_q}/contents{suffix}"


def _raw_url(owner: str, repo: str, branch: str, path: str) -> str:
    """Build a safe raw.githubusercontent.com URL."""
    owner_q = quote(str(owner).strip(), safe="")
    repo_q = quote(str(repo).strip(), safe="")
    branch_q = quote(str(branch).strip(), safe="")
    path_q = _quote_path(path)
    return f"https://raw.githubusercontent.com/{owner_q}/{repo_q}/{branch_q}/{path_q}"


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

    def _raw_headers(self) -> dict[str, str]:
        """Headers for raw file downloads. Never include bearer auth."""
        return {
            "User-Agent": self.USER_AGENT,
            "Accept": "text/plain,*/*",
        }

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
            - Empty list ``[]`` or ``""`` for 404s (depending on parse_json)

        Raises:
            GitHubRateLimitError: if rate limited and wait time exceeds a sane bound.
            httpx.HTTPStatusError: for other non-2xx statuses.
        """
        client = await self._get_client()
        # Bound concurrent API calls globally (see _api_semaphore).  Acquiring
        # per-request (rather than per caller) means list_repo_contents,
        # fetch_file and retries are all bounded even when fetch_directory
        # recurses concurrently.
        async with self._api_semaphore:
            response = await client.request(method, url, params=params)

        # --- rate limit handling ---
        # Primary limit: 403 + X-RateLimit-Remaining: "0".
        # Secondary limit (abuse detection): 403 + Retry-After, often with
        # remaining > 0.  Without the Retry-After branch a secondary limit
        # surfaces as HTTPStatusError and silently drops files/dirs.
        if response.status_code == 403:
            remaining = response.headers.get("X-RateLimit-Remaining")
            retry_after = response.headers.get("Retry-After")
            if remaining == "0" or retry_after:
                if retry_after:
                    try:
                        wait = max(1.0, float(retry_after))
                    except (TypeError, ValueError):
                        wait = _DEFAULT_RATELIMIT_WAIT
                else:
                    wait = _DEFAULT_RATELIMIT_WAIT
                    reset = response.headers.get("X-RateLimit-Reset")
                    if reset:
                        with contextlib.suppress(TypeError, ValueError):
                            # X-RateLimit-Reset is a unix timestamp (UTC, in seconds).
                            wait = max(1.0, float(reset) - time.time())
                # Cap the wait so we never block forever in a pipeline.
                if wait > 300:
                    raise GitHubRateLimitError(
                        f"GitHub rate limit exhausted; reset in {wait:.0f}s (>300s cap).",  # noqa: E501
                    )
                logger.warning(
                    "GitHub rate limit hit; sleeping %.1fs before retrying %s",
                    wait,
                    url,
                )
                await asyncio.sleep(wait)
                async with self._api_semaphore:
                    response = await client.request(method, url, params=params)
                if response.status_code == 403:
                    remaining = response.headers.get("X-RateLimit-Remaining")
                    retry_after = response.headers.get("Retry-After")
                    if remaining == "0" or retry_after:
                        raise GitHubRateLimitError(
                            "GitHub rate limit exhausted after retry.",
                        )

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
        url = _contents_url(owner, repo, path)
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
                },
            )
        return result

    async def fetch_raw_file(self, download_url: str) -> str:
        """Fetch raw file content from a ``download_url``.

        Returns empty string on 404.
        """
        parsed = urlparse(download_url)
        if parsed.scheme != "https" or parsed.netloc.lower() not in _TRUSTED_RAW_HOSTS:
            logger.warning("Rejected untrusted raw download URL: %s", download_url)
            return ""

        response: httpx.Response | None = None
        for attempt in range(1, _RAW_FETCH_ATTEMPTS + 1):
            try:
                # Bound concurrent raw downloads too — raw hosts also
                # rate-limit, and a burst of parallel fetches can trigger it.
                async with (
                    httpx.AsyncClient(
                        timeout=self._timeout,
                        follow_redirects=True,
                    ) as client,
                    self._api_semaphore,
                ):
                    response = await client.get(
                        download_url,
                        headers=self._raw_headers(),
                    )
                break
            except httpx.RequestError as exc:
                if attempt < _RAW_FETCH_ATTEMPTS:
                    await asyncio.sleep(0.5 * attempt)
                    continue
                logger.warning(
                    "Failed to fetch raw file %s after %d attempts: %s: %s",
                    download_url,
                    _RAW_FETCH_ATTEMPTS,
                    type(exc).__name__,
                    exc,
                )
                return ""
        # The loop above either breaks (response set) or returns "" on exhaustion.
        if response is None:
            logger.warning(
                "fetch_raw_file: no response after retries for %s",
                download_url,
            )
            return ""
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
        url = _contents_url(owner, repo, path)
        try:
            data = await self._request(
                "GET",
                url,
                params={"ref": branch},
                parse_json=True,
            )
        except GitHubRateLimitError:
            raw_url = _raw_url(owner, repo, branch, path)
            logger.warning(
                "GitHub Contents API rate-limited for %s/%s/%s; falling back to raw URL.",  # noqa: E501
                owner,
                repo,
                path,
            )
            return await self.fetch_raw_file(raw_url)
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
        ``max_files`` (default 200) caps the total number of files *returned*
        across the entire recursion — once reached, remaining entries are
        skipped with a warning.  This prevents a root-level fetch on a
        large repo from making hundreds of API calls.  The budget counts
        successful fetches (not attempts), so empty/failed files do not
        starve subsequent subdirectories.

        Files at each directory level and subdirectory recursions are
        fetched **concurrently**, bounded by the client's internal
        semaphore (``max_concurrent_api``), rather than sequentially —
        dramatically reducing wall time for repos with many files.  The
        ``max_files`` budget is split across subdirectories *before* they
        are launched in parallel, so it remains a true global cap rather
        than a per-branch allowance that can explode API calls.

        Returns a list of ``(path, content)`` tuples where ``path`` is the
        full repo path of the file (e.g. ``"subdir/file.txt"``), enabling
        callers to filter on either the full path or the basename.  Empty
        list on 404 or empty dir.
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
                "max_depth reached for %s/%s/%s — skipping.",
                owner,
                repo,
                path,
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
            file_path = entry.get("path") or name
            download_url = entry.get("download_url")
            if not download_url:
                # Fallback to Contents API fetch_file (handles base64 payload).
                # Concurrency is bounded by _api_semaphore inside _request.
                try:
                    content = await self.fetch_file(owner, repo, file_path, branch)
                except Exception as exc:
                    logger.warning("Failed to fetch %s: %s", name, exc)
                    return None
            else:
                # Concurrency is bounded by _api_semaphore inside fetch_raw_file.
                try:
                    content = await self.fetch_raw_file(download_url)
                except Exception as exc:
                    logger.warning("Failed to fetch raw %s: %s", download_url, exc)
                    return None
            if content:
                return (file_path, content)
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
                *(_fetch_one_file(e) for e in files_to_fetch),
            )
            fetched_here = 0
            for item in file_results:
                if item is not None:
                    results.append(item)
                    fetched_here += 1
            # Decrement by *successful* fetches so max_files is a true cap on
            # files returned (matching the docstring), not on failed attempts.
            # The previous code used len(files_to_fetch) (attempts), which
            # consumed budget for empty/failed files and starved subdirectories.
            remaining_budget -= fetched_here

        # --- Concurrent subdirectory recursion ---
        if remaining_budget > 0 and dir_entries:
            # Split the remaining budget across subdirectories BEFORE launching
            # them concurrently.  Pre-allocating shares (instead of handing each
            # subdir the full remaining budget) keeps max_files a true global
            # cap while still recursing in parallel for wall-time.
            n_dirs = len(dir_entries)
            base = remaining_budget // n_dirs if n_dirs else 0
            extra = remaining_budget % n_dirs if n_dirs else 0
            sub_budgets = [base + (1 if i < extra else 0) for i in range(n_dirs)]

            async def _recurse_subdir(
                entry: dict,
                sub_budget: int,
            ) -> list[tuple[str, str]]:
                if sub_budget <= 0:
                    return []
                # Use `or` fallback so a present-but-None "path" (which GitHub
                # never sends but defensive code should survive) doesn't crash
                # the recursive fetch_directory with NoneType.strip().
                sub_path = entry.get("path") or entry.get("name") or ""
                try:
                    return await self.fetch_directory(
                        owner,
                        repo,
                        sub_path,
                        branch,
                        max_depth=max_depth - 1,
                        max_files=sub_budget,
                    )
                except Exception as exc:
                    logger.warning("Subdirectory recursion failed: %s", exc)
                    return []

            sub_results = await asyncio.gather(
                *(
                    _recurse_subdir(e, b)
                    for e, b in zip(dir_entries, sub_budgets, strict=False)
                ),
            )
            for sub in sub_results:
                results.extend(sub)
        elif remaining_budget <= 0 and dir_entries:
            logger.warning(
                "max_files budget exhausted — skipping %d subdirectories in %s/%s/%s.",
                len(dir_entries),
                owner,
                repo,
                path,
            )

        return results
