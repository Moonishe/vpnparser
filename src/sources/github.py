"""Async GitHub API client for fetching files from repos.

Wraps the GitHub Contents API (https://docs.github.com/rest/repos/contents).
Handles authentication, rate limits, and 404s gracefully.

GitHub Enterprise is out of scope: ``api_base`` is configurable, but raw
downloads are pinned to ``_TRUSTED_RAW_HOSTS`` (a fixed literal), which is the
entire SSRF guard for that path.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import logging
import random
import time
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import quote, urlparse

import httpx

from src.utils.http import read_limited_text
from src.utils.net import is_safe_public_url, redact_proxy_url

logger = logging.getLogger(__name__)

# Seconds to wait when primary rate limit is exhausted (fallback, normally
# derived from X-RateLimit-Reset header).
_DEFAULT_RATELIMIT_WAIT = 60.0

#: Pause before the single 5xx retry (see ``_request``).
_SERVER_ERROR_RETRY_DELAY = 2.0
_TRUSTED_RAW_HOSTS = {"raw.githubusercontent.com"}
_RAW_FETCH_ATTEMPTS = 3

#: A single Contents API directory listing is capped at 1000 entries with no
#: pagination endpoint; directories beyond that are only fully visible through
#: the Git Trees API (see ``_list_repo_tree``).
_CONTENTS_LISTING_LIMIT = 1000

#: Statuses worth retrying on a raw download: the raw host throttles bursts
#: with 429, and 5xx are transient by definition.
_RETRIABLE_RAW_STATUSES = frozenset({429, 500, 502, 503, 504})

#: Upper bound on a honoured ``Retry-After``, so a hostile header cannot park
#: the pipeline for hours.
_MAX_RETRY_AFTER = 30.0

#: Hard cap on a single raw file. ``max_files``/``max_concurrent_urls`` multiply
#: whatever one download costs, so an oversized blob must not travel further
#: into the parsers (the httpx timeout bounds idle time, not volume). Enforced
#: while streaming, so an oversized body is never fully buffered.
MAX_RAW_FILE_BYTES = 12 * 1024 * 1024

#: Statuses treated as a refusal in fetch_raw_file: the trusted-host allow-list
#: below is the whole SSRF guard for raw downloads, and a redirect destination
#: cannot be re-validated against it without re-entering the fetch path, so raw
#: redirects are rejected rather than followed. (GitHub Enterprise is out of
#: scope: its raw host would have to join _TRUSTED_RAW_HOSTS, which is
#: deliberately a fixed literal.) 300/305/306 are included for completeness
#: (httpx would otherwise treat them as a normal body); 304 (Not Modified)
#: is deliberately excluded — it is not a redirect.
_RAW_REDIRECT_STATUSES = frozenset({300, 301, 302, 303, 305, 306, 307, 308})


def _retry_after_delay(header_value: str | None, fallback: float) -> float:
    """Return the delay to wait before a retry, honouring ``Retry-After``.

    ``Retry-After`` may be a delta in seconds or an absolute HTTP-date (RFC 7231).
    Only the numeric form used to be parsed; the date form fell back to a short
    backoff and could hammer a throttled endpoint.

    Raises:
        GitHubRateLimitError: if the requested wait exceeds 300s — fail fast
            instead of parking the pipeline (mirrors the ``>300s`` cap in
            :meth:`GitHubClient._request`).
    """
    if not header_value:
        return fallback
    try:
        seconds = float(header_value)
    except (TypeError, ValueError):
        seconds = None
    if seconds is None:
        try:
            parsed = parsedate_to_datetime(header_value)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            seconds = (parsed - datetime.now(UTC)).total_seconds()
        except (TypeError, ValueError, OverflowError):
            return fallback
    if seconds > 300:
        raise GitHubRateLimitError(
            f"GitHub rate limit wait {seconds:.0f}s exceeds >300s cap.",
        )
    return min(max(0.0, seconds), _MAX_RETRY_AFTER)


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
    # Branch names may contain "/" (feature/test): the raw host does NOT
    # decode %2F in the ref position, so percent-encoding the slash made the
    # URL 404 for every file of such a branch.
    branch_q = quote(str(branch).strip(), safe="/")
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
        #: Separate client for raw downloads — never carries auth headers.
        self._raw_client: httpx.AsyncClient | None = None
        self._api_base_checked = False
        self._timeout = timeout
        # Lock to avoid creating multiple clients on concurrent first calls.
        self._lock = asyncio.Lock()
        # Semaphore to bound concurrent HTTP requests across all operations
        # (file fetches, directory listings).  Prevents overwhelming the API
        # when fetch_directory recurses into a large repo tree. Capped at 50:
        # a caller-supplied burst must not trip the secondary rate limit on
        # its own.
        self._api_semaphore = asyncio.Semaphore(max(1, min(max_concurrent_api, 50)))
        #: Repo tree cache: (owner, repo, branch) -> in-flight or settled fetch.
        #: A settled future carries the recursive Trees API listing (or
        #: ``None``); failed fetches are removed again so a transient error
        #: cannot pin a repo to "no tree". Parallel callers await the very
        #: same future, so concurrent recursive listings share one request.
        self._tree_cache: dict[
            tuple[str, str, str],
            asyncio.Future[list[dict[str, object]] | None],
        ] = {}

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
        # Fail closed: never issue requests (and, when a token is set,
        # never send the bearer credential) to a host that is not a
        # verified public https endpoint. A misconfigured or
        # attacker-controlled ``github_api_base`` could otherwise be an
        # SSRF pivot into internal services or the cloud metadata API.
        # Validated on every call, not just once: DNS rebinding (TTL 0)
        # can swap the address between the first check and a later
        # request, so a cached verdict would reopen the SSRF window.
        parts = urlparse(self.api_base)
        if parts.scheme.lower() != "https":
            raise ValueError(f"GitHub api_base must use https, got {parts.scheme!r}")
        if not await is_safe_public_url(self.api_base, timeout=5.0):
            raise ValueError(
                "Refusing to send GitHub requests to non-public "
                f"api_base {parts.hostname!r}."
            )
        self._api_base_checked = True
        if self._client is not None:
            return self._client
        async with self._lock:
            if self._client is None:
                self._client = httpx.AsyncClient(
                    base_url=self.api_base,
                    headers=self._headers(),
                    timeout=self._timeout,
                    follow_redirects=False,
                )
        return self._client

    async def _get_raw_client(self) -> httpx.AsyncClient:
        """Lazily create the client for raw.githubusercontent.com fetches.

        A SECOND client, deliberately: the API client's default headers carry
        ``Authorization: Bearer <token>``, and httpx merges client headers
        with per-request ones — routing raw fetches through it would leak the
        token to the raw host. The raw client has no base_url and no auth
        headers at all (see ``_raw_headers``), and shares the API's semaphore
        so raw downloads cannot burst past the same limit.
        """
        if self._raw_client is not None:
            return self._raw_client
        async with self._lock:
            if self._raw_client is None:
                self._raw_client = httpx.AsyncClient(
                    timeout=self._timeout,
                    follow_redirects=False,
                )
        return self._raw_client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
        if self._raw_client is not None:
            await self._raw_client.aclose()
            self._raw_client = None
        # Drop the cached validation so a reused instance re-checks api_base.
        self._api_base_checked = False

    async def __aenter__(self) -> GitHubClient:
        await self._get_client()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: object,
    ) -> None:
        await self.aclose()

    # --- low-level request helper ---

    @staticmethod
    def _check_no_redirect(response: httpx.Response, url: str) -> None:
        """Reject 3xx explicitly: the client never follows redirects."""
        status = getattr(response, "status_code", 0)
        if 300 <= status < 400:
            msg = f"Unexpected redirect {status} for {url!r} — refusing to follow"
            raise ValueError(msg)

    @staticmethod
    def _check_response_size(response: httpx.Response, url: str) -> None:
        """Reject API bodies larger than 10 MiB before parsing."""
        headers = getattr(response, "headers", {}) or {}
        get_header = getattr(headers, "get", None)
        length_raw = None
        if callable(get_header):
            length_raw = get_header("Content-Length")
            if length_raw is None:
                length_raw = get_header("content-length")
        if length_raw is not None:
            try:
                length = int(str(length_raw))
            except (TypeError, ValueError):
                length = None
            if length is not None and length > 10 * 1024 * 1024:
                msg = f"GitHub API response too large for {url!r}"
                raise ValueError(msg)
        content = getattr(response, "content", None)
        if isinstance(content, (bytes, bytearray)) and len(content) > 10 * 1024 * 1024:
            msg = f"GitHub API response too large for {url!r}"
            raise ValueError(msg)

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
            ValueError: on an unexpected redirect or an oversized body.
        """
        client = await self._get_client()
        # Wall-clock budget for the whole request chain (mirrors the manager's
        # timeout*DOWNLOAD_TIMEOUT_FACTOR): httpx timeouts restart per chunk.
        budget = self._timeout * 4 or 120
        async with asyncio.timeout(budget):
            # Bound concurrent API calls globally (see _api_semaphore).
            # Acquiring per-request (rather than per caller) means
            # list_repo_contents, fetch_file and retries are all bounded even
            # when fetch_directory recurses concurrently.
            async with self._api_semaphore:
                response = await client.request(method, url, params=params)
            self._check_no_redirect(response, url)
            self._check_response_size(response, url)

            # --- rate limit handling ---
            # Primary limit: 403 + X-RateLimit-Remaining: "0".
            # Secondary limit (abuse detection): 403 or 429, often with
            # Retry-After and remaining > 0.  Without the 429 branch a secondary
            # limit surfaces as HTTPStatusError and silently drops files/dirs.
            # The wait carries jitter: every in-flight request derives the same
            # wait from the same X-RateLimit-Reset, and retrying in lockstep is
            # exactly the burst that trips the secondary limit a second time.
            if response.status_code in (403, 429):
                remaining = response.headers.get("X-RateLimit-Remaining")
                retry_after = response.headers.get("Retry-After")
                if remaining == "0" or retry_after:
                    raw_wait: float | None = None
                    if retry_after:
                        try:
                            raw_wait = max(1.0, float(retry_after))
                        except (TypeError, ValueError):
                            raw_wait = None
                            wait = _DEFAULT_RATELIMIT_WAIT
                        else:
                            # Hard cap: a hostile Retry-After must fail fast
                            # instead of parking the pipeline for minutes.
                            if raw_wait > 300:
                                raise GitHubRateLimitError(
                                    f"GitHub rate limit wait {raw_wait:.0f}s "
                                    "exceeds >300s cap.",
                                )
                            wait = min(raw_wait, _MAX_RETRY_AFTER)
                    else:
                        wait = _DEFAULT_RATELIMIT_WAIT
                        reset = response.headers.get("X-RateLimit-Reset")
                        if reset:
                            with contextlib.suppress(TypeError, ValueError):
                                # X-RateLimit-Reset is a unix timestamp (UTC).
                                # Capped like Retry-After: never park the
                                # pipeline for hours on a hostile header.
                                raw_wait = max(1.0, float(reset) - time.time())
                                if raw_wait > 300:
                                    raise GitHubRateLimitError(
                                        f"GitHub rate limit wait {raw_wait:.0f}s "
                                        "exceeds >300s cap.",
                                    )
                                wait = min(
                                    raw_wait,
                                    _MAX_RETRY_AFTER,
                                )
                    wait *= 1.0 + random.random() * 0.25
                    logger.warning(
                        "GitHub rate limit hit; sleeping %.1fs before retrying %s",
                        wait,
                        url,
                    )
                    await asyncio.sleep(wait)
                    async with self._api_semaphore:
                        response = await client.request(method, url, params=params)
                    self._check_no_redirect(response, url)
                    self._check_response_size(response, url)
                    if response.status_code in (403, 429):
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

            # --- transient 5xx: one retry with a short backoff ---
            # A 502/503/504 from api.github.com used to surface as
            # HTTPStatusError and cost the file (or the whole directory) for the
            # run; GitHub's own status page documents these as transient. A plain
            # 500 is deliberately NOT retried here (unlike the publisher/raw
            # clients): for the Contents/Trees API it usually signals a problem
            # with the request itself, not a blip. The retried answer is re-run
            # through the SAME handling (404-empty, rate-limit wait): a 503
            # flipping to 404 must read as "gracefully empty", not as a failure,
            # and a flip to 429 must be waited out.
            if response.status_code in (502, 503, 504):
                logger.warning(
                    "GitHub %d for %s; retrying once after backoff.",
                    response.status_code,
                    url,
                )
                delay = min(
                    _SERVER_ERROR_RETRY_DELAY * (2**0) + random.uniform(0, 1), 30.0
                )
                await asyncio.sleep(delay)
                async with self._api_semaphore:
                    response = await client.request(method, url, params=params)
                self._check_no_redirect(response, url)
                self._check_response_size(response, url)
                if response.status_code == 404:
                    logger.debug("GitHub 404 for %s?%s", url, params)
                    return [] if parse_json else ""
                if response.status_code in (403, 429):
                    remaining = response.headers.get("X-RateLimit-Remaining")
                    retry_after = response.headers.get("Retry-After")
                    if remaining == "0" or retry_after:
                        raise GitHubRateLimitError(
                            "GitHub rate limit hit on a retried (5xx) request.",
                        )

            self._check_no_redirect(response, url)
            self._check_response_size(response, url)
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
    ) -> list[dict[str, object]]:
        """List files in a repo directory.

        Returns a list of dicts with keys: ``name``, ``path``, ``download_url``,
        ``type`` (``"file"`` or ``"dir"``). Returns an empty list on 404.

        The Contents API hard-caps a directory listing at 1000 entries with no
        pagination; when the response hits that cap the listing is re-read
        through the recursive Git Trees API so nothing beyond the first 1000
        files is silently dropped from a large directory.
        """
        url = _contents_url(owner, repo, path)
        data = await self._request("GET", url, params={"ref": branch}, parse_json=True)
        if isinstance(data, dict):
            # Single file returned (path points to a file, not a dir).
            data = [data]
        if not isinstance(data, list):
            logger.warning(
                "Unexpected GitHub contents response for %s: %s",
                url,
                # download_url entries may carry ?token= for private repos.
                redact_proxy_url(repr(data)[:1000]),
            )
            return []
        if len(data) >= _CONTENTS_LISTING_LIMIT:
            # Likely truncated: the only complete view of a directory this size
            # is the recursive tree. On failure keep the partial listing — it
            # is no worse than what every previous run got.
            tree = await self._list_repo_tree(owner, repo, path, branch)
            if tree is not None:
                return tree
        result: list[dict[str, object]] = []
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

    async def _list_repo_tree(
        self,
        owner: str,
        repo: str,
        path: str,
        branch: str,
    ) -> list[dict[str, object]] | None:
        """Return the entries under *path* via the Git Trees API (recursive).

        ``GET /repos/{owner}/{repo}/git/trees/{branch}?recursive=1`` walks the
        whole tree in one request, so a directory with more entries than the
        Contents API listing cap is only fully visible through it. Only the
        direct children of *path* are returned, mapped to the same shape as
        :meth:`list_repo_contents` (``download_url`` is always ``None`` — the
        Trees API does not carry it, and callers fall back to the Contents
        API per file, which does).

        Returns ``None`` when the tree cannot be fetched (rate limit beyond
        the wait bound, missing ref, truncated payload); the caller then
        keeps its possibly truncated Contents listing.
        """
        key = (
            str(owner).strip().lower(),
            str(repo).strip().lower(),
            str(branch).strip(),
        )
        if key not in self._tree_cache:
            # The first caller starts the fetch and publishes the future
            # BEFORE awaiting, so concurrent recursive listings (fetch_directory
            # gathers subdirectories in parallel) join the same in-flight
            # request instead of issuing a duplicate Trees API call each.
            future: asyncio.Future[list[dict[str, object]] | None] = (
                asyncio.ensure_future(self._fetch_repo_tree(owner, repo, branch))
            )
            self._tree_cache[key] = future
        else:
            future = self._tree_cache[key]
        try:
            tree = await future
        except BaseException:
            # A failed or cancelled future must never stay cached: the first
            # waiter's timeout/shutdown would otherwise cancel the shared
            # future and poison it for every later caller, turning one
            # source's hiccup into a run-wide CancelledError. Successful
            # trees stay cached (see below); anything else is retried fresh.
            if self._tree_cache.get(key) is future:
                self._tree_cache.pop(key, None)
            raise
        if tree is None:
            # Only *successful* trees are retained: a transient failure (rate
            # limit wait exceeded, network blip) must not pin this repo to an
            # eternal "no tree" state for the rest of the run.
            self._tree_cache.pop(key, None)
            return None
        # Normalize the prefix the same way URL building does: a raw path in
        # Windows style ("dir\sub") would never match any tree path, and the
        # empty result used to REPLACE a correct (possibly truncated) Contents
        # listing instead of complementing it.
        prefix = str(_clean_repo_path(path)).strip("/")
        results: list[dict[str, object]] = []
        for entry in tree:
            if not isinstance(entry, dict):
                continue
            tree_path = str(entry.get("path") or "")
            if prefix:
                if not tree_path.startswith(prefix + "/"):
                    continue
                rel = tree_path[len(prefix) + 1 :]
            else:
                rel = tree_path
            if not rel or "/" in rel:
                # Only direct children of the requested directory.
                continue
            etype = entry.get("type")
            results.append(
                {
                    "name": rel.rsplit("/", 1)[-1],
                    "path": tree_path,
                    "download_url": None,
                    "type": "file" if etype == "blob" else "dir",
                },
            )
        return results

    async def _fetch_repo_tree(
        self,
        owner: str,
        repo: str,
        branch: str,
    ) -> list[dict[str, object]] | None:
        """Fetch the recursive tree of *branch*, or ``None`` on failure."""
        url = (
            f"/repos/{quote(str(owner).strip(), safe='')}/"
            f"{quote(str(repo).strip(), safe='')}/git/trees/"
            # The whole branch, percent-encoded as ONE path segment (mirrors
            # _raw_url): a branch named "feature/test" must not turn the tree
            # ref into two path segments, which GitHub would route wrong.
            f"{quote(str(branch).strip(), safe='')}"
        )
        try:
            data = await self._request(
                "GET",
                url,
                params={"recursive": "1"},
                parse_json=True,
            )
        except Exception as exc:
            logger.warning(
                "Failed to list tree of %s/%s via Trees API: %s",
                owner,
                repo,
                exc,
            )
            return None
        if not isinstance(data, dict):
            logger.warning(
                "Unexpected GitHub trees response for %s: %s",
                url,
                # Tree payloads may embed URLs with ?token= for private repos.
                redact_proxy_url(repr(data)[:1000]),
            )
            return None
        if data.get("truncated"):
            logger.warning(
                "Tree of %s/%s is truncated by the Trees API — files beyond "
                "the truncation point are invisible.",
                owner,
                repo,
            )
            # The truncated listing must NOT replace the Contents listing it
            # is a fallback for: the requested directory may have been cut
            # off entirely, so returning it silently *lost* files. The
            # caller keeps its (capped but known-good) listing instead.
            return None
        entries = data.get("tree")
        if not isinstance(entries, list):
            return None
        return [entry for entry in entries if isinstance(entry, dict)]

    async def fetch_raw_file(self, download_url: str) -> str:
        """Fetch raw file content from a ``download_url``.

        Network errors *and* transient statuses (429 — the raw host throttles
        bursts — plus 5xx) are retried up to ``_RAW_FETCH_ATTEMPTS`` times,
        honouring ``Retry-After``. The body is streamed and dropped as soon as it
        passes ``MAX_RAW_FILE_BYTES``, so an oversized file is never buffered
        whole nor handed to the parsers.

        Returns:
            The file content, or an empty string on 404, on an untrusted URL,
            on an oversized body, or when every attempt hit a network error.

        Raises:
            httpx.HTTPStatusError: for non-retriable statuses, and for
                retriable ones that were still failing on the last attempt.
        """
        # Private repos get a ``?token=...`` on every Contents API download_url;
        # it authenticates the raw download, so no log line may carry it.
        log_url = redact_proxy_url(download_url)
        parsed = urlparse(download_url)
        if parsed.scheme != "https" or parsed.netloc.lower() not in _TRUSTED_RAW_HOSTS:
            logger.warning("Rejected untrusted raw download URL: %s", log_url)
            return ""

        for attempt in range(1, _RAW_FETCH_ATTEMPTS + 1):
            backoff = 0.5 * attempt
            retry_delay: float | None = None
            try:
                # One client per instance, not per attempt: a fresh
                # AsyncClient re-parses the CA bundle (~blocking) and
                # re-handshakes on every attempt of every file. The client is
                # the raw one — no auth headers, see _get_raw_client.
                client = await self._get_raw_client()
                # Bound concurrent raw downloads too — raw hosts also
                # rate-limit, and a burst of parallel fetches can trigger it.
                async with (
                    self._api_semaphore,
                    client.stream(
                        "GET",
                        download_url,
                        headers=self._raw_headers(),
                    ) as response,
                ):
                    if response.status_code == 404:
                        logger.debug("404 fetching raw file %s", log_url)
                        return ""
                    if response.status_code in _RAW_REDIRECT_STATUSES:
                        # Never follow a redirect from the trusted host here: the
                        # destination is not re-validated, so it could be any host
                        # (SSRF). Raw file URLs do not legitimately redirect.
                        logger.warning(
                            "Raw download %s redirects (%d) - refusing to follow.",
                            log_url,
                            response.status_code,
                        )
                        return ""
                    if response.status_code in _RETRIABLE_RAW_STATUSES:
                        # May raise GitHubRateLimitError for a hostile
                        # Retry-After (>300s): it is not an httpx error, so it
                        # bypasses the handlers below and fails fast.
                        retry_delay = _retry_after_delay(
                            response.headers.get("Retry-After"),
                            backoff,
                        )
                    response.raise_for_status()
                    # Wall-clock budget: httpx read timeouts restart per chunk,
                    # so a 1-byte/29s slow drip held the connection for hours.
                    async with asyncio.timeout(self._timeout * 4 or 120):
                        body = await read_limited_text(
                            response,
                            max_bytes=MAX_RAW_FILE_BYTES,
                        )
            except httpx.HTTPStatusError as exc:
                if retry_delay is None or attempt >= _RAW_FETCH_ATTEMPTS:
                    raise
                # Jitter like the API path: parallel fetches derive the same
                # delay from the same Retry-After and must not retry in lockstep.
                sleep_delay = retry_delay * (1.0 + random.random() * 0.25)
                logger.warning(
                    "Raw fetch of %s got HTTP %d (attempt %d/%d) — retry in %.1fs",
                    log_url,
                    exc.response.status_code,
                    attempt,
                    _RAW_FETCH_ATTEMPTS,
                    sleep_delay,
                )
                await asyncio.sleep(sleep_delay)
                continue
            except httpx.RequestError as exc:
                if attempt < _RAW_FETCH_ATTEMPTS:
                    delay = min(2.0 * (2 ** (attempt - 1)) + random.uniform(0, 1), 30.0)
                    await asyncio.sleep(delay)
                    continue
                logger.warning(
                    "Failed to fetch raw file %s after %d attempts: %s: %s",
                    log_url,
                    _RAW_FETCH_ATTEMPTS,
                    type(exc).__name__,
                    # httpx error strings embed the full request URL, token
                    # included — redact the message as well as the URL.
                    redact_proxy_url(str(exc)),
                )
                return ""
            except TimeoutError as exc:
                # The wall-clock budget (asyncio.timeout above) expired
                # mid-body: a slow drip that outlived every chunk read
                # timeout. Bare TimeoutError is NOT an httpx.RequestError,
                # so without this handler it used to escape fetch_raw_file
                # entirely — failing the WHOLE source in the manager instead
                # of degrading this one file to "".
                if attempt < _RAW_FETCH_ATTEMPTS:
                    delay = min(2.0 * (2 ** (attempt - 1)) + random.uniform(0, 1), 30.0)
                    await asyncio.sleep(delay)
                    continue
                logger.warning(
                    "Raw fetch of %s timed out after %d attempt(s): %s",
                    log_url,
                    _RAW_FETCH_ATTEMPTS,
                    exc,
                )
                return ""
            if body is None:
                logger.warning(
                    "Raw file %s exceeded the %d byte limit — discarded.",
                    log_url,
                    MAX_RAW_FILE_BYTES,
                )
                return ""
            return body
        # Only reachable when _RAW_FETCH_ATTEMPTS is not positive.
        return ""

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
            try:
                return await self.fetch_raw_file(raw_url)
            except httpx.HTTPStatusError as exc:
                # The raw fallback raises when a retriable status (429/5xx) is
                # still failing on its last attempt; keep fetch_file's contract of
                # returning an empty string on failure instead of propagating.
                logger.warning(
                    "Raw fallback for %s/%s/%s failed: HTTP %s",
                    owner,
                    repo,
                    path,
                    exc.response.status_code,
                )
                return ""
        if not isinstance(data, dict):
            logger.warning(
                "Unexpected GitHub file response for %s: %s",
                url,
                # download_url may carry ?token= for private repos.
                redact_proxy_url(repr(data)[:1000]),
            )
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
        file_entries: list[dict[str, object]] = []
        dir_entries: list[dict[str, object]] = []
        for entry in entries:
            etype = entry.get("type", "file")
            if etype == "file":
                file_entries.append(entry)
            elif etype == "dir":
                dir_entries.append(entry)

        # --- Concurrent file fetches at this level ---
        async def _fetch_one_file(entry: dict[str, Any]) -> tuple[str, str] | None:
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
                    logger.warning(
                        "Failed to fetch raw %s: %s",
                        redact_proxy_url(download_url),
                        redact_proxy_url(str(exc)),
                    )
                    return None
            if content:
                return (file_path, content)
            logger.warning(
                "Fetched empty content for %s/%s/%s (download_url=%s)",
                owner,
                repo,
                file_path,
                redact_proxy_url(str(download_url)) if download_url else "<none>",
            )
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
                entry: dict[str, object],
                sub_budget: int,
            ) -> list[tuple[str, str]]:
                if sub_budget <= 0:
                    return []
                # Use `or` fallback so a present-but-None "path" (which GitHub
                # never sends but defensive code should survive) doesn't crash
                # the recursive fetch_directory with NoneType.strip().
                sub_path = str(entry.get("path") or entry.get("name") or "")
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
