"""GitHub publisher — commits the subscription file to a repo via the API.

Uses the GitHub Contents API (PUT /repos/{owner}/{repo}/contents/{path}) to
create or update a file. The flow is:

1. GET the file to obtain its current ``sha`` (needed to update an existing
   file). A 404 means the file does not exist yet -> create without ``sha``.
2. PUT the base64-encoded content with the ``sha`` (for updates) or without
   it (for creation).

Handles 404 (create), 409 (conflict — abort this run), and primary rate
limits (sleep + retry, bounded).
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import logging
import time
from typing import Any
from urllib.parse import quote

import httpx

logger = logging.getLogger(__name__)

# Fallback wait when X-RateLimit-Reset is missing/unparseable.
_DEFAULT_RATELIMIT_WAIT = 60.0
# Upper bound on a single rate-limit sleep to avoid blocking the pipeline forever.
_RATELIMIT_WAIT_CAP = 300.0


def _clean_repo_path(path: str) -> str:
    """Normalize and validate a GitHub repository path."""
    path = (path or "").strip().replace("\\", "/").strip("/")
    if not path:
        raise ValueError("repository path must not be empty")
    parts = [part for part in path.split("/") if part]
    if any(part in (".", "..") for part in parts):
        raise ValueError(f"unsafe repository path: {path!r}")
    return "/".join(parts)


def _contents_url(owner: str, repo: str, path: str) -> str:
    """Build a safe GitHub Contents API URL path."""
    owner_q = quote(str(owner).strip(), safe="")
    repo_q = quote(str(repo).strip(), safe="")
    clean_path = _clean_repo_path(path)
    path_q = "/".join(quote(part, safe="") for part in clean_path.split("/"))
    return f"/repos/{owner_q}/{repo_q}/contents/{path_q}"


class GitHubPublishError(Exception):
    """Raised when publishing to GitHub fails in a non-recoverable way."""


class GitHubPublisher:
    """Publishes a subscription file to a GitHub repo via the Contents API.

    Lifecycle:
        Prefer ``async with GitHubPublisher(...) as pub:`` so the underlying
        ``httpx.AsyncClient`` is closed. Otherwise call ``await pub.aclose()``
        when done.
    """

    USER_AGENT = "vpn-config-parser/1.0"

    def __init__(
        self,
        token: str,
        owner: str,
        repo: str,
        branch: str = "main",
        api_base: str = "https://api.github.com",
        timeout: float = 30.0,
    ) -> None:
        if not token:
            raise ValueError("GitHub token is required for publishing.")
        if not owner or not repo:
            raise ValueError("GitHub owner and repo are required for publishing.")

        self.token = token
        self.owner = owner
        self.repo = repo
        self.branch = branch
        self.api_base = api_base.rstrip("/")
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None
        self._lock = asyncio.Lock()

    # --- client lifecycle ---

    def _headers(self) -> dict[str, str]:
        return {
            "User-Agent": self.USER_AGENT,
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.token}",
            "X-GitHub-Api-Version": "2022-11-28",
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

    async def __aenter__(self) -> GitHubPublisher:
        await self._get_client()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    # --- internal helpers ---

    async def _get_file_sha(self, path: str) -> str | None:
        """Return the current blob SHA of ``path``, or None if it doesn't exist.

        Uses GET /repos/{owner}/{repo}/contents/{path}?ref={branch}.
        """
        url = _contents_url(self.owner, self.repo, path)
        client = await self._get_client()
        response = await client.get(url, params={"ref": self.branch})

        if response.status_code == 404:
            logger.info(
                "File %s does not exist yet in %s/%s — will create.",
                path,
                self.owner,
                self.repo,
            )
            return None

        # Rate-limited 403 -> wait & retry once.
        if response.status_code == 403 and self._is_rate_limited(response):
            await self._wait_for_rate_limit(response)
            response = await client.get(url, params={"ref": self.branch})
            if response.status_code == 404:
                return None

        if response.status_code == 409:
            # Repository is empty or branch mismatch — treat as "no file yet".
            logger.warning(
                "GitHub returned 409 for %s/%s (empty repo or branch gone) — treating as missing.",  # noqa: E501
                self.owner,
                self.repo,
            )
            return None

        response.raise_for_status()
        data: Any = response.json()
        if isinstance(data, dict):
            sha = data.get("sha")
            if isinstance(sha, str):
                return sha
        logger.warning("Unexpected SHA response for %s: %r", path, data)
        return None

    @staticmethod
    def _is_rate_limited(response: httpx.Response) -> bool:
        """True when a 403 is due to a primary or secondary rate limit."""
        if response.headers.get("X-RateLimit-Remaining") == "0":
            return True
        # Secondary rate limit: GitHub sends Retry-After.
        return bool(response.headers.get("Retry-After"))

    async def _wait_for_rate_limit(self, response: httpx.Response) -> None:
        """Sleep until the rate limit resets (bounded by the cap).

        Handles both primary (X-RateLimit-Reset) and secondary
        (Retry-After: seconds or HTTP-date) rate limits.
        """
        wait = _DEFAULT_RATELIMIT_WAIT
        retry_after = response.headers.get("Retry-After")
        if retry_after:
            try:
                wait = max(1.0, float(retry_after))
            except ValueError:
                try:
                    from email.utils import parsedate_to_datetime

                    retry_dt = parsedate_to_datetime(retry_after)
                    wait = max(1.0, retry_dt.timestamp() - time.time())
                except (TypeError, ValueError, OSError):
                    pass
        else:
            reset = response.headers.get("X-RateLimit-Reset")
            if reset:
                with contextlib.suppress(TypeError, ValueError):
                    wait = max(1.0, float(reset) - time.time())
        if wait > _RATELIMIT_WAIT_CAP:
            raise GitHubPublishError(
                f"GitHub rate limit exhausted; reset in {wait:.0f}s "
                f"(>{_RATELIMIT_WAIT_CAP}s cap) — aborting publish."
            )
        logger.warning(
            "GitHub rate limit hit while publishing; sleeping %.1fs before retrying.",
            wait,
        )
        await asyncio.sleep(wait)

    # --- public API ---

    async def publish_file(self, path: str, content: str, commit_message: str) -> bool:
        """Create or update ``path`` in the repo with ``content``.

        Args:
            path: Repo path for the file (e.g. ``output/subscription.txt``).
            content: UTF-8 text content to commit.
            commit_message: Commit message for the PUT.

        Returns:
            True on success, False on a recoverable failure (409 conflict,
            network error). Raises ``GitHubPublishError`` on non-recoverable
            failures (rate limit beyond cap, missing auth).
        """
        path = _clean_repo_path(path)

        try:
            content_bytes = content.encode("utf-8")
        except Exception:
            logger.exception("Failed to encode content for %s", path)
            return False

        content_b64 = base64.b64encode(content_bytes).decode("ascii")

        # Step 1: fetch current sha (None if file does not exist yet).
        try:
            sha = await self._get_file_sha(path)
        except httpx.HTTPStatusError:
            logger.exception("Failed to GET %s for SHA", path)
            return False
        except GitHubPublishError:
            raise
        except Exception:
            logger.exception("Unexpected error fetching SHA for %s", path)
            return False

        # Step 2: PUT the file.
        url = _contents_url(self.owner, self.repo, path)
        body: dict[str, Any] = {
            "message": commit_message,
            "content": content_b64,
            "branch": self.branch,
        }
        if sha:
            body["sha"] = sha

        client = await self._get_client()
        try:
            response = await client.put(url, json=body)
        except httpx.RequestError:
            logger.exception("Network error publishing %s", path)
            return False

        # Rate-limited 403 -> wait & retry once.
        if response.status_code == 403 and self._is_rate_limited(response):
            await self._wait_for_rate_limit(response)
            try:
                response = await client.put(url, json=body)
            except httpx.RequestError:
                logger.exception("Network error on retry publishing %s", path)
                return False

        if response.status_code in (200, 201):
            action = "updated" if sha else "created"
            logger.info(
                "Successfully %s %s in %s/%s.", action, path, self.owner, self.repo
            )
            return True

        if response.status_code == 409:
            logger.error(
                "GitHub 409 conflict publishing %s (race or empty repo). Aborting this publish.",  # noqa: E501
                path,
            )
            return False

        if response.status_code == 422:
            # Often: branch does not exist, or sha mismatch already handled.
            try:
                detail = response.json()
            except Exception:
                detail = response.text
            logger.error("GitHub 422 publishing %s: %s", path, detail)
            return False

        # Any other non-2xx.
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError:
            logger.exception(
                "GitHub publish failed for %s: HTTP %s",
                path,
                response.status_code,
            )
            return False

        return False
