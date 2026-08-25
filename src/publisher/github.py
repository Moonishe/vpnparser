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
from datetime import UTC
from typing import Any
from urllib.parse import quote

import httpx

logger = logging.getLogger(__name__)

# Fallback wait when X-RateLimit-Reset is missing/unparseable.
_DEFAULT_RATELIMIT_WAIT = 60.0
# Upper bound on a single rate-limit sleep to avoid blocking the pipeline forever.
_RATELIMIT_WAIT_CAP = 300.0
#: Retries for the optimistic-lock conflict (409): a parallel run or a manual
#: commit can bump the file SHA between our GET and PUT.
_CONFLICT_RETRIES = 2


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
                    follow_redirects=False,
                )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> GitHubPublisher:
        await self._get_client()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: object,
    ) -> None:
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
                    if retry_dt.tzinfo is None:
                        # HTTP-dates are GMT; a naive datetime would otherwise
                        # be interpreted in the runner's local timezone.

                        retry_dt = retry_dt.replace(tzinfo=UTC)
                    wait = max(1.0, retry_dt.timestamp() - time.time())
                # OverflowError: a date far beyond datetime's range.
                except (TypeError, ValueError, OSError, OverflowError):
                    pass
        else:
            reset = response.headers.get("X-RateLimit-Reset")
            if reset:
                with contextlib.suppress(TypeError, ValueError):
                    wait = max(1.0, float(reset) - time.time())
        if wait > _RATELIMIT_WAIT_CAP:
            raise GitHubPublishError(
                f"GitHub rate limit exhausted; reset in {wait:.0f}s "
                f"(>{_RATELIMIT_WAIT_CAP}s cap) — aborting publish.",
            )
        logger.warning(
            "GitHub rate limit hit while publishing; sleeping %.1fs before retrying.",
            wait,
        )
        await asyncio.sleep(wait)

    # --- public API ---

    async def _send(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        *,
        json_body: dict[str, Any] | None = None,
    ) -> httpx.Response:
        """One API call with a single rate-limit wait+retry on 403."""
        response = await client.request(method, url, json=json_body)
        if response.status_code == 403 and self._is_rate_limited(response):
            await self._wait_for_rate_limit(response)
            response = await client.request(method, url, json=json_body)
        return response

    async def _get_branch_head(self, client: httpx.AsyncClient) -> str | None:
        """HEAD commit SHA of the branch, or None for an empty/missing repo."""
        from urllib.parse import quote as _quote

        url = (
            f"/repos/{_quote(self.owner, safe='')}/"
            f"{_quote(self.repo, safe='')}/git/ref/heads/"
            f"{_quote(self.branch, safe='')}"
        )
        response = await self._send(client, "GET", url)
        if response.status_code in (404, 409):
            # 409: empty repository — GitHub answers 409 on git refs there.
            logger.info(
                "Branch %s has no commits yet in %s/%s — first commit will create it.",
                self.branch,
                self.owner,
                self.repo,
            )
            return None
        if response.status_code != 200:
            logger.error(
                "Cannot read ref heads/%s of %s/%s: HTTP %s",
                self.branch,
                self.owner,
                self.repo,
                response.status_code,
            )
            raise GitHubPublishError(
                f"Cannot read branch ref: HTTP {response.status_code}",
            )
        data = response.json()
        obj = data.get("object") if isinstance(data, dict) else None
        sha = obj.get("sha") if isinstance(obj, dict) else None
        if not isinstance(sha, str):
            raise GitHubPublishError("Unexpected ref response shape")
        return sha

    async def publish_files_batch(
        self,
        files: list[tuple[str, str]],
        commit_message: str,
    ) -> bool:
        """Commit many files as ONE atomic commit via the Git Data API.

        Flow: read branch head → create a tree carrying every file's inline
        content → create a commit on that tree → fast-forward the branch ref.
        A failure at any step leaves the ref untouched, so the repository
        keeps its previous state instead of the half-published mix the
        per-file Contents API loop produced.

        Args:
            files: ``(repo_path, utf-8 text content)`` pairs.
            commit_message: Message for the single commit.

        Returns:
            True on success; False on a recoverable failure (conflict retries
            exhausted, network error). Raises ``GitHubPublishError`` on
            non-recoverable ones (rate limit beyond cap).
        """
        cleaned: list[tuple[str, str]] = []
        seen_paths: set[str] = set()
        for path, content in files:
            clean = _clean_repo_path(path)
            key = clean.lower()
            if key in seen_paths:
                continue
            seen_paths.add(key)
            try:
                content.encode("utf-8")
            except Exception:
                logger.exception("Failed to encode content for %s", clean)
                return False
            cleaned.append((clean, content))
        if not cleaned:
            return True

        from urllib.parse import quote as _quote

        base = f"/repos/{_quote(self.owner, safe='')}/{_quote(self.repo, safe='')}/git"
        client = await self._get_client()

        for attempt in range(1, _CONFLICT_RETRIES + 2):
            try:
                base_commit = await self._get_branch_head(client)
            except httpx.RequestError:
                logger.exception("Network error reading branch head")
                return False
            tree_entries = [
                {"path": path, "mode": "100644", "type": "blob", "content": content}
                for path, content in cleaned
            ]
            tree_payload: dict[str, Any] = {"tree": tree_entries}
            if base_commit:
                try:
                    commit_resp = await self._send(
                        client,
                        "GET",
                        f"{base}/commits/{base_commit}",
                    )
                except httpx.RequestError:
                    logger.exception("Network error reading base commit")
                    return False
                if commit_resp.status_code != 200:
                    logger.error(
                        "Cannot read base commit %s: HTTP %s",
                        base_commit,
                        commit_resp.status_code,
                    )
                    return False
                parent_tree = (commit_resp.json().get("tree") or {}).get("sha")
                if isinstance(parent_tree, str) and parent_tree:
                    tree_payload["base_tree"] = parent_tree

            try:
                tree_resp = await self._send(
                    client,
                    "POST",
                    f"{base}/trees",
                    json_body=tree_payload,
                )
            except httpx.RequestError:
                logger.exception("Network error creating tree")
                return False
            if tree_resp.status_code not in (200, 201):
                logger.error(
                    "Git Data trees call failed: HTTP %s: %s",
                    tree_resp.status_code,
                    tree_resp.text[:300],
                )
                return False
            new_tree = tree_resp.json().get("sha")

            commit_payload: dict[str, Any] = {
                "message": commit_message,
                "tree": new_tree,
            }
            if base_commit:
                commit_payload["parents"] = [base_commit]
            try:
                new_commit_resp = await self._send(
                    client,
                    "POST",
                    f"{base}/commits",
                    json_body=commit_payload,
                )
            except httpx.RequestError:
                logger.exception("Network error creating commit")
                return False
            if new_commit_resp.status_code not in (200, 201):
                logger.error(
                    "Git Data commit call failed: HTTP %s: %s",
                    new_commit_resp.status_code,
                    new_commit_resp.text[:300],
                )
                return False
            new_commit = new_commit_resp.json().get("sha")

            if base_commit is None:
                # Empty repository: the first push must CREATE the ref.
                ref_resp = await self._send(
                    client,
                    "POST",
                    f"{base}/refs",
                    json_body={
                        "ref": f"refs/heads/{self.branch}",
                        "sha": new_commit,
                    },
                )
            else:
                ref_resp = await self._send(
                    client,
                    "PATCH",
                    f"{base}/refs/heads/{self.branch}",
                    json_body={"sha": new_commit, "force": False},
                )
            if ref_resp.status_code in (200, 201):
                logger.info(
                    "Batch-published %d file(s) to %s/%s@%s as one commit %s.",
                    len(cleaned),
                    self.owner,
                    self.repo,
                    self.branch,
                    str(new_commit)[:12],
                )
                return True
            if ref_resp.status_code == 422 and attempt <= _CONFLICT_RETRIES:
                # Not-fast-forward: a competing run/manual commit moved the
                # ref between our read and update. Rebuild on the fresh head.
                logger.warning(
                    "Branch %s moved during batch publish (attempt %d); "
                    "rebasing onto the new head.",
                    self.branch,
                    attempt,
                )
                continue
            logger.error(
                "Ref update failed for %s/%s@%s: HTTP %s: %s",
                self.owner,
                self.repo,
                self.branch,
                ref_resp.status_code,
                ref_resp.text[:300],
            )
            return False
        return False

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
                "Successfully %s %s in %s/%s.",
                action,
                path,
                self.owner,
                self.repo,
            )
            return True

        # 409 = optimistic-lock race: another run (or a manual commit) bumped
        # the file's SHA after our GET. Re-fetch the SHA and retry a couple of
        # times before giving up — parallel runs are queued by the workflow
        # concurrency group, but manual commits and manual-dispatched runs can
        # still collide.
        if response.status_code == 409:
            for attempt in range(1, _CONFLICT_RETRIES + 1):
                logger.warning(
                    "GitHub 409 conflict publishing %s; fetching fresh SHA "
                    "(retry %d/%d).",
                    path,
                    attempt,
                    _CONFLICT_RETRIES,
                )
                try:
                    sha = await self._get_file_sha(path)
                except Exception:
                    logger.exception("Failed to GET %s for SHA after conflict", path)
                    break
                if sha:
                    body["sha"] = sha
                else:
                    # The file was deleted by a competing commit: PUT without
                    # a "sha" key creates it — "sha": null would 422 forever.
                    body.pop("sha", None)
                try:
                    response = await client.put(url, json=body)
                except httpx.RequestError:
                    logger.exception(
                        "Network error on conflict retry publishing %s", path
                    )
                    return False
                if response.status_code in (200, 201):
                    action = "updated" if sha else "created"
                    logger.info(
                        "Successfully %s %s in %s/%s (after conflict).",
                        action,
                        path,
                        self.owner,
                        self.repo,
                    )
                    return True
                if response.status_code == 422:
                    # A create-vs-create race surfaced mid-retry: the shared
                    # 422 recovery below can still fix this — don't abort.
                    break
                if response.status_code != 409:
                    break
            else:
                # Loop exhausted with the conflict still unresolved.
                logger.error(
                    "GitHub 409 conflict publishing %s (race or empty repo). Aborting this publish.",  # noqa: E501
                    path,
                )
                return False

        if response.status_code == 422:
            # Create-vs-create race: our GET saw no file (or a stale SHA) but
            # a parallel run created/updated it before our PUT — GitHub
            # answers 422 ("sha wasn't supplied" / invalid sha). Mirror the
            # 409 path: re-fetch the current SHA and retry once. This also
            # recovers the 409-on-GET case where the file actually exists.
            try:
                fresh_sha = await self._get_file_sha(path)
            except Exception:
                logger.exception("Failed to GET %s for SHA after 422", path)
                fresh_sha = None
            if fresh_sha:
                body["sha"] = fresh_sha
                try:
                    response = await client.put(url, json=body)
                except httpx.RequestError:
                    logger.exception("Network error on 422 retry publishing %s", path)
                    return False
                if response.status_code in (200, 201):
                    logger.info(
                        "Successfully updated %s in %s/%s (after 422 race).",
                        path,
                        self.owner,
                        self.repo,
                    )
                    return True
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
