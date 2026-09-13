"""Source manager — orchestrates fetching VPN configs from all configured sources.

Loads source definitions from ``config/sources.json`` and runtime settings from
``config/settings.yaml``, then fetches files concurrently from each enabled
source via :class:`GitHubClient`. Per-source errors are isolated: one failing
source never stops the others.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urljoin, urlparse, urlsplit, urlunsplit
from weakref import WeakKeyDictionary

import httpx
import yaml

from src.scheduler.settings import Settings
from src.sources.github import GitHubClient
from src.sources.list_types import DEFAULT_LIST_TYPE, infer_source_list_type
from src.sources.source_options import (
    DEFAULT_FETCH_ATTEMPTS,
    DEFAULT_FETCH_TIMEOUT,
    DEFAULT_LISTED_URL_ATTEMPTS,
    _direct_fetch_overrides,
    _fetch_timeout,
    _filter_files,
    _float_source_value,
    _int_source_value,
    _source_default_country,
)
from src.utils.http import read_limited_text
from src.utils.net import (
    RESOLVER_CONCURRENCY,
    SAFE_URL_SCHEMES,
    redact_proxy_url,
    resolve_global_ips,
)

logger = logging.getLogger(__name__)

#: Statuses httpx treats as redirects. Followed manually so every hop can be
#: re-validated against the SSRF guard. 300/305/306 are included for
#: completeness (httpx would otherwise treat them as a normal body);
#: 304 (Not Modified) is deliberately excluded — it is not a redirect.
_REDIRECT_STATUSES = frozenset({300, 301, 302, 303, 305, 306, 307, 308})

#: Maximum number of redirects followed for one untrusted URL.
_MAX_REDIRECT_HOPS = 5

#: Hard cap on the body accepted from one untrusted URL. The listed URLs are
#: written by a third party, so an endless or multi-gigabyte stream must not be
#: buffered into memory — the httpx timeout bounds idle time, not volume.
MAX_DOWNLOAD_BYTES = 12 * 1024 * 1024

#: Wall-clock budget for one attempt at one untrusted URL, as a multiple of the
#: per-operation ``timeout``. httpx restarts its read timer on every chunk, so a
#: host dripping one byte just before each read timeout keeps the stream open
#: forever while staying far below MAX_DOWNLOAD_BYTES. The budget also covers
#: the whole redirect chain, which is several operations by itself.
DOWNLOAD_TIMEOUT_FACTOR = 4.0

#: Fallbacks for the per-source ``timeout``/``attempts`` knobs live in
#: :mod:`src.sources.source_options` and are imported above.

#: Process-wide ceiling on untrusted downloads in flight. Two constraints pin it:
#: every fetch keeps one host lookup busy while it validates its target, and
#: more than :data:`~src.utils.net.RESOLVER_CONCURRENCY` lookups at once queue
#: past their own resolve timeout — a healthy source then looks unresolvable
#: and is dropped as non-public. The memory side used to be "same constant":
#: with :data:`MAX_DOWNLOAD_BYTES` buffered per fetch plus the decode copy,
#: 50 in-flight downloads peaked near 1.5 GB — enough to OOM a runner alongside
#: the later Xray stage. The download ceiling is therefore derived from the
#: byte budget, and the resolver still bounds it from above via ``min(...)``.
#: The per-source ``max_concurrent_urls`` semaphores enforce neither bound:
#: the shipped config alone runs four url-list sources of 20 at once.
#: The per-fetch cost counts the body (12 MiB cap) plus its decoded str copy
#: and split churn — the repo's own measurements put one fetch near 30 MB
#: with non-ASCII payloads, ~2.5x the body bytes the old estimate used.
#: The 384 MiB total download budget keeps the fetch stage at ~5% of a
#: 7 GB Actions runner's usable memory, leaving headroom for the Xray stage.
_FETCH_MEMORY_BUDGET_MIB = 30
_MAX_DOWNLOADS_FOR_MEMORY = max(1, (384 // _FETCH_MEMORY_BUDGET_MIB))

#: A comma only separates two URLs when a ``scheme://`` follows it. Inside a
#: single URL a comma is a legal character (``.../list?alpn=h3,h2``): the old
#: blanket ``replace(",", " ")`` silently truncated such URLs and fetched the
#: wrong address.
_URL_COMMA_SPLIT_RE = re.compile(r",(?=[A-Za-z][A-Za-z0-9+.\-]*://)")
MAX_INFLIGHT_DOWNLOADS = min(RESOLVER_CONCURRENCY, _MAX_DOWNLOADS_FOR_MEMORY)

#: Addresses tried per hop before the hop is declared unreachable. Pinning the
#: connection to one validated address (see :class:`_PinnedTarget`) loses the
#: connector's own walk over the ``getaddrinfo`` list, so a host whose first
#: answer is unroutable here — an AAAA record on an IPv4-only runner — must
#: still fall back to the next one.
_MAX_PINNED_ADDRESSES = 4

#: One gate per event loop: an ``asyncio.Semaphore`` binds to the loop that
#: first blocks on it, so a single module-level instance would raise "bound to a
#: different event loop" as soon as a second ``asyncio.run`` contended for it.
#: Every fetch of one run shares a loop, which is the scope that shares the
#: resolver pool and the memory budget.
_download_gates: WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Semaphore] = (
    WeakKeyDictionary()
)


def _host_literal(host: str) -> str:
    """Return *host* in URL form, re-bracketing an IPv6 literal."""
    return f"[{host}]" if ":" in host else host


def _redact_url(url: str) -> str:
    """Mask userinfo and credential query values for logs and published errors.

    Delegates to the shared redactor: GitHub raw ``download_url``s carry
    ``?token=`` for private repos, and these strings land in ``run-summary.json``.
    """
    return redact_proxy_url(url)


def _safe_error_message(exc: BaseException, *, limit: int = 300) -> str:
    """Short, bounded, single-line error text for logs and results.

    Full tracebacks and long messages can expose internal paths and stack
    structure; error strings also land in ``run-summary.json``, which is
    published to the repository. URL credentials (``user:pass@host``) are
    masked — httpx error strings embed the full request URL. The traceback
    itself stays in the debug log.
    """
    text = str(exc).strip() or type(exc).__name__
    # Error strings (and httpx ones in particular) can embed the full request
    # URL with credentials, sometimes across several lines; redact every line,
    # not just the first, before the value lands in run-summary.json.
    lines = [ln.strip() for ln in text.splitlines()] or [type(exc).__name__]
    joined = " | ".join(_redact_url(ln) for ln in lines)
    if len(joined) > limit:
        joined = f"{joined[: limit - 1]}…"
    return joined


def _download_gate() -> asyncio.Semaphore:
    """Return the download gate of the running event loop, creating it once."""
    loop = asyncio.get_running_loop()
    gate = _download_gates.get(loop)
    if gate is None:
        gate = asyncio.Semaphore(MAX_INFLIGHT_DOWNLOADS)
        _download_gates[loop] = gate
    return gate


@dataclass(frozen=True)
class _PinnedTarget:
    """A URL bound to the addresses its host was actually validated on.

    Validating the *name* and then handing the same name to httpx leaves a
    check-to-connect window: httpx resolves independently, so a record with
    TTL 0 can answer the guard with a public address and the connection with
    ``127.0.0.1`` or ``169.254.169.254`` (DNS rebinding). Connecting to the
    address the guard approved closes the window.

    Attributes:
        connect_urls: ``url`` with its host replaced by each approved address.
        host_header: ``Host`` value carrying the original host and port, so
            virtual hosting keeps working.
        extensions: httpx request extensions; ``sni_hostname`` keeps TLS
            negotiating and verifying against the hostname, not the address.
    """

    connect_urls: tuple[str, ...]
    host_header: str
    extensions: dict[str, str]


@dataclass
class SourceResult:
    """Result of fetching a single source.

    Attributes:
        source_name: Name of the source (from sources.json).
        files: List of ``(filename, content)`` tuples. For ``subscription``
            sources the single file is included here as one tuple.
        error: Error message if the fetch failed; ``None`` on success.
    """

    source_name: str
    files: list[tuple[str, str]] = field(default_factory=list)
    error: str | None = None
    list_type: str = DEFAULT_LIST_TYPE
    default_country: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


class SourceManager:
    """Loads config and fetches from all enabled GitHub sources concurrently."""

    def __init__(
        self,
        sources_file: str = "config/sources.json",
        settings_file: str = "config/settings.yaml",
        github_token: str | None = None,
    ) -> None:
        self.sources_file = Path(sources_file)
        self.settings_file = Path(settings_file)
        self.github_token = github_token

        # Loaded config ------------------------------------------------------
        self.settings: dict[str, Any] = self._load_settings()
        self.sources: list[dict[str, Any]] = self._load_sources()

        # Concurrency control ------------------------------------------------
        max_concurrent = self._settings_sources().get("max_concurrent_fetches", 10)
        try:
            max_concurrent = int(max_concurrent)
        except (TypeError, ValueError):
            max_concurrent = 10
        self._semaphore = asyncio.Semaphore(max(1, min(max_concurrent, 50)))

        # GitHub client (lazily used inside fetch_source; lifecycle owned here)
        # `or` (not the get() default): a present-but-empty key — YAML parses
        # bare "github_api_base:" as None — must not reach GitHubClient, whose
        # api_base.rstrip("/") would crash the whole pipeline at startup.
        api_base = (
            self._settings_sources().get("github_api_base") or "https://api.github.com"
        )
        self._github = GitHubClient(token=github_token, api_base=api_base)

    # --- config loading ---

    def _settings_sources(self) -> dict[str, Any]:
        raw = (
            self.settings.get("sources", {}) if isinstance(self.settings, dict) else {}
        )
        assert isinstance(raw, dict)
        return raw

    def _load_settings(self) -> dict[str, Any]:
        if not self.settings_file.exists():
            logger.warning("Settings file not found: %s", self.settings_file)
            return {}
        try:
            with self.settings_file.open("r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            return data if isinstance(data, dict) else {}
        except (yaml.YAMLError, OSError):
            logger.exception("Failed to load settings %s", self.settings_file)
            logger.warning(
                "Using default settings after failing to load %s",
                self.settings_file,
            )
            return {}

    def _load_sources(self) -> list[dict[str, Any]]:
        if not self.sources_file.exists():
            logger.warning("Sources file not found: %s", self.sources_file)
            return []
        try:
            with self.sources_file.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, OSError):
            logger.exception("Failed to load sources %s", self.sources_file)
            return []
        sources = data.get("sources", []) if isinstance(data, dict) else []
        return [s for s in sources if isinstance(s, dict)]

    # --- public API ---

    def enabled_sources(self) -> list[dict[str, Any]]:
        """Return only sources that are enabled.

        Hand-written string values are parsed rather than tested for
        truthiness: ``"true"``/``"yes"``/``"1"``/``"on"`` enable a source and
        ``"false"``/``"no"``/``"0"``/``"off"`` disable it. Plain ``bool(...)``
        would enable ``"false"`` — every non-empty string is truthy.
        """
        return [
            s
            for s in self.sources
            if Settings.as_bool(s.get("enabled", False), default=False)
        ]

    async def fetch_all(self) -> list[SourceResult]:
        """Fetch from all enabled sources concurrently.

        Concurrency is bounded by ``max_concurrent_fetches`` from settings.
        Per-source errors are captured in ``SourceResult.error`` and never
        propagate to the caller. Returns results in the same order as the
        enabled sources appear in ``sources.json``.
        """
        enabled = self.enabled_sources()
        if not enabled:
            logger.info("No enabled sources to fetch.")
            return []

        tasks = [self._fetch_with_semaphore(s) for s in enabled]
        # return_exceptions=True so one raising task can never discard the
        # results of all the others — fulfils the "never propagate" contract.
        raw_results = await asyncio.gather(*tasks, return_exceptions=True)
        results: list[SourceResult] = []
        for source, raw in zip(enabled, raw_results, strict=False):
            if isinstance(raw, Exception):
                name = (
                    source.get("name", "<unnamed>")
                    if isinstance(source, dict)
                    else "<unnamed>"
                )
                logger.error(
                    "Unhandled error fetching source '%s': %s",
                    name,
                    _safe_error_message(raw),
                )
                logger.debug("Fetch of source '%s' raised:", name, exc_info=raw)
                results.append(
                    SourceResult(source_name=name, error=_safe_error_message(raw))
                )
            elif isinstance(raw, BaseException):
                # Cancellation / system exit — must propagate, not be swallowed.
                raise raw
            else:
                results.append(raw)
        return results

    async def _fetch_with_semaphore(self, source: dict[str, Any]) -> SourceResult:
        async with self._semaphore:
            return await self.fetch_source(source)

    async def fetch_source(self, source: dict[str, Any]) -> SourceResult:
        """Fetch a single source. Never raises — errors become ``SourceResult.error``.

        Supported source types:
            * ``subscription`` — fetch a single file at ``path``; its content
              is a base64 blob (kept as a single (filename, content) tuple).
            * ``raw`` — fetch all files in the directory at ``path``; each file
              may contain one or more proxy config links.
            * ``url-list`` — fetch an index file at ``url`` containing one URL
              per line, then fetch each listed URL concurrently. Supports
              ``{YYYY}``, ``{MM}``, ``{DD}``, ``{M}``, ``{YYYYMM}``,
              ``{YYYYMMDD}`` placeholders.
        """
        name = (
            source.get("name", "<unnamed>") if isinstance(source, dict) else "<unnamed>"
        )
        list_type: str = DEFAULT_LIST_TYPE
        try:
            stype = source.get("type", "")
            owner = source.get("owner", "")
            repo = source.get("repo", "")
            path = source.get("path", "")
            branch = source.get("branch", "main")
            url = source.get("url", "")
            list_type = infer_source_list_type(source)
            default_country = self._source_default_country(source)

            if stype == "url" or (stype == "subscription" and url):
                content = await self._fetch_direct_url(
                    str(url),
                    **self._direct_fetch_overrides(source),
                )
                if not content:
                    redacted_url = _redact_url(str(url))
                    return SourceResult(
                        source_name=name,
                        error=f"url source '{redacted_url}' is empty or not found",
                        list_type=list_type,
                        default_country=default_country,
                    )
                filename = (
                    self._safe_filename(str(source.get("filename") or ""))
                    or self._filename_from_url(str(url))
                    or f"{name}.txt"
                )
                return SourceResult(
                    source_name=name,
                    files=[(filename, content)],
                    list_type=list_type,
                    default_country=default_country,
                )

            if stype == "url-list":
                return await self._fetch_url_list(
                    source,
                    name,
                    list_type,
                    default_country,
                )

            # subscription requires path; raw allows empty path (= root directory).
            if not (owner and repo):
                return SourceResult(
                    source_name=name,
                    error=f"source '{name}' is missing owner/repo",
                    list_type=list_type,
                    default_country=default_country,
                )
            if stype == "subscription" and not path:
                return SourceResult(
                    source_name=name,
                    error=f"subscription source '{name}' requires a file path",
                    list_type=list_type,
                    default_country=default_country,
                )

            if stype == "subscription":
                content = await self._github.fetch_file(owner, repo, path, branch)
                if not content:
                    return SourceResult(
                        source_name=name,
                        error=f"subscription file '{path}' is empty or not found",
                        list_type=list_type,
                        default_country=default_country,
                    )
                filename = path.replace("\\", "/").rsplit("/", 1)[-1] or f"{name}.txt"
                return SourceResult(
                    source_name=name,
                    files=[(filename, content)],
                    list_type=list_type,
                    default_country=default_country,
                )

            if stype == "raw":
                max_depth = self._int_source_value(source, "max_depth", 3, maximum=10)
                max_files = self._int_source_value(
                    source, "max_files", 200, maximum=1000
                )
                files = await self._github.fetch_directory(
                    owner,
                    repo,
                    path,
                    branch,
                    max_depth=max_depth,
                    max_files=max_files,
                )
                files = self._filter_files(source, files)
                if not files:
                    return SourceResult(
                        source_name=name,
                        error=f"directory '{path}' is empty or not found",
                        list_type=list_type,
                        default_country=default_country,
                    )
                return SourceResult(
                    source_name=name,
                    files=files,
                    list_type=list_type,
                    default_country=default_country,
                )

            return SourceResult(
                source_name=name,
                error=(
                    f"unknown source type '{stype}' "
                    "(expected 'subscription', 'raw', 'url' or 'url-list')"
                ),
                list_type=list_type,
                default_country=default_country,
            )
        except Exception as exc:
            # Isolate failures: surface a concise reason as a structured error.
            # Full tracebacks stay in the debug log — error strings end up in
            # run-summary.json, which is published to the repository.
            logger.error(
                "Failed to fetch source '%s': %s", name, _safe_error_message(exc)
            )
            logger.debug("Fetch of source '%s' raised:", name, exc_info=True)
            return SourceResult(
                source_name=name,
                error=_safe_error_message(exc),
                list_type=list_type,
            )

    @staticmethod
    async def _fetch_direct_url(
        url: str,
        timeout: float = DEFAULT_FETCH_TIMEOUT,
        attempts: int = DEFAULT_FETCH_ATTEMPTS,
        retry_delay: float = 2.0,
        client: httpx.AsyncClient | None = None,
    ) -> str:
        """Fetch a direct HTTP(S) text source from an untrusted URL.

        These URLs come from third-party indexes (``url-list`` sources), so the
        fetch is guarded three ways: the host must resolve to public addresses
        only (SSRF guard), the streamed body is discarded past
        ``MAX_DOWNLOAD_BYTES``, and every attempt runs under a wall-clock budget
        of ``timeout * DOWNLOAD_TIMEOUT_FACTOR`` seconds.

        Args:
            client: Shared client for a whole url-list batch. A fresh
                ``AsyncClient`` re-parses the CA bundle and re-handshakes per
                URL — a 200-URL index paid that 200 times. When omitted, a
                per-call client is created (the standalone/tools path).

        Returns:
            The response body, ``""`` on 404 or on an oversized body.

        Raises:
            ValueError: If the URL is not absolute http(s), points at a
                non-public host, or redirects more than
                ``_MAX_REDIRECT_HOPS`` times.
            httpx.HTTPError: If every attempt failed.
            TimeoutError: If the last attempt outlived its wall-clock budget.
        """
        parsed = urlparse((url or "").strip())
        if parsed.scheme not in SAFE_URL_SCHEMES or not parsed.netloc:
            msg = f"source url must be absolute HTTP/HTTPS: {_redact_url(url)!r}"
            raise ValueError(msg)

        max_attempts = max(1, attempts)
        last_error: Exception | None = None
        budget = timeout * DOWNLOAD_TIMEOUT_FACTOR
        headers = {
            "User-Agent": "vpn-config-parser/1.0",
            "Accept": "text/plain,*/*",
        }

        def _retryable(exc: Exception) -> bool:
            # Deterministic 4xx never succeed on retry (408 timeout and 429
            # rate-limit are the retriable exceptions): retrying them just
            # burns attempts x budget wall clock.
            if isinstance(exc, httpx.HTTPStatusError):
                status = exc.response.status_code if exc.response is not None else 0
                if 400 <= status < 500 and status not in (408, 429):
                    return False
            return True

        # follow_redirects=False: httpx would follow a hop to 127.0.0.1 or to
        # the cloud metadata endpoint without re-checking it, so redirects are
        # walked manually with a fresh SSRF check per hop.
        if client is not None:
            for attempt in range(1, max_attempts + 1):
                try:
                    # The gate is taken *outside* the budget: queue time is not
                    # the host's fault, and charging it to the fetch would time
                    # out healthy sources under load. Only the validated fetch
                    # itself is charged to the budget.
                    async with _download_gate():
                        async with asyncio.timeout(budget):
                            return await SourceManager._get_validated(
                                client, url, headers
                            )
                except (httpx.RequestError, httpx.HTTPStatusError) as exc:
                    last_error = exc
                    if not _retryable(exc):
                        break
                except TimeoutError:
                    last_error = TimeoutError(
                        f"fetch of {_redact_url(url)!r} "
                        f"exceeded its {budget:.1f}s budget",
                    )
                if attempt >= max_attempts:
                    break
                logger.warning(
                    "Direct source fetch failed for %s (attempt %d/%d): %s",
                    _redact_url(url),
                    attempt,
                    max_attempts,
                    _safe_error_message(last_error),
                )
                delay = min(
                    max(0.0, retry_delay) * (2 ** (attempt - 1)) + random.uniform(0, 1),
                    30.0,
                )
                await asyncio.sleep(delay)
            if last_error is not None:
                raise last_error
            return ""  # pragma: no cover
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as owned:
            for attempt in range(1, max_attempts + 1):
                try:
                    # The gate is taken *outside* the budget: queue time is not
                    # the host's fault, and charging it to the fetch would time
                    # out healthy sources under load. Only the validated fetch
                    # itself is charged to the budget.
                    async with _download_gate():
                        async with asyncio.timeout(budget):
                            return await SourceManager._get_validated(
                                owned, url, headers
                            )
                except (httpx.RequestError, httpx.HTTPStatusError) as exc:
                    last_error = exc
                    if not _retryable(exc):
                        break
                except TimeoutError:
                    last_error = TimeoutError(
                        f"fetch of {_redact_url(url)!r} "
                        f"exceeded its {budget:.1f}s budget",
                    )
                if attempt >= max_attempts:
                    break
                logger.warning(
                    "Direct source fetch failed for %s (attempt %d/%d): %s",
                    _redact_url(url),
                    attempt,
                    max_attempts,
                    _safe_error_message(last_error),
                )
                delay = min(
                    max(0.0, retry_delay) * (2 ** (attempt - 1)) + random.uniform(0, 1),
                    30.0,
                )
                await asyncio.sleep(delay)
        if last_error is not None:
            raise last_error
        return ""  # pragma: no cover

    @staticmethod
    async def _pin_public_target(url: str) -> _PinnedTarget:
        """Validate ``url`` against the SSRF guard and pin it to its addresses.

        Resolution happens exactly once, under the shared download gate, and the
        connection then goes to what was resolved — see :class:`_PinnedTarget`
        for why handing httpx the hostname instead is not enough.

        Returns:
            The target bound to the public addresses of its host.

        Raises:
            ValueError: If the URL is not http(s), carries no host, or its host
                does not resolve exclusively to public addresses.
        """
        try:
            parts = urlsplit(url)
            host = parts.hostname
            # Reading the port is what validates it; a redirect may well point
            # at "http://host:99999/".
            port = f":{parts.port}" if parts.port is not None else ""
        except ValueError:
            parts = None
            host = None
            port = ""
        if parts is None or not host or parts.scheme.lower() not in SAFE_URL_SCHEMES:
            logger.warning("Dropped non-public source url: %s", _redact_url(url))
            msg = f"refusing to fetch non-public url: {_redact_url(url)!r}"
            raise ValueError(msg)

        # ``None`` = transient resolver failure (timeout / NXDOMAIN moment):
        # a dropped URL is final for the whole run, so one retry is cheap
        # insurance against losing a whole upstream index to one slow answer.
        # ``[]`` is a terminal SSRF verdict and is never retried — the same
        # split is_public_host uses.
        addresses = await resolve_global_ips(host)
        if addresses is None:
            await asyncio.sleep(0.25)
            addresses = await resolve_global_ips(host)
        if not addresses:
            logger.warning("Dropped non-public source url: %s", _redact_url(url))
            msg = f"refusing to fetch non-public url: {_redact_url(url)!r}"
            raise ValueError(msg)

        userinfo = ""
        if parts.username or parts.password:
            # Credentials in a plaintext sources.json URL leak into logs and
            # run-summary.json; warn so the operator notices the exposure.
            logger.warning(
                "Source URL for host %s contains userinfo; "
                "credentials in plaintext sources.json may leak",
                _redact_url(host),
            )
            # urlsplit() returns percent-ENCODED credentials (it does not
            # decode them), so they are rebuilt as-is: re-quoting turned
            # "p%40ss" into "p%2540ss" and the server answered 401 for a
            # password that was never wrong.
            username = parts.username or ""
            password = parts.password or ""
            userinfo = f"{username}:{password}@" if password else f"{username}@"
        connect_urls = tuple(
            urlunsplit(
                (
                    parts.scheme,
                    f"{userinfo}{_host_literal(address)}{port}",
                    parts.path,
                    parts.query,
                    parts.fragment,
                ),
            )
            for address in addresses[:_MAX_PINNED_ADDRESSES]
        )
        return _PinnedTarget(
            connect_urls=connect_urls,
            host_header=f"{_host_literal(host)}{port}",
            extensions=(
                {"sni_hostname": host} if parts.scheme.lower() == "https" else {}
            ),
        )

    @staticmethod
    async def _stream_hop(
        client: httpx.AsyncClient,
        pinned: _PinnedTarget,
        headers: dict[str, str],
        logical_url: str | None = None,
    ) -> tuple[str | None, str]:
        """GET one hop, falling back over the addresses approved for it.

        Args:
            client: Client used to issue the request.
            pinned: Target produced by :meth:`_pin_public_target`.
            headers: Request headers; ``Host`` is taken from *pinned*.
            logical_url: Human-facing URL of this hop (hostname form), for
                diagnostics alongside the pinned IP ``connect_url``.

        Returns:
            ``(location, body)``. ``location`` is the redirect target when the
            hop answered with one, and is ``None`` otherwise — then ``body``
            holds the payload, ``""`` for a 404 or an oversized response.

        Raises:
            httpx.RequestError: If none of the approved addresses answered.
        """
        request_headers = {**headers, "Host": pinned.host_header}
        last_error: httpx.RequestError | None = None
        for connect_url in pinned.connect_urls:
            try:
                async with client.stream(
                    "GET",
                    connect_url,
                    headers=request_headers,
                    extensions=pinned.extensions,
                ) as response:
                    if response.status_code == 404:
                        return None, ""
                    if response.status_code in _REDIRECT_STATUSES:
                        location = response.headers.get("location")
                        if location:
                            return location.strip(), ""
                        # A 3xx without Location used to fall through to
                        # raise_for_status() (a no-op for 3xx), read an empty
                        # body and surface as a "successful" empty fetch.
                        msg = (
                            f"redirect {response.status_code} without a "
                            f"Location header — refusing to treat it as success"
                        )
                        raise ValueError(msg)
                    response.raise_for_status()
                    body = await read_limited_text(
                        response,
                        max_bytes=MAX_DOWNLOAD_BYTES,
                    )
            except httpx.TransportError as exc:
                # Any transport failure on one pinned address (connect/read/
                # write timeouts, resets, protocol errors — e.g. IPv6 TIMEOUT
                # on an IPv4-only runner) must still try the next approved
                # address instead of failing the whole fetch. HTTPStatusError
                # (a completed response) is handled by the caller, not here.
                last_error = exc
                continue
            if body is None:
                logger.warning(
                    "Discarded oversized response for %s from %s (limit %d bytes).",
                    _redact_url(logical_url or connect_url),
                    _redact_url(connect_url),
                    MAX_DOWNLOAD_BYTES,
                )
                return None, ""
            return None, body
        if last_error is None:  # connect_urls is never empty; defensive
            raise RuntimeError
        raise last_error

    @staticmethod
    async def _get_validated(
        client: httpx.AsyncClient,
        url: str,
        headers: dict[str, str],
    ) -> str:
        """GET ``url``, re-validating every redirect hop against the SSRF guard.

        Returns:
            The response body, or ``""`` on 404 or an oversized body.

        Raises:
            ValueError: If a hop is not a public http(s) URL, an https URL
                redirects to http, or the redirect chain is longer than
                ``_MAX_REDIRECT_HOPS``.
        """
        target = url
        prior_scheme = urlsplit(target).scheme.lower()
        for _hop in range(_MAX_REDIRECT_HOPS + 1):
            pinned = await SourceManager._pin_public_target(target)
            location, body = await SourceManager._stream_hop(
                client, pinned, headers, logical_url=target
            )
            if location is None:
                return body
            # Relative redirects resolve against the *logical* URL, never the
            # pinned address one.
            target = urljoin(target, location)
            # A server-controlled redirect must not downgrade TLS, mirroring
            # proxy_pool's hop chain: an https source refetching over http is
            # refused instead of silently handing the fetch to plaintext.
            scheme = urlsplit(target).scheme.lower()
            if prior_scheme == "https" and scheme == "http":
                msg = f"https->http redirect refused: {_redact_url(target)!r}"
                raise ValueError(msg)
            prior_scheme = scheme
        msg = f"too many redirects while fetching {_redact_url(url)!r}"
        raise ValueError(msg)

    @staticmethod
    def _filename_from_url(url: str) -> str:
        parsed = urlparse((url or "").strip())
        # Sanitize override-safe: never return directory components.
        # Backslashes are normalized first: PurePosixPath does not treat
        # "dir\\file.txt" as a path separator, leaking the whole string.
        return PurePosixPath(parsed.path.replace("\\", "/")).name or ""

    @staticmethod
    def _safe_filename(raw: str) -> str:
        """Basename-only filename (no traversal via source override)."""
        return PurePosixPath((raw or "").strip().replace("\\", "/")).name or ""

    async def _fetch_url_list(
        self,
        source: dict[str, Any],
        name: str,
        list_type: str,
        default_country: str | None,
    ) -> SourceResult:
        """Fetch a file containing a list of URLs, then fetch each URL concurrently.

        The input file is expected to contain one URL per line. Lines that are
        empty, comments, or not absolute http/https URLs are skipped.
        """
        url = str(source.get("url") or "")
        if not url:
            return SourceResult(
                source_name=name,
                error=f"url-list source '{name}' is missing url",
                list_type=list_type,
                default_country=default_country,
            )

        # The index is an untrusted URL like every other one in the source:
        # ignoring the configured timeout here gave a hung mirror 30s*4 per try
        # and three tries, minutes of the job budget the operator had already
        # capped at ``timeout``.
        index_content = await self._fetch_direct_url(
            url,
            **self._direct_fetch_overrides(source),
        )
        if not index_content:
            return SourceResult(
                source_name=name,
                error=f"url-list index '{_redact_url(str(url))}' is empty or not found",
                list_type=list_type,
                default_country=default_country,
            )

        from datetime import UTC, datetime

        # Date tokens in listed URLs must be stable regardless of the runner's
        # local timezone — a local-time boundary produced yesterday's date.
        now = datetime.now(UTC)
        date_tokens = {
            "{YYYY}": now.strftime("%Y"),
            "{MM}": now.strftime("%m"),
            "{DD}": now.strftime("%d"),
            "{M}": str(now.month),
            "{YYYYMM}": now.strftime("%Y%m"),
            "{YYYYMMDD}": now.strftime("%Y%m%d"),
        }

        # Cap early: a 12MB index holds ~500k URLs; collecting all
        # before slicing to max_files wastes memory.
        max_files_early = self._int_source_value(source, "max_files", 200)
        max_files_early = min(max(1, max_files_early), 1000)
        seen: set[str] = set()
        urls: list[str] = []
        for line in index_content.splitlines():
            if len(urls) >= max_files_early:
                break
            line = line.strip()
            if not line or line.startswith(("#", "//")):
                continue
            # Some lists include URLs after labels like "URL: ..."; keep only the URL.
            # Split tokens on whitespace, then on commas that precede another
            # scheme:// — commas inside a URL itself are legal and must stay.
            candidates = [
                part.strip()
                for token in line.split()
                for part in _URL_COMMA_SPLIT_RE.split(token)
            ]
            for candidate in candidates:
                parsed = urlparse(candidate)
                if parsed.scheme in {"http", "https"} and parsed.netloc:
                    for token, value in date_tokens.items():
                        candidate = candidate.replace(token, value)
                    if candidate not in seen:
                        seen.add(candidate)
                        urls.append(candidate)
                    break

        if not urls:
            redacted_url = _redact_url(str(url))
            return SourceResult(
                source_name=name,
                error=f"url-list index '{redacted_url}' contains no valid URLs",
                list_type=list_type,
                default_country=default_country,
            )

        max_files = self._int_source_value(source, "max_files", 200, maximum=1000)
        urls = urls[:max_files]

        concurrency = self._int_source_value(
            source, "max_concurrent_urls", 10, maximum=50
        )
        concurrency = max(1, concurrency)
        semaphore = asyncio.Semaphore(concurrency)
        timeout = self._fetch_timeout(source)
        attempts = self._int_source_value(
            source,
            "attempts",
            DEFAULT_LISTED_URL_ATTEMPTS,
            maximum=10,
        )

        async def fetch_one(target: str) -> tuple[str, str] | None:
            async with semaphore:
                try:
                    content = await self._fetch_direct_url(
                        target,
                        timeout=timeout,
                        attempts=attempts,
                        # One client for the whole url-list batch: a fresh
                        # AsyncClient per URL re-parsed the CA bundle and
                        # re-handshaked 200 times for a 200-URL index.
                        client=shared_client,
                    )
                except Exception as exc:
                    logger.warning(
                        "url-list fetch failed for %s: %s",
                        _redact_url(target),
                        _safe_error_message(exc),
                    )
                    return None
                if not content:
                    logger.warning(
                        "url-list fetch returned empty content for %s",
                        _redact_url(target),
                    )
                    return None
                filename = (
                    self._safe_filename(str(source.get("filename") or ""))
                    or self._filename_from_url(target)
                    or f"{name}.txt"
                )
                return (filename, content)

        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
        ) as shared_client:
            tasks = [fetch_one(target) for target in urls]
            fetched = await asyncio.gather(*tasks)
        files = [item for item in fetched if item is not None]

        # Disambiguate duplicate filenames: a source-wide ``filename`` (or
        # index URLs sharing one basename) used to collapse every download to
        # the same entry, losing all but one file downstream.
        used_names: set[str] = set()
        deduped_files: list[tuple[str, str]] = []
        for filename, content in files:
            final = filename
            n = 1
            while final in used_names:
                suffix = PurePosixPath(filename).suffix
                if suffix:
                    stem = filename[: len(filename) - len(suffix)]
                    final = f"{stem}_{n}{suffix}"
                else:
                    # No extension: never invent one ("data" → "data_1").
                    final = f"{filename}_{n}"
                n += 1
            used_names.add(final)
            deduped_files.append((final, content))
        files = deduped_files

        if not files:
            return SourceResult(
                source_name=name,
                error=f"url-list source '{name}' fetched {len(urls)} URLs but none returned content",  # noqa: E501
                list_type=list_type,
                default_country=default_country,
            )

        return SourceResult(
            source_name=name,
            files=files,
            list_type=list_type,
            default_country=default_country,
        )

    @staticmethod
    def _source_default_country(source: dict[str, Any]) -> str | None:
        return _source_default_country(source)

    @staticmethod
    def _int_source_value(
        source: dict[str, Any],
        key: str,
        default: int,
        *,
        minimum: int = 1,
        maximum: int | None = None,
    ) -> int:
        return _int_source_value(source, key, default, minimum=minimum, maximum=maximum)

    @classmethod
    def _fetch_timeout(cls, source: dict[str, Any]) -> float:
        return _fetch_timeout(source)

    @classmethod
    def _direct_fetch_overrides(cls, source: dict[str, Any]) -> dict[str, Any]:
        return _direct_fetch_overrides(source)

    @staticmethod
    def _float_source_value(source: dict[str, Any], key: str, default: float) -> float:
        return _float_source_value(source, key, default)

    @staticmethod
    def _filter_files(
        source: dict[str, Any],
        files: list[tuple[str, str]],
    ) -> list[tuple[str, str]]:
        return _filter_files(source, files)

    # --- cleanup ---

    async def aclose(self) -> None:
        """Close the underlying GitHub HTTP client. Safe to call multiple times."""
        await self._github.aclose()

    async def __aenter__(self) -> SourceManager:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: object,
    ) -> None:
        await self.aclose()
