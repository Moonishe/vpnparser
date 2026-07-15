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
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

import httpx
import yaml

from src.sources.github import GitHubClient
from src.sources.list_types import DEFAULT_LIST_TYPE, infer_source_list_type

logger = logging.getLogger(__name__)


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
        self.settings: dict = self._load_settings()
        self.sources: list[dict] = self._load_sources()

        # Concurrency control ------------------------------------------------
        max_concurrent = self._settings_sources().get("max_concurrent_fetches", 10)
        try:
            max_concurrent = int(max_concurrent)
        except (TypeError, ValueError):
            max_concurrent = 10
        self._semaphore = asyncio.Semaphore(max(1, max_concurrent))

        # GitHub client (lazily used inside fetch_source; lifecycle owned here)
        api_base = self._settings_sources().get(
            "github_api_base", "https://api.github.com"
        )
        self._github = GitHubClient(token=github_token, api_base=api_base)

    # --- config loading ---

    def _settings_sources(self) -> dict:
        return (
            self.settings.get("sources", {}) if isinstance(self.settings, dict) else {}
        )

    def _load_settings(self) -> dict:
        if not self.settings_file.exists():
            logger.warning("Settings file not found: %s", self.settings_file)
            return {}
        try:
            with self.settings_file.open("r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            return data if isinstance(data, dict) else {}
        except (yaml.YAMLError, OSError) as exc:
            logger.error("Failed to load settings %s: %s", self.settings_file, exc)
            return {}

    def _load_sources(self) -> list[dict]:
        if not self.sources_file.exists():
            logger.warning("Sources file not found: %s", self.sources_file)
            return []
        try:
            with self.sources_file.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            logger.error("Failed to load sources %s: %s", self.sources_file, exc)
            return []
        sources = data.get("sources", []) if isinstance(data, dict) else []
        return [s for s in sources if isinstance(s, dict)]

    # --- public API ---

    def enabled_sources(self) -> list[dict]:
        """Return only sources with ``enabled: true``."""
        return [s for s in self.sources if s.get("enabled", False) is True]

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
        for source, raw in zip(enabled, raw_results):
            if isinstance(raw, Exception):
                name = (
                    source.get("name", "<unnamed>")
                    if isinstance(source, dict)
                    else "<unnamed>"
                )
                logger.error(
                    "Unhandled error fetching source '%s': %s",
                    name,
                    raw,
                    exc_info=raw,
                )
                results.append(SourceResult(source_name=name, error=str(raw)))
            elif isinstance(raw, BaseException):
                # Cancellation / system exit — must propagate, not be swallowed.
                raise raw
            else:
                results.append(raw)
        return results

    async def _fetch_with_semaphore(self, source: dict) -> SourceResult:
        async with self._semaphore:
            return await self.fetch_source(source)

    async def fetch_source(self, source: dict) -> SourceResult:
        """Fetch a single source. Never raises — errors become ``SourceResult.error``.

        Supported source types:
            * ``subscription`` — fetch a single file at ``path``; its content
              is a base64 subscription blob (kept as a single (filename, content) tuple).
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
                content = await self._fetch_direct_url(str(url))
                if not content:
                    return SourceResult(
                        source_name=name,
                        error=f"url source '{url}' is empty or not found",
                        list_type=list_type,
                        default_country=default_country,
                    )
                filename = (
                    str(source.get("filename") or "").strip()
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
                return await self._fetch_url_list(source, name, list_type, default_country)

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
                filename = path.rsplit("/", 1)[-1] or f"{name}.txt"
                return SourceResult(
                    source_name=name,
                    files=[(filename, content)],
                    list_type=list_type,
                    default_country=default_country,
                )

            if stype == "raw":
                max_depth = self._int_source_value(source, "max_depth", 3)
                max_files = self._int_source_value(source, "max_files", 200)
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
                    "(expected 'subscription', 'raw', or 'url')"
                ),
                list_type=list_type,
                default_country=default_country,
            )
        except Exception as exc:
            # Isolate failures: log and surface as a structured error.
            logger.error("Failed to fetch source '%s': %s", name, exc, exc_info=True)
            return SourceResult(source_name=name, error=str(exc), list_type=list_type)

    @staticmethod
    async def _fetch_direct_url(
        url: str,
        timeout: float = 30.0,
        attempts: int = 3,
        retry_delay: float = 2.0,
    ) -> str:
        """Fetch a direct HTTPS text source."""
        parsed = urlparse((url or "").strip())
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError(f"source url must be absolute HTTP/HTTPS: {url!r}")

        max_attempts = max(1, attempts)
        last_error: Exception | None = None
        headers = {
            "User-Agent": "vpn-config-parser/1.0",
            "Accept": "text/plain,*/*",
        }
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            for attempt in range(1, max_attempts + 1):
                try:
                    response = await client.get(url, headers=headers)
                    if response.status_code == 404:
                        return ""
                    response.raise_for_status()
                    return response.text
                except (httpx.RequestError, httpx.HTTPStatusError) as exc:
                    last_error = exc
                    if attempt >= max_attempts:
                        break
                    logger.warning(
                        "Direct source fetch failed for %s (attempt %d/%d): %s",
                        url,
                        attempt,
                        max_attempts,
                        exc,
                    )
                    await asyncio.sleep(max(0.0, retry_delay))
        if last_error is not None:
            raise last_error
        return ""

    @staticmethod
    def _filename_from_url(url: str) -> str:
        parsed = urlparse((url or "").strip())
        return PurePosixPath(parsed.path).name or ""

    async def _fetch_url_list(
        self,
        source: dict,
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

        index_content = await self._fetch_direct_url(url)
        if not index_content:
            return SourceResult(
                source_name=name,
                error=f"url-list index '{url}' is empty or not found",
                list_type=list_type,
                default_country=default_country,
            )

        from datetime import datetime

        now = datetime.now()
        date_tokens = {
            "{YYYY}": now.strftime("%Y"),
            "{MM}": now.strftime("%m"),
            "{DD}": now.strftime("%d"),
            "{M}": str(now.month),
            "{YYYYMM}": now.strftime("%Y%m"),
            "{YYYYMMDD}": now.strftime("%Y%m%d"),
        }

        seen: set[str] = set()
        urls: list[str] = []
        for line in index_content.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "//")):
                continue
            # Some lists include URLs after labels like "URL: ..."; keep only the URL.
            candidates = [part.strip() for part in line.replace(",", " ").split()]
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
            return SourceResult(
                source_name=name,
                error=f"url-list index '{url}' contains no valid URLs",
                list_type=list_type,
                default_country=default_country,
            )

        max_files = self._int_source_value(source, "max_files", 200)
        urls = urls[:max_files]

        concurrency = self._int_source_value(source, "max_concurrent_urls", 10)
        concurrency = max(1, concurrency)
        semaphore = asyncio.Semaphore(concurrency)
        timeout = self._float_source_value(source, "timeout", 30.0)
        attempts = self._int_source_value(source, "attempts", 1)

        async def fetch_one(target: str) -> tuple[str, str] | None:
            async with semaphore:
                try:
                    content = await self._fetch_direct_url(
                        target, timeout=timeout, attempts=attempts
                    )
                except Exception as exc:
                    logger.warning("url-list fetch failed for %s: %s", target, exc)
                    return None
                if not content:
                    return None
                filename = (
                    str(source.get("filename") or "").strip()
                    or self._filename_from_url(target)
                    or f"{name}.txt"
                )
                return (filename, content)

        tasks = [fetch_one(target) for target in urls]
        fetched = await asyncio.gather(*tasks)
        files = [item for item in fetched if item is not None]

        if not files:
            return SourceResult(
                source_name=name,
                error=f"url-list source '{name}' fetched {len(urls)} URLs but none returned content",
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
    def _source_default_country(source: dict) -> str | None:
        raw = source.get("default_country")
        if raw is None:
            return None
        text = str(raw).strip().upper()
        return text if len(text) == 2 and text.isalpha() else None

    @staticmethod
    def _int_source_value(source: dict, key: str, default: int) -> int:
        """Read a positive integer source setting.

        Booleans are explicitly rejected — ``bool`` is a subclass of ``int``
        in Python (``int(True) == 1``), so without this guard a config value
        like ``max_files: false`` would silently become ``1`` instead of
        falling back to the default.
        """
        raw = source.get(key, default)
        if isinstance(raw, bool):
            return default
        try:
            value = int(raw)
        except (TypeError, ValueError):
            return default
        return max(1, value)

    @staticmethod
    def _float_source_value(source: dict, key: str, default: float) -> float:
        """Read a float source setting, rejecting booleans."""
        raw = source.get(key, default)
        if isinstance(raw, bool):
            return default
        try:
            value = float(raw)
        except (TypeError, ValueError):
            return default
        return value

    @staticmethod
    def _filter_files(
        source: dict,
        files: list[tuple[str, str]],
    ) -> list[tuple[str, str]]:
        """Apply optional include_files/exclude_files filters to raw sources.

        Non-list values (str, int, None) are silently ignored — only actual
        lists are iterated.  ``None`` items inside a list are skipped so they
        cannot become the literal string ``"none"`` and accidentally filter
        out every file.

        Filter entries are normalized identically to filenames (backslashes
        converted to forward slashes, leading/trailing slashes stripped,
        lowercased) so that ``"/keep.txt"`` or ``"dir\\\\file.txt"`` in the
        config match the corresponding file.
        """

        def _norm(value: object) -> str:
            return str(value).strip().replace("\\", "/").strip("/").lower()

        def _to_filter_set(key: str) -> set[str]:
            raw = source.get(key)
            if not isinstance(raw, list):
                return set()
            return {
                _norm(item) for item in raw if item is not None and str(item).strip()
            }

        include = _to_filter_set("include_files")
        exclude = _to_filter_set("exclude_files")
        if not include and not exclude:
            return files

        filtered: list[tuple[str, str]] = []
        for filename, content in files:
            key = _norm(filename)
            basename = PurePosixPath(key).name
            match_keys = {key, basename}
            if include and not (include & match_keys):
                continue
            if exclude & match_keys:
                continue
            filtered.append((filename, content))
        return filtered

    # --- cleanup ---

    async def aclose(self) -> None:
        """Close the underlying GitHub HTTP client. Safe to call multiple times."""
        await self._github.aclose()

    async def __aenter__(self) -> SourceManager:
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()
