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
from pathlib import Path

import yaml

from src.sources.github import GitHubClient
from src.sources.list_types import infer_source_list_type

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
    list_type: str = "mixed"

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
        results = await asyncio.gather(*tasks, return_exceptions=False)
        # gather preserves order of the input tasks.
        return list(results)

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
        """
        name = source.get("name", "<unnamed>")
        stype = source.get("type", "")
        owner = source.get("owner", "")
        repo = source.get("repo", "")
        path = source.get("path", "")
        branch = source.get("branch", "main")
        list_type = infer_source_list_type(source)

        # subscription requires path; raw allows empty path (= root directory).
        if not (owner and repo):
            return SourceResult(
                source_name=name,
                error=f"source '{name}' is missing owner/repo",
                list_type=list_type,
            )
        if stype == "subscription" and not path:
            return SourceResult(
                source_name=name,
                error=f"subscription source '{name}' requires a file path",
                list_type=list_type,
            )

        try:
            if stype == "subscription":
                content = await self._github.fetch_file(owner, repo, path, branch)
                if not content:
                    return SourceResult(
                        source_name=name,
                        error=f"subscription file '{path}' is empty or not found",
                        list_type=list_type,
                    )
                filename = path.rsplit("/", 1)[-1] or f"{name}.txt"
                return SourceResult(
                    source_name=name,
                    files=[(filename, content)],
                    list_type=list_type,
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
                    )
                return SourceResult(source_name=name, files=files, list_type=list_type)

            return SourceResult(
                source_name=name,
                error=f"unknown source type '{stype}' (expected 'subscription' or 'raw')",
                list_type=list_type,
            )
        except Exception as exc:
            # Isolate failures: log and surface as a structured error.
            logger.error("Failed to fetch source '%s': %s", name, exc, exc_info=True)
            return SourceResult(source_name=name, error=str(exc), list_type=list_type)

    @staticmethod
    def _int_source_value(source: dict, key: str, default: int) -> int:
        """Read a positive integer source setting."""
        try:
            value = int(source.get(key, default))
        except (TypeError, ValueError):
            return default
        return max(1, value)

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
        """

        def _to_filter_set(key: str) -> set[str]:
            raw = source.get(key)
            if not isinstance(raw, list):
                return set()
            return {
                str(item).strip().lower()
                for item in raw
                if item is not None and str(item).strip()
            }

        include = _to_filter_set("include_files")
        exclude = _to_filter_set("exclude_files")
        if not include and not exclude:
            return files

        filtered: list[tuple[str, str]] = []
        for filename, content in files:
            key = str(filename).strip().lower()
            if include and key not in include:
                continue
            if key in exclude:
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
