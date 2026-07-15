"""Pipeline context and state objects.

These dataclasses carry the shared, mutable state between stages without
polluting the orchestrator.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.parsers.base import Config
from src.scheduler.settings import Settings


@dataclass
class ListResult:
    """A list label together with its configs and per-list statistics."""

    label: str
    configs: list[Config] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)


@dataclass
class PipelineContext:
    """Dependencies and shared bookkeeping for the whole pipeline run."""

    settings: Settings
    github_token: str | None
    sources_path: str
    liveness_stats: dict[str, Any] = field(default_factory=dict)
    output_stats: dict[str, Any] = field(default_factory=dict)
    health_history: dict[str, Any] | None = None
    proxy_health_history: Any = None
    proxy_health_file: str | None = None


@dataclass
class PipelineState:
    """Mutable state passed from stage to stage."""

    sources: list[Any] = field(default_factory=list)
    parsed: dict[str, list[Config]] = field(default_factory=dict)
    preprocessed: dict[str, list[Config]] = field(default_factory=dict)
    quality_filtered: dict[str, list[Config]] = field(default_factory=dict)
    validated: dict[str, list[Config]] = field(default_factory=dict)
    aggregated: list[Config] = field(default_factory=list)
    split_configs: dict[str, list[Config]] = field(default_factory=dict)
    output_files: list[str] = field(default_factory=list)
    summary_file: str | None = None
    published: bool = False
