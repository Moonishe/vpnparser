"""Settings loading and typed accessor helpers.

Centralises YAML settings parsing and the various ``_as_*`` coercion helpers so
that stage classes do not need to duplicate the fallback logic.
"""

from __future__ import annotations

import logging
from typing import Any

import yaml

logger = logging.getLogger(__name__)


def load_settings(path: str) -> dict[str, Any]:
    """Load settings from a YAML file, returning an empty dict on failure."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except FileNotFoundError:
        logger.exception("Settings file not found: %s — using defaults.", path)
        return {}
    except yaml.YAMLError:
        logger.exception("Failed to parse settings %s — using defaults.", path)
        return {}
    return data or {}


class Settings:
    """Thin wrapper around the raw settings dict with typed accessors."""

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    def section(self, key: str) -> dict[str, Any]:
        """Return a settings section (empty dict if missing or not a dict)."""
        section = self._data.get(key, {})
        return section if isinstance(section, dict) else {}

    def get(self, key: str, default: Any = None) -> Any:
        """Return a top-level setting."""
        return self._data.get(key, default)

    @staticmethod
    def as_int(value: Any, default: int, *, minimum: int | None = None) -> int:
        """Coerce ``value`` to int, falling back to ``default`` and optional bound."""
        try:
            result = int(value)
        except (TypeError, ValueError):
            result = int(default)
        if minimum is not None and result < minimum:
            result = minimum
        return result

    @staticmethod
    def as_float(value: Any, default: float, *, minimum: float | None = None) -> float:
        """Coerce ``value`` to float, falling back to ``default`` and optional bound."""
        try:
            result = float(value)
        except (TypeError, ValueError):
            result = float(default)
        if minimum is not None and result < minimum:
            result = minimum
        return result

    @staticmethod
    def as_bool(value: Any, default: bool) -> bool:
        """Coerce ``value`` to bool, falling back to ``default``."""
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in {"true", "1", "yes", "on"}
        if value is None:
            return default
        return bool(value)

    @staticmethod
    def as_list(value: Any) -> list[Any]:
        """Return a list or an empty list if the value is not a list."""
        if isinstance(value, list):
            return list(value)
        return []
