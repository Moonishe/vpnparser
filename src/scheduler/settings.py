"""Settings loading and typed accessor helpers.

Centralises YAML settings parsing and the various ``_as_*`` coercion helpers so
that stage classes do not need to duplicate the fallback logic.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


class SettingsParseError(RuntimeError):
    """An existing settings file exists but does not yield a usable mapping.

    Raised only on the strict path (:meth:`Settings.load_strict`) used before a
    full pipeline run: silently falling back to defaults there would publish
    unvalidated configs with every validator disabled.
    """


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
    if data is None:
        return {}
    if not isinstance(data, dict):
        logger.warning(
            "Settings root is %s, expected dict — using defaults.",
            type(data).__name__,
        )
        return {}
    return data


def load_settings_strict(path: str) -> dict[str, Any]:
    """Load an *existing* settings file, refusing broken YAML or a bad root.

    Unlike :func:`load_settings` this never falls back to ``{}``: a truncated
    commit, invalid YAML or a non-mapping root must abort the run instead of
    quietly disabling TCP/TLS/Xray validation and the country filter.
    """
    if not Path(path).is_file():
        msg = f"Settings file not found: {path}"
        raise FileNotFoundError(msg)
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        msg = (
            f"Settings file {path} failed to parse — refusing to run on "
            f"defaults: they disable TCP/TLS/Xray validation and the country "
            f"filter. Original error: {exc}"
        )
        raise SettingsParseError(msg) from exc
    if data is None or not isinstance(data, dict) or not data:
        kind = type(data).__name__
        msg = (
            f"Settings file {path} did not yield a non-empty mapping (got "
            f"{kind}) — refusing to run on defaults."
        )
        raise SettingsParseError(msg)
    return data


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
