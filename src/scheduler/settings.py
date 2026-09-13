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
        with open(path, encoding="utf-8-sig") as fh:
            data = yaml.safe_load(fh)
    except FileNotFoundError:
        logger.warning("Settings file not found: %s — using defaults.", path)
        return {}
    except yaml.YAMLError:
        logger.exception("Failed to parse settings %s — using defaults.", path)
        return {}
    except (OSError, UnicodeDecodeError) as exc:
        logger.warning("Cannot read settings %s (%s) — using defaults.", path, exc)
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
        # utf-8-sig like the lenient loader: a BOM must not fail strict
        # while passing lenient.
        with open(path, encoding="utf-8-sig") as fh:
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
        # None = the key is simply absent (absent-key readers pass their
        # .get() default through here): silence, not garbage. Warning on it
        # used to fire three times per quality-section read and drown the
        # real typos.
        if value is None:
            return int(default)
        # bool is an int subclass (True == 1): accept it only when already a
        # bool-shaped default is impossible — a `max_configs: true` typo must
        # not silently become 1 (mirrors source_options._int_source_value).
        if isinstance(value, bool):
            return int(default)
        try:
            result = int(value)
        except (TypeError, ValueError):
            # Garbage in the YAML must not pass silently: an operator typo
            # would otherwise read exactly like the default in the logs.
            logger.warning(
                "settings: non-integer value %r — using default %d",
                value,
                int(default),
            )
            result = int(default)
        if minimum is not None and result < minimum:
            result = minimum
        return result

    @staticmethod
    def as_float(value: Any, default: float, *, minimum: float | None = None) -> float:
        """Coerce ``value`` to float, falling back to ``default`` and optional bound."""
        import math

        if value is None:
            return float(default)
        if isinstance(value, bool):
            return float(default)
        try:
            result = float(value)
        except (TypeError, ValueError):
            logger.warning(
                "settings: non-numeric value %r — using default %s",
                value,
                float(default),
            )
            result = float(default)
        if not math.isfinite(result):
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
            norm = value.strip().lower()
            if norm in {"true", "1", "yes", "on"}:
                return True
            if norm in {"false", "0", "no", "off", ""}:
                return False
            # Typo ("flase", "ture", "enabled") used to silently become
            # False and quietly disable validators (fail-open). Warn loudly.
            logger.warning(
                "Unrecognized boolean string %r — treating as False. "
                "Expected one of true/false/1/0/yes/no/on/off.",
                value,
            )
            return False
        if value is None:
            return default
        return bool(value)

    @staticmethod
    def as_list(value: Any) -> list[Any]:
        """Return a list or an empty list if the value is not a list."""
        if isinstance(value, list):
            return list(value)
        return []
