"""Helpers for source white/black list classification."""

from __future__ import annotations

from typing import Any

DEFAULT_LIST_TYPE = "mixed"

_ALIASES = {
    "black": "blacklist",
    "blacklist": "blacklist",
    "black_list": "blacklist",
    "black-list": "blacklist",
    "bl": "blacklist",
    "white": "whitelist",
    "whitelist": "whitelist",
    "white_list": "whitelist",
    "white-list": "whitelist",
    "wl": "whitelist",
    "mixed": "mixed",
    "common": "mixed",
    "general": "mixed",
    "pool": "mixed",
}


def normalize_list_type(value: Any) -> str:
    """Normalize a user-facing source list type.

    Unknown values intentionally fall back to ``mixed`` so one bad config value
    cannot break the whole source fetch.
    """
    if value is None:
        return DEFAULT_LIST_TYPE
    text = str(value).strip().lower()
    if not text:
        return DEFAULT_LIST_TYPE
    return _ALIASES.get(text, DEFAULT_LIST_TYPE)


def infer_source_list_type(source: dict[str, Any]) -> str:
    """Return explicit or name/path-inferred source list type."""
    explicit = (
        source.get("list_type")
        or source.get("group")
        or source.get("category")
        or source.get("bucket")
    )
    if explicit:
        return normalize_list_type(explicit)

    haystack = " ".join(
        str(source.get(key, "")) for key in ("name", "path", "repo")
    ).lower()
    if "black" in haystack or "obhod_bl" in haystack or "-bl" in haystack:
        return "blacklist"
    if "white" in haystack or "obhod_wl" in haystack or "-wl" in haystack:
        return "whitelist"
    return DEFAULT_LIST_TYPE
