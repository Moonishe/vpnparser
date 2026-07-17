"""Tests for src.sources.list_types — normalize_list_type & infer_source_list_type."""

from __future__ import annotations

from src.sources.list_types import infer_source_list_type, normalize_list_type


def test_normalize_list_type_none() -> None:
    """line 41: None input returns 'mixed'."""
    assert normalize_list_type(None) == "mixed"


def test_normalize_list_type_empty_string() -> None:
    """line 44: empty / whitespace-only string returns 'mixed'."""
    assert normalize_list_type("") == "mixed"
    assert normalize_list_type("  ") == "mixed"


def test_normalize_list_type_known_aliases() -> None:
    """All known aliases map to the correct list type."""
    cases: list[tuple[str, str]] = [
        ("black", "blacklist"),
        ("blacklist", "blacklist"),
        ("black_list", "blacklist"),
        ("black-list", "blacklist"),
        ("bl", "blacklist"),
        ("white", "whitelist"),
        ("whitelist", "whitelist"),
        ("white_list", "whitelist"),
        ("white-list", "whitelist"),
        ("wl", "whitelist"),
        ("mixed", "mixed"),
        ("common", "mixed"),
        ("general", "mixed"),
        ("pool", "mixed"),
    ]
    for value, expected in cases:
        assert normalize_list_type(value) == expected, f"value={value!r}"


def test_normalize_list_type_unknown_falls_back_to_mixed() -> None:
    """Unknown values fall back to 'mixed'."""
    assert normalize_list_type("unknown") == "mixed"
    assert normalize_list_type("something_else") == "mixed"


def test_infer_source_list_type_explicit_list_type() -> None:
    """'list_type' key is used when present."""
    result = infer_source_list_type({"list_type": "blacklist"})
    assert result == "blacklist"


def test_infer_source_list_type_explicit_group() -> None:
    """'group' key is used when list_type is absent."""
    result = infer_source_list_type({"group": "whitelist"})
    assert result == "whitelist"


def test_infer_source_list_type_explicit_category() -> None:
    """'category' key is used when list_type/group are absent."""
    result = infer_source_list_type({"category": "mixed"})
    assert result == "mixed"


def test_infer_source_list_type_explicit_bucket() -> None:
    """'bucket' key is used when other explicit keys are absent."""
    result = infer_source_list_type({"bucket": "blacklist"})
    assert result == "blacklist"


def test_infer_source_list_type_from_name_contains_black() -> None:
    """'black' in name infers blacklist."""
    result = infer_source_list_type({"name": "my-blacklist-source"})
    assert result == "blacklist"


def test_infer_source_list_type_from_name_contains_white() -> None:
    """'white' in name infers whitelist."""
    result = infer_source_list_type({"name": "my-whitelist-source"})
    assert result == "whitelist"


def test_infer_source_list_type_from_path_bl_tag() -> None:
    """-bl suffix in path infers blacklist."""
    result = infer_source_list_type({"path": "sources/obhod-bl"})
    assert result == "blacklist"


def test_infer_source_list_type_from_path_wl_tag() -> None:
    """-wl suffix in path infers whitelist."""
    result = infer_source_list_type({"path": "sources/source-wl"})
    assert result == "whitelist"


def test_infer_source_list_type_from_repo_black() -> None:
    """'black' in repo name infers blacklist."""
    result = infer_source_list_type({"repo": "blacklist-repo"})
    assert result == "blacklist"


def test_infer_source_list_type_no_match_returns_mixed() -> None:
    """When no indicators are found, returns 'mixed'."""
    result = infer_source_list_type({"name": "generic-source"})
    assert result == "mixed"


def test_infer_source_list_type_empty_source() -> None:
    """Empty source dict returns 'mixed'."""
    assert infer_source_list_type({}) == "mixed"


def test_infer_source_list_type_black_checked_before_white() -> None:
    """When both 'black' and 'white' appear, blacklist wins (checked first)."""
    result = infer_source_list_type({"name": "black-and-white-list"})
    assert result == "blacklist"
