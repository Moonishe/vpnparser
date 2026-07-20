"""Tests for src.scheduler.settings module — 100% coverage."""

from __future__ import annotations

from src.scheduler.settings import Settings, load_settings

# ---------------------------------------------------------------------------
# load_settings
# ---------------------------------------------------------------------------


def test_load_settings_success(tmp_path):
    """load_settings returns parsed YAML dict."""
    cfg = tmp_path / "settings.yaml"
    cfg.write_text("key: value\nnested:\n  inner: 42\n", encoding="utf-8")
    result = load_settings(str(cfg))
    assert result == {"key": "value", "nested": {"inner": 42}}


def test_load_settings_file_not_found(caplog):
    """load_settings returns {} on FileNotFoundError."""
    caplog.set_level("WARNING")
    result = load_settings("/nonexistent/path/settings.yaml")
    assert result == {}
    assert "Settings file not found" in caplog.text


def test_load_settings_yaml_error(tmp_path, caplog):
    """load_settings returns {} on YAML parse error (lines 25-27)."""
    caplog.set_level("WARNING")
    bad = tmp_path / "bad.yaml"
    bad.write_text("{invalid: yaml: broken\n", encoding="utf-8")
    result = load_settings(str(bad))
    assert result == {}


def test_load_settings_empty(tmp_path):
    """load_settings returns {} when YAML file is empty/None."""
    empty = tmp_path / "empty.yaml"
    empty.write_text("", encoding="utf-8")
    result = load_settings(str(empty))
    assert result == {}

    null_doc = tmp_path / "null.yaml"
    null_doc.write_text("null\n", encoding="utf-8")
    result2 = load_settings(str(null_doc))
    assert result2 == {}


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


def test_settings_init():
    """Settings wraps a dict."""
    s = Settings({"a": 1})
    assert s._data == {"a": 1}


def test_settings_section_missing():
    """section() returns empty dict for missing key."""
    s = Settings({})
    assert s.section("nope") == {}


def test_settings_section_not_dict():
    """section() returns empty dict when value is not a dict."""
    s = Settings({"key": "string_value"})
    assert s.section("key") == {}


def test_settings_get_existing():
    """get() returns value for existing key (line 44)."""
    s = Settings({"a": 1, "b": None})
    assert s.get("a") == 1
    assert s.get("b") is None


def test_settings_get_default():
    """get() returns default for missing key."""
    s = Settings({})
    assert s.get("missing", "fallback") == "fallback"
    assert s.get("another") is None


def test_settings_as_int_valid():
    """as_int returns the integer value."""
    assert Settings.as_int("42", 0) == 42
    assert Settings.as_int(99, 0) == 99


def test_settings_as_int_invalid():
    """as_int returns default on invalid value."""
    assert Settings.as_int("not-a-number", 10) == 10
    assert Settings.as_int(None, 5) == 5


def test_settings_as_int_minimum():
    """as_int clamps to minimum."""
    assert Settings.as_int("3", 10, minimum=5) == 5
    assert Settings.as_int("10", 10, minimum=5) == 10


def test_settings_as_float_valid():
    """as_float returns the float value."""
    assert Settings.as_float("3.14", 0.0) == 3.14
    assert Settings.as_float(2.5, 0.0) == 2.5


def test_settings_as_float_invalid():
    """as_float returns default on invalid value."""
    assert Settings.as_float("not-a-float", 1.0) == 1.0
    assert Settings.as_float(None, 0.5) == 0.5


def test_settings_as_float_minimum():
    """as_float clamps to minimum (line 65)."""
    result = Settings.as_float(0.5, default=1.0, minimum=1.0)
    assert result == 1.0

    result2 = Settings.as_float(2.0, default=1.0, minimum=0.5)
    assert result2 == 2.0


def test_settings_as_bool_bool():
    """as_bool returns bool value unchanged."""
    assert Settings.as_bool(True, False) is True
    assert Settings.as_bool(False, True) is False


def test_settings_as_bool_str():
    """as_bool parses string truthy values."""
    assert Settings.as_bool("true", False) is True
    assert Settings.as_bool("True", False) is True
    assert Settings.as_bool("1", False) is True
    assert Settings.as_bool("yes", False) is True
    assert Settings.as_bool("on", False) is True
    assert Settings.as_bool("false", True) is False
    assert Settings.as_bool("no", True) is False
    assert Settings.as_bool("0", True) is False


def test_settings_as_bool_none():
    """as_bool returns default for None."""
    assert Settings.as_bool(None, True) is True
    assert Settings.as_bool(None, False) is False


def test_settings_as_bool_fallback():
    """as_bool with non-bool non-str non-None value -> bool(value) (line 77)."""
    # Non-empty list is truthy
    assert Settings.as_bool([1, 2, 3], default=False) is True
    # Empty list is falsy
    assert Settings.as_bool([], default=True) is False
    # Integer truthiness
    assert Settings.as_bool(1, default=False) is True
    assert Settings.as_bool(0, default=True) is False


def test_settings_as_list_valid():
    """as_list returns a copy of the list."""
    original = [1, 2, 3]
    result = Settings.as_list(original)
    assert result == [1, 2, 3]
    # Ensure it's a copy.
    result.append(4)
    assert original == [1, 2, 3]


def test_settings_as_list_non_list():
    """as_list returns [] for non-list value (line 82-84)."""
    assert Settings.as_list("not a list") == []
    assert Settings.as_list(42) == []
    assert Settings.as_list(None) == []
    assert Settings.as_list({"a": 1}) == []
