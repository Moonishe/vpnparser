"""Tests for src.utils.paths module — 100% coverage."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.utils.paths import (
    _find_project_root,
    resolve_safe_output_path,
    safe_open,
    validate_safe_output_path,
)

# ---------------------------------------------------------------------------
# _find_project_root
# ---------------------------------------------------------------------------


def test_find_project_root_fallback(tmp_path, monkeypatch):
    """When pyproject.toml is not found, fall back to cwd (line 27-32)."""
    monkeypatch.chdir(tmp_path)
    root = _find_project_root("pyproject.toml")
    assert root == Path.cwd()


# ---------------------------------------------------------------------------
# resolve_safe_output_path
# ---------------------------------------------------------------------------


def test_resolve_safe_output_path_rejects_dotdot(tmp_path):
    """Path with '..' component raises ValueError (line 74)."""
    base = tmp_path / "base"
    base.mkdir()
    with pytest.raises(ValueError, match="unsafe path contains '..'"):
        resolve_safe_output_path("../other", base_dir=base)


def test_resolve_safe_output_path_relative_escapes_base(tmp_path):
    """Line 89: relative path resolves outside base_dir via junction/symlink.

    A relative path without ``..`` can still escape *base_dir* when the path
    traverses a directory junction or symlink that points outside *base_dir*.
    We use ``mklink /J`` (directory junction) on Windows.
    """
    import subprocess

    base = tmp_path / "base"
    base.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("data", encoding="utf-8")

    link = base / "escape"
    try:
        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(outside)],
            check=True,
            capture_output=True,
            timeout=10,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        pytest.skip(
            "Cannot create directory junction (insufficient permissions "
            "or unsupported platform)"
        )

    with pytest.raises(ValueError, match="path escapes base directory"):
        resolve_safe_output_path("escape/secret.txt", base_dir=base)


def test_resolve_safe_output_path_absolute_outside_warns(tmp_path, caplog):
    """Absolute path outside base_dir logs a warning (line 90-95)."""
    caplog.set_level("WARNING")
    # Target is inside tmp_path but outside a *nested* base_dir.
    base = tmp_path / "base"
    base.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "file.txt"
    target.write_text("data", encoding="utf-8")

    # base_dir=base, target is outside base -> logs warning.
    result = resolve_safe_output_path(target, base_dir=base)
    assert result == target.resolve()
    assert "absolute output path" in caplog.text


def test_resolve_safe_output_path_must_exist(tmp_path):
    """must_exist=True raises FileNotFoundError when file missing (line 98)."""
    missing = tmp_path / "nonexistent.txt"
    with pytest.raises(FileNotFoundError, match="does not exist"):
        resolve_safe_output_path(missing, must_exist=True)


def test_resolve_safe_output_path_relative(tmp_path):
    """Relative path resolved against base_dir."""
    base = tmp_path / "base"
    base.mkdir()
    target = base / "sub" / "file.txt"
    target.parent.mkdir(parents=True)
    target.write_text("data", encoding="utf-8")

    result = resolve_safe_output_path("sub/file.txt", base_dir=base)
    assert result == target.resolve()


def test_resolve_safe_output_path_absolute_inside(tmp_path):
    """Absolute path inside base_dir is accepted."""
    target = tmp_path / "inside.txt"
    target.write_text("data", encoding="utf-8")
    result = resolve_safe_output_path(target, base_dir=tmp_path)
    assert result == target.resolve()


# ---------------------------------------------------------------------------
# validate_safe_output_path
# ---------------------------------------------------------------------------


def test_validate_safe_output_path_true(tmp_path):
    """Returns True for a safe path."""
    target = tmp_path / "safe.txt"
    target.write_text("data", encoding="utf-8")
    assert validate_safe_output_path(target, base_dir=tmp_path) is True


def test_validate_safe_output_path_false(tmp_path, caplog):
    """Returns False and logs warning for an unsafe path (line 118)."""
    caplog.set_level("WARNING")
    base = tmp_path / "base"
    base.mkdir()
    assert validate_safe_output_path("../escape", base_dir=base) is False
    assert "Rejected unsafe path" in caplog.text


# ---------------------------------------------------------------------------
# safe_open
# ---------------------------------------------------------------------------


def test_safe_open_read(tmp_path):
    """safe_open with 'r' mode returns readable file (line 132-133)."""
    file = tmp_path / "readme.txt"
    file.write_text("hello world", encoding="utf-8")
    fh = safe_open(file, mode="r", base_dir=tmp_path)
    assert fh.read() == "hello world"
    fh.close()


def test_safe_open_write(tmp_path):
    """safe_open with 'w' mode returns writable file."""
    file = tmp_path / "output.txt"
    fh = safe_open(file, mode="w", base_dir=tmp_path)
    fh.write("written data")
    fh.close()
    assert file.read_text(encoding="utf-8") == "written data"


def test_safe_open_must_exist_raises(tmp_path):
    """safe_open with 'r' mode raises FileNotFoundError for missing file."""
    missing = tmp_path / "ghost.txt"
    with pytest.raises(FileNotFoundError):
        safe_open(missing, mode="r", base_dir=tmp_path)


def test_safe_open_escape_raises(tmp_path):
    """safe_open raises ValueError when path escapes base_dir."""
    base = tmp_path / "base"
    base.mkdir()
    with pytest.raises(ValueError):
        safe_open("../escape.txt", mode="w", base_dir=base)
