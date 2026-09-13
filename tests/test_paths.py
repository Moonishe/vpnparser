"""Tests for src.utils.paths module — 100% coverage."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from src.utils.paths import (
    _find_project_root,
    _walk_for_anchor,
    resolve_safe_output_path,
    safe_open,
    validate_safe_output_path,
    write_text_atomic,
)

# ---------------------------------------------------------------------------
# _find_project_root
# ---------------------------------------------------------------------------


def test_find_project_root_fallback(tmp_path, monkeypatch):
    """(clears the lru cache: the real function must not poison other tests)"""
    _walk_for_anchor.cache_clear()
    try:
        return _find_project_root_fallback_impl(tmp_path, monkeypatch)
    finally:
        _walk_for_anchor.cache_clear()


def _find_project_root_fallback_impl(tmp_path, monkeypatch):
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


def _link_dir(link: Path, target: Path) -> None:
    """Create a directory link at *link* pointing at *target*.

    POSIX gets a symlink; Windows gets a directory junction, which — unlike a
    symlink — needs no elevated privileges. Skips the test when neither works.
    """
    if os.name != "nt":
        try:
            link.symlink_to(target, target_is_directory=True)
        except OSError as exc:  # pragma: no cover - depends on the sandbox
            pytest.skip(f"cannot create symlink: {exc}")
        return

    import subprocess

    try:
        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)],
            check=True,
            capture_output=True,
            timeout=10,
        )
    except (
        subprocess.CalledProcessError,
        FileNotFoundError,
        subprocess.TimeoutExpired,
    ) as exc:  # pragma: no cover - depends on the sandbox
        pytest.skip(f"cannot create directory junction: {exc}")


def test_resolve_safe_output_path_relative_escapes_base(tmp_path):
    """A relative path that escapes base_dir through a link is rejected.

    A relative path without ``..`` can still escape *base_dir* when it
    traverses a symlink (POSIX) or a directory junction (Windows) pointing
    outside *base_dir*. Both platforms are covered so this security branch is
    not silently skipped in CI.
    """
    base = tmp_path / "base"
    base.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("data", encoding="utf-8")

    _link_dir(base / "escape", outside)

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


def test_resolve_safe_output_path_strict_rejects_absolute_outside(tmp_path):
    """strict=True turns the warned-about escape into a hard error."""
    base = tmp_path / "base"
    base.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "file.txt"
    target.write_text("data", encoding="utf-8")

    with pytest.raises(ValueError, match="path escapes base directory"):
        resolve_safe_output_path(target, base_dir=base, strict=True)


def test_resolve_safe_output_path_strict_allows_absolute_inside(tmp_path):
    """strict=True still accepts an absolute path inside base_dir."""
    target = tmp_path / "inside.txt"
    target.write_text("data", encoding="utf-8")
    result = resolve_safe_output_path(target, base_dir=tmp_path, strict=True)
    assert result == target.resolve()


def test_resolve_safe_output_path_default_allows_absolute_outside(tmp_path):
    """The default (strict=False) behaviour is unchanged — dozens of tests rely
    on passing absolute tmp_path locations."""
    base = tmp_path / "base"
    base.mkdir()
    target = tmp_path / "outside.txt"
    target.write_text("data", encoding="utf-8")
    assert resolve_safe_output_path(target, base_dir=base) == target.resolve()


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


def test_validate_safe_output_path_strict_absolute_outside(tmp_path):
    """The absolute escape is safe by default and unsafe under strict=True."""
    base = tmp_path / "base"
    base.mkdir()
    target = tmp_path / "outside.txt"
    target.write_text("data", encoding="utf-8")

    assert validate_safe_output_path(target, base_dir=base) is True
    assert validate_safe_output_path(target, base_dir=base, strict=True) is False


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


def test_safe_open_forwards_strict(tmp_path):
    """strict=True must be reachable through safe_open, not only the resolvers.

    safe_open builds its path with resolve_safe_output_path too, so without the
    passthrough the strict mode was simply unavailable to callers that open
    files through this helper.
    """
    base = tmp_path / "base"
    base.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("data", encoding="utf-8")

    # Default: an absolute path outside base_dir is allowed (with a warning).
    fh = safe_open(outside, mode="r", base_dir=base)
    assert fh.read() == "data"
    fh.close()

    with pytest.raises(ValueError, match="path escapes base directory"):
        safe_open(outside, mode="r", base_dir=base, strict=True)


def test_safe_open_strict_passes_kwargs_through(tmp_path):
    """The keyword-only strict flag does not shadow open() kwargs."""
    target = tmp_path / "encoded.txt"
    fh = safe_open(target, mode="w", base_dir=tmp_path, strict=True, encoding="utf-8")
    fh.write("привет")
    fh.close()
    assert target.read_text(encoding="utf-8") == "привет"


# ---------------------------------------------------------------------------
# write_text_atomic
# ---------------------------------------------------------------------------


def test_write_text_atomic_writes_and_replaces(tmp_path):
    """The target gets the content; a previous version is replaced."""
    target = tmp_path / "state.json"
    target.write_text("old", encoding="utf-8")
    write_text_atomic(target, '{"new": 1}')
    assert target.read_text(encoding="utf-8") == '{"new": 1}'
    # No temp files are left behind next to the target.
    assert [p.name for p in tmp_path.iterdir()] == ["state.json"]


def test_write_text_atomic_creates_parent_dirs(tmp_path):
    """Missing parent directories are created on demand."""
    target = tmp_path / "nested" / "deep" / "state.json"
    write_text_atomic(target, "data")
    assert target.read_text(encoding="utf-8") == "data"


def test_write_text_atomic_cleans_temp_on_failure(tmp_path, monkeypatch):
    """A failing write raises and does not leave a temp file behind."""
    target = tmp_path / "state.json"

    def _boom(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr("src.utils.paths.os.replace", _boom)
    with pytest.raises(OSError, match="disk full"):
        write_text_atomic(target, "data")
    assert [p.name for p in tmp_path.iterdir()] == []


class TestProjectRootOverride:
    """VPNPARSER_PROJECT_ROOT pins the containment base explicitly.

    The installed console script launches from an arbitrary cwd: without the
    override its "safe" output base silently followed the caller's directory.
    """

    def test_env_override_wins(self, monkeypatch, tmp_path) -> None:
        monkeypatch.setenv("VPNPARSER_PROJECT_ROOT", str(tmp_path))
        _walk_for_anchor.cache_clear()
        try:
            assert _find_project_root() == tmp_path.resolve()
        finally:
            _walk_for_anchor.cache_clear()

    def test_cache_returns_same_object_until_cleared(
        self, monkeypatch, tmp_path
    ) -> None:
        _walk_for_anchor.cache_clear()
        try:
            a = _find_project_root()
            b = _find_project_root()
            assert a is b
        finally:
            _walk_for_anchor.cache_clear()

    def test_blank_override_is_ignored(self, monkeypatch, tmp_path) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / "pyproject.toml").write_text("", encoding="utf-8")
        monkeypatch.setenv("VPNPARSER_PROJECT_ROOT", "   ")
        _walk_for_anchor.cache_clear()
        try:
            assert _find_project_root() == tmp_path.resolve()
        finally:
            _walk_for_anchor.cache_clear()


def test_find_project_root_rejects_non_directory_override(
    tmp_path, monkeypatch
) -> None:
    """VPNPARSER_PROJECT_ROOT pointing at a file/missing path is ignored."""
    # Module-level imports (conftest monkeypatches the module attribute with
    # an isolated root, so a function-local import would test the mock).
    target = tmp_path / "pyproject.toml"
    target.write_text("", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    _walk_for_anchor.cache_clear()
    try:
        monkeypatch.setenv("VPNPARSER_PROJECT_ROOT", str(tmp_path / "nope"))
        assert _find_project_root() == tmp_path
        f = tmp_path / "afile.txt"
        f.write_text("x", encoding="utf-8")
        monkeypatch.setenv("VPNPARSER_PROJECT_ROOT", str(f))
        assert _find_project_root() == tmp_path
    finally:
        _walk_for_anchor.cache_clear()


def test_find_project_root_honours_late_env_change(tmp_path, monkeypatch) -> None:
    """The override is read fresh (only the CWD walk is cached)."""
    (tmp_path / "pyproject.toml").write_text("", encoding="utf-8")
    other = tmp_path / "other"
    other.mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("VPNPARSER_PROJECT_ROOT", raising=False)
    _walk_for_anchor.cache_clear()
    try:
        assert _find_project_root() == tmp_path
        monkeypatch.setenv("VPNPARSER_PROJECT_ROOT", str(other))
        assert _find_project_root() == other
    finally:
        _walk_for_anchor.cache_clear()
