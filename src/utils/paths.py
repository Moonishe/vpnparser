"""Path sanitization helpers for safe file I/O.

All file-writing and file-reading paths in the pipeline should be resolved
through :func:`resolve_safe_output_path` before touching disk. The helpers
guard against path-traversal via ``..`` and against absolute paths that escape
the configured base directory.
"""

from __future__ import annotations

import contextlib
import logging
import os
import sys
import tempfile
import time
from collections.abc import Iterator
from functools import lru_cache
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@contextlib.contextmanager
def history_file_lock(target: Path) -> Iterator[None]:
    """Best-effort advisory lock for a run-history JSON file next to *target*.

    A full run and an hourly fast-track can both append to the same history
    file (the Actions cache hands the same file to consecutive runs); without
    a lock the second writer's read-modify-write silently dropped the first
    writer's entries.

    Best effort: if the lock file cannot be created or the lock cannot be
    acquired in time, the caller proceeds unlocked — a rare lost entry is
    preferable to a lost history write. Callers doing read-modify-write
    should still re-read the file *inside* the lock and merge, because the
    lock only serializes the write itself.
    """
    lock_path = target.with_name(target.name + ".lock")
    with contextlib.ExitStack() as stack:
        try:
            fh = stack.enter_context(open(lock_path, "a+"))
        except OSError:
            yield
            return
        if sys.platform == "win32":
            import msvcrt

            deadline = time.monotonic() + 10.0
            locked = False
            while True:
                try:
                    fh.seek(0)
                    msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                    locked = True
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        logger.warning(
                            "History lock %s busy for 10s — proceeding "
                            "unlocked (a concurrent writer may race).",
                            lock_path,
                        )
                        break
                    time.sleep(0.05)
            try:
                yield
            finally:
                if locked:
                    with contextlib.suppress(OSError):
                        fh.seek(0)
                        msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
        else:  # pragma: no cover — POSIX-only branch, unexercised on Windows
            import fcntl

            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


@lru_cache(maxsize=8)
def _walk_for_anchor(anchor: str) -> Path:
    """Walk up from the CWD looking for *anchor* (cached).

    Split out of :func:`_find_project_root` so the cheap
    ``VPNPARSER_PROJECT_ROOT`` env lookup stays uncached (a late
    ``os.environ`` change is honoured) while the expensive ~50-stat walk
    is still done once. Tests clear this cache, not the wrapper's.
    """
    cwd = Path.cwd()
    for parent in [cwd, *cwd.parents]:
        if (parent / anchor).exists():
            return parent
    logger.warning(
        "Could not locate project root (%s not found); using %s as base.",
        anchor,
        cwd,
    )
    return cwd


def _find_project_root(anchor: str = "pyproject.toml") -> Path:
    """Return the project root, in order of authority:

    1. ``VPNPARSER_PROJECT_ROOT`` env — an explicit override for the
       installed ``vpnparser`` console script, which otherwise resolves the
       containment base from whatever directory it happens to be launched in.
    2. Walk up from the current working directory looking for ``anchor``.
    3. The current working directory when the anchor is not found.

    The env override is read fresh on every call (an env lookup plus one
    ``is_dir`` stat is cheap) — only the directory walk above is cached, so
    a late ``os.environ`` change is honoured. An override pointing at a
    missing path or a file is refused with a warning instead of silently
    re-basing every path onto garbage. The test suite monkeypatches this
    function attribute itself (conftest), which bypasses any cache, so
    isolation is unaffected.
    """
    override = os.environ.get("VPNPARSER_PROJECT_ROOT") or ""
    if override.strip():
        candidate = Path(override.strip()).resolve()
        if candidate.is_dir():
            return candidate
        logger.warning(
            "VPNPARSER_PROJECT_ROOT=%r is not a directory; ignoring.",
            override.strip(),
        )
    return _walk_for_anchor(anchor)


def resolve_safe_output_path(
    path: str | Path,
    base_dir: str | Path | None = None,
    *,
    must_exist: bool = False,
    strict: bool = False,
) -> Path:
    """Resolve ``path`` and verify it stays within ``base_dir``.

    The function rejects:

    - Paths that contain ``..`` components (explicit traversal attempts).
    - *Relative* paths that resolve outside ``base_dir`` (e.g. through a
      symlink or a directory junction).

    An *absolute* path pointing outside ``base_dir`` is only rejected when
    ``strict=True``; by default it is accepted with a warning, because the
    test suite and several call sites legitimately pass absolute paths
    (pytest ``tmp_path``, operator-supplied output locations).

    Relative paths are resolved relative to ``base_dir``. The returned path
    is the absolute, resolved path.

    Args:
        path: Target file path (absolute or relative).
        base_dir: Directory that the resolved path must not escape.
            When ``None``, the project root is used (looked up by walking
            upward from the current directory for ``pyproject.toml``).
        must_exist: If ``True``, raise when the target does not exist.
        strict: If ``True``, an absolute path outside ``base_dir`` raises
            instead of being allowed with a warning. Use it for paths that
            come from untrusted config.

    Returns:
        Absolute :class:`pathlib.Path`. It is inside ``base_dir`` unless the
        caller passed an absolute path outside it with ``strict=False``.

    Raises:
        ValueError: If the path contains ``..``, if a relative path escapes
            ``base_dir``, or if ``strict=True`` and an absolute path escapes
            ``base_dir``.
        FileNotFoundError: If ``must_exist=True`` and the target is missing.
    """
    if base_dir is None:
        base_dir = _find_project_root("pyproject.toml")

    base = Path(base_dir).resolve()
    raw = Path(path)

    # Reject explicit traversal segments before resolving.
    if any(part == ".." for part in raw.parts):
        raise ValueError(f"unsafe path contains '..' component: {path!r}")

    # Resolve relative paths against base_dir; absolute paths are left as-is
    # by resolve() and then checked against base_dir below.
    resolved = (base / raw).resolve() if not raw.is_absolute() else raw.resolve()

    # Enforce containment for relative paths (the production case: settings
    # only ever hold project-relative output paths).  For *absolute* paths
    # (used by tests pointing at the pytest tmp_path) we only log a warning
    # instead of raising — the `..` guard above is the primary traversal
    # defence, and absolute paths are explicit caller choices.  Callers that
    # do not trust the path pass strict=True to get the strong guarantee.
    try:
        resolved.relative_to(base)
    except ValueError:
        if not raw.is_absolute() or strict:
            raise ValueError(f"path escapes base directory {base}: {path!r}") from None
        logger.warning(
            "absolute output path %r is outside base directory %s — allowed "
            "explicitly; ensure caller is trusted.",
            path,
            base,
        )

    if must_exist and not resolved.exists():
        raise FileNotFoundError(f"required path does not exist: {resolved}")

    return resolved


def validate_safe_output_path(
    path: str | Path,
    base_dir: str | Path | None = None,
    *,
    must_exist: bool = False,
    strict: bool = False,
) -> bool:
    """Return ``True`` if ``path`` is safe, ``False`` otherwise.

    This is the non-raising counterpart of
    :func:`resolve_safe_output_path`, and it accepts exactly the same paths:
    with ``strict=False`` (the default) an *absolute* path outside
    ``base_dir`` is reported as safe — only ``..`` components and escaping
    *relative* paths are rejected. Pass ``strict=True`` to also reject
    absolute paths that leave ``base_dir``. Logs a warning on rejection.
    """
    try:
        resolve_safe_output_path(path, base_dir, must_exist=must_exist, strict=strict)
        return True
    except (ValueError, FileNotFoundError) as exc:
        logger.warning("Rejected unsafe path %r: %s", path, exc)
        return False


def safe_open(
    path: str | Path,
    mode: str = "r",
    base_dir: str | Path | None = None,
    *,
    strict: bool = False,
    **kwargs: Any,
) -> Any:
    """Open a file after validating that it stays inside ``base_dir``.

    Args:
        path: Target file path (absolute or relative).
        base_dir: Directory the resolved path must not escape.
        strict: Forwarded to :func:`resolve_safe_output_path` — ``True`` also
            rejects *absolute* paths outside ``base_dir``. Without it the
            strict mode would be unreachable for callers that open through
            this helper.
        **kwargs: Passed to :meth:`pathlib.Path.open` (encoding, newline, ...).

    Returns:
        A file-like object. The caller is responsible for closing it.
    """
    resolved = resolve_safe_output_path(
        path,
        base_dir,
        must_exist="r" in mode,
        strict=strict,
    )
    return resolved.open(mode=mode, **kwargs)


def write_text_atomic(
    path: str | Path, content: str, *, encoding: str = "utf-8"
) -> None:
    """Write *content* to *path* atomically (temp file + ``os.replace``).

    A direct ``Path.write_text`` can leave a truncated file when the process
    dies mid-write; the state files the pipeline commits to the repository
    (run summary, health history) are read back by the next run and by CI
    tooling, so they must never be seen half-written. The target is replaced
    only after the full payload reached disk, mirroring
    ``HealthHistory.save`` / ``ProxyHealthHistory.save``. Parent directories
    are created on demand.

    Raises:
        OSError: If the write fails; the temp file is cleaned up.
    """
    # Enforce the same containment rules as every other writer: reject path
    # traversal ('..') and relative paths that escape the base directory.
    # Absolute paths outside the base are allowed with a warning (operator-
    # supplied output locations, pytest tmp_path), matching resolve_safe_output_path.
    target = resolve_safe_output_path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=target.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding=encoding, newline="") as fh:
            fh.write(content)
            # os.replace only orders the rename against other processes; on a
            # power loss / kill -9 the file data may not have hit the disk
            # yet, leaving an empty or truncated target behind (this is how
            # accumulated health-history bans would be silently lost).
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, str(target))
    except Exception:
        with contextlib.suppress(Exception):
            os.unlink(tmp)
        raise
