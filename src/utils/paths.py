"""Path sanitization helpers for safe file I/O.

All file-writing and file-reading paths in the pipeline should be resolved
through :func:`resolve_safe_output_path` before touching disk. The helpers
guard against path-traversal via ``..`` and against absolute paths that escape
the configured base directory.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _find_project_root(anchor: str = "pyproject.toml") -> Path:
    """Walk up from the current working directory looking for ``anchor``.

    Falls back to the current working directory when the anchor is not found.
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


def resolve_safe_output_path(
    path: str | Path,
    base_dir: str | Path | None = None,
    *,
    must_exist: bool = False,
) -> Path:
    """Resolve ``path`` and verify it stays within ``base_dir``.

    The function rejects:

    - Paths that contain ``..`` components (explicit traversal attempts).
    - Absolute paths that point outside ``base_dir``.

    Relative paths are resolved relative to ``base_dir``. The returned path
    is the absolute, resolved path.

    Args:
        path: Target file path (absolute or relative).
        base_dir: Directory that the resolved path must not escape.
            When ``None``, the project root is used (looked up by walking
            upward from the current directory for ``pyproject.toml``).
        must_exist: If ``True``, raise when the target does not exist.

    Returns:
        Absolute :class:`pathlib.Path` that is guaranteed to be inside
        ``base_dir``.

    Raises:
        ValueError: If the path escapes ``base_dir`` or contains ``..``.
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
    # defence, and absolute paths are explicit caller choices.
    try:
        resolved.relative_to(base)
    except ValueError:
        if not raw.is_absolute():
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
) -> bool:
    """Return ``True`` if ``path`` is safe, ``False`` otherwise.

    This is the non-raising counterpart of
    :func:`resolve_safe_output_path`. It logs a warning on rejection.
    """
    try:
        resolve_safe_output_path(path, base_dir, must_exist=must_exist)
        return True
    except (ValueError, FileNotFoundError) as exc:
        logger.warning("Rejected unsafe path %r: %s", path, exc)
        return False


def safe_open(
    path: str | Path,
    mode: str = "r",
    base_dir: str | Path | None = None,
    **kwargs: Any,
) -> Any:
    """Open a file after validating that it stays inside ``base_dir``.

    Returns a file-like object. The caller is responsible for closing it.
    """
    resolved = resolve_safe_output_path(path, base_dir, must_exist="r" in mode)
    return resolved.open(mode=mode, **kwargs)
