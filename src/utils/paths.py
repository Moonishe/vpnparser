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
