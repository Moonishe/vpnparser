"""Shared pytest fixtures.

The suite must never touch the developer's working copy: several tests drive a
full :class:`~src.scheduler.runner.PipelineRunner` run, and the production
defaults for the health-history files are *project-relative*
(``output/health-history.json``, ``output/proxy-health-history.json``).  Without
isolation those runs overwrite real pipeline artifacts, so a plain ``pytest``
between two production runs silently rewrites the health/ban history.

Both fixtures here are autouse:

- :func:`_isolated_project_root` repoints the project-root anchor used by
  :func:`src.utils.paths.resolve_safe_output_path` at a per-test temp
  directory, so every relative output path lands in ``tmp``.
- :func:`_restore_environ` snapshots and restores ``os.environ`` so a test that
  sets an API key cannot leak it into later tests (or delete the developer's
  real key for the rest of the session).

A test that genuinely needs the real project root can opt out with
``@pytest.mark.real_project_root``.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from src.utils import paths as paths_module


def pytest_configure(config: pytest.Config) -> None:
    """Register the opt-out marker used by :func:`_isolated_project_root`."""
    config.addinivalue_line(
        "markers",
        "real_project_root: run against the real repository root instead of a "
        "temp directory (opts out of output-path isolation).",
    )


@pytest.fixture(autouse=True)
def _isolated_project_root(
    request: pytest.FixtureRequest,
    tmp_path_factory: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[Path | None]:
    """Redirect project-relative output paths into a per-test temp root."""
    if request.node.get_closest_marker("real_project_root"):
        yield None
        return

    root = tmp_path_factory.mktemp("project_root")
    # resolve_safe_output_path() locates the root by this anchor; create it so
    # the temp root looks like a real project to any non-patched lookup.
    (root / "pyproject.toml").write_text("", encoding="utf-8")

    monkeypatch.setattr(
        paths_module,
        "_find_project_root",
        lambda anchor="pyproject.toml": root,
    )
    yield root


@pytest.fixture(autouse=True)
def _restore_environ() -> Iterator[None]:
    """Undo any ``os.environ`` mutation a test performs without monkeypatch."""
    snapshot = dict(os.environ)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(snapshot)
