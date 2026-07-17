"""Tests for src.main — _setup_logging coverage (lines 31-44).

We patch ``setLevel`` on the specific ``httpx`` and ``httpcore`` loggers rather
than replacing ``logging.getLogger`` globally, so pytest's logging
infrastructure (which calls ``logging.getLogger()`` for the root logger during
session teardown) is not disrupted.
"""

from __future__ import annotations

import logging

from src.main import _setup_logging


def test_setup_logging_verbose(monkeypatch) -> None:
    """_setup_logging(True): httpx/httpcore at INFO level (lines 31-44)."""
    levels: list[int] = []

    monkeypatch.setattr(logging, "basicConfig", lambda **kw: None)

    httpx_logger = logging.getLogger("httpx")
    httpcore_logger = logging.getLogger("httpcore")

    monkeypatch.setattr(httpx_logger, "setLevel", lambda level: levels.append(level))
    monkeypatch.setattr(httpcore_logger, "setLevel", lambda level: levels.append(level))

    _setup_logging(True)
    assert len(levels) == 2, f"expected 2 setLevel calls, got {len(levels)}"
    assert levels[0] == logging.INFO
    assert levels[1] == logging.INFO


def test_setup_logging_not_verbose(monkeypatch) -> None:
    """_setup_logging(False): httpx/httpcore at WARNING level (lines 31-44)."""
    levels: list[int] = []

    monkeypatch.setattr(logging, "basicConfig", lambda **kw: None)

    httpx_logger = logging.getLogger("httpx")
    httpcore_logger = logging.getLogger("httpcore")

    monkeypatch.setattr(httpx_logger, "setLevel", lambda level: levels.append(level))
    monkeypatch.setattr(httpcore_logger, "setLevel", lambda level: levels.append(level))

    _setup_logging(False)
    assert len(levels) == 2, f"expected 2 setLevel calls, got {len(levels)}"
    assert levels[0] == logging.WARNING
    assert levels[1] == logging.WARNING
