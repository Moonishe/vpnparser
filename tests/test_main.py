"""Tests for src.main — _setup_logging and the encoding-safe log handler.

We patch ``setLevel`` on the specific ``httpx`` and ``httpcore`` loggers rather
than replacing ``logging.getLogger`` globally, so pytest's logging
infrastructure (which calls ``logging.getLogger()`` for the root logger during
session teardown) is not disrupted.
"""

from __future__ import annotations

import codecs
import io
import logging

from src.main import _EncodingSafeStreamHandler, _setup_logging


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


# --- _EncodingSafeStreamHandler --------------------------------------------


class _LegacyConsoleStream:
    """Stream that accepts only what its code page can encode.

    This is how a Windows console behaves: writing a character the active code
    page cannot represent raises ``UnicodeEncodeError``. An unusable codec name
    degrades to ASCII, so a handler that guesses the wrong codec loses the
    record instead of writing a degraded one.
    """

    def __init__(self, encoding: str | None) -> None:
        self.encoding = encoding
        self.written: list[str] = []

    def _codec(self) -> str:
        try:
            codecs.lookup(self.encoding or "")
        except LookupError:
            return "ascii"
        assert self.encoding is not None
        return self.encoding

    def write(self, text: str) -> int:
        text.encode(self._codec())  # raises UnicodeEncodeError like the console
        self.written.append(text)
        return len(text)

    def flush(self) -> None:
        return None


def _emit(stream: _LegacyConsoleStream, message: str) -> None:
    handler = _EncodingSafeStreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))
    handler.emit(logging.LogRecord("t", logging.INFO, "p", 1, message, None, None))


def test_handler_ascii_message_written_unchanged() -> None:
    """The happy path writes the formatted record as-is."""
    stream = _LegacyConsoleStream("cp437")
    _emit(stream, "plain ascii")
    assert stream.written == ["plain ascii\n"]


def test_handler_falls_back_to_stream_encoding() -> None:
    """On an English console (cp437) the record must still be written.

    Re-encoding through a hardcoded cp1251 kept the Cyrillic characters, so the
    second write raised again and the record disappeared from the log.
    """
    stream = _LegacyConsoleStream("cp437")
    _emit(stream, "Кириллица в логе")
    assert stream.written, "record was dropped instead of being downgraded"
    assert "?" in stream.written[0]


def test_handler_downgrades_chars_missing_from_cp1251() -> None:
    """Emoji on a cp1251 console are replaced, not dropped."""
    stream = _LegacyConsoleStream("cp1251")
    _emit(stream, "готово 🎉")
    assert stream.written
    assert "?" in stream.written[0]


def test_handler_survives_unknown_stream_encoding() -> None:
    """An unusable codec name on the stream falls back to ASCII."""
    stream = _LegacyConsoleStream("definitely-not-a-codec")
    _emit(stream, "Кириллица")
    assert stream.written == ["?" * len("Кириллица") + "\n"]


def test_handler_writes_to_stream_without_encoding_attribute() -> None:
    """A stream with no ``encoding`` attribute (e.g. StringIO) still works."""
    stream = io.StringIO()
    handler = _EncodingSafeStreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))
    handler.emit(logging.LogRecord("t", logging.INFO, "p", 1, "Юникод", None, None))
    assert stream.getvalue() == "Юникод\n"
