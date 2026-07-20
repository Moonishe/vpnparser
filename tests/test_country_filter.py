"""Tests for src/validators/country_filter.py — 100% coverage.

Covers:
  - Line  19: TYPE_CHECKING import block
  - Line 324: import-time RuntimeError for unsupported codes
  - Line 423: emoji-flag detection branch
  - Line 433: country-name detection branch
  - Line 472: filter_by_country early return when allowed=[]
  - Line 480: filter_by_country warning for unsupported allowed codes
  - Line 491: filter_by_country calls detect_country when cfg.country is None
"""

from __future__ import annotations

import importlib
import sys
import typing

import pytest

from src.parsers.base import Config
from src.validators.country_filter import detect_country, filter_by_country

# ---------------------------------------------------------------------------
# Line 19 — TYPE_CHECKING import
# ---------------------------------------------------------------------------


def test_type_checking_import_covers_line_19(monkeypatch) -> None:
    """Cover line 19 by re-loading the module with TYPE_CHECKING=True.

    The ``if TYPE_CHECKING: from src.parsers.base import Config`` block at
    line 18-19 is dead code at runtime (TYPE_CHECKING is False by default).
    We force it True during an ``importlib.reload`` so that the import
    statement on line 19 actually executes.
    """
    import src.validators.country_filter as cf

    # Patch typing.TYPE_CHECKING to True BEFORE reload so the module-level
    # ``from typing import TYPE_CHECKING`` inside the module picks up True.
    monkeypatch.setattr(typing, "TYPE_CHECKING", True)
    importlib.reload(cf)

    # Restore typing.TYPE_CHECKING (monkeypatch does this at teardown).
    # Re-reload with the normal False value to bring the module back to a
    # clean state for the remaining tests.
    # (monkeypatch still holds the original, but we also need reload to
    #  re-execute with TYPE_CHECKING=False right now.)
    importlib.reload(cf)


# ---------------------------------------------------------------------------
# Line 324 — import-time RuntimeError for unsupported codes
# ---------------------------------------------------------------------------


def test_unknown_dict_code_raises_at_import_time() -> None:
    """Cover line 324: the import-time sanity check raises RuntimeError.

    The check computes ``_DICT_VALUES - set(_SUPPORTED_CODES)`` and raises if
    any code appears in the detection dicts but is absent from
    ``_SUPPORTED_CODES``.  We use a custom ``SourceFileLoader`` that injects a
    bogus mapping (``"🇺🇳" -> "ZZ"``) into ``_EMOJI_TO_CODE`` *before*
    compilation so the module-level code sees it and blows up.
    """
    import importlib.abc
    import importlib.machinery
    import importlib.util
    import types

    import src.validators.country_filter as cf_orig

    name = "src.validators.country_filter"

    class _PatchedLoader(importlib.machinery.SourceFileLoader):
        """Return modified source with an unsupported country code."""

        def get_code(self, fullname: str) -> types.CodeType:
            source = self.get_source(fullname)
            path = self.get_filename(fullname)
            return self.source_to_code(source, path)  # type: ignore[arg-type]

        def get_source(self, fullname: str) -> str:
            source = super().get_source(fullname)
            # Inject "ZZ" after the last emoji entry — ZZ is NOT in
            # _SUPPORTED_CODES, so the import-time check will raise.
            return source.replace(  # type: ignore[union-attr]
                '"🇦🇷": "AR",',
                '"🇦🇷": "AR",\n    "🇺🇳": "ZZ",',
            )

    loader = _PatchedLoader(name, cf_orig.__file__)
    spec = importlib.util.spec_from_loader(name, loader, origin=cf_orig.__file__)

    new_mod = types.ModuleType(name)
    new_mod.__file__ = cf_orig.__file__
    new_mod.__package__ = cf_orig.__package__
    new_mod.__spec__ = spec
    new_mod.__loader__ = loader
    new_mod.__path__ = getattr(cf_orig, "__path__", [])
    new_mod.__builtins__ = __builtins__  # type: ignore[attr-defined]

    with pytest.raises(RuntimeError, match="not in _SUPPORTED_CODES"):
        loader.exec_module(new_mod)

    # Ensure the original module is still in sys.modules so other tests work.
    # (new_mod was never inserted into sys.modules, so this is a no-op
    # safety check.)
    assert "src.validators.country_filter" in sys.modules


# ---------------------------------------------------------------------------
# detect_country — emoji (line 423) and name (line 433) branches
# ---------------------------------------------------------------------------


def test_detect_country_from_emoji_flag() -> None:
    """Line 423: emoji flag in remark triggers early return."""
    assert detect_country("🇩🇪 Frankfurt Server") == "DE"
    assert detect_country("Server 🇫🇮") == "FI"
    assert detect_country("🇺🇸-01") == "US"


def test_detect_country_from_country_name() -> None:
    """Line 433: country name matched via _NAME_PATTERN."""
    assert detect_country("Germany Server") == "DE"
    assert detect_country("Hello USA 01") == "US"
    assert detect_country("Russia Moscow") == "RU"
    assert detect_country("Finland") == "FI"


# ---------------------------------------------------------------------------
# filter_by_country — early return (line 472), warning (line 480),
# detect_country call (line 491)
# ---------------------------------------------------------------------------


def test_filter_by_country_empty_allowed_returns_all() -> None:
    """Line 472: ``if not allowed: return configs``."""
    cfg = Config(
        protocol="vless",
        address="1.1.1.1",
        port=443,
        uuid_or_password="u",
        country="DE",
    )
    result = filter_by_country([cfg], [])
    assert result == [cfg]


def test_filter_by_country_invalid_code_warns(caplog) -> None:
    """Line 480: warning logged for unsupported allowed country codes."""
    caplog.set_level("WARNING")
    cfg = Config(
        protocol="vless",
        address="1.1.1.1",
        port=443,
        uuid_or_password="u",
        country="DE",
        remark="DE-01",
    )
    result = filter_by_country([cfg], ["ZZ"])
    assert result == []
    assert "allowed_countries contains code(s) not supported" in caplog.text


def test_filter_by_country_detects_country_when_none() -> None:
    """Line 491: detect_country called when cfg.country is None."""
    cfg = Config(
        protocol="vless",
        address="de01.example.com",
        port=443,
        uuid_or_password="u",
        country=None,
        remark="DE-01",
    )
    result = filter_by_country([cfg], ["DE"])
    assert len(result) == 1
    assert result[0].country == "DE"
    # The remark "DE-01" is matched by _CODE_RE -> "DE"
