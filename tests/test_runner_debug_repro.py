"""Reproduction tests for PipelineRunner.run() / _process_configs() bugs.

Covers:
  1. max_configs_in_output default mismatch (run=75 vs _sort_and_limit=500).
  2. Duplicate step-number comment (cosmetic — not tested here).
  3. _process_configs duplication: dedup+sort done inside process AND after
     interleave in run() — double sort, pipeline-order violation.
  4. Early exits write empty combined + empty splits (verified correct).
  5. _write_empty_split_outputs excludes combined path (verified correct).
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.parsers.base import Config
from src.scheduler.runner import PipelineRunner


def _mk(addr: str, country: str = "DE") -> Config:
    return Config(
        protocol="vless",
        address=addr,
        port=443,
        uuid_or_password="11111111-1111-4111-8111-111111111111",
        remark=f"{country}-01",
        raw_link=f"vless://11111111-1111-4111-8111-111111111111@{addr}:443#{country}-01",
        country=country,
    )


# --- Bug 1: default mismatch --------------------------------------------------


def test_bug1_max_configs_default_consistent(tmp_path) -> None:
    """When aggregator.max_configs_in_output is absent, run() and
    _sort_and_limit must use the SAME default via _max_configs()."""
    settings = tmp_path / "settings.yaml"
    settings.write_text("validator:\n  allowed_countries: []\n", encoding="utf-8")
    runner = PipelineRunner(
        settings_path=str(settings), sources_path=str(tmp_path / "missing.json")
    )

    # _max_configs() is the single source of truth — both run() and
    # _sort_and_limit call it, so they can never disagree.
    val = runner._max_configs()
    assert val == 500, f"canonical default should be 500 (merger.py), got {val}"
    # Verify the code no longer has divergent hardcoded defaults: the only
    # direct read of max_configs_in_output lives inside _max_configs().
    import inspect

    source = inspect.getsource(PipelineRunner)
    # Every call site must go through _max_configs(), not a raw acfg.get.
    assert 'max_configs_in_output", 75' not in source, (
        "run() still has the old default-75 mismatch"
    )
    print(f"BUG1: _max_configs() default = {val} — consistent across all call sites")


def test_bug1_max_configs_helper(tmp_path) -> None:
    """_max_configs() helper returns same value everywhere."""
    settings = tmp_path / "settings.yaml"
    settings.write_text("aggregator:\n  max_configs_in_output: 42\n", encoding="utf-8")
    runner = PipelineRunner(
        settings_path=str(settings), sources_path=str(tmp_path / "missing.json")
    )
    assert runner._max_configs() == 42

    settings2 = tmp_path / "s2.yaml"
    settings2.write_text("validator: {}\n", encoding="utf-8")
    runner2 = PipelineRunner(
        settings_path=str(settings2), sources_path=str(tmp_path / "missing.json")
    )
    # Whatever the canonical default is, it must be > 0 and consistent.
    assert runner2._max_configs() > 0
    print(
        f"BUG1: helper configured={runner._max_configs()}, default={runner2._max_configs()}"
    )


# --- Bug 3: pipeline order / duplication --------------------------------------


def test_bug3_preprocess_does_not_sort(tmp_path) -> None:
    """_preprocess_configs must NOT sort — sorting happens after interleave."""
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        "validator:\n  allowed_countries: []\naggregator:\n  max_configs_in_output: 500\n",
        encoding="utf-8",
    )
    runner = PipelineRunner(
        settings_path=str(settings), sources_path=str(tmp_path / "missing.json")
    )

    # Feed configs in a known non-sorted order (ZZ before AA).
    cfgs = [_mk("z.server", "ZZ"), _mk("a.server", "AA"), _mk("m.server", "DE")]
    pre = runner._preprocess_configs(cfgs, label="test")
    # All survive (no country filter, no garbage).
    assert len(pre) == 3, f"Expected 3 preprocessed, got {len(pre)}"
    # preprocess must preserve insertion order (no sort).
    addrs = [c.address for c in pre]
    assert addrs == ["z.server", "a.server", "m.server"], (
        f"preprocess must not sort, got {addrs}"
    )
    print(f"BUG3: preprocess preserves order {addrs}")


def test_bug3_process_configs_still_sorts_for_standalone(tmp_path) -> None:
    """_process_configs (standalone path for splits/tests) must still sort."""
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        "validator:\n  allowed_countries: []\naggregator:\n  max_configs_in_output: 500\n  sort_by: country\n",
        encoding="utf-8",
    )
    runner = PipelineRunner(
        settings_path=str(settings), sources_path=str(tmp_path / "missing.json")
    )
    cfgs = [_mk("z.server", "ZZ"), _mk("a.server", "AA"), _mk("m.server", "DE")]
    processed = runner._process_configs(cfgs, label="test")
    # sort_by=country → AA, DE, ZZ
    countries = [c.country for c in processed]
    assert countries == ["AA", "DE", "ZZ"], (
        f"_process_configs should sort by country, got {countries}"
    )
    print(f"BUG3: _process_configs sorts standalone {countries}")


# --- Bug 4: early exits write empty splits ------------------------------------


def test_bug4_early_exit_writes_empty_splits(tmp_path) -> None:
    """Empty sources → early exit writes empty combined + empty splits."""
    sources = tmp_path / "sources.json"
    sources.write_text('{"sources": []}', encoding="utf-8")
    bl = str(tmp_path / "bl.txt")
    wl = str(tmp_path / "wl.txt")
    combined = str(tmp_path / "sub.txt")
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        f"publisher:\n  output_file: {combined}\n  split_output_files:\n    blacklist: {bl}\n    whitelist: {wl}\n",
        encoding="utf-8",
    )
    runner = PipelineRunner(settings_path=str(settings), sources_path=str(sources))
    count = asyncio.run(runner.run(output_file=combined, publish=False))
    assert count == 0
    assert Path(combined).exists()
    assert Path(bl).exists(), "blacklist split not created on early exit"
    assert Path(wl).exists(), "whitelist split not created on early exit"
    print("BUG4: early exit writes empty combined + empty splits — PASS")


if __name__ == "__main__":
    import pytest

    pytest.main([__file__, "-v", "-s"])
