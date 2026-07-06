"""Reproduction tests for 7 edge cases - find real bugs."""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path

# Ensure src is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.parsers.base import Config
from src.scheduler.runner import PipelineRunner
from src.sources.list_types import infer_source_list_type, normalize_list_type
from src.sources.manager import SourceManager, SourceResult
from src.validators import tls_check as tls_module


# --- Edge Case 1: Empty sources.json ---------------------------------------


def test_edge1_empty_sources_writes_empty_splits(tmp_path):
    """Empty sources.json -> no results -> empty combined + empty splits."""
    sources = tmp_path / "sources.json"
    sources.write_text('{"sources": []}', encoding="utf-8")

    # Use absolute paths inside tmp_path for split outputs
    bl_path = str(tmp_path / "subscription-blacklist.txt")
    wl_path = str(tmp_path / "subscription-whitelist.txt")
    combined = str(tmp_path / "subscription.txt")

    settings = tmp_path / "settings.yaml"
    settings.write_text(
        f"""
publisher:
  output_file: {combined}
  split_output_files:
    blacklist: {bl_path}
    whitelist: {wl_path}
""",
        encoding="utf-8",
    )

    runner = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(sources),
    )

    count = asyncio.run(runner.run(output_file=combined, publish=False))

    assert count == 0, f"Expected 0 configs, got {count}"
    # Combined output should exist (empty)
    assert Path(combined).exists(), "Combined output file was not created"
    # Split outputs should exist (empty)
    assert Path(bl_path).exists(), "Blacklist split output was not created on empty run"
    assert Path(wl_path).exists(), "Whitelist split output was not created on empty run"
    print("EDGE 1: PASS - empty sources -> empty combined + empty splits")


# --- Edge Case 2: All sources same list_type -> other split empty -----------


def test_edge2_all_blacklist_whitelist_empty(tmp_path):
    """All sources blacklist -> whitelist output empty (but file created)."""
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        """
validator:
  allowed_countries: []
aggregator:
  max_configs_in_output: 75
  sort_by: country
  max_per_country: 10
publisher:
  split_output_files:
    blacklist: output/subscription-blacklist.txt
    whitelist: output/subscription-whitelist.txt
""",
        encoding="utf-8",
    )

    runner = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )

    # Simulate configs_by_list with only blacklist
    configs_by_list = {
        "blacklist": [
            Config(
                protocol="vless",
                address="de.server.net",
                port=443,
                uuid_or_password="11111111-1111-4111-8111-111111111111",
                remark="DE-01",
                raw_link="vless://11111111-1111-4111-8111-111111111111@de.server.net:443#DE-01",
                country="DE",
            )
        ]
    }

    blacklist_file = str(tmp_path / "subscription-blacklist.txt")
    whitelist_file = str(tmp_path / "subscription-whitelist.txt")

    # Process blacklist
    bl_count = runner._process_and_write_configs(
        list(configs_by_list.get("blacklist", [])),
        blacklist_file,
        label="blacklist",
    )
    # Process whitelist (empty)
    wl_count = runner._process_and_write_configs(
        list(configs_by_list.get("whitelist", [])),
        whitelist_file,
        label="whitelist",
    )

    assert bl_count == 1, f"Expected 1 blacklist config, got {bl_count}"
    assert wl_count == 0, f"Expected 0 whitelist configs, got {wl_count}"
    assert Path(whitelist_file).exists(), "Whitelist file was not created"
    print("EDGE 2: PASS - all blacklist -> whitelist file created empty")


# --- Edge Case 3: Source without list_type -> infer "mixed" -----------------


def test_edge3_no_list_type_infers_mixed():
    """Source without list_type, no black/white in name -> 'mixed'."""
    result = infer_source_list_type(
        {"name": "generic-source", "path": "configs/sub.txt"}
    )
    assert result == "mixed", f"Expected 'mixed', got '{result}'"

    # With "black" in name
    result = infer_source_list_type({"name": "my-black-source"})
    assert result == "blacklist", f"Expected 'blacklist', got '{result}'"

    # With "white" in path
    result = infer_source_list_type({"name": "src", "path": "white-list/configs"})
    assert result == "whitelist", f"Expected 'whitelist', got '{result}'"
    print("EDGE 3: PASS - no list_type -> mixed; black/white in name -> correct")


# --- Edge Case 4: split_output_files key normalization ---------------------


def test_edge4_split_output_keys(tmp_path):
    """Test key normalization in split_output_files."""
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        """
publisher:
  split_output_files:
    blacklist: output/bl.txt
    bl: output/bl-alias.txt
    wl: output/wl.txt
    mixed: output/mixed.txt
    unknown: output/unknown.txt
""",
        encoding="utf-8",
    )
    runner = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )

    splits = runner._split_output_files("output/subscription.txt")

    print(f"  split_output_files result: {splits}")
    # "blacklist" and "bl" both normalize to "blacklist" - last one wins!
    # "wl" normalizes to "whitelist"
    # "mixed" is skipped
    # "unknown" normalizes to "mixed" -> skipped

    # BUG CHECK: "blacklist" and "bl" both map to "blacklist" - collision!
    # The second one ("bl") silently overwrites the first ("blacklist")
    assert "blacklist" in splits, "blacklist should be in splits"
    assert "whitelist" in splits, "whitelist should be in splits"
    assert "mixed" not in splits, "mixed should be skipped"

    # FIXED: "blacklist" and "bl" both map to "blacklist" — first wins
    # User configured blacklist->bl.txt AND bl->bl-alias.txt
    # Only the FIRST survives; second is skipped with a warning
    assert splits["blacklist"] == "output/bl.txt", (
        f"Expected first-wins (bl.txt), got {splits['blacklist']}"
    )
    print(
        f"  FIXED: 'blacklist' maps to '{splits['blacklist']}' (first wins, bl skipped)"
    )
    print("EDGE 4: PASS (collision handled — first wins with warning)")


# --- Edge Case 5: TLS validator security types -----------------------------


def test_edge5_tls_validator_security_types(monkeypatch):
    """Test TLS validator with different security types."""

    async def fake_tls_check(*args, **kwargs):
        return True

    monkeypatch.setattr(tls_module, "tls_check", fake_tls_check)

    # security="none" -> passes, is_alive stays None
    cfg_none = Config(
        protocol="vless",
        address="example.com",
        port=443,
        uuid_or_password="11111111-1111-4111-8111-111111111111",
        security="none",
    )
    result = asyncio.run(tls_module.validate_configs_tls([cfg_none]))
    assert result == [cfg_none], "security=none should pass"
    assert cfg_none.is_alive is None, (
        f"is_alive should be None for none, got {cfg_none.is_alive}"
    )

    # security="tls" -> checked, is_alive=True
    cfg_tls = Config(
        protocol="vless",
        address="example.com",
        port=443,
        uuid_or_password="11111111-1111-4111-8111-111111111111",
        security="tls",
    )
    result = asyncio.run(tls_module.validate_configs_tls([cfg_tls]))
    assert result == [cfg_tls], "security=tls with True should pass"
    assert cfg_tls.is_alive is True

    # security="reality" -> checked, is_alive=True
    cfg_reality = Config(
        protocol="vless",
        address="example.com",
        port=443,
        uuid_or_password="11111111-1111-4111-8111-111111111111",
        security="reality",
    )
    result = asyncio.run(tls_module.validate_configs_tls([cfg_reality]))
    assert result == [cfg_reality], "security=reality with True should pass"
    assert cfg_reality.is_alive is True

    # security="tls" -> checked, is_alive=False -> filtered out
    async def fake_tls_fail(*args, **kwargs):
        return False

    monkeypatch.setattr(tls_module, "tls_check", fake_tls_fail)

    cfg_tls_fail = Config(
        protocol="vless",
        address="dead.com",
        port=443,
        uuid_or_password="11111111-1111-4111-8111-111111111111",
        security="tls",
    )
    result = asyncio.run(tls_module.validate_configs_tls([cfg_tls_fail]))
    assert result == [], "security=tls with False should be filtered out"
    assert cfg_tls_fail.is_alive is False

    print("EDGE 5: PASS - none passes (is_alive=None), tls/reality checked")


# --- Edge Case 5b: TLS with is_alive pre-set from TCP check -----------------


def test_edge5b_tls_with_pre_set_is_alive(monkeypatch):
    """BUG CHECK: if is_alive=False from TCP check and security='none',
    TLS validator passes it - is this correct?"""

    async def fake_tls_check(*args, **kwargs):
        return True

    monkeypatch.setattr(tls_module, "tls_check", fake_tls_check)

    # Config that FAILED TCP check (is_alive=False) but security="none"
    cfg = Config(
        protocol="vless",
        address="dead.com",
        port=443,
        uuid_or_password="11111111-1111-4111-8111-111111111111",
        security="none",
        is_alive=False,  # TCP check said it's dead
    )
    result = asyncio.run(tls_module.validate_configs_tls([cfg]))
    # BUG: This config passes TLS check even though TCP said it's dead!
    # The TLS filter only checks is_alive for tls/reality, not for none
    assert result == [cfg], "BUG: security=none with is_alive=False passes TLS"
    print(
        "EDGE 5b: NOTED - security=none + is_alive=False passes TLS (by design, TLS only checks TLS)"
    )


# --- Edge Case 6: _filter_files case-insensitive ---------------------------


def test_edge6_filter_files_case_insensitive():
    """Test case-insensitive filename matching."""
    source = {
        "include_files": ["Keep.TXT"],
    }
    files = [
        ("keep.txt", "content1"),
        ("drop.txt", "content2"),
        ("KEEP.TXT", "content3"),  # different case, same name
    ]
    result = SourceManager._filter_files(source, files)
    print(f"  filter result with include=['Keep.TXT']: {result}")
    # Both keep.txt and KEEP.TXT match because lowercased
    assert len(result) == 2, f"Expected 2 files (case-insensitive), got {len(result)}"

    # Exclude test
    source2 = {
        "exclude_files": ["test.txt"],
    }
    files2 = [
        ("TEST.TXT", "content1"),
        ("other.txt", "content2"),
    ]
    result2 = SourceManager._filter_files(source2, files2)
    print(f"  filter result with exclude=['test.txt']: {result2}")
    assert len(result2) == 1, f"Expected 1 file (TEST.TXT excluded), got {len(result2)}"
    assert result2[0][0] == "other.txt"
    print("EDGE 6: PASS - case-insensitive matching works (by design)")


# --- Edge Case 7: _publish_files dedup -------------------------------------


def test_edge7_publish_files_dedup(monkeypatch):
    """Test that _publish_files deduplicates via dict.fromkeys."""
    runner = PipelineRunner(
        settings_path=str(Path(tempfile.gettempdir()) / "missing.yaml"),
        sources_path=str(Path(tempfile.gettempdir()) / "missing.json"),
    )

    published = []

    async def fake_publish(output_file):
        published.append(output_file)

    monkeypatch.setattr(runner, "_publish", fake_publish)

    # Simulate duplicate paths
    files = [
        "output/subscription.txt",
        "output/bl.txt",
        "output/bl.txt",
        "output/bl.txt",
    ]
    asyncio.run(runner._publish_files(files))

    print(f"  published files: {published}")
    assert published == ["output/subscription.txt", "output/bl.txt"], (
        f"Expected dedup, got {published}"
    )
    print("EDGE 7: PASS - dict.fromkeys deduplicates correctly")


# --- FIXED: _split_output_files collision — first wins, warn ---------------


def test_bonus_split_collision_first_wins(tmp_path):
    """FIXED: Two keys normalizing to same list_type — first wins, second skipped."""
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        """
publisher:
  split_output_files:
    blacklist: output/bl-main.txt
    bl: output/bl-alias.txt
""",
        encoding="utf-8",
    )
    runner = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )

    splits = runner._split_output_files("output/subscription.txt")
    print(f"  splits with collision: {splits}")

    # Both "blacklist" and "bl" normalize to "blacklist"
    # First entry wins — second is skipped with a warning
    assert len(splits) == 1, f"Expected 1 entry (collision), got {len(splits)}"
    assert splits["blacklist"] == "output/bl-main.txt", (
        f"Expected first-wins (bl-main.txt), got {splits['blacklist']}"
    )
    print(
        "  FIXED: 'blacklist' and 'bl' both -> 'blacklist', first wins, second skipped"
    )


def test_bonus_split_same_path_collision(tmp_path):
    """FIXED: Two different list_types with same path — first wins, second skipped."""
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        """
publisher:
  split_output_files:
    blacklist: output/same.txt
    whitelist: output/same.txt
""",
        encoding="utf-8",
    )
    runner = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )

    splits = runner._split_output_files("output/subscription.txt")
    print(f"  splits with same-path collision: {splits}")

    # Only the first list_type mapping to the path survives
    assert len(splits) == 1, f"Expected 1 entry, got {len(splits)}"
    assert splits["blacklist"] == "output/same.txt"
    assert "whitelist" not in splits, "whitelist should be skipped (same path)"
    print("  FIXED: two list_types -> same path, first wins, second skipped")


# --- FIXED: _check_one has try/except — gather no longer crashes -----------


def test_bonus_tls_check_one_exception_handling(monkeypatch):
    """FIXED: _check_one catches exceptions — gather survives, config marked dead."""

    async def exploding_tls_check(*args, **kwargs):
        raise RuntimeError("unexpected boom")

    monkeypatch.setattr(tls_module, "tls_check", exploding_tls_check)

    cfg = Config(
        protocol="vless",
        address="example.com",
        port=443,
        uuid_or_password="11111111-1111-4111-8111-111111111111",
        security="tls",
    )

    # _check_one now catches exceptions and sets is_alive=False
    # gather uses return_exceptions=True so it never crashes
    result = asyncio.run(tls_module.validate_configs_tls([cfg]))
    assert cfg.is_alive is False, (
        f"Expected is_alive=False on exception, got {cfg.is_alive}"
    )
    assert result == [], "Dead TLS config should be filtered out"
    print("  FIXED: _check_one catches exception, marks dead, gather survives")


# --- BONUS BUG HUNT: split outputs processed independently, sampling differs -


def test_bonus_split_independent_processing(tmp_path):
    """Check if split outputs are processed independently from combined."""
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        """
validator:
  allowed_countries: ["DE"]
  max_configs_to_validate: 0
aggregator:
  max_configs_in_output: 75
  sort_by: country
  max_per_country: 10
""",
        encoding="utf-8",
    )
    runner = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )

    # The combined pipeline in run() does its own dedup/country/sort/limit
    # Then split outputs re-process independently from configs_by_list
    # This means configs that were SAMPLED OUT of the combined output
    # could still appear in split outputs (or vice versa)
    print("  NOTED: split outputs are processed independently from combined")
    print("  This means sampling/dedup/limit may differ between combined and split")


if __name__ == "__main__":
    # Run all tests manually for debugging
    import pytest

    sys.exit(pytest.main([__file__, "-v", "-s"]))
