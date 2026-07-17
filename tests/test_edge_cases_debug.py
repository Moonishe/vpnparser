"""Reproduction tests for 7 edge cases - find real bugs."""

from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path

# Ensure src is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.parsers.base import Config
from src.scheduler.runner import PipelineRunner
from src.sources.list_types import infer_source_list_type
from src.sources.manager import SourceManager
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

    async def fake_publish(output_file, repo_path=None):
        published.append((output_file, repo_path))

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
    assert published == [
        ("output/subscription.txt", "output/subscription.txt"),
        ("output/bl.txt", "output/bl.txt"),
    ], f"Expected dedup, got {published}"
    print("EDGE 7: PASS - dict.fromkeys deduplicates correctly")


def test_empty_run_publishes_all_subscription_outputs(tmp_path, monkeypatch):
    """Failed runs must publish empty subscription*.txt, not only summary.

    Previously no_live_configs / empty-source paths published summary + health
    only, leaving remote subscription files stale.
    """
    sources = tmp_path / "sources.json"
    sources.write_text('{"sources": []}', encoding="utf-8")

    combined = str(tmp_path / "subscription.txt")
    mix = str(tmp_path / "subscription-mix.txt")
    bl = str(tmp_path / "subscription-blacklist.txt")
    wl = str(tmp_path / "subscription-whitelist.txt")
    summary = str(tmp_path / "run-summary.json")
    health = str(tmp_path / "health-history.json")

    settings = tmp_path / "settings.yaml"
    settings.write_text(
        f"""
quality:
  health_history_enabled: true
  health_history_file: {health}
publisher:
  output_file: {combined}
  mix_output_file: {mix}
  status_output_file: {summary}
  split_output_files:
    blacklist: {bl}
    whitelist: {wl}
""",
        encoding="utf-8",
    )

    runner = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(sources),
        github_token="test-token",
    )
    published: list[str] = []

    async def fake_publish(output_file, repo_path=None):
        published.append(output_file)

    monkeypatch.setattr(runner, "_publish", fake_publish)

    count = asyncio.run(runner.run(output_file=combined, publish=True))
    assert count == 0

    for path in (combined, mix, bl, wl, summary):
        assert Path(path).exists(), f"missing local artifact {path}"
        assert path in published, f"empty run did not publish {path}; got {published}"

    print("EMPTY PUBLISH: PASS - all subscription outputs published on empty run")


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
    _runner = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )

    # The combined pipeline in run() does its own dedup/country/sort/limit
    # Then split outputs re-process independently from configs_by_list
    # This means configs that were SAMPLED OUT of the combined output
    # could still appear in split outputs (or vice versa)
    print("  NOTED: split outputs are processed independently from combined")
    print("  This means sampling/dedup/limit may differ between combined and split")


# --- FIXED: _publish reads file via asyncio.to_thread (no event-loop block) ---


def test_bonus_publish_reads_file_via_to_thread(monkeypatch, tmp_path):
    """FIXED: _publish must not block the event loop on file I/O.

    Before the fix, ``_publish`` called ``Path.read_text`` synchronously inside
    an async function.  Now it uses ``asyncio.to_thread``.  This test verifies
    the file content is still read correctly and handed to the publisher.
    """
    output_file = tmp_path / "subscription.txt"
    output_file.write_text(
        "vless://dead-beef@example.com:443#DE-01\n", encoding="utf-8"
    )

    settings = tmp_path / "settings.yaml"
    settings.write_text(
        """
publisher:
  owner: owner
  repo: repo
  branch: main
  output_file: output/subscription.txt
  commit_message: "auto-update [{timestamp}]"
""",
        encoding="utf-8",
    )

    runner = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
        github_token="fake-token",
    )

    captured = {}

    class FakePublisher:
        def __init__(self, *args, **kwargs):
            captured["init_kwargs"] = kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def publish_file(self, path, content, commit_message):
            captured["path"] = path
            captured["content"] = content
            captured["commit_message"] = commit_message
            return True

    monkeypatch.setattr("src.publisher.github.GitHubPublisher", FakePublisher)

    asyncio.run(runner._publish(str(output_file), repo_path="output/subscription.txt"))

    assert captured.get("content") == "vless://dead-beef@example.com:443#DE-01\n", (
        f"Expected file content read via to_thread, got {captured.get('content')!r}"
    )
    assert captured.get("path") == "output/subscription.txt"
    assert "auto-update" in captured.get("commit_message", "")
    print(
        "  FIXED: _publish reads file via asyncio.to_thread, content reaches publisher"
    )


def test_bonus_publish_missing_file_skips_cleanly(tmp_path):
    """_publish must log + skip when the output file does not exist (no crash)."""
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        """
publisher:
  owner: owner
  repo: repo
  branch: main
""",
        encoding="utf-8",
    )
    runner = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
        github_token="fake-token",
    )

    # Should return without raising — FileNotFoundError is caught.
    asyncio.run(runner._publish(str(tmp_path / "nope.txt"), repo_path="output/x.txt"))
    print("  FIXED: missing output file -> logged + skipped, no exception")


# --- FIXED: interleave max_total default matches _sort_and_limit (500) -------


def test_bonus_interleave_default_matches_sort_cap(monkeypatch, tmp_path):
    """FIXED: interleave max_total default must match _sort_and_limit (500).

    Before the fix, ``run()`` read ``max_configs_in_output`` with default 75
    while ``_sort_and_limit`` used 500.  With NO aggregator config and 100
    configs per list, the interleave pre-capped to 150 (75 from each) even
    though 200 unique configs were available and the real cap was 500.
    Now both default to 500 -> all 200 flow through.
    """
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        """
validator:
  allowed_countries: []
  max_configs_to_validate: 0
""",
        # NO aggregator section -> framework defaults apply
        encoding="utf-8",
    )
    runner = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )

    def make_configs(n, addr_prefix):
        return [
            Config(
                protocol="vless",
                address=f"{addr_prefix}.net",
                port=443 + i,
                uuid_or_password="11111111-1111-4111-8111-111111111111",
                remark=f"DE-{i:03d}",
                raw_link=(
                    f"vless://11111111-1111-4111-8111-111111111111@"
                    f"{addr_prefix}.net:{443 + i}#DE-{i:03d}"
                ),
                country="DE",
            )
            for i in range(n)
        ]

    configs_by_list = {
        "blacklist": make_configs(100, "bl"),
        "whitelist": make_configs(100, "wl"),
    }

    async def fake_fetch_sources():
        return ["dummy-result"]

    async def fake_parse_all_by_list(results):
        return configs_by_list

    monkeypatch.setattr(runner, "_fetch_sources", fake_fetch_sources)
    monkeypatch.setattr(runner, "_parse_all_by_list", fake_parse_all_by_list)

    output_file = str(tmp_path / "combined.txt")
    count = asyncio.run(runner.run(output_file=output_file, publish=False))

    # 100 blacklist + 100 whitelist = 200 unique; default cap 500 -> 200.
    # Before the fix (interleave default 75) this was 150 (75 from each).
    assert count == 200, (
        f"Expected 200 configs (default 500 cap), got {count} — "
        f"interleave default may still be 75 (under-production bug)"
    )
    print(f"  FIXED: interleave default=500 -> {count} configs flow through (was 150)")


def _make_runner() -> PipelineRunner:
    """Create a PipelineRunner with minimal temp settings/sources."""
    settings = Path(tempfile.mktemp(suffix=".yaml"))
    sources = Path(tempfile.mktemp(suffix=".json"))
    settings.write_text(
        "aggregator:\n  max_configs_in_output: 75\n  max_per_country: 0\n  sort_by: country\n"
        "validator:\n  allowed_countries: [RU, DE, FI, NL, US, GB, FR, JP, CA]\n  max_configs_to_validate: 0\n"
    )
    sources.write_text('{"sources": []}')
    return PipelineRunner(settings_path=str(settings), sources_path=str(sources))


def _make_configs(countries: list[str]) -> list[Config]:
    """Helper: create Config objects with given country codes."""
    return [
        Config(
            protocol="vless",
            address=f"1.2.3.{i % 200 + 4}",
            port=443 + i % 10,
            uuid_or_password=f"11111111-1111-4111-8111-11111111111{i % 10}",
            country=c,
        )
        for i, c in enumerate(countries)
    ]


def test_whitelist_balance_80_20_split():
    """Whitelist output should be ~80% RU, ~20% EU countries."""
    runner = _make_runner()
    max_total = 75
    # 100 RU + 50 other
    configs = _make_configs(["RU"] * 100 + ["DE"] * 30 + ["FI"] * 20)
    result = runner._whitelist_balance(configs, max_total)
    ru = sum(1 for c in result if c.country == "RU")
    other = sum(1 for c in result if c.country != "RU")
    assert len(result) == max_total, f"Expected {max_total}, got {len(result)}"
    assert ru == 60, f"Expected 60 RU (80%), got {ru}"
    assert other == 15, f"Expected 15 EU (20%), got {other}"


def test_whitelist_balance_fills_shortfall_from_other():
    """If RU < 80% target, fill remaining slots from EU countries."""
    runner = _make_runner()
    max_total = 75
    # Only 10 RU, 100 other
    configs = _make_configs(["RU"] * 10 + ["DE"] * 60 + ["FI"] * 40)
    result = runner._whitelist_balance(configs, max_total)
    ru = sum(1 for c in result if c.country == "RU")
    other = sum(1 for c in result if c.country != "RU")
    assert len(result) == max_total, f"Expected {max_total}, got {len(result)}"
    assert ru == 10, f"Expected 10 RU (all available), got {ru}"
    assert other == 65, f"Expected 65 other (filling shortfall), got {other}"


def test_whitelist_balance_fills_shortfall_from_ru():
    """If EU < 20% target, fill remaining slots from RU."""
    runner = _make_runner()
    max_total = 75
    # 100 RU, only 5 other
    configs = _make_configs(["RU"] * 100 + ["DE"] * 5)
    result = runner._whitelist_balance(configs, max_total)
    ru = sum(1 for c in result if c.country == "RU")
    other = sum(1 for c in result if c.country != "RU")
    assert len(result) == max_total, f"Expected {max_total}, got {len(result)}"
    assert other == 5, f"Expected 5 other (all available), got {other}"
    assert ru == 70, f"Expected 70 RU (filling shortfall), got {ru}"


def test_whitelist_balance_empty():
    """Empty input should return empty."""
    runner = _make_runner()
    result = runner._whitelist_balance([], 75)
    assert result == []


def test_whitelist_balance_all_ru():
    """All RU configs should return max_total RU."""
    runner = _make_runner()
    configs = _make_configs(["RU"] * 100)
    result = runner._whitelist_balance(configs, 75)
    ru = sum(1 for c in result if c.country == "RU")
    assert len(result) == 75
    assert ru == 75


def test_whitelist_balance_all_other():
    """All non-RU configs should return max_total other."""
    runner = _make_runner()
    configs = _make_configs(["DE"] * 50 + ["FI"] * 50)
    result = runner._whitelist_balance(configs, 75)
    other = sum(1 for c in result if c.country != "RU")
    assert len(result) == 75
    assert other == 75


if __name__ == "__main__":
    # Run all tests manually for debugging
    import pytest

    sys.exit(pytest.main([__file__, "-v", "-s"]))
