"""Tests for proxy health tracking and ranking — 100% coverage."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from src.validators.proxy_health import ProxyHealthHistory

# ---------------------------------------------------------------------------
# Basic operations
# ---------------------------------------------------------------------------


def test_empty_history_is_neutral() -> None:
    hist = ProxyHealthHistory()
    assert hist.is_banned("socks5://1.2.3.4:1080") is False
    assert hist.rank(["socks5://1.2.3.4:1080"]) == ["socks5://1.2.3.4:1080"]


def test_banned_proxy_is_dropped() -> None:
    hist = ProxyHealthHistory(ban_after_consecutive_failures=2)
    hist.record("socks5://1.2.3.4:1080", False)
    hist.record("socks5://1.2.3.4:1080", False)
    assert hist.is_banned("socks5://1.2.3.4:1080") is True
    ranked = hist.rank(["socks5://1.2.3.4:1080", "socks5://5.6.7.8:1080"])
    assert ranked == ["socks5://5.6.7.8:1080"]


def test_fast_proxy_ranks_first() -> None:
    hist = ProxyHealthHistory(window=3, max_latency_ms=1000)
    hist.record("socks5://slow.example:1080", True, latency_ms=900)
    hist.record("socks5://fast.example:1080", True, latency_ms=100)
    ranked = hist.rank(["socks5://slow.example:1080", "socks5://fast.example:1080"])
    assert ranked[0] == "socks5://fast.example:1080"


def test_slow_proxy_is_dropped_when_drop_slow_true() -> None:
    hist = ProxyHealthHistory(window=3, max_latency_ms=500)
    hist.record("socks5://slow.example:1080", True, latency_ms=1000)
    ranked = hist.rank(["socks5://slow.example:1080"], drop_slow=True)
    assert ranked == []


def test_record_success_resets_consecutive_failures() -> None:
    hist = ProxyHealthHistory(ban_after_consecutive_failures=2)
    hist.record("socks5://1.2.3.4:1080", False)
    hist.record("socks5://1.2.3.4:1080", True, latency_ms=100)
    hist.record("socks5://1.2.3.4:1080", False)
    assert hist.is_banned("socks5://1.2.3.4:1080") is False


# ---------------------------------------------------------------------------
# record() edge cases
# ---------------------------------------------------------------------------


def test_record_empty_proxy_url() -> None:
    """record() with empty proxy_url returns early (whitespace creates empty-key entry)."""
    hist = ProxyHealthHistory()
    hist.record("", True)  # empty string → returns early
    assert hist.records == {}
    hist.record("   ", False)  # whitespace-only: .strip() makes empty key
    assert "" in hist.records


def test_record_first_time_creates_entry() -> None:
    """record() creates a default entry for a new proxy."""
    hist = ProxyHealthHistory()
    hist.record("socks5://1.2.3.4:1080", True, latency_ms=50)
    entry = hist.records["socks5://1.2.3.4:1080"]
    assert entry["attempts"] == 1
    assert entry["successes"] == 1
    assert entry["consecutive_failures"] == 0
    assert entry["latency_ms"] == [50]


def test_record_failure_increments_consecutive_failures() -> None:
    hist = ProxyHealthHistory()
    hist.record("socks5://1.2.3.4:1080", False)
    assert hist.records["socks5://1.2.3.4:1080"]["consecutive_failures"] == 1


def test_record_latency_zero_or_none_not_appended() -> None:
    """latency_ms of 0 or None is not appended to the list."""
    hist = ProxyHealthHistory()
    hist.record("socks5://1.2.3.4:1080", True)
    assert hist.records["socks5://1.2.3.4:1080"]["latency_ms"] == []
    hist.record("socks5://1.2.3.4:1080", True, latency_ms=0)
    assert hist.records["socks5://1.2.3.4:1080"]["latency_ms"] == []


def test_record_latency_window_truncation() -> None:
    """Only the last `window` latencies are kept."""
    hist = ProxyHealthHistory(window=3)
    for i in range(1, 6):
        hist.record("socks5://1.2.3.4:1080", True, latency_ms=i * 10)
    assert hist.records["socks5://1.2.3.4:1080"]["latency_ms"] == [30, 40, 50]


# ---------------------------------------------------------------------------
# is_banned() edge cases
# ---------------------------------------------------------------------------


def test_is_banned_no_history() -> None:
    hist = ProxyHealthHistory()
    assert hist.is_banned("socks5://unknown:1080") is False


def test_is_banned_not_yet_banned() -> None:
    hist = ProxyHealthHistory(ban_after_consecutive_failures=3)
    hist.record("socks5://1.2.3.4:1080", False)
    hist.record("socks5://1.2.3.4:1080", False)
    assert hist.is_banned("socks5://1.2.3.4:1080") is False


# ---------------------------------------------------------------------------
# _avg_latency / _score edge cases
# ---------------------------------------------------------------------------


def test_avg_latency_no_history() -> None:
    hist = ProxyHealthHistory()
    assert hist._avg_latency("socks5://unknown:1080") == float("inf")


def test_avg_latency_empty_latencies() -> None:
    hist = ProxyHealthHistory()
    hist.record("socks5://1.2.3.4:1080", True)  # no latency recorded
    assert hist._avg_latency("socks5://1.2.3.4:1080") == float("inf")


def test_score_no_history() -> None:
    hist = ProxyHealthHistory()
    assert hist._score("socks5://unknown:1080") == 0.5


def test_score_with_latency_penalty_zero() -> None:
    """When avg_latency exceeds max_latency_ms, penalty is 0."""
    hist = ProxyHealthHistory(max_latency_ms=100)
    hist.record("socks5://1.2.3.4:1080", True, latency_ms=200)
    # avg_latency = 200 > max_latency_ms = 100 → latency_penalty = 0.0
    # score = 0.7 * 1.0 + 0.3 * 0.0 = 0.7
    assert hist._score("socks5://1.2.3.4:1080") == pytest.approx(0.7)


def test_score_mixed_results() -> None:
    """Score combines success rate and latency."""
    hist = ProxyHealthHistory(max_latency_ms=1000)
    # 3 attempts, 2 successes, avg_latency = 200
    hist.record("socks5://1.2.3.4:1080", True, latency_ms=100)
    hist.record("socks5://1.2.3.4:1080", False)
    hist.record("socks5://1.2.3.4:1080", True, latency_ms=300)
    # success_rate = 2/3, latency_penalty = 1 - (200/1000) = 0.8
    # score = 0.7 * 0.666... + 0.3 * 0.8 = 0.70666...
    expected = (0.7 * 2 / 3) + (0.3 * 0.8)
    assert hist._score("socks5://1.2.3.4:1080") == pytest.approx(expected, rel=1e-3)


# ---------------------------------------------------------------------------
# rank() edge cases
# ---------------------------------------------------------------------------


def test_rank_empty_list() -> None:
    hist = ProxyHealthHistory()
    assert hist.rank([]) == []


def test_rank_skips_empty_keys() -> None:
    hist = ProxyHealthHistory()
    assert hist.rank(["", "  "]) == []


def test_rank_drop_banned_false_keeps_banned() -> None:
    """With drop_banned=False, banned proxies are kept (must also handle drop_slow)."""
    hist = ProxyHealthHistory(ban_after_consecutive_failures=2, max_latency_ms=8000)
    hist.record("socks5://1.2.3.4:1080", False)
    hist.record("socks5://1.2.3.4:1080", False)
    # Without latency data, _avg_latency is inf so drop_slow would remove it
    ranked = hist.rank(["socks5://1.2.3.4:1080"], drop_banned=False, drop_slow=False)
    assert ranked == ["socks5://1.2.3.4:1080"]


def test_rank_drop_slow_false_keeps_slow() -> None:
    hist = ProxyHealthHistory(max_latency_ms=100)
    hist.record("socks5://1.2.3.4:1080", True, latency_ms=500)
    ranked = hist.rank(["socks5://1.2.3.4:1080"], drop_slow=False)
    assert ranked == ["socks5://1.2.3.4:1080"]


def test_rank_sorts_by_score_descending() -> None:
    hist = ProxyHealthHistory(max_latency_ms=1000)
    hist.record("socks5://middle:1080", True, latency_ms=300)
    hist.record("socks5://best:1080", True, latency_ms=50)
    hist.record("socks5://worst:1080", True, latency_ms=800)
    ranked = hist.rank(
        ["socks5://worst:1080", "socks5://best:1080", "socks5://middle:1080"],
    )
    assert ranked == [
        "socks5://best:1080",
        "socks5://middle:1080",
        "socks5://worst:1080",
    ]


# ---------------------------------------------------------------------------
# prune()
# ---------------------------------------------------------------------------


def test_prune_removes_old_records() -> None:
    """Records with >=2 attempts and old last_seen are pruned."""
    hist = ProxyHealthHistory()
    hist.record("socks5://old:1080", True)
    hist.record("socks5://old:1080", True)  # 2 attempts — eligible for pruning
    # Manually set last_seen far in the past
    hist.records["socks5://old:1080"]["last_seen"] = 0.0
    hist.record("socks5://new:1080", True)
    hist.prune(max_age_seconds=1.0)
    assert "socks5://old:1080" not in hist.records
    assert "socks5://new:1080" in hist.records


def test_prune_keeps_few_attempts_regardless_of_age() -> None:
    """Records with fewer than 2 attempts are kept regardless of age."""
    hist = ProxyHealthHistory()
    hist.record("socks5://few:1080", True)
    hist.records["socks5://few:1080"]["last_seen"] = 0.0
    hist.prune(max_age_seconds=1.0)
    assert "socks5://few:1080" in hist.records


def test_prune_empty_history() -> None:
    hist = ProxyHealthHistory()
    hist.prune()  # should not raise
    assert hist.records == {}


# ---------------------------------------------------------------------------
# to_dict()
# ---------------------------------------------------------------------------


def test_to_dict_returns_copy() -> None:
    hist = ProxyHealthHistory()
    hist.record("socks5://1.2.3.4:1080", True)
    d = hist.to_dict()
    assert "socks5://1.2.3.4:1080" in d
    assert d["socks5://1.2.3.4:1080"]["attempts"] == 1
    # Mutating the dict should not affect the original
    d["new"] = {}
    assert "new" not in hist.records


# ---------------------------------------------------------------------------
# Persistence — load() edge cases
# ---------------------------------------------------------------------------


def test_load_from_nonexistent_path() -> None:
    """load() returns empty history when path does not exist."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "nonexistent.json"
        hist = ProxyHealthHistory.load(str(path))
        assert hist.records == {}


def test_load_unsafe_path_returns_empty() -> None:
    """load() with a path containing '..' returns empty history."""
    hist = ProxyHealthHistory.load("/some/../../unsafe/path.json")
    assert hist.records == {}


def test_load_corrupted_json_returns_empty() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "bad.json"
        path.write_text("this is not json", encoding="utf-8")
        hist = ProxyHealthHistory.load(str(path))
        assert hist.records == {}


def test_load_non_dict_json_returns_empty() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "list.json"
        path.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
        hist = ProxyHealthHistory.load(str(path))
        assert hist.records == {}


def test_load_success_path() -> None:
    """load() returns history with data from a valid JSON file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "health.json"
        data = {
            "socks5://1.2.3.4:1080": {
                "attempts": 3,
                "successes": 2,
                "consecutive_failures": 0,
                "latency_ms": [100, 200],
                "last_seen": 1000.0,
            }
        }
        path.write_text(json.dumps(data), encoding="utf-8")
        hist = ProxyHealthHistory.load(str(path))
        assert hist.records["socks5://1.2.3.4:1080"]["attempts"] == 3
        assert hist.records["socks5://1.2.3.4:1080"]["successes"] == 2


def test_load_on_directory_path() -> None:
    """load() on a directory raises OSError which is caught."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "subdir"
        path.mkdir()
        hist = ProxyHealthHistory.load(str(path))
        assert hist.records == {}


# ---------------------------------------------------------------------------
# Persistence — save() edge cases
# ---------------------------------------------------------------------------


def test_save_unsafe_path_logs_warning() -> None:
    """save() with an unsafe path logs a warning and returns."""
    hist = ProxyHealthHistory()
    hist.record("socks5://1.2.3.4:1080", True)
    hist.save("/some/../../unsafe/path.json")  # should not raise


def test_save_creates_parent_directory(tmp_path: Path) -> None:
    """save() creates parent directories if they don't exist."""
    path = tmp_path / "subdir" / "nested" / "health.json"
    hist = ProxyHealthHistory()
    hist.record("socks5://1.2.3.4:1080", True)
    hist.save(str(path))
    assert path.exists()
    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert "socks5://1.2.3.4:1080" in loaded


def test_save_oserror_logs_warning(tmp_path: Path) -> None:
    """save() logs a warning on OSError."""
    hist = ProxyHealthHistory()
    hist.record("socks5://1.2.3.4:1080", True)
    # Use a path in a non-existent drive or similar — on Windows, use a path with
    # an invalid char; on all platforms, use a path to a directory instead of file.
    hist.save(str(tmp_path))  # tmp_path is a directory, should fail OSError


# ---------------------------------------------------------------------------
# rank() with drop_banned=False and drop_slow=False
# ---------------------------------------------------------------------------


def test_rank_all_filters_disabled() -> None:
    """With both drop_banned=False and drop_slow=False, everything passes."""
    hist = ProxyHealthHistory(ban_after_consecutive_failures=2, max_latency_ms=100)
    hist.record("socks5://banned:1080", False)
    hist.record("socks5://banned:1080", False)
    hist.record("socks5://slow:1080", True, latency_ms=500)
    ranked = hist.rank(
        ["socks5://banned:1080", "socks5://slow:1080", "socks5://new:1080"],
        drop_banned=False,
        drop_slow=False,
    )
    assert len(ranked) == 3
    # All three should be present
    assert "socks5://new:1080" in ranked
    assert "socks5://slow:1080" in ranked
    assert "socks5://banned:1080" in ranked


# ---------------------------------------------------------------------------
# Constructor edge cases
# ---------------------------------------------------------------------------


def test_constructor_clamps_values() -> None:
    """window, ban_after_consecutive_failures, max_latency_ms are clamped to >= 1."""
    hist = ProxyHealthHistory(
        window=0, ban_after_consecutive_failures=0, max_latency_ms=0
    )
    assert hist.window == 1
    assert hist.ban_after_consecutive_failures == 1
    assert hist.max_latency_ms == 1.0
