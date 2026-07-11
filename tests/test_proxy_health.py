"""Tests for proxy health tracking and ranking."""

from __future__ import annotations

import tempfile
from pathlib import Path

from src.validators.proxy_health import ProxyHealthHistory


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


def test_history_persistence() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "proxy-health.json"
        hist = ProxyHealthHistory(
            window=3,
            ban_after_consecutive_failures=2,
            max_latency_ms=8000,
        )
        hist.record("socks5://1.2.3.4:1080", True, latency_ms=100)
        hist.record("socks5://1.2.3.4:1080", False)
        hist.save(str(path))

        loaded = ProxyHealthHistory.load(str(path), window=3, ban_after_consecutive_failures=2)
        assert loaded.records["socks5://1.2.3.4:1080"]["attempts"] == 2
        assert loaded.records["socks5://1.2.3.4:1080"]["successes"] == 1


def test_record_success_resets_consecutive_failures() -> None:
    hist = ProxyHealthHistory(ban_after_consecutive_failures=2)
    hist.record("socks5://1.2.3.4:1080", False)
    hist.record("socks5://1.2.3.4:1080", True, latency_ms=100)
    hist.record("socks5://1.2.3.4:1080", False)
    assert hist.is_banned("socks5://1.2.3.4:1080") is False
