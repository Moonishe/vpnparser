"""Tests for src.aggregator.output — generate_output, generate_plain, write_subscription."""

from __future__ import annotations

import base64

from src.aggregator.output import generate_output, generate_plain, write_subscription
from src.parsers.base import Config


def test_generate_output_default_is_base64() -> None:
    """line 89: generate_output default (and 'base64') yields base64."""
    result = generate_output([], fmt="base64")
    decoded = base64.b64decode(result).decode("utf-8")
    assert decoded.startswith("vmess://")


def test_generate_output_plain_format() -> None:
    """line 87: generate_output with fmt='plain' returns plain text."""
    cfg = Config(
        protocol="vless",
        address="example.com",
        port=443,
        uuid_or_password="uuid",
        raw_link="vless://uuid@example.com:443#remark",
    )
    result = generate_output([cfg], fmt="plain")
    assert result.startswith("vmess://")
    assert "vless://uuid@example.com:443#remark" in result


def test_generate_output_unknown_format_falls_back_to_base64() -> None:
    """line 89: unknown format falls back to base64."""
    result = generate_output([], fmt="unknown")
    assert isinstance(result, str)
    decoded = base64.b64decode(result).decode("utf-8")
    assert decoded.startswith("vmess://")


def test_generate_plain_empty_returns_watermark_only() -> None:
    """Empty config list returns just the watermark link."""
    result = generate_plain([])
    assert result.startswith("vmess://")
    assert "\n" not in result


def test_generate_plain_skips_empty_raw_link() -> None:
    """Configs with empty raw_link are excluded from output."""
    cfg_with_link = Config(
        protocol="vless",
        address="a.com",
        port=443,
        uuid_or_password="uuid",
        raw_link="vless://uuid@a.com:443",
    )
    cfg_no_link = Config(
        protocol="trojan",
        address="b.com",
        port=443,
        uuid_or_password="pass",
        raw_link="",
    )
    result = generate_plain([cfg_no_link, cfg_with_link])
    lines = result.split("\n")
    assert len(lines) == 2  # watermark + cfg_with_link
    assert "vless://uuid@a.com:443" in lines


def test_write_subscription_creates_file_and_returns_count(tmp_path) -> None:
    """lines 105-113: write_subscription writes file, returns config count."""
    cfg = Config(
        protocol="vless",
        address="example.com",
        port=443,
        uuid_or_password="uuid",
        raw_link="vless://uuid@example.com:443",
    )
    filepath = str(tmp_path / "subscription.txt")
    count = write_subscription([cfg], filepath, fmt="plain")
    assert count == 1
    assert tmp_path.joinpath("subscription.txt").exists()
    content = tmp_path.joinpath("subscription.txt").read_text(encoding="utf-8")
    assert cfg.raw_link in content


def test_write_subscription_empty_creates_file_with_watermark(tmp_path) -> None:
    """Empty config list still writes watermark-only output."""
    filepath = str(tmp_path / "empty_sub.txt")
    count = write_subscription([], filepath, fmt="plain")
    assert count == 0
    assert tmp_path.joinpath("empty_sub.txt").exists()
    content = tmp_path.joinpath("empty_sub.txt").read_text(encoding="utf-8")
    assert content.startswith("vmess://")


def test_write_subscription_creates_parent_dirs(tmp_path) -> None:
    """line 109: write_subscription creates parent directories when absent."""
    filepath = str(tmp_path / "nested" / "deep" / "sub.txt")
    cfg = Config(
        protocol="vless",
        address="a.com",
        port=443,
        uuid_or_password="uuid",
        raw_link="vless://uuid@a.com:443",
    )
    count = write_subscription([cfg], filepath, fmt="plain")
    assert count == 1
    assert tmp_path.joinpath("nested", "deep", "sub.txt").exists()
    content = tmp_path.joinpath("nested", "deep", "sub.txt").read_text(encoding="utf-8")
    assert cfg.raw_link in content
