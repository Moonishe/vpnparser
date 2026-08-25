"""Tests for src.aggregator.output — generate_output, generate_plain, write_subscription."""

from __future__ import annotations

import base64

from src.aggregator.output import (
    _watermark_link,
    _with_country_fragment,
    generate_output,
    generate_plain,
    is_watermark_vmess,
    write_subscription,
)
from src.parsers.base import Config, extract_remark
from src.validators.country_filter import detect_country


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


def test_generate_plain_drops_raw_link_with_newline():
    """A raw_link carrying \\n cannot inject lines into the subscription."""
    good = Config(
        protocol="vless",
        address="a.com",
        port=443,
        uuid_or_password="11111111-1111-4111-8111-111111111111",
        raw_link="vless://u@a.com:443",
    )
    evil = Config(
        protocol="vless",
        address="b.com",
        port=443,
        uuid_or_password="22222222-2222-4222-8222-222222222222",
        raw_link="vless://u@b.com:443\nevil://x@evil.com:1",
    )
    out = generate_plain([good, evil])
    assert "evil://x@evil.com:1" not in out
    assert out.count("\n") == 1  # watermark + the one safe link


def test_generate_plain_drops_raw_link_with_control_chars():
    cfg = Config(
        protocol="vless",
        address="c.com",
        port=443,
        uuid_or_password="33333333-3333-4333-8333-333333333333",
        raw_link="vless://u@c.com:443\x00",
    )
    out = generate_plain([cfg])
    assert "\x00" not in out


# --- country stamping (_with_country_fragment) ---
# The hourly fast-track revalidation reparses the published subscription,
# where remarks are often opaque numbers. Without a country label in the
# link, the country filter drops the config before it is even probed and
# every fast-track run shrank the published set (observed: 167 → 33).


def _cfg(raw_link: str, country: str | None, remark: str = "") -> Config:
    return Config(
        protocol="vless",
        address="a.com",
        port=443,
        uuid_or_password="uuid",
        remark=remark,
        raw_link=raw_link,
        country=country,
    )


def test_country_stamped_into_link_without_fragment() -> None:
    link = _with_country_fragment(_cfg("vless://u@a.com:443", "RU"))
    assert link == "vless://u@a.com:443#RU"


def test_country_appended_to_opaque_numeric_fragment() -> None:
    """The observed real-world case: published remarks like '5777'."""
    link = _with_country_fragment(_cfg("ss://YWVz@a.com:443#5777", "NL"))
    assert link == "ss://YWVz@a.com:443#5777-NL"
    # The stamped label must be detectable after a publish → reparse cycle.
    assert detect_country(extract_remark(link.split("#", 1)[1])) == "NL"


def test_country_not_duplicated_when_remark_already_detectable() -> None:
    link = _with_country_fragment(
        _cfg("vless://u@a.com:443#Frankfurt-01", "DE", remark="Frankfurt-01")
    )
    assert link == "vless://u@a.com:443#Frankfurt-01"


def test_no_country_keeps_raw_link_untouched() -> None:
    raw = "vless://u@a.com:443#5777"
    assert _with_country_fragment(_cfg(raw, None)) == raw


def test_encoded_fragment_keeps_encoding_before_suffix() -> None:
    raw = "ss://YWVz@a.com:443#%D0%A4%D0%BB%D0%B0%D0%B3"
    link = _with_country_fragment(_cfg(raw, "FI"))
    assert link == raw + "-FI"


def test_vmess_ps_field_stamped_with_country() -> None:
    payload = base64.b64encode(
        b'{"v":"2","ps":"5777","add":"a.com","port":"443"}'
    ).decode()
    link = _with_country_fragment(_cfg(f"vmess://{payload}", "RU"))
    body = link[len("vmess://") :]
    obj = __import__("json").loads(base64.b64decode(body + "=" * (-len(body) % 4)))
    assert obj["ps"] == "5777-RU"


def test_vmess_garbage_payload_returned_unchanged() -> None:
    raw = "vmess://!!!not-base64!!!"
    assert _with_country_fragment(_cfg(raw, "RU")) == raw


def test_generate_plain_uses_stamped_links() -> None:
    cfg = _cfg("vless://u@a.com:443", "DE")
    out = generate_plain([cfg])
    assert "vless://u@a.com:443#DE" in out


# ---------------------------------------------------------------------------
# is_watermark_vmess — structural detection, slug-independent
# ---------------------------------------------------------------------------


def test_watermark_detected_regardless_of_slug(monkeypatch) -> None:
    """The remark embeds the publishing environment's repo slug.

    A fast-track run elsewhere (fork, local clone) used to compare against
    its OWN slug and miss the watermark — revalidating the 0.0.0.0 dummy as
    a real config. Detection must be structural.
    """
    monkeypatch.setenv("GITHUB_OWNER", "someone-else")
    monkeypatch.setenv("GITHUB_REPO", "some-fork")
    foreign = _watermark_link()
    assert is_watermark_vmess(foreign)


def test_watermark_detection_rejects_real_configs() -> None:
    assert not is_watermark_vmess("vless://u@a.com:443#DE")
    payload = base64.b64encode(
        b'{"v":"2","ps":"x","add":"1.2.3.4","port":"443"}'
    ).decode()
    assert not is_watermark_vmess(f"vmess://{payload}")
    assert not is_watermark_vmess("vmess://!!!not-base64!!!")
    assert not is_watermark_vmess("")
    assert not is_watermark_vmess("ss://YWVz@a.com:443")
