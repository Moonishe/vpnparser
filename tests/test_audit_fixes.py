"""Audit coverage fixes — tests for previously uncovered branches.

Covers the lines listed in the audit task without touching other files.
No real network: DNS/resolver and OS replace are mocked.
"""

from __future__ import annotations

import base64
import json
import os
import typing
import zlib

import pytest

import src.parsers.base as base_module
import src.parsers.subscription as subscription_module
from src.aggregator.merger import deduplicate
from src.aggregator.output import (
    _vmess_with_country,
    is_watermark_vmess,
    write_subscription,
)
from src.parsers.base import (
    Config,
    find_all_links,
    is_garbage_config,
    parse_qs_single,
    safe_b64decode,
    split_host_port,
)
from src.parsers.hysteria2 import Hysteria2Parser
from src.parsers.shadowsocks import ShadowsocksParser
from src.parsers.subscription import _b64_to_bytes, _stream_decompress
from src.parsers.tuic import TuicParser
from src.parsers.vless import VlessParser
from src.parsers.vmess import VmessParser
from src.validators import address_guard
from src.validators.address_guard import (
    _as_canonical_ip,
    _is_ip_literal,
    resolve_pinned_addresses,
)
from src.validators.country_filter import detect_country


def _vmess_link_with(extra: dict) -> str:
    payload = {
        "v": "2",
        "ps": "RU-01",
        "add": "ru.example.com",
        "port": "443",
        "id": "11111111-1111-4111-8111-111111111111",
        "net": "tcp",
        "tls": "none",
    }
    payload.update(extra)
    encoded = base64.b64encode(json.dumps(payload).encode()).decode("ascii")
    return f"vmess://{encoded}"


# --- src/parsers/base.py ---


def test_dedup_key_mport_exception_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """base.py:152-153 — mport parsing failure falls back to empty."""

    def _boom(_qs: str) -> dict[str, str]:
        raise RuntimeError("boom")

    monkeypatch.setattr(base_module, "parse_qs_single", _boom)
    cfg = Config(
        protocol="hysteria2",
        address="example.com",
        port=443,
        uuid_or_password="pass",
        raw_link="hysteria2://pass@example.com:443?mport=443-500",
    )
    key = cfg.dedup_key
    assert isinstance(key, tuple)
    assert key[0] == "hysteria2"
    assert key[2] == 443


def test_safe_b64decode_none() -> None:
    """base.py:257 — None input returns empty string."""
    assert safe_b64decode(None) == ""


def test_safe_b64decode_unquote_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """base.py:260-261 — unquote failure returns empty string."""

    def _boom(_data: str) -> str:
        raise ValueError("bad percent")

    monkeypatch.setattr(base_module, "unquote", _boom)
    assert safe_b64decode("aGVsbG8=") == ""


def test_parse_qs_single_skips_empty_pair() -> None:
    """base.py:297 — empty pair between && is skipped."""
    assert parse_qs_single("a=1&&b=2") == {"a": "1", "b": "2"}
    assert parse_qs_single("a=1&") == {"a": "1"}


def test_split_host_port_rejects_space_slash_backslash() -> None:
    """base.py:388 — whitespace and path separators are rejected."""
    assert split_host_port("exa mple.com:443") is None
    assert split_host_port("example.com/a:443") is None
    assert split_host_port("example.com\\a:443") is None


def test_split_host_port_rejects_controls() -> None:
    """base.py:390 — control chars and DEL are rejected."""
    assert split_host_port("a\x01b:443") is None
    assert split_host_port("a\x7fb:443") is None


def test_split_host_port_rejects_bad_chars() -> None:
    """base.py:409 — URL delimiters in host are rejected."""
    assert split_host_port("exa!mple.com:443") is None
    assert split_host_port("exa@mple.com:443") is None


def test_split_host_port_int_conversion_failure() -> None:
    """base.py:417-418 — int() failure returns None (digit-limit guard)."""
    long_port = "9" * 5000
    assert split_host_port(f"example.com:{long_port}") is None


def test_find_all_links_none_and_bytes() -> None:
    """base.py:565 — None and non-str input return empty list."""
    assert find_all_links(None) == []
    assert find_all_links(b"vless://x@y:443") == []  # type: ignore[arg-type]
    assert find_all_links("") == []


def test_find_all_links_strips_trailing_punctuation() -> None:
    """base.py:581 — trailing prose punctuation is stripped."""
    links = find_all_links("vless://u@example.com:443,")
    assert links == ["vless://u@example.com:443"]
    links = find_all_links("(vless://u@example.com:443;)")
    assert links == ["vless://u@example.com:443"]


def test_is_garbage_watermark_masquerade() -> None:
    """base.py:788 — crafted vmess 0.0.0.0 is garbage."""
    cfg = Config(
        protocol="vmess",
        address="0.0.0.0",
        port=1,
        uuid_or_password="11111111-1111-4111-8111-111111111111",
    )
    assert is_garbage_config(cfg) is True


def test_is_garbage_ss_base64_userinfo_placeholder() -> None:
    """base.py:854-869 — SIP002 placeholder password detected via decode."""
    cred = base64.b64encode(b"aes-256-gcm:PASSWORD").decode()
    link = f"ss://{cred}@192.0.2.10:8388"
    assert is_garbage_config(link) is True


def test_is_garbage_ss_base64_userinfo_decode_failure() -> None:
    """base.py:870-871 — invalid base64 userinfo probe fails soft."""
    link = "ss://!!!@192.0.2.10:8388"
    assert is_garbage_config(link) is False


# --- src/parsers/hysteria2.py ---


def test_hysteria2_mport_bracketed_no_port() -> None:
    """hysteria2.py:153,171 — [::1] + mport appends range."""
    cfg = Hysteria2Parser().parse("hysteria2://pass@[::1]?mport=443-500#r")
    assert cfg is not None
    assert cfg.address == "::1"
    assert cfg.port == 443


def test_hysteria2_mport_bracketed_colon_no_port() -> None:
    """hysteria2.py:173 — '[::1]:' + mport uses rpartition branch."""
    cfg = Hysteria2Parser().parse("hysteria2://pass@[::1]:?mport=443-500#r")
    assert cfg is not None
    assert cfg.address == "::1"
    assert cfg.port == 443


def test_hysteria2_authority_port_wins_over_mport() -> None:
    """hysteria2 authority plain port wins over mport range."""
    cfg = Hysteria2Parser().parse("hysteria2://pass@example.com:8443?mport=443-500#r")
    assert cfg is not None
    assert cfg.port == 8443


def test_hysteria2_obfs_allowlist() -> None:
    """hysteria2.py:190 — unknown obfs value is rejected."""
    assert (
        Hysteria2Parser().parse("hysteria2://pass@example.com:443?obfs=bad#r") is None
    )
    cfg = Hysteria2Parser().parse("hysteria2://pass@example.com:443?obfs=salamander#r")
    assert cfg is not None


# --- other parsers ---


def test_shadowsocks_unknown_cipher() -> None:
    """shadowsocks.py:196 — unknown method is rejected."""
    assert ShadowsocksParser().parse("ss://badcipher:pass123@example.com:8388") is None


def test_tuic_invalid_congestion_control() -> None:
    """tuic.py:111 — unknown congestion_control is rejected."""
    assert (
        TuicParser().parse("tuic://mytoken@example.com:443?congestion_control=bad#r")
        is None
    )


def test_tuic_invalid_udp_relay_mode() -> None:
    """tuic.py:114 — unknown udp_relay_mode is rejected."""
    assert (
        TuicParser().parse("tuic://mytoken@example.com:443?udp_relay_mode=bad#r")
        is None
    )


def test_vless_password_in_userinfo_rejected() -> None:
    """vless.py:73 — userinfo with password part is malformed."""
    link = "vless://11111111-1111-4111-8111-111111111111:secret@example.com:443#r"
    assert VlessParser().parse(link) is None


def test_vmess_non_integral_float_aid() -> None:
    """vmess.py:172 — float non-integral aid is ignored, link survives."""
    cfg = VmessParser().parse(_vmess_link_with({"aid": 1.5}))
    assert cfg is not None
    assert cfg.alter_id is None


# --- src/parsers/subscription.py ---


def test_b64_to_bytes_none() -> None:
    """subscription.py:59 — None returns empty bytes."""
    assert _b64_to_bytes(None) == b""


def test_b64_to_bytes_unquote_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """subscription.py:62-63 — unquote failure returns empty bytes."""

    def _boom(_data: str) -> str:
        raise ValueError("bad percent")

    monkeypatch.setattr(subscription_module, "unquote", _boom)
    assert _b64_to_bytes("aGVsbG8=") == b""


def test_stream_decompress_tail_bomb(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """subscription.py:100 — flush pushing past cap raises ValueError."""

    class _FakeDec:
        unconsumed_tail = b""

        def decompress(self, _data: bytes, _limit: int) -> bytes:
            return b"AB"

        def flush(self, _length: int) -> bytes:
            return b"CDEFG"

    monkeypatch.setattr(subscription_module, "_MAX_DECOMPRESSED_BYTES", 5)
    monkeypatch.setattr(
        subscription_module.zlib,
        "decompressobj",
        lambda _wbits: _FakeDec(),
    )
    with pytest.raises(ValueError):
        _stream_decompress(zlib.compress(b"hello"), 15)


# --- src/aggregator/merger.py ---


def test_deduplicate_skips_none() -> None:
    """merger.py:72 — None entries are skipped."""
    cfg = Config(
        protocol="vless",
        address="example.com",
        port=443,
        uuid_or_password="11111111-1111-4111-8111-111111111111",
    )
    result = deduplicate([None, cfg])  # type: ignore[list-item]
    assert result == [cfg]


def test_deduplicate_dedup_key_exception_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """merger.py:75-76 — dedup_key failure uses repr fallback key."""

    def _boom(self: Config) -> tuple[str, str, int, str]:
        raise RuntimeError("boom")

    monkeypatch.setattr(Config, "dedup_key", property(_boom))
    cfg = Config(
        protocol="vless",
        address="example.com",
        port=443,
        uuid_or_password="11111111-1111-4111-8111-111111111111",
    )
    result = deduplicate([cfg])
    assert result == [cfg]


# --- src/aggregator/output.py ---


def test_is_watermark_non_dict_payload() -> None:
    """output.py:80 — vmess payload that is not a dict is not watermark."""
    body = base64.b64encode(b"[]").decode()
    assert is_watermark_vmess(f"vmess://{body}") is False


def test_vmess_with_country_non_dict() -> None:
    """output.py:122 — non-dict vmess payload is returned unchanged."""
    body = base64.b64encode(b"[]").decode()
    link = f"vmess://{body}"
    assert _vmess_with_country(link, "DE") == link


def test_vmess_with_country_already_labeled() -> None:
    """output.py:125 — ps already carrying country is left unchanged."""
    payload = {
        "v": "2",
        "ps": "DE-01",
        "add": "example.com",
        "port": "443",
        "id": "11111111-1111-4111-8111-111111111111",
    }
    link = "vmess://" + base64.b64encode(json.dumps(payload).encode()).decode()
    assert _vmess_with_country(link, "US") == link


def test_write_subscription_replace_failure_cleans_tmp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """output.py:245-248 — failed atomic replace removes tmp and raises."""
    cfg = Config(
        protocol="vless",
        address="example.com",
        port=443,
        uuid_or_password="u",
        raw_link="vless://u@example.com:443",
    )

    def _boom(_src: str, _dst: str) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", _boom)
    with pytest.raises(OSError):
        write_subscription([cfg], "output/sub-audit-fix.txt", fmt="plain")


# --- src/validators/country_filter.py ---


def test_detect_country_ambiguous_prefix_skipped() -> None:
    """country_filter.py:527-528 — lettered prefix vetoes ambiguous match."""
    assert detect_country("myserver", "cdn-in1.example.com") is None


def test_detect_country_ambiguous_bare_returns() -> None:
    """country_filter.py:529 — bare ambiguous stamp returns code."""
    assert detect_country("myserver", "us1-node.example.com") == "US"


# --- src/validators/address_guard.py ---


def test_address_guard_type_checking_import(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """address_guard.py:41 — execute the TYPE_CHECKING import."""
    import importlib

    monkeypatch.setattr(typing, "TYPE_CHECKING", True)
    try:
        reloaded = importlib.reload(address_guard)
        assert reloaded is not None
    finally:
        monkeypatch.undo()
        importlib.reload(address_guard)


def test_as_canonical_ip_small_int_and_garbage() -> None:
    """address_guard.py:148-150 — bare int and non-numeric short names."""
    assert _as_canonical_ip("1") is None
    assert _as_canonical_ip("localhost") is None


def test_is_ip_literal() -> None:
    """address_guard.py:158 — literal detection helper."""
    assert _is_ip_literal("8.8.8.8") is True
    assert _is_ip_literal("example.com") is False


async def test_resolve_pinned_addresses_empty_host() -> None:
    """address_guard.py:240 — empty host fails closed with []."""
    assert await resolve_pinned_addresses(None) == []
    assert await resolve_pinned_addresses("") == []


# --- audit leftovers batch ---


def test_is_valid_host_rejects_garbage() -> None:
    """base.is_valid_host: empty/space/slash/controls/deny-set/colon."""
    from src.parsers.base import is_valid_host

    assert is_valid_host("example.com") is True
    assert is_valid_host("2001:db8::1") is True
    assert is_valid_host("") is False
    assert is_valid_host(None) is False  # type: ignore[arg-type]
    assert is_valid_host("   ") is False
    assert is_valid_host("exa mple.com") is False
    assert is_valid_host("example.com/a") is False
    assert is_valid_host("example.com\\a") is False
    assert is_valid_host("a\x01b") is False
    assert is_valid_host("a\x7fb") is False
    assert is_valid_host("exa!mple.com") is False
    assert is_valid_host("exa;mple.com") is False
    assert is_valid_host("exa,mple.com") is False
    assert is_valid_host("exa%mple.com") is False
    assert is_valid_host("exa$mple.com") is False
    assert is_valid_host("exa&mple.com") is False
    assert is_valid_host("exa+mple.com") is False
    assert is_valid_host("exa*mple.com") is False
    assert is_valid_host("exa=mple.com") is False
    assert is_valid_host("exa~mple.com") is False
    assert is_valid_host("exa|mple.com") is False
    assert is_valid_host("exa^mple.com") is False
    assert is_valid_host("bad:host") is False


def test_url_parsers_reject_invalid_host() -> None:
    """vless/trojan/vmess return None on invalid host."""
    from src.parsers.trojan import TrojanParser

    good_uuid = "11111111-1111-4111-8111-111111111111"
    assert VlessParser().parse(f"vless://{good_uuid}@exa;mple.com:443") is None
    assert TrojanParser().parse("trojan://secret@exa|mple.com:443") is None
    assert VmessParser().parse(_vmess_link_with({"add": "exa^mple.com"})) is None
    # Valid hosts still parse.
    assert VlessParser().parse(f"vless://{good_uuid}@example.com:443") is not None


def test_split_host_port_rejects_bracketed_non_ipv6() -> None:
    """base.split_host_port bracket branch requires an IPv6 literal."""
    assert split_host_port("[example.com]:443") is None
    assert split_host_port("[1.2.3.4]:443") is None
    assert split_host_port("[2001:db8::1]:443") == ("2001:db8::1", 443)
    assert split_host_port("[::1]:443") == ("::1", 443)


def test_hysteria2_hopping_range_preserved_and_hashed() -> None:
    """hysteria2 authority-range/mport survive in hopping_port_range + hash."""
    parser = Hysteria2Parser()
    via_authority = parser.parse("hy2://pass@example.com:443-500#x")
    via_mport = parser.parse("hy2://pass@example.com?mport=443-500#x")
    plain = parser.parse("hy2://pass@example.com:443#x")
    other = parser.parse("hy2://pass@example.com:443,8443#x")
    assert via_authority is not None and via_authority.hopping_port_range == "443-500"
    assert via_authority.port == 443
    assert via_mport is not None and via_mport.hopping_port_range == "443-500"
    assert plain is not None and plain.hopping_port_range is None
    assert other is not None and other.hopping_port_range == "443,8443"
    assert via_authority.dedup_key != plain.dedup_key
    assert via_authority.dedup_key != other.dedup_key
    # Same range dedups even across authority/mport spellings.
    assert via_authority.dedup_key == via_mport.dedup_key


def test_is_garbage_vmess_json_placeholders() -> None:
    """base string branch decodes vmess JSON and scans add/sni/host."""
    payload = {
        "v": "2",
        "ps": "x",
        "add": "SERVER_IP_1",
        "port": "443",
        "id": "11111111-1111-4111-8111-111111111111",
    }
    link = "vmess://" + base64.b64encode(json.dumps(payload).encode()).decode()
    assert is_garbage_config(link) is True
    payload_ok = dict(payload, add="real-server.net")
    ok_link = "vmess://" + base64.b64encode(json.dumps(payload_ok).encode()).decode()
    assert is_garbage_config(ok_link) is False
    # Undecodable payload is left alone (no false positive).
    assert is_garbage_config("vmess://!!!not-base64!!!") is False


def test_is_watermark_urlsafe_and_noise() -> None:
    """output.is_watermark_vmess normalises urlsafe alphabet + noise."""
    payload = {
        "v": "2",
        "ps": "x",
        "add": "0.0.0.0",
        "port": "1",
        "id": "00000000-0000-0000-0000-000000000000",
    }
    body = base64.b64encode(json.dumps(payload).encode()).decode()
    assert is_watermark_vmess("vmess://" + body) is True
    urlsafe = body.replace("+", "-").replace("/", "_").rstrip("=")
    assert is_watermark_vmess("vmess://" + urlsafe) is True
    noisy = body[:10] + "\n" + body[10:] + "﻿"
    assert is_watermark_vmess("vmess://" + noisy) is True


def test_host_ambiguous_my_server_not_malaysia() -> None:
    """country_filter _HOST_AMBIGUOUS_RE: '-' without digit is prose."""
    assert detect_country("", "my-server.example.com") is None
    assert detect_country("", "in-house.example.com") is None
    # Digit-bearing stamps still detect.
    assert detect_country("x", "us1-node.example.com") == "US"
    assert detect_country("", "us-01.example.com") == "US"
    # Hyphen city stamps still resolve via the city regex.
    assert detect_country("", "id-jakarta.example.com") == "ID"


def test_filter_by_country_none_fail_closed() -> None:
    """filter_by_country(None) raises ValueError; filter stage propagates."""
    import pytest as _pytest

    from src.validators.country_filter import filter_by_country as _fbc

    cfg = Config(
        protocol="vless",
        address="example.com",
        port=443,
        uuid_or_password="u",
        country="DE",
    )
    with _pytest.raises(ValueError):
        _fbc([cfg], None)  # type: ignore[arg-type]


def test_country_filter_stage_none_fail_closed() -> None:
    """filter.py must not coerce None allowed list to [] (fail-open)."""
    import pytest as _pytest

    from src.scheduler.context import PipelineContext
    from src.scheduler.settings import Settings
    from src.scheduler.stages.filter import CountryFilter

    ctx = PipelineContext(
        settings=Settings({"validator": {"allowed_countries": None}}),
        github_token=None,
        sources_path="missing.json",
    )
    with _pytest.raises(ValueError):
        CountryFilter(ctx).filter_countries([], list_type="mixed")


def test_parser_network_security_allowlist_resets() -> None:
    """vless/trojan/vmess unknown network/security reset to defaults."""
    from src.parsers.trojan import TrojanParser

    good_uuid = "11111111-1111-4111-8111-111111111111"
    vless = VlessParser().parse(f"vless://{good_uuid}@example.com:443?type=kcp")
    assert vless is not None and vless.network == "tcp"
    vless_sec = VlessParser().parse(
        f"vless://{good_uuid}@example.com:443?security=bogus"
    )
    assert vless_sec is not None and vless_sec.security == "none"
    trojan = TrojanParser().parse("trojan://secret@example.com:443?type=kcp")
    assert trojan is not None and trojan.network == "tcp"
    vmess = VmessParser().parse(_vmess_link_with({"net": "kcp"}))
    assert vmess is not None and vmess.network == "tcp"


def test_merger_sort_limit_skip_none() -> None:
    """merger sort/limit skip None like deduplicate."""
    from src.aggregator.merger import limit_per_country, sort_configs

    cfg = Config(
        protocol="vless",
        address="example.com",
        port=443,
        uuid_or_password="11111111-1111-4111-8111-111111111111",
    )
    assert sort_configs([None, cfg]) == [cfg]  # type: ignore[list-item]
    assert limit_per_country([None, cfg], max_per_country=5) == [cfg]  # type: ignore[list-item]
    assert limit_per_country([None, cfg], max_per_country=0) == [cfg]  # type: ignore[list-item]


def test_with_country_fragment_caps_but_keeps_code() -> None:
    """output non-vmess fragment capped at 256 chars, code preserved."""
    from src.aggregator.output import _with_country_fragment

    long_frag = "A" * 300
    cfg = Config(
        protocol="vless",
        address="a.com",
        port=443,
        uuid_or_password="u",
        remark="x",
        raw_link=f"vless://u@a.com:443#{long_frag}",
        country="DE",
    )
    out = _with_country_fragment(cfg)
    frag = out.split("#", 1)[1]
    assert len(frag) <= 256
    assert frag.endswith("-DE")
    # Short fragment keeps the full country suffix and reparses.
    short = Config(
        protocol="vless",
        address="a.com",
        port=443,
        uuid_or_password="u",
        remark="5777",
        raw_link="vless://u@a.com:443#5777",
        country="NL",
    )
    assert _with_country_fragment(short) == "vless://u@a.com:443#5777-NL"


def test_shadowsocks_none_plain_rejected() -> None:
    """ss none/plain ciphers are unencrypted and never published."""
    assert ShadowsocksParser().parse("ss://none:pass123@example.com:8388") is None
    assert ShadowsocksParser().parse("ss://plain:pass123@example.com:8388") is None
    cred_none = base64.b64encode(b"none:pass123").decode()
    assert ShadowsocksParser().parse(f"ss://{cred_none}@example.com:8388") is None
