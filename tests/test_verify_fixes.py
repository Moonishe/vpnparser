"""Regression tests for the audit fix batch (no-verdict, clash, dedup)."""

from __future__ import annotations

import pytest

from src.aggregator import clash as clash_module
from src.notify.report import _safe_int
from src.parsers.base import Config
from src.scheduler.runner import _canonical_output_path
from src.scheduler.settings import Settings


def _cfg(**kwargs) -> Config:
    base = {
        "protocol": "vless",
        "address": "example.com",
        "port": 443,
        "uuid_or_password": "11111111-1111-4111-8111-111111111111",
        "raw_link": "vless://x@example.com:443",
    }
    base.update(kwargs)
    return Config(**base)  # type: ignore[arg-type]


def test_clash_skips_shadowtls() -> None:
    cfg = _cfg(protocol="shadowtls", uuid_or_password="pw", raw_link="shadowtls://x")
    assert clash_module.config_to_clash_proxy(cfg, set()) is None


def test_clash_anytls_minimal() -> None:
    cfg = _cfg(
        protocol="anytls",
        uuid_or_password="pw",
        raw_link="anytls://x",
        sni="s.example.com",
        alpn="h2",
    )
    proxy = clash_module.config_to_clash_proxy(cfg, set())
    assert proxy is not None and proxy["type"] == "anytls"
    assert proxy["sni"] == "s.example.com"
    assert proxy["alpn"] == ["h2"]


def test_clash_bad_port_and_alter_id() -> None:
    bad_port = _cfg(port="abc")  # type: ignore[arg-type]
    assert clash_module.config_to_clash_proxy(bad_port, set()) is None
    bad_aid = _cfg(protocol="vmess", alter_id="xx")  # type: ignore[arg-type]
    assert clash_module.config_to_clash_proxy(bad_aid, set()) is None


def test_clash_unknown_network_skipped() -> None:
    cfg = _cfg(network="kcp")
    assert clash_module.config_to_clash_proxy(cfg, set()) is None
    tcp = _cfg(network="tcp")
    assert clash_module.config_to_clash_proxy(tcp, set()) is not None


def test_clash_hy2_alpn_and_tuic_sni_strip() -> None:
    hy2 = _cfg(
        protocol="hysteria2",
        uuid_or_password="pw",
        raw_link="hy2://x",
        sni="s.example.com",
        alpn="h3",
    )
    proxy = clash_module.config_to_clash_proxy(hy2, set())
    assert proxy is not None and proxy.get("alpn") == ["h3"]
    tuic = _cfg(
        protocol="tuic",
        uuid_or_password="11111111-1111-4111-8111-111111111111:pw",
        raw_link="tuic://x",
        sni="  s.example.com  ",
    )
    proxy2 = clash_module.config_to_clash_proxy(tuic, set())
    assert proxy2 is not None and proxy2.get("sni") == "s.example.com"


def test_dedup_security_and_uuid_case() -> None:
    a = _cfg(security="tls")
    b = _cfg(security="TLS")
    assert a.dedup_key == b.dedup_key
    c = _cfg(uuid_or_password="AAAAAAAA-1111-4111-8111-111111111111")
    d = _cfg(uuid_or_password="aaaaaaaa-1111-4111-8111-111111111111")
    assert c.dedup_key == d.dedup_key
    # Passwords stay case-sensitive.
    t1 = _cfg(protocol="trojan", uuid_or_password="Pass")
    t2 = _cfg(protocol="trojan", uuid_or_password="pass")
    assert t1.dedup_key != t2.dedup_key


def test_dedup_bad_port_total() -> None:
    a = _cfg(port="bad")  # type: ignore[arg-type]
    b = _cfg(port="bad")  # type: ignore[arg-type]
    assert a.dedup_key == b.dedup_key
    assert a.dedup_key[2] == 0


async def test_probe_timeout_is_no_verdict() -> None:
    import asyncio

    from src.validators import singbox_probe as sb
    from src.validators import xray_probe as xp

    async def _slow(*_a, **_k):
        await asyncio.sleep(10)
        return 0.1

    cfg = _cfg()
    # Mock the bodies slow so the ceiling (not spawn failure) trips.
    orig_xp = xp._xray_probe_check_body
    xp._xray_probe_check_body = _slow  # type: ignore[assignment]
    try:
        with pytest.raises(xp._NoVerdictError):
            await xp.xray_probe_check(
                cfg,
                xray_path="/x",
                per_config_timeout=0.01,
                pin_address=False,
            )
    finally:
        xp._xray_probe_check_body = orig_xp  # type: ignore[assignment]
    # Sing-box wrapper with a slow body.
    orig = sb._singbox_probe_check_body
    sb._singbox_probe_check_body = _slow  # type: ignore[assignment]
    try:
        with pytest.raises(sb._NoVerdictError):
            await sb.singbox_probe_check(
                cfg,
                singbox_path="/x",
                per_config_timeout=0.01,
            )
    finally:
        sb._singbox_probe_check_body = orig  # type: ignore[assignment]


def test_safe_int_and_settings() -> None:
    assert _safe_int("abc") == 0
    assert _safe_int(None) == 0
    assert _safe_int("12") == 12
    assert Settings.as_bool("flase", True) is False
    assert Settings.as_float("nan", 1.5) == 1.5
    assert Settings.as_float("inf", 1.5) == 1.5


def test_canonical_paths_equal() -> None:
    assert _canonical_output_path("output/x.txt") == _canonical_output_path(
        "./output/x.txt"
    )
