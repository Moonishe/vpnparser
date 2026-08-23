"""Tests for the Clash/Mihomo YAML subscription output."""

from __future__ import annotations

import yaml

from src.aggregator.clash import (
    config_to_clash_proxy,
    configs_to_clash,
    write_clash_subscription,
)
from src.parsers.base import Config


def _vless(**overrides) -> Config:
    fields: dict = dict(
        protocol="vless",
        address="v.example",
        port=443,
        uuid_or_password="11111111-1111-4111-8111-111111111111",
        raw_link="vless://x",
        remark="DE-01",
    )
    fields.update(overrides)
    return Config(**fields)


def test_vless_tls_ws_proxy_shape() -> None:
    cfg = _vless(
        security="tls",
        network="ws",
        path="/ws",
        host="v.example",
        sni="v.example",
        alpn="h2,http/1.1",
    )
    proxy = config_to_clash_proxy(cfg, set())
    assert proxy is not None
    assert proxy["type"] == "vless"
    assert proxy["tls"] is True
    assert proxy["servername"] == "v.example"
    assert proxy["alpn"] == ["h2", "http/1.1"]
    assert proxy["skip-cert-verify"] is True
    assert proxy["network"] == "ws"
    assert proxy["ws-opts"]["path"] == "/ws"
    assert proxy["ws-opts"]["headers"]["Host"] == "v.example"


def test_vless_reality_fields() -> None:
    cfg = _vless(
        security="reality",
        network="grpc",
        path="/grpc-svc",
        pbk="pub-key",
        sid="abcd",
        fp="firefox",
        flow="xtls-rprx-vision",
    )
    proxy = config_to_clash_proxy(cfg, set())
    assert proxy is not None
    assert proxy["reality-opts"] == {"public-key": "pub-key", "short-id": "abcd"}
    assert proxy["client-fingerprint"] == "firefox"
    assert proxy["flow"] == "xtls-rprx-vision"
    assert proxy["grpc-opts"]["grpc-service-name"] == "grpc-svc"


def test_vless_reality_without_pbk_is_inexpressible() -> None:
    """Reality without a public key cannot be expressed in Mihomo.

    Publishing it as plain TLS would hand out an entry that can never
    handshake, while the Xray probe fail-closes the same case.
    """
    cfg = _vless(security="reality", fp="firefox", sid="abcd")
    assert config_to_clash_proxy(cfg, set()) is None


def test_vmess_carries_client_fingerprint() -> None:
    """The probe-validated uTLS fingerprint must survive into Clash vmess."""
    cfg = _vless(
        protocol="vmess",
        uuid_or_password="11111111-1111-4111-8111-111111111111",
        fp="chrome",
    )
    proxy = config_to_clash_proxy(cfg, set())
    assert proxy is not None
    assert proxy["client-fingerprint"] == "chrome"


def test_vmess_alter_id_passthrough() -> None:
    cfg = _vless(protocol="vmess", alter_id=64)
    proxy = config_to_clash_proxy(cfg, set())
    assert proxy is not None
    assert proxy["type"] == "vmess"
    assert proxy["alterId"] == 64
    assert proxy["cipher"] == "auto"


def test_trojan_and_ss_shapes() -> None:
    trojan = config_to_clash_proxy(
        _vless(protocol="trojan", security="tls", sni="t.example"), set()
    )
    assert trojan is not None
    assert trojan["type"] == "trojan"
    assert trojan["password"] == "11111111-1111-4111-8111-111111111111"
    assert trojan["tls"] is True

    ss = config_to_clash_proxy(_vless(protocol="ss", ss_method="aes-256-gcm"), set())
    assert ss is not None
    assert ss["type"] == "ss"
    assert ss["cipher"] == "aes-256-gcm"

    assert config_to_clash_proxy(_vless(protocol="ss", ss_method=None), set()) is None


def test_hysteria2_and_tuic_shapes() -> None:
    hy2 = config_to_clash_proxy(_vless(protocol="hysteria2", sni="h.example"), set())
    assert hy2 is not None
    assert hy2["type"] == "hysteria2"
    assert hy2["skip-cert-verify"] is True

    tuic = config_to_clash_proxy(
        _vless(protocol="tuic", uuid_or_password="uuid:pass", sni="t.example"), set()
    )
    assert tuic is not None
    assert tuic["type"] == "tuic"
    assert tuic["uuid"] == "uuid"
    assert tuic["password"] == "pass"
    assert tuic["sni"] == "t.example"

    # v4 token-only tuic links are not expressible.
    assert (
        config_to_clash_proxy(_vless(protocol="tuic", uuid_or_password="token"), set())
        is None
    )


def test_duplicate_names_get_suffixes() -> None:
    used: set[str] = set()
    first = config_to_clash_proxy(_vless(remark="same"), used)
    second = config_to_clash_proxy(_vless(address="w.example", remark="same"), used)
    assert first is not None and second is not None
    assert first["name"] == "same"
    assert second["name"] == "same #2"


def test_httpupgrade_translated_to_ws_upgrade() -> None:
    cfg = _vless(
        security="tls",
        network="httpupgrade",
        path="/up",
        host="up.example",
        sni="up.example",
    )
    proxy = config_to_clash_proxy(cfg, set())
    assert proxy is not None
    assert proxy["network"] == "ws"
    assert proxy["ws-opts"]["v2ray-http-upgrade"] is True
    assert proxy["ws-opts"]["path"] == "/up"
    assert proxy["ws-opts"]["headers"]["Host"] == "up.example"


def test_xhttp_transport_fields() -> None:
    cfg = _vless(security="tls", network="xhttp", path="/x", host="x.example")
    proxy = config_to_clash_proxy(cfg, set())
    assert proxy is not None
    assert proxy["network"] == "xhttp"
    assert proxy["xhttp-opts"] == {"path": "/x", "host": "x.example"}


def test_configs_without_raw_link_skipped() -> None:
    cfg = _vless(raw_link="")
    assert configs_to_clash([cfg]) == []


def test_write_clash_subscription_writes_yaml(tmp_path) -> None:
    configs = [
        _vless(security="tls", sni="v.example"),
        _vless(protocol="hysteria2", sni="h.example", raw_link="hy2://x"),
    ]
    out = tmp_path / "clash.yaml"
    count = write_clash_subscription(configs, str(out))
    assert count == 2
    data = yaml.safe_load(out.read_text(encoding="utf-8"))
    assert [p["type"] for p in data["proxies"]] == ["vless", "hysteria2"]


def test_write_clash_subscription_write_error(tmp_path) -> None:
    target = tmp_path / "no-such-dir" / "clash.yaml"
    # The parent does not exist and is not created -> OSError -> 0.
    count = write_clash_subscription([], str(target))
    assert count == 0
