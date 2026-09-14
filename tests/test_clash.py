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
        _vless(
            protocol="tuic",
            uuid_or_password="11111111-1111-4111-8111-111111111111:pass",
            sni="t.example",
        ),
        set(),
    )
    assert tuic is not None
    assert tuic["type"] == "tuic"
    assert tuic["uuid"] == "11111111-1111-4111-8111-111111111111"
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


def test_write_clash_subscription_write_error(tmp_path, monkeypatch) -> None:
    target = tmp_path / "clash.yaml"

    # write_text_atomic creates parent dirs itself, so a missing directory is
    # not an error; force the OSError branch directly. One real config pins
    # the branch: an empty list would return 0 even on a successful write.
    def _boom(*_args: object, **_kwargs: object) -> None:
        raise OSError("disk gone")

    monkeypatch.setattr("src.aggregator.clash.write_text_atomic", _boom)
    count = write_clash_subscription(
        [_vless(security="tls", sni="v.example")], str(target)
    )
    assert count == 0
    assert not target.exists()


# ---------------------------------------------------------------------------
# Transport branches: splithttp rename, h2 opts
# ---------------------------------------------------------------------------


def test_splithttp_transport_mapped_to_xhttp() -> None:
    """splithttp is Xray's name for the transport; Mihomo only knows xhttp."""
    cfg = _vless(security="tls", network="splithttp", path="/sp", host="sp.example")
    proxy = config_to_clash_proxy(cfg, set())
    assert proxy is not None
    assert proxy["network"] == "xhttp"
    assert proxy["xhttp-opts"] == {"path": "/sp", "host": "sp.example"}


def test_h2_transport_fields() -> None:
    """h2 opts take a path plus a host *list* (semicolon or comma separated)."""
    cfg = _vless(
        security="tls",
        network="h2",
        path="/h2",
        host="a.example; b.example,,c.example",
        sni="a.example",
    )
    proxy = config_to_clash_proxy(cfg, set())
    assert proxy is not None
    assert proxy["network"] == "h2"
    assert proxy["h2-opts"] == {
        "path": "/h2",
        "host": ["a.example", "b.example", "c.example"],
    }


def test_h2_transport_without_params_yields_empty_opts() -> None:
    proxy = config_to_clash_proxy(_vless(network="h2"), set())
    assert proxy is not None
    assert proxy["network"] == "h2"
    assert proxy["h2-opts"] == {}


# ---------------------------------------------------------------------------
# Inexpressible configs: missing credentials, unknown protocol
# ---------------------------------------------------------------------------


def test_config_without_credentials_or_endpoint_skipped() -> None:
    """A config with no address, port or credential cannot become a proxy."""
    assert config_to_clash_proxy(_vless(address=""), set()) is None
    assert config_to_clash_proxy(_vless(port=0), set()) is None
    assert config_to_clash_proxy(_vless(uuid_or_password=""), set()) is None


def test_unknown_protocol_is_inexpressible() -> None:
    """Protocols Mihomo has no type for are skipped, not corrupted."""
    assert config_to_clash_proxy(_vless(protocol="wireguard"), set()) is None


# ---------------------------------------------------------------------------
# Per-protocol extras: trojan fingerprint, hysteria2 obfs
# ---------------------------------------------------------------------------


def test_trojan_carries_client_fingerprint() -> None:
    proxy = config_to_clash_proxy(_vless(protocol="trojan", fp="chrome"), set())
    assert proxy is not None
    assert proxy["client-fingerprint"] == "chrome"


def test_hysteria2_obfs_passthrough() -> None:
    """Without the salamander fields an obfs-required server is dead on arrival."""
    proxy = config_to_clash_proxy(
        _vless(protocol="hysteria2", obfs="salamander", obfs_password="hunter2"),
        set(),
    )
    assert proxy is not None
    assert proxy["obfs"] == "salamander"
    assert proxy["obfs-password"] == "hunter2"

    plain = config_to_clash_proxy(_vless(protocol="hysteria2"), set())
    assert plain is not None
    assert "obfs" not in plain
    assert "obfs-password" not in plain


# ---------------------------------------------------------------------------
# configs_to_clash: dead configs are skipped like in the base64 twin
# ---------------------------------------------------------------------------


def test_configs_to_clash_skips_dead_configs() -> None:
    """The YAML twin must never publish a config the base64 twin refuses."""
    alive = _vless()
    dead = _vless(address="dead.example", raw_link="vless://dead", is_alive=False)
    unchecked = _vless(address="maybe.example", raw_link="vless://maybe")
    servers = [p["server"] for p in configs_to_clash([alive, dead, unchecked])]
    assert servers == ["v.example", "maybe.example"]


# ---------------------------------------------------------------------------
# write_clash_subscription: failure paths
# ---------------------------------------------------------------------------


def test_write_clash_subscription_serialize_error(monkeypatch) -> None:
    """A yaml.dump ValueError is a logged warning, not a crash."""

    def _boom(*args: object, **kwargs: object) -> str:
        raise ValueError("cannot represent")

    monkeypatch.setattr(yaml, "safe_dump", _boom)
    assert write_clash_subscription([_vless()], "output/clash.yaml") == 0


def test_write_clash_subscription_atomic_write_failure(monkeypatch, tmp_path) -> None:
    """An OSError from the atomic writer is a logged warning, not a crash."""

    def _boom(_path: object, _payload: str, **_kw: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr("src.aggregator.clash.write_text_atomic", _boom)
    assert write_clash_subscription([_vless()], str(tmp_path / "clash.yaml")) == 0


class TestTuicAlpn:
    """Tuic entries carry ALPN like every other protocol's writer."""

    def test_tuic_alpn_emitted(self) -> None:
        from src.parsers.tuic import TuicParser

        cfg = TuicParser().parse(
            "tuic://11111111-1111-4111-8111-111111111111:pw@a.com:443?sni=s&alpn=h3#T"
        )
        assert cfg is not None and cfg.alpn == "h3"
        proxy = config_to_clash_proxy(cfg, set())
        assert proxy["alpn"] == ["h3"]

    def test_tuic_without_alpn_omits_key(self) -> None:
        from src.parsers.tuic import TuicParser

        cfg = TuicParser().parse(
            "tuic://11111111-1111-4111-8111-111111111111:pw@a.com:443?sni=s#T"
        )
        proxy = config_to_clash_proxy(cfg, set())
        assert "alpn" not in proxy


class TestNetworkWhitespace:
    """Untrimmed network= values must not demote a ws entry to plain TCP."""

    def test_vless_type_ws_with_space(self) -> None:
        from src.parsers.vless import VlessParser

        cfg = VlessParser().parse(
            "vless://11111111-1111-4111-8111-111111111111@a.com:443"
            "?type=ws%20&path=/p&host=a.com#X"
        )
        assert cfg is not None
        assert cfg.network == "ws"
        proxy = config_to_clash_proxy(cfg, set())
        assert proxy.get("network") == "ws"
        assert "ws-opts" in proxy

    def test_vless_type_uppercase_ws(self) -> None:
        from src.parsers.vless import VlessParser

        cfg = VlessParser().parse(
            "vless://11111111-1111-4111-8111-111111111111@a.com:443?type=WS#X"
        )
        assert cfg is not None and cfg.network == "ws"

    def test_trojan_type_ws_with_space(self) -> None:
        from src.parsers.trojan import TrojanParser

        cfg = TrojanParser().parse("trojan://pw@a.com:443?type=ws%20&path=/p#X")
        assert cfg is not None
        assert cfg.network == "ws"
        proxy = config_to_clash_proxy(cfg, set())
        assert proxy.get("network") == "ws"


class TestTuicAdvancedParams:
    """tuic congestion/udp-relay reach the Clash entry (stored since 0.2.0)."""

    def test_tuic_congestion_and_udp_relay(self) -> None:
        from src.parsers.tuic import TuicParser

        cfg = TuicParser().parse(
            "tuic://11111111-1111-4111-8111-111111111111:pw@a.com:443?sni=s"
            "&congestion_control=cubic&udp_relay_mode=native#T",
        )
        assert cfg is not None
        proxy = config_to_clash_proxy(cfg, set())
        assert proxy["congestion-controller"] == "cubic"
        assert proxy["udp-relay-mode"] == "native"

    def test_tuic_without_params_omits_keys(self) -> None:
        from src.parsers.tuic import TuicParser

        cfg = TuicParser().parse(
            "tuic://11111111-1111-4111-8111-111111111111:pw@a.com:443?sni=s#T"
        )
        proxy = config_to_clash_proxy(cfg, set())
        assert "congestion-controller" not in proxy
        assert "udp-relay-mode" not in proxy


def test_skipped_proxy_does_not_burn_a_name(tmp_path) -> None:
    """Name reservation happens after expressibility checks.

    An inexpressible config (reality without pbk) used to reserve its remark
    first, so the next same-remark proxy came out "name #2" instead of "name".
    """
    from src.aggregator.clash import configs_to_clash

    bad = _vless(security="reality", sni="v.example")
    bad.remark = "dup"
    good = _vless(security="tls", sni="v.example")
    good.remark = "dup"
    proxies = configs_to_clash([bad, good])
    assert [p["name"] for p in proxies] == ["dup"]


def test_all_expressible_proxies_carry_names() -> None:
    """Every emitted entry needs "name": hysteria2/tuic returns used to
    skip the reservation done for the other protocols."""
    from src.aggregator.clash import configs_to_clash

    hy2 = _vless(
        protocol="hysteria2",
        raw_link="hy2://x",
        remark="hy",
        uuid_or_password="secret",
    )
    tuic = _vless(
        protocol="tuic",
        remark="tu",
        uuid_or_password="11111111-1111-4111-8111-111111111111:pw",
    )
    proxies = configs_to_clash([hy2, tuic])
    assert len(proxies) == 2
    assert [p["name"] for p in proxies] == ["hy", "tu"]
    assert all("server" in p and "port" in p for p in proxies)


def test_clash_drops_v4_token_with_colon() -> None:
    """A v4 token containing ":" is opaque, not a v5 uuid:password pair:
    Mihomo needs a real uuid, so it is skipped here (base64 keeps it)."""
    from src.aggregator.clash import configs_to_clash

    cfg = _vless(
        protocol="tuic",
        remark="v4",
        uuid_or_password="tok:en",
    )
    assert configs_to_clash([cfg]) == []


# --- SNI field name and per-protocol transport support (Mihomo docs) ---
# TrojanOption names the SNI "sni" (no "servername"); vless/vmess use
# "servername". Mihomo ignores unknown keys, so a trojan entry used to lose
# its SNI. And `network` is per-protocol: an unsupported value silently
# degrades to TCP, so it must be skipped rather than published dead.


def _clash_qa_config(
    protocol: str,
    *,
    network: str = "tcp",
    security: str = "tls",
    sni: str | None = "sni.example.invalid",
    path: str | None = None,
    host: str | None = None,
):
    """Build a Config for the Clash SNI / transport cases."""
    from src.parsers.base import Config

    return Config(
        protocol=protocol,
        address="203.0.113.10",
        port=443,
        uuid_or_password="qa-secret",
        network=network,
        security=security,
        path=path,
        host=host,
        sni=sni,
    )


def test_trojan_sni_is_written_as_sni_not_servername() -> None:
    from src.aggregator.clash import config_to_clash_proxy

    proxy = config_to_clash_proxy(_clash_qa_config("trojan"), set())
    assert proxy is not None
    assert proxy["sni"] == "sni.example.invalid"
    assert "servername" not in proxy


def test_vless_sni_is_written_as_servername() -> None:
    from src.aggregator.clash import config_to_clash_proxy

    proxy = config_to_clash_proxy(_clash_qa_config("vless"), set())
    assert proxy is not None
    assert proxy["servername"] == "sni.example.invalid"
    assert "sni" not in proxy


def test_vmess_sni_is_written_as_servername() -> None:
    from src.aggregator.clash import config_to_clash_proxy

    proxy = config_to_clash_proxy(_clash_qa_config("vmess"), set())
    assert proxy is not None
    assert proxy["servername"] == "sni.example.invalid"
    assert "sni" not in proxy


def test_trojan_xhttp_network_is_skipped() -> None:
    from src.aggregator.clash import config_to_clash_proxy

    cfg = _clash_qa_config("trojan", network="xhttp")
    assert config_to_clash_proxy(cfg, set()) is None


def test_trojan_ws_network_is_kept() -> None:
    from src.aggregator.clash import config_to_clash_proxy

    cfg = _clash_qa_config(
        "trojan", network="ws", path="/qa", host="ws.example.invalid"
    )
    proxy = config_to_clash_proxy(cfg, set())
    assert proxy is not None
    assert proxy["network"] == "ws"
    assert "ws-opts" in proxy


def test_vmess_xhttp_network_is_skipped() -> None:
    from src.aggregator.clash import config_to_clash_proxy

    cfg = _clash_qa_config("vmess", network="xhttp")
    assert config_to_clash_proxy(cfg, set()) is None


def test_vless_xhttp_network_is_kept() -> None:
    from src.aggregator.clash import config_to_clash_proxy

    cfg = _clash_qa_config("vless", network="xhttp", path="/qa")
    proxy = config_to_clash_proxy(cfg, set())
    assert proxy is not None
    assert proxy["network"] == "xhttp"
    assert "xhttp-opts" in proxy


def test_converter_error_skips_config_not_batch(monkeypatch, caplog) -> None:
    """A raising converter skips its config instead of killing the batch.

    ``config_to_clash_proxy`` is total by contract (``None`` means
    inexpressible), but link fields arrive from untrusted subscriptions, so
    the ``ValueError``/``TypeError``/``AttributeError`` net around each
    conversion keeps one poisoned entry from dropping the whole YAML twin.
    """
    import logging

    import src.aggregator.clash as clash_module

    real_converter = clash_module.config_to_clash_proxy

    def _boom(cfg, used):
        if cfg.address == "boom.example":
            raise ValueError("poisoned link fields")
        return real_converter(cfg, used)

    monkeypatch.setattr(clash_module, "config_to_clash_proxy", _boom)
    caplog.set_level(logging.WARNING, logger="src.aggregator.clash")
    bad = _vless(address="boom.example", remark="bad")
    good = _vless(address="ok.example", remark="ok")
    proxies = clash_module.configs_to_clash([bad, good])
    assert [p["server"] for p in proxies] == ["ok.example"]
    assert "Skipping Clash-inexpressible config" in caplog.text
