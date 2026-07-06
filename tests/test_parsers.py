from __future__ import annotations

import base64
import json
from urllib.parse import quote

from src.aggregator.output import generate_base64
from src.parsers import PARSER_BY_SCHEME
from src.parsers.base import Config, find_all_links, is_garbage_config, split_host_port
from src.parsers.subscription import SubscriptionParser
from src.validators.country_filter import detect_country


def _vmess_link() -> str:
    payload = {
        "v": "2",
        "ps": "DE-01",
        "add": "de.example.com",
        "port": "443",
        "id": "11111111-1111-4111-8111-111111111111",
        "net": "ws",
        "tls": "tls",
        "path": "/ws",
        "host": "de.example.com",
        "sni": "de.example.com",
    }
    encoded = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
    return f"vmess://{encoded}"


def test_core_protocol_parsers_accept_valid_links() -> None:
    links = [
        _vmess_link(),
        "vless://11111111-1111-4111-8111-111111111111@example.com:443"
        "?type=ws&security=reality&sni=example.com&pbk=abc&sid=def#US-01",
        "trojan://secret@example.com:443?type=tcp&sni=example.com#GB-01",
        "ss://YWVzLTI1Ni1nY206cGFzcw@example.com:8388#FI-01",
    ]

    parsed = [PARSER_BY_SCHEME[link.split("://", 1)[0]].parse(link) for link in links]

    assert [cfg.protocol for cfg in parsed if cfg] == [
        "vmess",
        "vless",
        "trojan",
        "ss",
    ]
    assert all(cfg and cfg.raw_link for cfg in parsed)


def test_new_protocol_parsers_accept_valid_links() -> None:
    links = {
        "hy2": "hy2://pass@example.com:443?sni=example.com#DE-01",
        "tuic": "tuic://11111111-1111-4111-8111-111111111111:pass@example.com:443"
        "?sni=example.com#NL-01",
        "shadowtls": "shadowtls://pass@example.com:443?sni=example.com#JP-01",
        "anytls": "anytls://pass@example.com:443?sni=example.com#SG-01",
    }

    parsed = {scheme: PARSER_BY_SCHEME[scheme].parse(link) for scheme, link in links.items()}

    assert parsed["hy2"] and parsed["hy2"].protocol == "hysteria2"
    assert parsed["tuic"] and parsed["tuic"].network == "quic"
    assert parsed["shadowtls"] and parsed["shadowtls"].security == "tls"
    assert parsed["anytls"] and parsed["anytls"].security == "tls"


def test_find_all_links_includes_all_supported_schemes() -> None:
    text = " ".join(
        [
            "vmess://abc",
            "vless://u@example.com:443",
            "trojan://p@example.com:443",
            "ss://abc@example.com:443",
            "hysteria2://p@example.com:443",
            "hy2://p@example.com:443",
            "tuic://p@example.com:443",
            "shadowtls://p@example.com:443",
            "anytls://p@example.com:443",
        ]
    )

    assert len(find_all_links(text)) == 9


def test_subscription_parser_decodes_base64_blob() -> None:
    links = [
        "vless://11111111-1111-4111-8111-111111111111@example.com:443#DE-01",
        "trojan://secret@example.com:443#FR-01",
    ]
    blob = base64.b64encode("\n".join(links).encode("utf-8")).decode("ascii")

    parser = SubscriptionParser()

    assert parser.is_subscription(blob) is True
    assert parser.parse_subscription(blob) == links


def test_split_host_port_handles_ipv6_and_rejects_bare_ipv6() -> None:
    assert split_host_port("example.com:443") == ("example.com", 443)
    assert split_host_port("[2001:db8::1]:443") == ("2001:db8::1", 443)
    assert split_host_port("2001:db8::1") is None
    assert split_host_port("example.com:70000") is None


def test_garbage_detection_filters_placeholders_without_false_positive_password_words() -> None:
    bad = Config(
        protocol="vless",
        address="SERVER_IP_1",
        port=443,
        uuid_or_password="UUID",
    )
    good = Config(
        protocol="trojan",
        address="example.net",
        port=443,
        uuid_or_password="not-a-uuid-password",
        remark="free password vpn",
    )

    assert is_garbage_config(bad) is True
    assert is_garbage_config(good) is False


def test_country_detection_uses_remark_and_host_without_common_false_positives() -> None:
    assert detect_country("Frankfurt DE-01") == "DE"
    assert detect_country("contact us") is None
    assert detect_country("", "nl-ams.example.com") == "NL"
    assert detect_country("", "id-jakarta.example.com") == "ID"


def test_base64_output_contains_raw_links() -> None:
    remark = quote("DE-01")
    cfg = Config(
        protocol="vless",
        address="example.com",
        port=443,
        uuid_or_password="11111111-1111-4111-8111-111111111111",
        remark="DE-01",
        raw_link=f"vless://11111111-1111-4111-8111-111111111111@example.com:443#{remark}",
    )

    decoded = base64.b64decode(generate_base64([cfg])).decode("utf-8")

    assert decoded.startswith("vmess://")
    assert cfg.raw_link in decoded
