from __future__ import annotations

import base64
import json
from urllib.parse import quote

from src.aggregator.output import generate_base64
from src.parsers import PARSER_BY_SCHEME
from src.parsers.base import Config, find_all_links, is_garbage_config, split_host_port
from src.parsers.subscription import SubscriptionParser
from src.parsers.trojan import TrojanParser
from src.parsers.vless import VlessParser
from src.parsers.vmess import VmessParser
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

    parsed = {
        scheme: PARSER_BY_SCHEME[scheme].parse(link) for scheme, link in links.items()
    }

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


def test_garbage_detection_filters_placeholders_without_false_positive_password_words() -> (
    None
):
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


def test_country_detection_uses_remark_and_host_without_common_false_positives() -> (
    None
):
    assert detect_country("Frankfurt DE-01") == "DE"
    assert detect_country("contact us") is None
    assert detect_country("", "nl-ams.example.com") == "NL"
    assert detect_country("", "id-jakarta.example.com") == "ID"


def _vmess(payload: dict) -> str:
    encoded = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
    return f"vmess://{encoded}"


_GOOD_UUID = "11111111-1111-4111-8111-111111111111"


def test_parser_rejects_malformed_inputs_found_by_debug() -> None:
    """Regression cases fixed by the parser-debug pass.

    Each input below was previously accepted and is now rejected (None):
    - vmess: bool/non-integral-float port, whitespace address, non-UUID id
    - vless: whitespace/percent-encoded UUID, non-UUID userinfo
    - trojan: whitespace-only password after percent-decoding
    Valid links (including IPv6 hosts, non-hyphenated UUIDs and percent-encoded
    passwords) must still parse successfully.
    """
    vm, vl, tr = VmessParser(), VlessParser(), TrojanParser()

    reject = [
        (
            "vmess bool port",
            vm,
            _vmess({"add": "a.com", "port": True, "id": _GOOD_UUID}),
        ),
        (
            "vmess non-integral float port",
            vm,
            _vmess({"add": "a.com", "port": 443.5, "id": _GOOD_UUID}),
        ),
        ("vmess port 0", vm, _vmess({"add": "a.com", "port": 0, "id": _GOOD_UUID})),
        (
            "vmess port 65536",
            vm,
            _vmess({"add": "a.com", "port": "65536", "id": _GOOD_UUID}),
        ),
        (
            "vmess whitespace address",
            vm,
            _vmess({"add": "   ", "port": "443", "id": _GOOD_UUID}),
        ),
        (
            "vmess non-uuid id",
            vm,
            _vmess({"add": "a.com", "port": "443", "id": "not-a-uuid"}),
        ),
        ("vmess missing port", vm, _vmess({"add": "a.com", "id": _GOOD_UUID})),
        ("vless empty uuid", vl, "vless://@example.com:443"),
        ("vless whitespace uuid", vl, "vless://%20@example.com:443"),
        ("vless non-uuid", vl, "vless://garbage@example.com:443"),
        ("vless port 0", vl, f"vless://{_GOOD_UUID}@example.com:0"),
        ("vless port out of range", vl, f"vless://{_GOOD_UUID}@example.com:70000"),
        ("trojan empty password", tr, "trojan://@example.com:443"),
        ("trojan whitespace password", tr, "trojan://%20@example.com:443"),
        ("trojan port out of range", tr, "trojan://secret@example.com:99999"),
    ]
    for name, parser, link in reject:
        assert parser.parse(link) is None, f"{name} should be rejected"

    # Valid inputs must still parse.
    assert (
        vm.parse(_vmess({"add": "a.com", "port": "443", "id": _GOOD_UUID})) is not None
    )
    vm_float = vm.parse(_vmess({"add": "a.com", "port": 443.0, "id": _GOOD_UUID}))
    assert vm_float is not None and vm_float.port == 443
    non_hyphen = "11111111" + "1111" + "4111" + "8111" + "111111111111"
    assert (
        vm.parse(_vmess({"add": "a.com", "port": "443", "id": non_hyphen})) is not None
    )
    vl_ipv6 = vl.parse(f"vless://{_GOOD_UUID}@[2001:db8::1]:443")
    assert vl_ipv6 is not None and vl_ipv6.address == "2001:db8::1"
    tr_enc = tr.parse("trojan://p%40ss%21word@example.com:443")
    assert tr_enc is not None and tr_enc.uuid_or_password == "p@ss!word"


def test_tuic_shadowtls_anytls_debug_pass() -> None:
    """Regression cases for the tuic/shadowtls/anytls parser-debug pass.

    Covers:
    - Whitespace-only credentials rejected (consistent with trojan fix)
    - Leading/trailing whitespace stripped after percent-decoding
    - TUIC v4 (TOKEN, no colon) and v5 (UUID:PASSWORD, with colon) both parse
    - IPv6 bracketed hosts and path stripping work
    - Port range validation (0 / 99999 rejected)
    - None / empty / wrong-scheme inputs rejected
    """
    from src.parsers.anytls import AnyTlsParser
    from src.parsers.shadowtls import ShadowTlsParser
    from src.parsers.tuic import TuicParser

    tuic, stls, atls = TuicParser(), ShadowTlsParser(), AnyTlsParser()

    # --- rejected ---
    reject = [
        ("tuic empty cred", tuic, "tuic://@real-server.com:443"),
        ("tuic ws-only cred", tuic, "tuic://%20%20@real-server.com:443"),
        ("tuic v5 empty pass", tuic, "tuic://uuid:@real-server.com:443"),
        ("tuic v5 empty uuid", tuic, "tuic://:pass@real-server.com:443"),
        ("tuic port 0", tuic, "tuic://uuid:pass@real-server.com:0"),
        ("tuic port 99999", tuic, "tuic://uuid:pass@real-server.com:99999"),
        ("tuic bare ipv6", tuic, "tuic://uuid:pass@2001:db8::1:443"),
        ("shadowtls ws-only", stls, "shadowtls://%20@real-server.com:443"),
        ("shadowtls no-pass", stls, "shadowtls://real-server.com:443"),
        ("shadowtls port 0", stls, "shadowtls://pass@real-server.com:0"),
        ("anytls ws-only", atls, "anytls://%20@real-server.com:443"),
        ("anytls no-pass", atls, "anytls://real-server.com:443"),
        ("tuic None", tuic, None),
        ("shadowtls empty", stls, ""),
        ("tuic wrong-scheme", tuic, "hysteria2://uuid:pass@real-server.com:443"),
    ]
    for name, parser, link in reject:
        assert parser.parse(link) is None, f"{name} should be rejected"

    # --- whitespace stripped after percent-decoding ---
    tuic_ws = tuic.parse("tuic://%20uuid:pass@real-server.com:443")
    assert tuic_ws is not None and tuic_ws.uuid_or_password == "uuid:pass"
    stls_ws = stls.parse("shadowtls://%20pass@real-server.com:443")
    assert stls_ws is not None and stls_ws.uuid_or_password == "pass"
    atls_ws = atls.parse("anytls://%20pass@real-server.com:443")
    assert atls_ws is not None and atls_ws.uuid_or_password == "pass"
    # trailing whitespace also stripped
    tuic_trail = tuic.parse("tuic://uuid:pass%20@real-server.com:443")
    assert tuic_trail is not None and tuic_trail.uuid_or_password == "uuid:pass"

    # --- valid v4 (TOKEN) and v5 (UUID:PASSWORD) ---
    v4 = tuic.parse("tuic://mytoken@real-server.com:443?sni=x#NL-01")
    assert v4 is not None and v4.uuid_or_password == "mytoken"
    assert v4.network == "quic" and v4.security == "tls"
    v5 = tuic.parse(f"tuic://{_GOOD_UUID}:pass@real-server.com:443?sni=x")
    assert v5 is not None and v5.uuid_or_password == f"{_GOOD_UUID}:pass"

    # --- IPv6 and path stripping ---
    ipv6 = tuic.parse("tuic://uuid:pass@[2001:db8::1]:443?sni=x")
    assert ipv6 is not None and ipv6.address == "2001:db8::1" and ipv6.port == 443
    path = stls.parse("shadowtls://pass@real-server.com:443/extra/path?sni=x")
    assert path is not None and path.address == "real-server.com"

    # --- encoded special chars preserved (internal) ---
    enc = stls.parse("shadowtls://p%40ss@real-server.com:443")
    assert enc is not None and enc.uuid_or_password == "p@ss"

    # --- can_parse None guard ---
    assert tuic.can_parse(None) is False
    assert stls.can_parse(None) is False
    assert atls.can_parse(None) is False


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
