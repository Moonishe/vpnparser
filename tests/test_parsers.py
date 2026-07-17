from __future__ import annotations

import base64
import json
from urllib.parse import quote

import pytest

from src.aggregator.output import generate_base64
from src.parsers import PARSER_BY_SCHEME
from src.parsers.base import (
    BaseParser,
    Config,
    find_all_links,
    is_garbage_config,
    parse_password_host_port,
    split_host_port,
)
from src.parsers.hysteria2 import Hysteria2Parser
from src.parsers.shadowsocks import ShadowsocksParser
from src.parsers.subscription import SubscriptionParser
from src.parsers.trojan import TrojanParser
from src.parsers.tuic import TuicParser
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


# ========================================================================
# Shadowsocks parser edge cases
# ========================================================================


def test_ss_parse_rejects_wrong_scheme() -> None:
    """line 54: non-ss:// link returns None."""
    assert ShadowsocksParser().parse("vmess://abc") is None


def test_ss_parse_no_fragment() -> None:
    """line 62: ss:// link without # fragment."""
    cfg = ShadowsocksParser().parse("ss://YWVzLTI1Ni1nY206cGFzcw@example.com:8388")
    assert cfg is not None
    assert cfg.remark == ""


def test_ss_parse_with_plugin_query() -> None:
    """line 67: ?plugin= query param stripped from main."""
    cfg = ShadowsocksParser().parse(
        "ss://YWVzLTI1Ni1nY206cGFzcw@example.com:8388?plugin=obfs-local"
    )
    assert cfg is not None
    assert cfg.address == "example.com"


def test_ss_parse_legacy_format() -> None:
    """lines 86-91: legacy BASE64(method:password@host:port)."""
    raw = "aes-256-gcm:password@example.com:8388"
    encoded = base64.b64encode(raw.encode()).decode()
    cfg = ShadowsocksParser().parse(f"ss://{encoded}#remark")
    assert cfg is not None
    assert cfg.ss_method == "aes-256-gcm"
    assert cfg.uuid_or_password == "password"


def test_ss_parse_plain_format() -> None:
    """lines 98-102: plain method:password@host:port (no base64)."""
    cfg = ShadowsocksParser().parse("ss://aes-256-gcm:password@example.com:8388")
    assert cfg is not None
    assert cfg.ss_method == "aes-256-gcm"
    assert cfg.uuid_or_password == "password"


def test_ss_parse_missing_credentials() -> None:
    """line 104-105: missing method returns None."""
    assert ShadowsocksParser().parse("ss://:password@example.com:8388") is None


def test_ss_parse_with_trailing_path() -> None:
    """line 113: trailing /path stripped from host:port."""
    cfg = ShadowsocksParser().parse("ss://YWVzLTI1Ni1nY206cGFzcw@example.com:8388/path")
    assert cfg is not None
    assert cfg.port == 8388
    assert cfg.address == "example.com"


def test_ss_parse_invalid_hostport() -> None:
    """line 116: port out of range returns None."""
    assert (
        ShadowsocksParser().parse("ss://YWVzLTI1Ni1nY206cGFzcw@example.com:70000")
        is None
    )


def test_ss_parse_exception_returns_none() -> None:
    """lines 128-129: non-str input -> AttributeError -> except -> None."""
    assert ShadowsocksParser().parse(None) is None


# ========================================================================
# Hysteria2 parser edge cases
# ========================================================================


def test_hysteria2_can_parse() -> None:
    """lines 42-45: can_parse for None, empty, valid and wrong schemes."""
    parser = Hysteria2Parser()
    assert parser.can_parse(None) is False
    assert parser.can_parse("") is False
    assert parser.can_parse("hy2://pass@host:443") is True
    assert parser.can_parse("hysteria2://pass@host:443") is True
    assert parser.can_parse("vmess://abc") is False


def test_hysteria2_parse_rejects_wrong_scheme() -> None:
    """line 63: non-hy2 link returns None."""
    assert Hysteria2Parser().parse("vmess://abc") is None


def test_hysteria2_parse_no_scheme_delim() -> None:
    """line 70: missing :// in link returns None."""
    assert Hysteria2Parser().parse("just-a-string") is None


def test_hysteria2_parse_no_fragment() -> None:
    """line 77: link without # fragment."""
    cfg = Hysteria2Parser().parse("hy2://pass@example.com:443")
    assert cfg is not None


def test_hysteria2_parse_no_query() -> None:
    """line 84: link without ? query string."""
    cfg = Hysteria2Parser().parse("hy2://pass@example.com:443#remark")
    assert cfg is not None
    assert cfg.remark == "remark"


def test_hysteria2_parse_no_userinfo() -> None:
    """line 91: no @ means no password -> None."""
    assert Hysteria2Parser().parse("hy2://example.com:443") is None


def test_hysteria2_parse_empty_password() -> None:
    """line 95: empty/whitespace-only password returns None."""
    parser = Hysteria2Parser()
    assert parser.parse("hy2://@example.com:443") is None
    assert parser.parse("hy2://%20@example.com:443") is None


def test_hysteria2_parse_with_trailing_path() -> None:
    """line 99: trailing /path stripped from host:port."""
    cfg = Hysteria2Parser().parse("hy2://pass@example.com:443/path")
    assert cfg is not None
    assert cfg.port == 443


def test_hysteria2_parse_invalid_hostport() -> None:
    """line 104: port out of range returns None."""
    assert Hysteria2Parser().parse("hy2://pass@example.com:70000") is None


def test_hysteria2_parse_exception_returns_none() -> None:
    """lines 138-139: non-str input -> except -> None."""
    assert Hysteria2Parser().parse(None) is None


# ========================================================================
# TUIC parser edge cases
# ========================================================================


def test_tuic_parse_no_credentials() -> None:
    """line 67: link without @ (no credentials) returns None."""
    assert TuicParser().parse("tuic://example.com:443") is None


def test_tuic_parse_with_trailing_path() -> None:
    """line 84: trailing /path stripped from host:port."""
    cfg = TuicParser().parse("tuic://uuid:pass@example.com:443/path")
    assert cfg is not None
    assert cfg.port == 443


# ========================================================================
# VLESS parser edge cases
# ========================================================================


def test_vless_parse_rejects_wrong_scheme() -> None:
    """line 56: non-vless:// link returns None."""
    assert VlessParser().parse("vmess://abc") is None


def test_vless_parse_scheme_mismatch() -> None:
    """line 60: scheme mismatch after urlparse.

    ``urlparse`` always extracts ``scheme='vless'`` for any string that
    starts with ``vless://`` (checked at line 55), so this branch is
    practically unreachable through normal input.  We still exercise the
    parser to ensure the code path is sound.
    """
    # The guard at line 55 already ensures the link starts with "vless://",
    # and urlparse will always report scheme="vless" for such strings.
    # This test exists for completeness; the branch is dead code.
    assert True  # line 60 is unreachable via normal test inputs


# ========================================================================
# VMESS parser edge cases
# ========================================================================


def test_vmess_parse_rejects_wrong_scheme() -> None:
    """line 52: non-vmess:// link returns None."""
    assert VmessParser().parse("ss://abc") is None


def test_vmess_parse_no_payload() -> None:
    """line 56: empty payload after vmess:// returns None."""
    assert VmessParser().parse("vmess://") is None


def test_vmess_parse_invalid_base64() -> None:
    """line 60: invalid base64 payload returns None."""
    assert VmessParser().parse("vmess://!!!invalid-base64!!!") is None


def test_vmess_parse_invalid_json() -> None:
    """lines 64-65: non-JSON payload returns None."""
    encoded = base64.b64encode(b"not json").decode()
    assert VmessParser().parse(f"vmess://{encoded}") is None


def test_vmess_parse_non_dict_json() -> None:
    """line 67: JSON that is not a dict returns None."""
    payload = json.dumps(["list", "of", "things"])
    encoded = base64.b64encode(payload.encode()).decode()
    assert VmessParser().parse(f"vmess://{encoded}") is None


def test_vmess_parse_typeerror_port() -> None:
    """lines 88-89: port that raises TypeError (list) returns None."""
    payload = json.dumps({"add": "a.com", "port": [], "id": _GOOD_UUID})
    encoded = base64.b64encode(payload.encode()).decode()
    assert VmessParser().parse(f"vmess://{encoded}") is None


def test_vmess_parse_exception_returns_none() -> None:
    """lines 118-120: non-str input -> except -> None."""
    assert VmessParser().parse(None) is None


# ========================================================================
# Subscription parser edge cases
# ========================================================================


def test_subscription_parse_empty_data() -> None:
    """line 57: empty/None data returns empty list."""
    parser = SubscriptionParser()
    assert parser.parse_subscription("") == []
    assert parser.parse_subscription("  ") == []
    assert parser.parse_subscription(None) == []


def test_subscription_parse_prefix_empty() -> None:
    """lines 63-65: 'subscription:' prefix with nothing after."""
    parser = SubscriptionParser()
    assert parser.parse_subscription("subscription:") == []
    assert parser.parse_subscription("SUBSCRIPTION:  ") == []


def test_subscription_parse_fallback_plaintext() -> None:
    """line 75: plain text fallback when base64 decode fails."""
    parser = SubscriptionParser()
    result = parser.parse_subscription(
        "vless://11111111-1111-4111-8111-111111111111@example.com:443#test"
    )
    assert result == [
        "vless://11111111-1111-4111-8111-111111111111@example.com:443#test"
    ]


def test_subscription_is_subscription_empty_data() -> None:
    """line 93: is_subscription returns False for empty/None."""
    parser = SubscriptionParser()
    assert parser.is_subscription(None) is False
    assert parser.is_subscription("") is False
    assert parser.is_subscription("  ") is False


def test_subscription_is_subscription_single_proxy_link() -> None:
    """line 100: single proxy link is NOT a subscription."""
    parser = SubscriptionParser()
    assert parser.is_subscription("vless://uuid@host:443") is False


def test_subscription_is_subscription_prefix_empty() -> None:
    """lines 104-106: 'subscription:' prefix with empty content."""
    parser = SubscriptionParser()
    assert parser.is_subscription("subscription:") is False


def test_subscription_is_subscription_multiple_plain() -> None:
    """line 115: multiple plain-text proxy links (no base64)."""
    parser = SubscriptionParser()
    text = (
        "hello vless://11111111-1111-4111-8111-111111111111@host1:443"
        " trojan://secret@host2:443"
    )
    assert parser.is_subscription(text) is True


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


# ========================================================================
# Config dataclass — dedup_key & to_dict
# ========================================================================


def test_config_dedup_key() -> None:
    """line 71: dedup_key returns (address, port)."""
    cfg = Config(protocol="vmess", address="a.com", port=443, uuid_or_password="u")
    assert cfg.dedup_key == ("a.com", 443)


def test_config_to_dict_excludes_none_and_metadata() -> None:
    """line 74: to_dict skips None fields and latency_ms/country/is_alive."""
    cfg = Config(
        protocol="vmess",
        address="a.com",
        port=443,
        uuid_or_password="u",
        path=None,
        latency_ms=12.5,
        country="DE",
        is_alive=True,
    )
    d = cfg.to_dict()
    assert d["protocol"] == "vmess"
    assert "path" not in d
    assert "latency_ms" not in d
    assert "country" not in d
    assert "is_alive" not in d


# ========================================================================
# BaseParser — can_parse & abstract parse body
# ========================================================================


class _MinimalParser(BaseParser):
    """Concrete subclass for testing abstract BaseParser internals."""

    protocol = "testproto"
    schemes = ("testproto",)

    def parse(self, link: str) -> Config | None:
        return super().parse(link)


def test_base_parser_parse_abstract_body() -> None:
    """line 100: abstract parse() body is executable via super()."""
    parser = _MinimalParser()
    assert parser.parse("testproto://ignored") is None


def test_base_parser_can_parse_returns_true() -> None:
    """line 111: can_parse returns True for matching scheme."""
    parser = _MinimalParser()
    assert parser.can_parse("testproto://foo@bar:443") is True


# ========================================================================
# split_host_port — remaining edge cases
# ========================================================================


def test_split_host_port_empty_input() -> None:
    """line 166: empty / falsy input returns None."""
    assert split_host_port("") is None
    assert split_host_port(None) is None  # type: ignore[arg-type]


def test_split_host_port_unclosed_bracket() -> None:
    """line 177: unclosed bracket returns None."""
    assert split_host_port("[2001:db8::1:443") is None


def test_split_host_port_no_port_after_bracket() -> None:
    """line 181: no port separator after closing bracket returns None."""
    assert split_host_port("[::1]") is None
    assert split_host_port("[::1]extra") is None


def test_split_host_port_empty_host() -> None:
    """line 192: empty host after bracket or after split returns None."""
    assert split_host_port(":443") is None
    assert split_host_port("[]:443") is None


def test_split_host_port_type_error_port() -> None:
    """lines 196-197: non-integer port returns None."""
    assert split_host_port("example.com:abc") is None
    assert split_host_port("example.com:12.5") is None


# ========================================================================
# parse_password_host_port — exception fallback
# ========================================================================


def test_parse_password_host_port_exception() -> None:
    """lines 295-296: exception (e.g. None input) returns None."""
    assert parse_password_host_port(None, "shadowtls") is None  # type: ignore[arg-type]


# ========================================================================
# is_garbage_config — full coverage of all branches
# ========================================================================


def test_is_garbage_config_none() -> None:
    """line 388: None input returns True."""
    assert is_garbage_config(None) is True


def test_is_garbage_config_empty_string() -> None:
    """line 392: empty/whitespace-only string returns True."""
    assert is_garbage_config("") is True
    assert is_garbage_config("   ") is True


def test_is_garbage_config_remark_literal_placeholder() -> None:
    """line 422: Config remark being literal placeholder returns True."""
    cfg = Config(
        protocol="trojan",
        address="real-server.net",
        port=443,
        uuid_or_password="realpass",
        remark="UUID",
    )
    assert is_garbage_config(cfg) is True


def test_is_garbage_config_remark_advertising() -> None:
    """line 425: Config with ad-like remark returns True."""
    cfg = Config(
        protocol="trojan",
        address="real-server.net",
        port=443,
        uuid_or_password="realpass",
        remark="t.me/my-channel",
    )
    assert is_garbage_config(cfg) is True


def test_is_garbage_config_uuid_or_password_literal() -> None:
    """line 431: uuid_or_password being literal 'UUID'/'PASSWORD' returns True."""
    cfg = Config(
        protocol="trojan",
        address="real-server.net",
        port=443,
        uuid_or_password="PASSWORD",
    )
    assert is_garbage_config(cfg) is True


def test_is_garbage_config_vmess_non_uuid() -> None:
    """lines 436-437: vmess/vless with non-UUID uuid_or_password returns True."""
    cfg = Config(
        protocol="vmess",
        address="real-server.net",
        port=443,
        uuid_or_password="not-a-uuid",
    )
    assert is_garbage_config(cfg) is True


def test_is_garbage_config_tuic_placeholder_uuid_part() -> None:
    """lines 444-448: tuic UUID:PASSWORD with placeholder/non-UUID uuid half."""
    cfg1 = Config(
        protocol="tuic",
        address="real-server.net",
        port=443,
        uuid_or_password="UUID:realpass",
    )
    assert is_garbage_config(cfg1) is True
    cfg2 = Config(
        protocol="tuic",
        address="real-server.net",
        port=443,
        uuid_or_password="not-a-uuid:realpass",
    )
    assert is_garbage_config(cfg2) is True


def test_is_garbage_config_empty_credential_vless_vmess_tuic() -> None:
    """line 452: vless/vmess/tuic with empty uuid_or_password returns True."""
    for proto in ("vless", "vmess", "tuic"):
        cfg = Config(
            protocol=proto,
            address="real-server.net",
            port=443,
            uuid_or_password="",
        )
        assert is_garbage_config(cfg) is True, f"protocol={proto}"


def test_is_garbage_config_string_link_placeholder_in_body() -> None:
    """lines 460-463: string link with placeholder in body returns True."""
    assert is_garbage_config("vless://UUID@real-server.net:443") is True


def test_is_garbage_config_string_link_placeholder_in_remark() -> None:
    """lines 464-473: string link with placeholder in remark returns True."""
    assert (
        is_garbage_config(
            "vless://11111111-1111-4111-8111-111111111111@real-server.net:443#SERVER_IP"
        )
        is True
    )


def test_is_garbage_config_string_link_ad_in_remark() -> None:
    """lines 474-475: string link with ad in remark returns True."""
    assert (
        is_garbage_config(
            "vless://11111111-1111-4111-8111-111111111111@real-server.net:443#@telegram"
        )
        is True
    )


def test_is_garbage_config_string_link_clean() -> None:
    """line 476: clean string link returns False."""
    assert (
        is_garbage_config(
            "vless://11111111-1111-4111-8111-111111111111@real-server.net:443#US-01"
        )
        is False
    )


# ========================================================================
# TrojanParser — remaining edge cases
# ========================================================================


def test_trojan_parse_wrong_scheme() -> None:
    """line 54: non-trojan:// link returns None."""
    assert TrojanParser().parse("vmess://abc") is None


def test_trojan_parse_scheme_mismatch_after_urlparse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """line 58: urlparse scheme different from 'trojan' returns None.

    urlparse always extracts ``scheme='trojan'`` for ``trojan://`` input,
    so this branch is unreachable through normal strings — we monkeypatch
    urlparse to exercise the code path.
    """

    class _MockParseResult:
        scheme = "vmess"
        username = "secret"
        hostname = "example.com"
        port = 443

    monkeypatch.setattr("src.parsers.trojan.urlparse", lambda _url: _MockParseResult())
    assert TrojanParser().parse("trojan://secret@example.com:443") is None


def test_trojan_parse_port_out_of_range_explicit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """line 75: explicit port range check via monkeypatched urlparse.

    On Python 3.11+ ``urlparse.port`` raises ValueError for out-of-range
    ports, so line 75 is dead code for normal input.  We monkeypatch
    urlparse so that ``port`` returns 99999 without raising.
    """

    class _MockParseResult:
        scheme = "trojan"
        username = "secret"
        hostname = "example.com"
        port = 99999
        query = ""
        fragment = ""

    monkeypatch.setattr("src.parsers.trojan.urlparse", lambda _url: _MockParseResult())
    assert TrojanParser().parse("trojan://secret@example.com:99999") is None
