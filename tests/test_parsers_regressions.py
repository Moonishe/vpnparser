"""Regression tests for the parser-layer bug-fix pass.

Covers, in order of the findings they close:

1. ``find_all_links`` must keep bracketed IPv6 hosts intact (all schemes).
2. ``safe_b64decode`` must ignore interior whitespace when padding.
3. ``TrojanParser`` must keep a password containing colons.
4. ``VmessParser`` must accept ``vmess://BASE64#remark``.
5. ``is_garbage_config`` must agree between its string and Config branches.
6. ``ShadowsocksParser`` must decode base64 strictly so the plain format is
   detected deterministically.

Second pass (bugs found in / left by the first one):

7. ``VmessParser`` must coerce non-string JSON fields to ``str``.
8. ``is_garbage_config`` must still see placeholders inside the userinfo.
9. ``safe_b64decode`` must ignore a UTF-8 BOM.
10. ``Hysteria2Parser`` must accept port-hopping ports.
11. ``VmessParser`` must unbracket an IPv6 ``add``.
"""

from __future__ import annotations

import base64
import json

from src.parsers import PARSER_BY_SCHEME
from src.parsers.base import (
    Config,
    find_all_links,
    is_garbage_config,
    safe_b64decode,
)
from src.parsers.hysteria2 import Hysteria2Parser
from src.parsers.shadowsocks import ShadowsocksParser, _strict_b64decode
from src.parsers.subscription import SubscriptionParser
from src.parsers.trojan import TrojanParser
from src.parsers.vless import VlessParser
from src.parsers.vmess import VmessParser

_GOOD_UUID = "11111111-1111-4111-8111-111111111111"
_IPV6 = "2001:db8::1"

# (scheme, link) for every URI-shaped scheme, each with a bracketed IPv6 host.
_IPV6_LINKS: list[tuple[str, str]] = [
    ("vless", f"vless://{_GOOD_UUID}@[{_IPV6}]:443?security=tls#test"),
    ("trojan", f"trojan://secret@[{_IPV6}]:443?sni=real-server.net#test"),
    ("ss", f"ss://YWVzLTI1Ni1nY206cGFzcw@[{_IPV6}]:8388#test"),
    ("hysteria2", f"hysteria2://pass@[{_IPV6}]:443?sni=real-server.net#test"),
    ("hy2", f"hy2://pass@[{_IPV6}]:443#test"),
    ("tuic", f"tuic://{_GOOD_UUID}:pass@[{_IPV6}]:443?sni=real-server.net#test"),
    ("shadowtls", f"shadowtls://pass@[{_IPV6}]:443?sni=real-server.net#test"),
    ("anytls", f"anytls://pass@[{_IPV6}]:443#test"),
]


def test_find_all_links_keeps_bracketed_ipv6_host() -> None:
    """Every scheme's IPv6 link survives extraction whole and still parses."""
    for scheme, link in _IPV6_LINKS:
        found = find_all_links(link)
        assert found == [link], f"{scheme}: {found!r}"
        cfg = PARSER_BY_SCHEME[scheme].parse(found[0])
        assert cfg is not None, f"{scheme} did not parse"
        assert cfg.address == _IPV6, f"{scheme}: address={cfg.address!r}"
        assert cfg.port in (443, 8388), f"{scheme}: port={cfg.port!r}"


def test_find_all_links_ipv6_inside_prose_and_lists() -> None:
    """IPv6 links are extracted from surrounding prose without extra chars."""
    link = f"vless://{_GOOD_UUID}@[{_IPV6}]:443?security=tls#DE-1"
    assert find_all_links(f"Try {link}, it works.") == [link]
    assert find_all_links(f"[{link}]") == [link]
    assert find_all_links(f"see [config]({link})") == [link]
    assert find_all_links(f"<code>{link}</code>") == [link]
    assert find_all_links(f"{link}\n{link}") == [link, link]


def test_find_all_links_still_rejects_scheme_lookalikes() -> None:
    """Brackets in the host must not weaken the leading word-boundary guard."""
    assert find_all_links("boss://x") == []
    assert find_all_links("sss://x") == []
    assert find_all_links("less://x") == []
    assert find_all_links("vmess://") == []
    # A bracketed blob that is not an IPv6 literal must not be swallowed.
    assert find_all_links("ss://abc@[see below]") == ["ss://abc@"]


def test_safe_b64decode_ignores_interior_whitespace() -> None:
    """A MIME-wrapped payload decodes exactly like its single-line form."""
    links = "\n".join(
        [
            f"vless://{_GOOD_UUID}@real-server.net:443#DE-1",
            "trojan://secret@real-server.net:443#FR-1",
        ]
    )
    flat = base64.b64encode(links.encode("utf-8")).decode("ascii").rstrip("=")
    # The padding bug only shows up when the interior newlines shift
    # ``len(payload) % 4`` — MIME's 76-char wrapping of this payload does.
    assert len(flat) % 4 == 3
    wrapped = "\n".join(flat[i : i + 76] for i in range(0, len(flat), 76))
    assert wrapped.count("\n") == 1

    assert safe_b64decode(wrapped) == safe_b64decode(flat)
    assert safe_b64decode(wrapped) == links
    # CRLF wrapping (also common in HTTP subscription bodies) works too.
    assert safe_b64decode(wrapped.replace("\n", "\r\n")) == links


def test_trojan_password_with_colons_is_preserved() -> None:
    """urlparse splits userinfo on ":" — the parser must rejoin the halves."""
    cfg = TrojanParser().parse("trojan://pa:ss:word@real-server.net:443#x")
    assert cfg is not None
    assert cfg.uuid_or_password == "pa:ss:word"
    # A percent-encoded colon decodes to the same credential.
    enc = TrojanParser().parse("trojan://pa%3Ass%3Aword@real-server.net:443#x")
    assert enc is not None and enc.uuid_or_password == "pa:ss:word"
    # Degenerate userinfo made only of separators is still rejected.
    assert TrojanParser().parse("trojan://:@real-server.net:443") is None


def test_vmess_accepts_fragment_after_base64_payload() -> None:
    """``vmess://BASE64#remark`` parses and uses the fragment as remark."""
    payload = {"add": "real-server.net", "port": "443", "id": _GOOD_UUID}
    encoded = (
        base64.b64encode(json.dumps(payload).encode("utf-8"))
        .decode("ascii")
        .rstrip("=")
    )
    cfg = VmessParser().parse(f"vmess://{encoded}#DE%2D01")
    assert cfg is not None
    assert cfg.address == "real-server.net"
    assert cfg.remark == "DE-01"
    # The JSON ``ps`` field wins over the fragment when present.
    with_ps = dict(payload, ps="from-json")
    encoded_ps = (
        base64.b64encode(json.dumps(with_ps).encode("utf-8"))
        .decode("ascii")
        .rstrip("=")
    )
    cfg_ps = VmessParser().parse(f"vmess://{encoded_ps}#from-fragment")
    assert cfg_ps is not None and cfg_ps.remark == "from-json"
    # An empty payload with only a fragment is still rejected.
    assert VmessParser().parse("vmess://#remark") is None


def test_is_garbage_config_string_and_config_branches_agree() -> None:
    """Both branches must judge credentials identically."""
    link = "trojan://super-password-2024@real-server.net:443#DE-1"
    cfg = Config(
        protocol="trojan",
        address="real-server.net",
        port=443,
        uuid_or_password="super-password-2024",
        remark="DE-1",
    )
    assert is_garbage_config(link) is False
    assert is_garbage_config(cfg) is False

    placeholder = "vless://UUID@SERVER_IP:443"
    placeholder_cfg = Config(
        protocol="vless",
        address="SERVER_IP",
        port=443,
        uuid_or_password="UUID",
    )
    assert is_garbage_config(placeholder) is True
    assert is_garbage_config(placeholder_cfg) is True

    # A placeholder host is still caught when the credential is real.
    assert is_garbage_config(f"vless://{_GOOD_UUID}@SERVER_IP_1:443") is True
    # An "@" outside the authority is not a userinfo separator, so the host is
    # still scanned for placeholders.
    assert is_garbage_config("trojan://real-pass@real-server.net:443?x=a@b") is False
    assert is_garbage_config("trojan://real-pass@example.com:443?x=a@b") is True


def test_ss_plain_format_wins_over_lenient_base64() -> None:
    """A plain userinfo must never be misread as base64.

    Lenient decoding silently drops the ``:``/``-`` separators, so some plain
    userinfos decoded into garbage bytes that happened to contain a ``:`` —
    those bytes then replaced the real method/password (``psTqT``) or produced
    an empty password and killed the link outright (``qwhh3YWzbtXY6``).
    """
    parser = ShadowsocksParser()
    for password in ("psTqT", "qwhh3YWzbtXY6", "pa:ss:wo:rd"):
        cfg = parser.parse(f"ss://aes-256-gcm:{password}@real-server.net:8388")
        assert cfg is not None, password
        assert cfg.ss_method == "aes-256-gcm", password
        assert cfg.uuid_or_password == password
        assert cfg.address == "real-server.net"
        assert cfg.port == 8388


def test_ss_base64_formats_still_decode() -> None:
    """SIP002 and legacy base64 forms keep working under strict decoding."""
    sip002 = ShadowsocksParser().parse(
        "ss://YWVzLTI1Ni1nY206cGFzcw@real-server.net:8388#FI-01"
    )
    assert sip002 is not None
    assert (sip002.ss_method, sip002.uuid_or_password) == ("aes-256-gcm", "pass")

    legacy_raw = "aes-256-gcm:password@real-server.net:8388"
    legacy_b64 = base64.b64encode(legacy_raw.encode()).decode()
    legacy = ShadowsocksParser().parse(f"ss://{legacy_b64}#x")
    assert legacy is not None
    assert (legacy.ss_method, legacy.uuid_or_password) == ("aes-256-gcm", "password")

    # Percent-encoded padding ("=" -> "%3D") must still be accepted.
    quoted = ShadowsocksParser().parse(
        "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ%3D@real-server.net:8388"
    )
    assert quoted is not None and quoted.uuid_or_password == "password"


def _vmess_link(payload: dict[str, object], fragment: str = "") -> str:
    """Build a ``vmess://BASE64(JSON)`` link (optionally with a fragment)."""
    encoded = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
    return f"vmess://{encoded}{fragment}"


def test_vmess_coerces_non_string_json_fields() -> None:
    """Numeric JSON values must reach Config as ``str``, not as ``int``.

    Auto-generated panels number their nodes (``"ps": 2``).  The raw value used
    to land in ``Config.remark``, and the first consumer to call a string method
    on it (``is_garbage_config`` does ``remark.upper()``) raised AttributeError —
    which is not caught anywhere in the pipeline, so one such link aborted the
    entire run.
    """
    cfg = VmessParser().parse(
        _vmess_link(
            {
                "add": "real-server.net",
                "port": 443,
                "id": _GOOD_UUID,
                "ps": 2,
                "net": 7,
                "host": 8,
                "path": 9,
                "sni": 10,
                "alpn": 11,
                "fp": 12,
                "flow": 13,
            },
        ),
    )
    assert cfg is not None
    for field in ("remark", "network", "host", "path", "sni", "alpn", "fp", "flow"):
        value = getattr(cfg, field)
        assert isinstance(value, str), f"{field}={value!r}"
    assert cfg.remark == "2"
    # The crash site itself: this must return a verdict instead of raising.
    assert is_garbage_config(cfg) is False

    # A falsy non-string keeps the documented default / None.
    zeros = VmessParser().parse(
        _vmess_link(
            {"add": "real-server.net", "port": 443, "id": _GOOD_UUID, "net": 0},
        ),
    )
    assert zeros is not None
    assert zeros.network == "tcp"

    # Non-string ``add``/``id`` stay rejected outright.
    assert VmessParser().parse(_vmess_link({"add": 1, "port": 443, "id": 2})) is None


def test_vmess_unbrackets_ipv6_address() -> None:
    """A bracketed IPv6 ``add`` must be stored bare, like every other parser."""
    cfg = VmessParser().parse(
        _vmess_link({"add": f"[{_IPV6}]", "port": 443, "id": _GOOD_UUID}),
    )
    assert cfg is not None
    assert cfg.address == _IPV6
    # Same server via vless dedups against it because the keys now match.
    vless = VlessParser().parse(f"vless://{_GOOD_UUID}@[{_IPV6}]:443")
    assert vless is not None
    assert cfg.dedup_key[1:] == vless.dedup_key[1:]
    # A bracket pair with nothing inside is not an address.
    assert (
        VmessParser().parse(_vmess_link({"add": "[]", "port": 443, "id": _GOOD_UUID}))
        is None
    )


# (link, protocol, address, credential) — the Config below is what the parsers
# would build from the link, so both is_garbage_config branches must agree.
_CREDENTIAL_CASES: list[tuple[str, str, str, str]] = [
    ("vless://{cred}@real-server.net:443", "vless", "real-server.net", _GOOD_UUID),
    ("vless://{cred}@real-server.net:443", "vless", "real-server.net", "garbage"),
    ("vless://{cred}@real-server.net:443", "vless", "real-server.net", "SERVER_IP"),
    ("vless://{cred}@real-server.net:443", "vless", "real-server.net", "SERVER_IP_1"),
    ("vless://{cred}@real-server.net:443", "vless", "real-server.net", "UUID"),
    ("vless://{cred}@real-server.net:443", "vless", "real-server.net", ""),
    ("trojan://{cred}@real-server.net:443", "trojan", "real-server.net", "realpass"),
    (
        "trojan://{cred}@real-server.net:443",
        "trojan",
        "real-server.net",
        "super-password-2024",
    ),
    ("trojan://{cred}@real-server.net:443", "trojan", "real-server.net", "PUBLIC_KEY"),
    (
        "trojan://{cred}@real-server.net:443",
        "trojan",
        "real-server.net",
        "PUBLIC_KEY_1",
    ),
    ("trojan://{cred}@real-server.net:443", "trojan", "real-server.net", "SHORT_ID"),
    ("trojan://{cred}@real-server.net:443", "trojan", "real-server.net", "your-domain"),
    ("trojan://{cred}@real-server.net:443", "trojan", "real-server.net", "example.com"),
    ("trojan://{cred}@real-server.net:443", "trojan", "real-server.net", "PASSWORD"),
    (
        "tuic://{cred}@real-server.net:443",
        "tuic",
        "real-server.net",
        f"{_GOOD_UUID}:pw",
    ),
    ("tuic://{cred}@real-server.net:443", "tuic", "real-server.net", "UUID:pw"),
    ("tuic://{cred}@real-server.net:443", "tuic", "real-server.net", "notauuid:pw"),
    ("tuic://{cred}@real-server.net:443", "tuic", "real-server.net", "v5-token"),
    ("tuic://{cred}@real-server.net:443", "tuic", "real-server.net", ""),
]


def test_is_garbage_config_branches_agree_on_credentials() -> None:
    """Every credential shape gets the same verdict from both branches."""
    for template, protocol, address, credential in _CREDENTIAL_CASES:
        link = template.format(cred=credential)
        cfg = Config(
            protocol=protocol,
            address=address,
            port=443,
            uuid_or_password=credential,
        )
        assert is_garbage_config(link) is is_garbage_config(cfg), (
            f"{link!r} vs Config(credential={credential!r})"
        )


def test_is_garbage_config_still_sees_placeholders_in_userinfo() -> None:
    """Excluding the userinfo from the scan must not lose real placeholders.

    Regression: the userinfo was cut out of the placeholder scan wholesale to
    stop ``\\bPASSWORD\\b`` from flagging ``super-password-2024``, which also
    silenced SERVER_IP / PUBLIC_KEY / SHORT_ID / your-domain / example.com.
    """
    for credential in (
        "SERVER_IP",
        "SERVER_IP_1",
        "PUBLIC_KEY",
        "PUBLIC_KEY_1",
        "SHORT_ID",
        "your-domain",
        "example.com",
        "UUID",
        "PASSWORD",
    ):
        assert (
            is_garbage_config(f"trojan://{credential}@real-server.net:443") is True
        ), credential
    # The false positives the exclusion was meant to fix stay fixed.
    for credential in ("super-password-2024", "not-a-uuid-password", "my-uuid-2024"):
        assert (
            is_garbage_config(f"trojan://{credential}@real-server.net:443") is False
        ), credential
    # A vmess link keeps its credential inside the base64 JSON: no userinfo must
    # NOT be read as "empty credential".
    assert (
        is_garbage_config(
            _vmess_link({"add": "real-server.net", "port": 443, "id": _GOOD_UUID}),
        )
        is False
    )
    # Arbitrary text (no scheme at all) has no userinfo to judge either.
    assert is_garbage_config("just some prose about proxies") is False


def test_safe_b64decode_ignores_utf8_bom() -> None:
    """A BOM-prefixed base64 subscription must not be lost.

    ``\\ufeff`` is neither matched by ``\\s`` nor stripped by ``str.strip()``, so
    it stayed in the payload, made its length 4n+1 and decoded to "" — the whole
    source file was dropped with "No links found".
    """
    links = "\n".join(
        [
            f"vless://{_GOOD_UUID}@real-server.net:443#DE-1",
            "trojan://secret@real-server.net:443#FR-1",
        ]
    )
    flat = base64.b64encode(links.encode("utf-8")).decode("ascii")
    assert safe_b64decode(f"﻿{flat}") == links
    # BOM + MIME wrapping (both come from real HTTP/GitHub bodies) still works.
    wrapped = "\n".join(flat[i : i + 76] for i in range(0, len(flat), 76))
    assert safe_b64decode(f"﻿{wrapped}") == links

    parser = SubscriptionParser()
    assert parser.is_subscription(f"﻿{flat}") is True
    assert parser.parse_subscription(f"﻿{flat}") == find_all_links(links)


def test_hysteria2_accepts_port_hopping() -> None:
    """Port ranges/lists are valid hysteria2 — take the first port, keep the link.

    Regression: ``int("443-500")`` raised inside ``split_host_port``, so every
    port-hopping link was silently dropped at parse time.
    """
    parser = Hysteria2Parser()
    for hostport, address in (
        ("real-server.net:443-500", "real-server.net"),
        ("real-server.net:443,8443", "real-server.net"),
        ("real-server.net:443,8443,9443", "real-server.net"),
        (f"[{_IPV6}]:443-500", _IPV6),
    ):
        link = f"hy2://pass@{hostport}?sni=real-server.net#x"
        cfg = parser.parse(link)
        assert cfg is not None, link
        assert (cfg.address, cfg.port) == (address, 443), link
        # The full spec survives in raw_link for the published output.
        assert cfg.raw_link == link

    # A plain port is untouched, and an out-of-range first port is still rejected.
    plain = parser.parse("hy2://pass@real-server.net:443#x")
    assert plain is not None and plain.port == 443
    assert parser.parse("hy2://pass@real-server.net:0-500#x") is None
    assert parser.parse("hy2://pass@real-server.net:99999-100000#x") is None
    # A bare IPv6 host stays ambiguous and rejected.
    assert parser.parse(f"hy2://pass@{_IPV6}#x") is None


def test_hysteria2_rejects_whitespace_only_password() -> None:
    """The password is stripped once, so emptiness is the only check needed."""
    parser = Hysteria2Parser()
    for userinfo in ("%20", "%20%09%20", "%0A", "%C2%A0"):
        assert parser.parse(f"hy2://{userinfo}@real-server.net:443#x") is None, userinfo
    assert parser.parse("hysteria2://real-server.net:443#x") is None
    kept = parser.parse("hy2://%20pass%20@real-server.net:443#x")
    assert kept is not None and kept.uuid_or_password == "pass"


def test_strict_b64decode_rejects_invalid_lengths_without_raising() -> None:
    """The length/alphabet guards make the decode itself total."""
    # 4n+1 encodes no whole byte group — rejected before b64decode sees it.
    assert _strict_b64decode("YWJjZQ") != ""
    assert _strict_b64decode("YWJjZ") == ""
    assert _strict_b64decode("=") == ""
    assert _strict_b64decode("") == ""
    # A 4n+1 userinfo must therefore fall through to the plain-format branch.
    cfg = ShadowsocksParser().parse("ss://aes-256-gcm:YWJjZ@real-server.net:8388")
    assert cfg is not None
    assert (cfg.ss_method, cfg.uuid_or_password) == ("aes-256-gcm", "YWJjZ")
