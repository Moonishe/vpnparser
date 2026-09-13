"""Base parser interface and Config dataclass.

Every parser (vmess, vless, trojan, ss, subscription) implements BaseParser.
Config is the unified internal representation of a proxy server.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, ClassVar
from urllib.parse import unquote

logger = logging.getLogger(__name__)


@dataclass
class Config:
    """Unified proxy configuration extracted from any protocol link."""

    protocol: str  # vmess / vless / trojan / ss
    address: str
    port: int
    uuid_or_password: str  # uuid for vmess/vless, password for trojan/ss
    # transport
    network: str = "tcp"  # tcp / ws / grpc / h2
    security: str = "none"  # none / tls / reality
    # ws / grpc params
    path: str | None = None  # ws path, grpc serviceName
    host: str | None = None  # ws Host header, grpc authority
    # tls
    sni: str | None = None  # TLS SNI
    alpn: str | None = None  # TLS ALPN
    # reality
    fp: str | None = None  # fingerprint (chrome, firefox, etc.)
    pbk: str | None = None  # reality public key
    sid: str | None = None  # reality shortId
    # xtls
    flow: str | None = None  # xtls-rprx-vision
    # shadowsocks specific
    ss_method: str | None = None  # aes-256-gcm, chacha20-ietf-poly1305, etc.
    # vmess specific
    alter_id: int | None = None  # vmess "aid"; ignored by Xray >= 1.8.5
    # hysteria2 specific (salamander obfuscation). Stored so the Clash writer
    # and the sing-box probe can dial an obfs-required server; excluded from
    # is_garbage_config and detect_country inputs by the parsers.
    obfs: str | None = None  # "salamander"
    obfs_password: str | None = None
    # tuic v5 specific. Stored so the Clash writer can express them (Mihomo
    # TuicOption accepts both); Xray cannot dial tuic at all, so only the
    # sing-box probe consumes them — via the raw_link, which carries them.
    congestion_control: str | None = None  # "bbr" / "cubic" / "new_reno"
    udp_relay_mode: str | None = None  # "native" / "quic"
    # hysteria2 port-hopping range (e.g. "443-500" or "443,8443"). The Config
    # port holds the first port clients dial; the full spec selects the
    # endpoint, so it is part of the dedup hash (see dedup_key). Stored
    # explicitly instead of reparsing raw_link so authority-range and mport
    # forms survive _collapse_port_hopping.
    hopping_port_range: str | None = None
    # metadata
    remark: str = ""  # server display name (from # fragment or ps field)
    raw_link: str = ""  # original link for output generation
    # validation results (filled by validators, not parsers)
    latency_ms: float | None = None
    country: str | None = None
    is_alive: bool | None = None
    # source metadata (filled by the parsing stage)
    source_name: str | None = None
    source_file: str | None = None
    source_default_country: str | None = None
    # Xray probe bookkeeping (filled by xray_probe validator)
    xray_was_checked: bool | None = None
    xray_attempt_successes: int | None = None
    xray_attempts_per_config: int | None = None
    xray_proxy_successes: int | None = None
    xray_proxy_checks: int | None = None
    # quality / health bookkeeping (filled by quality filter / health history)
    quality_score: float | None = None
    quality_block_reason: str | None = None
    health_record: dict[str, Any] | None = None

    @property
    def dedup_key(self) -> tuple[str, str, int, str]:
        """Key for deduplication: (protocol, address, port, cred_hash).

        Different protocols or credentials on the same address:port are
        independent configs (e.g. VLESS + Trojan on one server, or two user
        accounts with different uuid/password on the same node).  The protocol
        and credential hash are both part of the key so they are never merged:
        collapsing distinct credentials silent-dropped working configs (e.g. an
        alive uuid next to a dead one on the same node). For REALITY the ``pbk``
        identifies the endpoint and is included in the hash, so several
        independent Reality endpoints still sharing one address:port survive.

        The transport fields (``network``, ``path``, ``host``, ``sni``,
        ``alpn``, ``fp``, ``sid``, ``flow``, ``alter_id``) are part of the hash
        too: two links that share a credential but reach different endpoints
        over it — a different ws path, a different SNI, a different REALITY
        shortId — are different servers, and collapsing them kept only whichever
        arrived first.  The same holds for hysteria2's ``obfs``/
        ``obfs_password``: an obfs-required server and the bare endpoint behind
        the same address:port are not interchangeable, so both fields are
        hashed as well.  Only presentation metadata (``remark``, ``raw_link``)
        and validation bookkeeping stay out of the key, so the same link from
        several sources still dedups.

        Hostnames are case-insensitive and an IPv6 literal has many textual
        spellings, so the address is normalised (lowercased; IPv6 collapsed)
        before it enters the key - otherwise ``Example.COM`` and
        ``example.com`` (or two spellings of one IPv6 literal) would survive
        as duplicates.
        """
        address = str(self.address or "")
        try:
            address_key = str(ipaddress.ip_address(address.strip().strip("[]")))
        except ValueError:
            address_key = address.strip().lower()

        # Credential identity distinguishes configs on the same node: the
        # user credential (uuid/password), the transport/tls/reality fields
        # that select the endpoint behind address:port, and the shadowsocks
        # method.  Hashing keeps the key short and avoids echoing secrets
        # into the (sometimes logged) key.  Fields are length-prefixed
        # instead of joined with a plain separator: a "\x00" is impossible
        # inside the encoded field value but was plausible inside a raw
        # credential ("%7C" == "|"), so "a|b"+"c" and "a"+"b|c" used to
        # collide. host/sni are lowercased like the address — the same
        # endpoint spelled differently is one config.
        def _part(value: Any) -> str:
            part = str(value or "")
            return f"{len(part)}\x00{part}" if part else ""

        # security/network are case-insensitive ("TLS" == "tls"); UUID hex
        # is case-insensitive per RFC 4122 but passwords are not — lower
        # the credential only for UUID-based protocols.
        protocol_lc = str(self.protocol or "").lower()
        security_norm = str(self.security or "").strip().lower()
        network_norm = str(self.network or "").strip().lower()
        ss_method_norm = str(self.ss_method or "").strip().lower()
        sid_norm = str(self.sid or "").strip().lower()
        uuid_part = str(self.uuid_or_password or "")
        if protocol_lc in ("vless", "vmess"):
            uuid_part = uuid_part.strip().lower()
        # Hysteria2 port-hopping range selects the endpoint: two links
        # that differ only by mport / authority range must not collapse.
        # The parser stores the original spec in hopping_port_range; older
        # Configs (or hand-built ones) fall back to raw_link parsing so the
        # same links still separate. A plain (non-range) mport is ignored by
        # the parser and stays out of the key.
        hopping_part = str(self.hopping_port_range or "").strip()
        if not hopping_part and protocol_lc == "hysteria2":
            try:
                _raw = str(self.raw_link or "")
                _no_frag = _raw.split("#", 1)[0]
                _qs = _no_frag.split("?", 1)[1] if "?" in _no_frag else ""
                _mport = str(parse_qs_single(_qs).get("mport") or "").strip()
                _authority: str = (
                    _no_frag.split("://", 1)[1] if "://" in _no_frag else _no_frag
                )
                _authority = _authority.split("?", 1)[0]
                if "@" in _authority:
                    _authority = _authority.rsplit("@", 1)[1]
                if "/" in _authority:
                    _authority = _authority.split("/", 1)[0]
                _auth_range = ""
                if _authority.startswith("["):
                    _close = _authority.find("]")
                    if _close != -1 and _authority[_close + 1 :].startswith(":"):
                        _cand = _authority[_close + 2 :]
                        if _HOPPING_RANGE_RE.fullmatch(_cand):
                            _auth_range = _cand
                elif ":" in _authority:
                    _cand = _authority.rpartition(":")[2]
                    if _HOPPING_RANGE_RE.fullmatch(_cand):
                        _auth_range = _cand
                if _auth_range:
                    hopping_part = _auth_range
                elif _mport and _HOPPING_RANGE_RE.fullmatch(_mport):
                    hopping_part = _mport
                else:
                    hopping_part = ""
            except Exception:
                hopping_part = ""
        cred_parts = [
            _part(security_norm),
            _part(network_norm),
            _part(self.path),
            _part(str(self.host or "").strip().lower()),
            _part(str(self.sni or "").strip().lower()),
            _part(self.alpn),
            _part(self.fp),
            _part(self.pbk),
            _part(sid_norm),
            _part(self.flow),
            _part(ss_method_norm),
            _part(self.alter_id),
            # Hysteria2 obfuscation selects the endpoint as much as a ws path
            # or a REALITY shortId does: without it an obfs-required server
            # and the bare endpoint collapsed into one dedup key and one of
            # the two configs was dropped.
            _part(self.obfs),
            _part(self.obfs_password),
            # TUIC v5 congestion control / relay mode select the endpoint
            # like a ws path does: same addr:port with different cc/urm are
            # different servers, collapsing them lost one.
            _part(str(self.congestion_control or "").strip().lower()),
            _part(str(self.udp_relay_mode or "").strip().lower()),
            _part(hopping_part),
            _part(uuid_part),
        ]
        # errors="ignore": a lone surrogate smuggled through a crafted vmess JSON
        # payload made .encode() raise UnicodeEncodeError — one link crashed the run
        # (and permanently disabled dedup in the filter stage). Malformed characters
        # are dropped instead of becoming a crash primitive.
        cred = hashlib.sha256(
            "".join(cred_parts).encode(errors="ignore"),
        ).hexdigest()
        try:
            port_int = int(self.port)
        except (TypeError, ValueError):
            # Total function: a malformed port must not disable dedup for
            # the whole batch (filter stage fail-open). The raw value still
            # separates keys via the credential hash.
            cred = hashlib.sha256(
                ("".join(cred_parts) + f"\x00port:{self.port}").encode(errors="ignore"),
            ).hexdigest()
            port_int = 0
        return (protocol_lc, address_key, port_int, cred)

    def to_dict(self) -> dict[str, object]:
        return {
            k: v
            for k, v in self.__dict__.items()
            if v is not None and k not in ("latency_ms", "country", "is_alive")
        }


class BaseParser(ABC):
    """Abstract base for all protocol parsers."""

    # subclasses set this, e.g. "vmess", "vless"
    protocol: ClassVar[str] = ""

    # URL schemes this parser accepts.  Defaults to ``(protocol,)`` — most
    # parsers handle exactly one scheme.  Parsers with aliases (e.g.
    # Hysteria2Parser accepts both ``hysteria2://`` and ``hy2://``) override
    # this.  Used by :data:`src.parsers.PARSER_BY_SCHEME` for O(1) dispatch
    # instead of an O(N) linear scan over ALL_PARSERS.
    schemes: ClassVar[tuple[str, ...]] = ()

    @abstractmethod
    def parse(self, link: str) -> Config | None:
        """Parse a single link into a Config object.

        Returns None if the link is malformed or doesn't match this parser's protocol.
        """
        ...

    def can_parse(self, link: str) -> bool:
        """Check if this parser handles the given link scheme.

        Returns ``False`` (never raises) for ``None`` or empty input —
        callers sometimes pass values from unreliable sources, and
        ``parse()`` already fails soft to ``None`` for the same reason.
        """
        if not link:
            return False
        return link.strip().lower().startswith(f"{self.protocol}://")


# --- utility functions shared across parsers ---


# Noise to drop before base64 decoding: any whitespace plus U+FEFF, the BOM as
# it appears once the bytes have been decoded to text.  U+FEFF is NOT matched by
# ``\s`` and NOT removed by ``str.strip()``, yet sources routinely carry one at
# the start of a file (``src/sources/github.py`` decodes bytes to text, keeping
# it), so it has to be listed explicitly.
_B64_NOISE_RE = re.compile(
    r"[\s\ufeff\u200b\u200c\u200d\u200e\u200f\u202a-\u202e\u2060]+"
)


def safe_b64decode(data: str | None) -> str:
    """Base64 decode with padding fix, percent-decoding and utf-8 fallback."""
    if data is None:
        return ""
    try:
        text = unquote(data)
    except Exception:
        return ""
    # Some sources percent-encode the base64 (most visibly the padding:
    # "…fQ%3D%3D"), which plain b64decode rejects. unquote() is safe here:
    # the base64 alphabet contains no "%", and unlike unquote_plus it does
    # not turn "+" into a space. (The shadowsocks parser normalises the same
    # way for the same reason.)
    # Drop ALL noise (not just the outer edges) and normalize URL-safe chars.
    # Interior newlines are ignored by b64decode but would corrupt the padding
    # arithmetic below - a MIME-wrapped payload (64/76 chars per line, no "=")
    # then decoded to "" and the whole subscription was lost.  A leading BOM
    # shifted the length to 4n+1 (padding 3, never valid) and lost it the same
    # way.
    cleaned = _B64_NOISE_RE.sub("", text).replace("-", "+").replace("_", "/")
    # fix padding
    padding = 4 - (len(cleaned) % 4)
    if padding != 4:
        cleaned += "=" * padding
    try:
        # validate=True: without it, non-alphabet characters are silently
        # dropped and the remaining bytes decode SHIFTED — garbage that can
        # still parse as JSON downstream. Reject the payload instead.
        return base64.b64decode(cleaned, validate=True).decode(
            "utf-8", errors="replace"
        )
    except Exception:
        return ""


def parse_qs_single(query_string: str) -> dict[str, str]:
    """Parse query string, returning single values (first occurrence).

    ``+`` is kept literal: unlike :func:`urllib.parse.parse_qs` it is NOT
    decoded as a space.  Reality ``pbk`` and other fields are base64 where a
    literal ``+`` from a non-percent-encoded source silently corrupted the
    key into spaces, producing a config that could never connect.
    """
    if not query_string:
        return {}
    result: dict[str, str] = {}
    for pair in query_string.split("&"):
        if not pair:
            continue
        key, _, value = pair.partition("=")
        # unquote_plus would turn "+" into a space; plain unquote keeps it.
        # The key is decoded BEFORE the membership check: storage uses the
        # decoded key, so comparing the still-encoded form let an encoded
        # duplicate slip past it ("ab=1&a%62=2" kept whichever pair came
        # last-ish depending on order).  First occurrence still wins,
        # matching the previous parse_qs-based behaviour.
        key = unquote(key).strip().lower()
        if key not in result:
            result[key] = unquote(value)
    return result


#: A remark is a display name; real ones are a few dozen characters. The
#: ``#fragment`` is unbounded external input, so a megabyte-long fragment
#: would ride into every published artifact (Clash name, base64 subscription)
#: unchanged — capped here once, at the single extraction point.
_MAX_REMARK_CHARS = 256


def extract_remark(fragment: str) -> str:
    """Extract display name from URL fragment (#remark)."""
    if not fragment:
        return ""
    return unquote(fragment)[:_MAX_REMARK_CHARS]


def cap_remark(remark: str | None) -> str:
    """Cap an externally-sourced remark to :data:`_MAX_REMARK_CHARS`.

    For remarks that do not come from a URL fragment (the vmess ``ps`` JSON
    field): same bound, no decoding.
    """
    return (remark or "")[:_MAX_REMARK_CHARS]


def split_host_port(hostport: str) -> tuple[str, int] | None:
    """Split a ``host:port`` string into ``(host, port)``.

    Handles:
    - Regular hostnames: ``example.com:443``
    - Bracketed IPv6: ``[::1]:443``, ``[2001:db8::1]:443``

    Returns ``None`` when:
    - No port is present (``example.com`` with no ``:``).
    - The port is not an integer in the valid range **1–65535**.
    - The host is empty after stripping brackets/whitespace.
    - A **bare** IPv6 address (multiple colons, no ``[…]`` brackets) is
      supplied — the port boundary is ambiguous per RFC 2732, so a proper
      IPv6 link must use brackets: ``[2001:db8::1]:443``.

    This replaces the ad-hoc ``rsplit(":", 1)`` + ``strip("[]")`` idiom that
    silently turned ``token@2001:db8::1`` (no port, bare IPv6) into the
    garbage config ``address='2001:db8:', port=1``.
    """
    if not hostport:
        return None

    # Strip the whole input so a padded bracketed IPv6 (e.g. ``  [::1]:443  ``)
    # is detected by the ``startswith("[")`` branch instead of falling through
    # to the bare-hostname branch and being rejected for having ``!= 1`` colons.
    hostport = hostport.strip()

    # Bracketed IPv6: [addr]:port
    if hostport.startswith("["):
        close = hostport.find("]")
        if close == -1:
            return None  # unclosed bracket
        host = hostport[1:close].strip()
        rest = hostport[close + 1 :]
        if not rest.startswith(":"):
            return None  # no port separator after bracket
        # Brackets mark an IPv6 literal per RFC 2732: the inside must be a
        # valid IP containing ':' (a bracketed hostname or IPv4 is malformed).
        if ":" not in host:
            return None
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return None
        port_str = rest[1:]
    else:
        # Regular hostname:port.  A bare IPv6 address (more than one colon,
        # no brackets) is ambiguous — reject it instead of guessing.
        if hostport.count(":") != 1:
            return None
        host, port_str = hostport.rsplit(":", 1)
        host = host.strip()

    if not is_valid_host(host):
        return None

    if not port_str.isascii() or not port_str.isdigit():
        # int() would happily accept unicode digits ("٤٤٣") and underscores
        # ("4_43"); a port is ASCII digits only.
        return None
    try:
        port = int(port_str)
    except (ValueError, TypeError):
        return None
    if not (1 <= port <= 65535):
        return None

    return (host, port)


def parse_password_host_port(
    link: str,
    protocol: str,
    *,
    network: str = "tcp",
) -> Config | None:
    """Parse a ``protocol://PASSWORD@HOST:PORT?params#REMARK`` link.

    Shared parser core for password-based protocols that follow the same URL
    shape (currently shadowtls and anytls).  Manual splitting is used instead
    of :func:`urllib.parse.urlparse` because urlparse does not extract userinfo
    for non-standard schemes.

    The password (URL userinfo) is percent-decoded with
    :func:`urllib.parse.unquote`.  ``sni`` and ``alpn`` are read from the query
    string; all other query params stay encoded in ``raw_link``.

    Args:
        link: Raw link string starting with ``protocol://``.
        protocol: Protocol name (must match the scheme prefix in *link*).
        network: Transport network value for the :class:`Config`
            (default ``"tcp"``).

    Returns:
        A :class:`Config` on success, or ``None`` if the link is malformed
        (missing/empty password, host or port; bad port range).
    """
    try:
        normalized = link.strip()
        low = normalized.lower()
        scheme = f"{protocol}://"
        if not low.startswith(scheme):
            return None

        body = normalized.split("://", 1)[1]

        # Split fragment (remark)
        if "#" in body:
            body, fragment = body.split("#", 1)
        else:
            fragment = ""
        remark = extract_remark(fragment)

        # Split query
        if "?" in body:
            hostport, query_str = body.split("?", 1)
        else:
            hostport, query_str = body, ""

        # Split userinfo (password) FIRST — before stripping path.
        # If we strip path first, a password containing "/" would be
        # truncated at the first "/" and lose the "@" separator.
        if "@" in hostport:
            userinfo, hostport = hostport.rsplit("@", 1)
            # Strip leading/trailing whitespace after percent-decoding: an
            # encoded leading/trailing space (``%20``) is almost always a
            # copy-paste/templating artifact, not an intentional credential
            # char, and storing it would break authentication.  Mirrors
            # TuicParser which does ``unquote(userinfo).strip()``.
            password = unquote(userinfo).strip()
        else:
            password = ""

        # Reject empty / whitespace-only passwords.
        if not password:
            return None

        # Strip path component from host:port only (e.g. trailing "/").
        if "/" in hostport:
            hostport = hostport.split("/", 1)[0]

        # Split host:port (handles bracketed IPv6, rejects bare IPv6).
        parsed_hp = split_host_port(hostport)
        if parsed_hp is None:
            return None
        host, port = parsed_hp

        query = parse_qs_single(query_str)

        def _clean(key: str) -> str | None:
            raw = query.get(key)
            return raw.strip() if raw and raw.strip() else None

        return Config(
            protocol=protocol,
            address=host,
            port=port,
            uuid_or_password=password,
            network=network,
            security="tls",
            sni=_clean("sni"),
            alpn=_clean("alpn"),
            remark=remark,
            raw_link=link.strip(),
        )
    except Exception:
        return None


# Scheme alternation: vmess, vless, trojan, ss, hysteria2, hy2,
# tuic, shadowtls, anytls.
# "hysteria2" requires the literal "2" (Hysteria v1 is a different protocol
# with no parser here). "hy2" is the short alias and must be listed explicitly
# — otherwise hy2:// links in source text are silently dropped by
# find_all_links and never reach the parser.
# wireguard:// is deliberately NOT here: there is no WireGuard parser (and no
# end-to-end support in probes/outputs), so extracting such links only burned
# parse budget on configs that were silently discarded afterwards.
# Scheme alternatives appear in three places below; keep them in sync.
_SCHEME_ALT = r"(?:vmess|vless|trojan|ss|hysteria2|hy2|tuic|shadowtls|anytls)"
# A link body must STOP before the next link: sources routinely join links
# with "," or ";" and a plain character class glued both into one
# unparseable match (both configs lost). The negative lookahead ends the run
# before a following scheme while still allowing commas inside query values
# ("alpn=h3,h2" has no "://" behind it).
# The backtick is excluded too: GitHub READMEs (the primary source) wrap
# links in markdown code spans, and a glued trailing "```" corrupted the port
# past parsing (vless://…:443` -> int("443`") raised) — whole configs lost.
_BEFORE_NEXT_SCHEME = rf"(?!\b{_SCHEME_ALT}://)"
# Not-a-link-character run with the next-scheme lookahead folded in.
_BODY_RUN = rf"(?:{_BEFORE_NEXT_SCHEME}[^\s<>'\"()\[\]{{}}`])+"

PROTOCOL_PATTERN = re.compile(
    # Leading \b: scheme names all start with a word char, so \b anchors the
    # match to a scheme boundary.  Without it, substrings matched the ``ss``
    # alternative inside unrelated words — e.g. ``boss://x``, ``sss://x`` and
    # ``less://x`` were all extracted as ``ss://x`` false positives.
    rf"\b{_SCHEME_ALT}://"
    # Optional userinfo terminated by "@".  "?" and "#" are excluded so a
    # remark containing "@" (ad remarks do) is not mistaken for userinfo.
    # "/" is excluded as well — userinfo never spans a path — and the run is
    # POSSESSIVE (*+).  Both keep the scan linear: with "/" allowed, a source
    # file of repeated "scheme://" made this group walk the entire tail hunting
    # for "@" at every match start — O(n²) overall (measured: 240 KB of filler
    # probed for 54 s; a 12 MB download would have burned hours of CPU).  The
    # possessive only cuts the failure-path re-scan; on the success path the
    # class already stops at the first "@", so extraction is unchanged
    # (byte-identical over the whole parser test corpus).
    r"(?:[^/\s<>'\"()\[\]{}@?#]*+@)?"
    # Either a bracketed IPv6 literal in the host position followed by the
    # rest of the link, or a plain (bracket-free) remainder.  Brackets are
    # accepted ONLY in the host position: allowing them anywhere would make
    # ``[vless://a@b:443]`` and markdown links swallow the closing bracket.
    rf"(?:\[[0-9A-Fa-f:.]+\](?:{_BEFORE_NEXT_SCHEME}[^\s<>'\"()\[\]{{}}`])*|{_BODY_RUN})",
    re.IGNORECASE,
)


def find_all_links(text: str | None) -> list[str]:
    """Find all proxy links in arbitrary text."""
    if not text or not isinstance(text, str):
        return []
    links = PROTOCOL_PATTERN.findall(text)
    # Strip trailing characters that real sources glue onto a link without
    # being part of it: prose punctuation, closing markup (markdown links,
    # ``</code>``/template braces), and the markdown inline-code backtick —
    # GitHub READMEs routinely wrap links in ``…``, and a trailing backtick
    # used to ride onto the port ("8388`"), fail split_host_port and silently
    # drop the config (vmess/vless still parsed but published the polluted
    # raw_link). Trailing "*" / "~" are prose/emphasis leftovers around a
    # link. '=' is deliberately NOT stripped: it is legitimate base64 padding
    # at the end of vmess/ss payloads, and safe_b64decode re-pads anyway; the
    # reported prose case ('#X =') is separated by a space, where the body
    # class already stops.
    # Trailing "." is sentence punctuation ("…:443." ends a sentence) and
    # never payload: base64 alphabets contain no dots, and a fully-qualified
    # root dot ("host.example.com.") is equivalent to none once split.
    # Without it the port arrived as "443.", failed int() inside
    # split_host_port, and the whole config was lost.
    return [link.rstrip(",;:.?)]}>`*~") for link in links]


# --- garbage / placeholder detection ---

# Placeholders used in example/template configs (not real servers).
_PLACEHOLDER_PATTERNS = re.compile(
    r"(?i)"
    r"\bUUID\b"  # literal "UUID" instead of real uuid
    r"|\bSERVER_IP"  # SERVER_IP, SERVER_IP_1, SERVER_IP_2... (no trailing \b: _ is a word char)  # noqa: E501
    r"|\bPUBLIC_KEY"  # PUBLIC_KEY, PUBLIC_KEY_1, ... (no trailing \b: would block _N suffix)  # noqa: E501
    r"|\bSHORT_ID"  # SHORT_ID, SHORT_ID_1, ... (no trailing \b: would block _N suffix)  # noqa: E501
    r"|\bPASSWORD\b"  # literal "PASSWORD"
    r"|\byour[_-]?domain\b"  # yourdomain.com, your-domain.com (word-bounded: not yourdomains.com)  # noqa: E501
    r"|\bexample\.com\b",  # example.com (IANA reserved; word-bounded: not bestexample.com)  # noqa: E501
)

# The subset of _PLACEHOLDER_PATTERNS that is safe to match *inside* a
# credential: everything except ``\bUUID\b`` / ``\bPASSWORD\b``, which
# false-positive on real credentials ("super-password-2024", "not-a-uuid-pass").
# Those two are handled by whole-value exact match in _is_garbage_credential.
_CREDENTIAL_PLACEHOLDER_PATTERNS = re.compile(
    r"(?i)"
    r"\bSERVER_IP"
    r"|\bPUBLIC_KEY"
    r"|\bSHORT_ID"
    r"|\byour[_-]?domain\b"
    r"|\bexample\.com\b",
)

# Advertising in remark — Telegram handles, URLs, promotional text.
# These configs are real servers but the remark is an ad for a channel/site.
# We filter them out so the subscription stays clean.
# Case-insensitive: ad remarks frequently use mixed case ("OneClickVPN",
# "V2Ray Pool", "Gozargah", "OPENPROXYLIST").  Without (?i) these slipped
# through the filter — _PLACEHOLDER_PATTERNS already used (?i), this one
# did not, which was an inconsistency that silently let mixed-case ads in.
_AD_PATTERNS = re.compile(
    r"(?i)"
    r"@"
    r"|https?://"
    r"|\.com\b"
    r"|\.net\b"
    r"|\.org\b"
    r"|\.ru\b"
    r"|\.ir\b"
    r"|\.io\b"
    r"|\.me\b"
    r"|t\.me/"
    r"|telegram"
    r"|channel"
    r"|subscribe"
    r"|канал"
    r"|подпиш"
    r"|купить"
    r"|openproxylist"
    r"|oneclickvpn"
    # Bounded quantifier, NOT ``v2ray.*pool``: the unbounded form re-scanned the
    # rest of the remark from every ``v2ray`` occurrence, so a remark that
    # repeats ``v2ray`` without ever containing ``pool`` cost O(n^2) — 17 s at
    # 160 KB, ~28 h at the 12 MB source download limit, with GarbageFilter
    # hanging the whole run before any sampling or dedup could shrink the input.
    # ``.`` (not ``[^\s]``) so the real ad remarks this targets — "V2Ray Pool",
    # "v2ray free pool" — keep matching across their spaces.
    r"|v2ray.{0,64}?pool"
    r"|shadowproxy"
    r"|gozargah",
)

# Upper bound on how much of a remark :func:`_has_ad_remark` inspects.  A remark
# is a display name: real ones are a few dozen characters, while the ``#fragment``
# of a link taken straight from a public source is bounded only by the 12 MB
# download limit.  Ad markers sit at the front of a remark, so scanning a fixed
# prefix loses nothing in practice and keeps the filter's cost constant per
# config no matter what a source ships.
_MAX_AD_SCAN_CHARS = 512

# Valid UUID format: either the hyphenated 8-4-4-4-12 form or 32 hex chars
# with NO hyphens at all. Module-level so it is compiled once, not looked up
# in re's internal cache on every is_garbage_config() call. Both are valid
# RFC 4122 representations that vmess/vless sources emit. Mixed hyphenation
# ("8-4-4 4-12" variants) is not an RFC 4122 representation — accepting it
# used to let hybrid-shaped garbage through and publish dead configs.
# ``\Z`` (not ``$``) so a trailing newline — e.g. from ``json.loads`` of a
# vmess "id" field — cannot sneak past validation.
_UUID_RE = re.compile(
    r"(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    r"|[0-9a-fA-F]{32})\Z",
)

# Port-hopping spec shared with hysteria2.py: at least two ASCII ports joined
# by "-" (range) or "," (list). ASCII digits only — ``\d`` would also match
# e.g. Arabic-Indic numerals, which no client accepts.
_HOPPING_RANGE_RE = re.compile(r"[0-9]{1,5}(?:[-,][0-9]{1,5})+")

# Transports/securities the downstream writers and probes can express. Clash
# knows tcp/ws/grpc/h2/httpupgrade/xhttp(+splithttp alias); Xray knows
# tcp/ws/grpc/httpupgrade/xhttp. Anything else (legacy kcp, quic on a
# vless link, typos) is reset to the protocol default with a warning instead
# of being dropped — dropping would lose live servers behind a renamed type,
# while the writers/probes still skip what they cannot express.
_ALLOWED_NETWORKS = frozenset(
    {"tcp", "ws", "grpc", "h2", "http", "httpupgrade", "xhttp", "splithttp"}
)
_ALLOWED_SECURITIES = frozenset({"none", "tls", "reality"})


def is_valid_host(host: str | None) -> bool:
    """Return ``True`` when *host* is a plausible DNS name / IP literal.

    Rejects empty values, whitespace, path separators, control characters
    (``ord < 33`` or ``127``) and URL delimiters that would split the link
    differently downstream. A ``:`` is only allowed inside a valid IP literal
    (bracketless IPv6 such as ``2001:db8::1``) — the port travels separately,
    so any other colon means the authority was mis-split.
    """
    if not isinstance(host, str):
        return False
    if not host or not host.strip():
        return False
    if "/" in host or "\\" in host:
        return False
    if any(ord(c) < 33 or ord(c) == 127 for c in host):
        return False
    if ":" in host:
        try:
            ipaddress.ip_address(host.strip().strip("[]"))
        except ValueError:
            return False
    bad_host_chars = (
        "!",
        "?",
        "#",
        "@",
        "(",
        ")",
        "[",
        "]",
        "{",
        "}",
        "<",
        ">",
        '"',
        "'",
        "`",
        ";",
        ",",
        "%",
        "$",
        "&",
        "+",
        "*",
        "=",
        "~",
        "|",
        "^",
    )
    return not any(c in host for c in bad_host_chars)


def _split_link_userinfo(body: str) -> tuple[str, str]:
    """Split a fragment-less link body into ``(userinfo, link_without_userinfo)``.

    Only the authority component is inspected: the ``@`` must appear before the
    first ``/`` or ``?``, otherwise an ``@`` inside a path or query string would
    be mistaken for the userinfo separator.

    Args:
        body: Link with the ``#fragment`` already removed.

    Returns:
        ``(userinfo, rest)`` where *rest* is *body* with ``userinfo@`` removed.
        ``userinfo`` is ``""`` when the link carries no credentials.
    """
    scheme_end = body.find("://")
    if scheme_end == -1:
        return ("", body)
    after_scheme = body[scheme_end + 3 :]
    authority_end = min(
        (i for i in (after_scheme.find("/"), after_scheme.find("?")) if i != -1),
        default=len(after_scheme),
    )
    at = after_scheme.rfind("@", 0, authority_end)
    if at == -1:
        return ("", body)
    return (after_scheme[:at], body[: scheme_end + 3] + after_scheme[at + 1 :])


def _has_ad_remark(remark: str) -> bool:
    """Judge a remark as advertising (channel handle, URL, promotional text).

    Only the first :data:`_MAX_AD_SCAN_CHARS` characters are inspected, so the
    check costs the same for a 30-character display name and for a multi-megabyte
    ``#fragment`` pulled from a public source.  Shared by both branches of
    :func:`is_garbage_config` so a link string and the :class:`Config` parsed
    from it are judged identically.

    Args:
        remark: Display name, already percent-decoded.

    Returns:
        ``True`` when the remark carries an advertising marker.
    """
    return _AD_PATTERNS.search(remark[:_MAX_AD_SCAN_CHARS]) is not None


def _is_garbage_credential(protocol: str, credential: str) -> bool:
    """Judge a single credential (uuid / password) as placeholder or malformed.

    Shared by both branches of :func:`is_garbage_config` so that a link string
    and the :class:`Config` parsed from it are always judged identically — the
    two used to disagree (``vless://garbage@host:443`` passed as a string while
    the equivalent Config was rejected).

    ``UUID`` / ``PASSWORD`` are matched only as the *whole* value: as
    sub-patterns they false-positive on real credentials such as
    ``super-password-2024``.  The remaining placeholders are matched anywhere
    (see :data:`_CREDENTIAL_PLACEHOLDER_PATTERNS`).

    Args:
        protocol: Protocol / link scheme (case-insensitive).
        credential: ``uuid_or_password`` value, already percent-decoded.

    Returns:
        ``True`` when the credential cannot belong to a real server.
    """
    proto = str(protocol or "").lower()
    if not credential:
        # These three protocols cannot work without a credential.
        return proto in ("vless", "vmess", "tuic")
    if credential.upper() in ("UUID", "PASSWORD"):
        return True
    if _CREDENTIAL_PLACEHOLDER_PATTERNS.search(credential):
        return True
    # A vless/vmess uuid must look like a real UUID (8-4-4-4-12 hex, hyphens
    # optional), not literal "UUID" or arbitrary text.
    if proto in ("vless", "vmess"):
        return _UUID_RE.match(credential) is None
    # TUIC v5 uses ``UUID:PASSWORD`` — but a non-UUID head is a v4 token
    # (opaque, colons allowed), not garbage: the parser keeps it and the
    # probe decides. Only literal placeholders ("UUID:pass") are rejected.
    if proto == "tuic" and ":" in credential:
        uuid_part = credential.split(":", 1)[0]
        return uuid_part.upper() in ("UUID", "PASSWORD")
    return False


def is_garbage_config(link_or_config: str | Config) -> bool:
    """Check if a link or Config is a placeholder/template, not a real server.

    Detects:
    - Literal placeholders: UUID, SERVER_IP_1, PUBLIC_KEY, SHORT_ID, PASSWORD
    - Example domains: example.com, yourdomain.com
    - Template remarks: "Replace ... with your ..."

    Returns ``True`` for ``None`` input (treat as garbage — safer to filter
    out than to crash on ``str(None)``).
    """
    if link_or_config is None:
        return True

    # Empty/whitespace-only strings are garbage (no real config is empty).
    if isinstance(link_or_config, str) and not link_or_config.strip():
        return True

    if isinstance(link_or_config, Config):
        cfg = link_or_config
        # Watermark masquerade: a source-crafted vmess with add="0.0.0.0"
        # mimics the display-only watermark the writer prepends. With
        # validators off it would be published and then silently dropped on
        # fast-track reparse (the runner treats it as the watermark).
        if (
            str(cfg.address).strip() == "0.0.0.0"
            and str(cfg.protocol).lower() == "vmess"
        ):
            return True
        # Check address, sni, host, pbk, sid for placeholders.
        # NOTE: uuid_or_password AND remark are deliberately EXCLUDED from the
        # combined regex check because ``\bUUID\b`` and ``\bPASSWORD\b`` would
        # false-positive on real credentials/remarks that contain those words
        # (e.g. trojan password "not-a-uuid-password", remark "free-password-vpn").
        # Both are validated separately below with exact-match checks only.
        fields_to_check = [
            cfg.address or "",
            cfg.sni or "",
            cfg.host or "",
            cfg.pbk or "",
            cfg.sid or "",
        ]
        combined = " ".join(str(f) for f in fields_to_check)
        if _PLACEHOLDER_PATTERNS.search(combined):
            return True
        # remark: check for literal placeholder values only (not word-boundary).
        if cfg.remark:
            remark_upper = cfg.remark.upper().strip()
            if remark_upper in (
                "UUID",
                "PASSWORD",
                "SERVER_IP",
                "PUBLIC_KEY",
                "SHORT_ID",
            ):
                return True
            # Filter advertising: @channel, http://, .com, .net, etc.
            if _has_ad_remark(cfg.remark):
                return True
        # uuid_or_password: literal placeholders + per-protocol format.  An
        # empty credential is garbage for vless/vmess/tuic (parsers reject
        # those, but is_garbage_config must be safe if called directly).
        return _is_garbage_credential(cfg.protocol, cfg.uuid_or_password)

    # String link — check raw text for placeholders.
    # Mirror the Config path: ``\bUUID\b`` / ``\bPASSWORD\b`` are NOT run on the
    # URL fragment (remark) nor on the userinfo (credential) because they
    # false-positive on real values such as ``free-password-vpn`` or
    # ``super-password-2024``.  Both go through the same narrower checks the
    # Config path uses (_is_garbage_credential / exact match + ad filter).
    raw = str(link_or_config)
    body, _, remark = raw.partition("#")
    scheme, _, _ = body.partition("://")
    userinfo, body_without_userinfo = _split_link_userinfo(body)
    # A rewritten body is the only reliable "this link carried userinfo" signal:
    # _split_link_userinfo also returns an empty userinfo for ``vless://@host``,
    # which IS garbage, while a link that keeps its credential elsewhere
    # (vmess:// stores it inside the base64 JSON) has no userinfo at all and must
    # not be judged as if the credential were empty.
    if body_without_userinfo != body:
        credential = unquote(userinfo).strip()
        # Plain shadowsocks userinfo is ``method:PASSWORD``; the Config branch
        # only ever holds the password half (``ss_method`` is not scanned), so
        # the string branch must judge the same part or the two disagree
        # (``ss://aes-256-gcm:PASSWORD@host:8388`` — literal placeholder as
        # the password — passed as a string while its Config was rejected).
        # SIP002 / legacy userinfos are base64 and contain no colon, so they
        # keep the whole-value check.
        if scheme.strip().lower() == "ss" and ":" in credential:
            credential = credential.split(":", 1)[1]
        elif scheme.strip().lower() == "ss" and credential:
            # SIP002 userinfo is base64(method:password) with no colon in
            # the encoded form: decode it and judge the password half, so
            # a placeholder password is caught in both branches.
            try:
                _cleaned = (
                    _B64_NOISE_RE.sub("", credential)
                    .replace("-", "+")
                    .replace("_", "/")
                )
                _body = _cleaned.rstrip("=")
                if _body and len(_body) % 4 != 1:
                    _padded = _body + "=" * (-len(_body) % 4)
                    _decoded = base64.b64decode(_padded, validate=True).decode(
                        "utf-8", errors="replace"
                    )
                    if ":" in _decoded:
                        _pass = _decoded.split(":", 1)[1]
                        if _is_garbage_credential("ss", _pass):
                            return True
            except Exception as exc:  # best-effort decode probe
                logger.debug("ss base64 userinfo probe failed: %s", exc)
        if _is_garbage_credential(scheme.strip(), credential):
            return True
    # The placeholder scan mirrors the Config path's body scan: the whole
    # query must NOT be scanned — that flagged
    # ``hy2://realpass@h:443?obfs-password=abc`` "garbage" because
    # \bPASSWORD\b matched inside the obfs parameter name while the same link
    # parsed into a Config passed as real.
    body_for_placeholder_scan = body_without_userinfo.split("?", 1)[0]
    if _PLACEHOLDER_PATTERNS.search(body_for_placeholder_scan):
        return True
    # But the query values that DO reach Config fields (``sni`` / ``host`` /
    # ``pbk`` / ``sid``, via parse_qs_single in every parser) are scanned by
    # the Config branch, so scan exactly those values here too — otherwise
    # ``trojan://real-pass@real-server.net:443?sni=example.com`` passed as a
    # string while its Config was rejected.
    if "?" in body_without_userinfo:
        query = parse_qs_single(body_without_userinfo.split("?", 1)[1])
        query_fields = " ".join(
            query.get(name) or "" for name in ("sni", "host", "pbk", "sid")
        )
        if _PLACEHOLDER_PATTERNS.search(query_fields):
            return True
    # vmess:// carries its endpoint inside base64 JSON, not in the authority:
    # a template payload (add/sni/host = SERVER_IP / example.com / ...) never
    # matches the authority scan above because it is still encoded. Decode
    # best-effort and scan the same fields the Config branch scans. A payload
    # that does not decode is left alone — a lost placeholder label is better
    # than a false positive on an undecodable link.
    if scheme.strip().lower() == "vmess":
        try:
            _payload = body_without_userinfo.split("://", 1)[1]
            _payload = _payload.split("?", 1)[0]
            _decoded = safe_b64decode(_payload)
            if _decoded:
                _obj = json.loads(_decoded)
                if isinstance(_obj, dict):
                    _vmess_fields = " ".join(
                        str(_obj.get(name) or "") for name in ("add", "sni", "host")
                    )
                    if _PLACEHOLDER_PATTERNS.search(_vmess_fields):
                        return True
        except Exception as exc:  # best-effort decode probe, never fail-closed
            logger.debug("vmess placeholder JSON probe failed: %s", exc)
    if remark:
        decoded_remark = unquote(remark)
        if decoded_remark.upper().strip() in (
            "UUID",
            "PASSWORD",
            "SERVER_IP",
            "PUBLIC_KEY",
            "SHORT_ID",
        ):
            return True
        if _has_ad_remark(decoded_remark):
            return True
    return False
