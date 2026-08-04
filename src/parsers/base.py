"""Base parser interface and Config dataclass.

Every parser (vmess, vless, trojan, ss, subscription) implements BaseParser.
Config is the unified internal representation of a proxy server.
"""

from __future__ import annotations

import base64
import ipaddress
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, ClassVar
from urllib.parse import parse_qs, unquote


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
    def dedup_key(self) -> tuple[str, str, int]:
        """Key for deduplication: (protocol, address, port).

        Different protocols or credentials on the same address:port are
        independent configs (e.g. VLESS + Trojan on one server).  The
        protocol is included so they are not merged.

        Hostnames are case-insensitive and an IPv6 literal has many textual
        spellings, so the address is normalised (lowercased; IPv6 collapsed)
        before it enters the key - otherwise ``Example.COM`` and
        ``example.com`` (or two spellings of one IPv6 literal) would survive
        as duplicates.
        """
        address = str(self.address or "")
        try:
            address_key = str(ipaddress.ip_address(address.strip("[]")))
        except ValueError:
            address_key = address.lower()
        return (str(self.protocol).lower(), address_key, int(self.port))

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
_B64_NOISE_RE = re.compile(r"[\s\ufeff]+")


def safe_b64decode(data: str) -> str:
    """Base64 decode with padding fix and utf-8 fallback."""
    # Drop ALL noise (not just the outer edges) and normalize URL-safe chars.
    # Interior newlines are ignored by b64decode but would corrupt the padding
    # arithmetic below — a MIME-wrapped payload (64/76 chars per line, no "=")
    # then decoded to "" and the whole subscription was lost.  A leading BOM
    # shifted the length to 4n+1 (padding 3, never valid) and lost it the same
    # way.
    cleaned = _B64_NOISE_RE.sub("", data).replace("-", "+").replace("_", "/")
    # fix padding
    padding = 4 - (len(cleaned) % 4)
    if padding != 4:
        cleaned += "=" * padding
    try:
        return base64.b64decode(cleaned).decode("utf-8", errors="replace")
    except Exception:
        return ""


def parse_qs_single(query_string: str) -> dict[str, str]:
    """Parse query string, returning single values (first occurrence)."""
    if not query_string:
        return {}
    raw = parse_qs(query_string, keep_blank_values=True)
    return {k: v[0] if v else "" for k, v in raw.items()}


def extract_remark(fragment: str) -> str:
    """Extract display name from URL fragment (#remark)."""
    if not fragment:
        return ""
    return unquote(fragment)


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
        port_str = rest[1:]
    else:
        # Regular hostname:port.  A bare IPv6 address (more than one colon,
        # no brackets) is ambiguous — reject it instead of guessing.
        if hostport.count(":") != 1:
            return None
        host, port_str = hostport.rsplit(":", 1)
        host = host.strip()

    if not host:
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

        return Config(
            protocol=protocol,
            address=host,
            port=port,
            uuid_or_password=password,
            network=network,
            security="tls",
            sni=query.get("sni"),
            alpn=query.get("alpn"),
            remark=remark,
            raw_link=link,
        )
    except Exception:
        return None


# Scheme alternation: vmess, vless, trojan, ss, hysteria2, hy2,
# tuic, shadowtls, anytls.
# "hysteria2" requires the literal "2" (Hysteria v1 is a different protocol
# with no parser here). "hy2" is the short alias and must be listed explicitly
# — otherwise hy2:// links in source text are silently dropped by
# find_all_links and never reach the parser.
PROTOCOL_PATTERN = re.compile(
    # Leading \b: scheme names all start with a word char, so \b anchors the
    # match to a scheme boundary.  Without it, substrings matched the ``ss``
    # alternative inside unrelated words — e.g. ``boss://x``, ``sss://x`` and
    # ``less://x`` were all extracted as ``ss://x`` false positives.
    r"\b(?:vmess|vless|trojan|ss|hysteria2|hy2|tuic|shadowtls|anytls)://"
    # Optional userinfo terminated by "@".  "?" and "#" are excluded so a
    # remark containing "@" (ad remarks do) is not mistaken for userinfo.
    r"(?:[^\s<>'\"()\[\]{}@?#]*@)?"
    # Either a bracketed IPv6 literal in the host position followed by the
    # rest of the link, or a plain (bracket-free) remainder.  Brackets are
    # accepted ONLY in the host position: allowing them anywhere would make
    # ``[vless://a@b:443]`` and markdown links swallow the closing bracket.
    r"(?:\[[0-9A-Fa-f:.]+\][^\s<>'\"()\[\]{}]*|[^\s<>'\"()\[\]{}]+)",
    re.IGNORECASE,
)


def find_all_links(text: str) -> list[str]:
    """Find all proxy links in arbitrary text."""
    links = PROTOCOL_PATTERN.findall(text)
    # Strip trailing prose punctuation that may have been captured.
    return [link.rstrip(".,;:!?)]}>") for link in links]


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

# Valid UUID format (8-4-4-4-12 hex, hyphens optional). Module-level so it is
# compiled once, not looked up in re's internal cache on every is_garbage_config()
# call.  Accepts both hyphenated (b831381d-4cfa-...) and non-hyphenated
# (b831381d4cfa...) forms — some vmess/vless sources emit 32 hex chars without
# hyphens, which is a valid RFC 4122 representation.
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$",
)


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
    proto = protocol.lower()
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
    # TUIC v5 uses ``UUID:PASSWORD`` — the uuid half before the first colon must
    # be a real UUID.  Without this, a placeholder like ``UUID:pass`` slipped
    # through (exact-match only ever saw the whole string).  TUIC v4 uses a bare
    # token (no colon) which is arbitrary, so it is not format-validated.
    if proto == "tuic" and ":" in credential:
        uuid_part = credential.split(":", 1)[0]
        if uuid_part.upper() in ("UUID", "PASSWORD"):
            return True
        return _UUID_RE.match(uuid_part) is None
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
    if body_without_userinfo != body and _is_garbage_credential(
        scheme.strip(),
        unquote(userinfo).strip(),
    ):
        return True
    if _PLACEHOLDER_PATTERNS.search(body_without_userinfo):
        return True
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
