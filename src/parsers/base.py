"""Base parser interface and Config dataclass.

Every parser (vmess, vless, trojan, ss, subscription) implements BaseParser.
Config is the unified internal representation of a proxy server.
"""

from __future__ import annotations

import base64
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import ClassVar
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

    @property
    def dedup_key(self) -> tuple[str, int]:
        """Key for deduplication: (address, port).

        One server = one config, regardless of protocol/uuid.
        This avoids cluttering output with multiple configs for the same server.
        """
        return (self.address, self.port)

    def to_dict(self) -> dict:
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


def safe_b64decode(data: str) -> str:
    """Base64 decode with padding fix and utf-8 fallback."""
    # strip whitespace and URL-safe chars
    cleaned = data.strip().replace("-", "+").replace("_", "/")
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
    link: str, protocol: str, *, network: str = "tcp"
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
            password = unquote(userinfo)
        else:
            password = ""

        # Reject empty / whitespace-only passwords.
        if not password or not password.strip():
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
    r"(?:vmess|vless|trojan|ss|hysteria2|hy2|tuic|shadowtls|anytls)://[^\s<>'\"]+",
    re.IGNORECASE,
)


def find_all_links(text: str) -> list[str]:
    """Find all proxy links in arbitrary text."""
    return PROTOCOL_PATTERN.findall(text)


# --- garbage / placeholder detection ---

# Placeholders used in example/template configs (not real servers).
_PLACEHOLDER_PATTERNS = re.compile(
    r"(?i)"
    r"\bUUID\b"  # literal "UUID" instead of real uuid
    r"|\bSERVER_IP"  # SERVER_IP, SERVER_IP_1, SERVER_IP_2... (no trailing \b: _ is a word char)
    r"|\bPUBLIC_KEY"  # PUBLIC_KEY, PUBLIC_KEY_1, ... (no trailing \b: would block _N suffix)
    r"|\bSHORT_ID"  # SHORT_ID, SHORT_ID_1, ... (no trailing \b: would block _N suffix)
    r"|\bPASSWORD\b"  # literal "PASSWORD"
    r"|\byour[_-]?domain\b"  # yourdomain.com, your-domain.com (word-bounded: not yourdomains.com)
    r"|\bexample\.com\b"  # example.com (IANA reserved; word-bounded: not bestexample.com)
)

# Advertising in remark — Telegram handles, URLs, promotional text.
# These configs are real servers but the remark is an ad for a channel/site.
# We filter them out so the subscription stays clean.
_AD_PATTERNS = re.compile(
    r"@"
    r"|https?://"
    r"|\.com\b"
    r"|\.net\b"
    r"|\.org\b"
    r"|\.ru\b"
    r"|\.ir\b"
    r"|\.io\b"
    r"|openproxylist"
    r"|oneclickvpn"
    r"|v2ray.*pool"
    r"|shadowproxy"
    r"|gozargah"
)

# Valid UUID format (8-4-4-4-12 hex, hyphens optional). Module-level so it is
# compiled once, not looked up in re's internal cache on every is_garbage_config()
# call.  Accepts both hyphenated (b831381d-4cfa-...) and non-hyphenated
# (b831381d4cfa...) forms — some vmess/vless sources emit 32 hex chars without
# hyphens, which is a valid RFC 4122 representation.
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$"
)


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
            if _AD_PATTERNS.search(cfg.remark):
                return True
        # uuid_or_password: check for literal placeholder values only.
        if cfg.uuid_or_password:
            uop_upper = cfg.uuid_or_password.upper()
            if uop_upper in ("UUID", "PASSWORD"):
                return True
            # UUID must look like a real UUID (8-4-4-4-12 hex, hyphens optional),
            # not literal "UUID". Accepts both hyphenated and non-hyphenated forms
            # (some vmess/vless sources emit 32 hex chars without hyphens).
            if cfg.protocol in ("vless", "vmess"):
                if not _UUID_RE.match(cfg.uuid_or_password):
                    return True
        else:
            # vless/vmess with empty uuid = garbage.
            if cfg.protocol in ("vless", "vmess"):
                return True
        return False

    # String link — check raw text for placeholders.
    return bool(_PLACEHOLDER_PATTERNS.search(str(link_or_config)))
