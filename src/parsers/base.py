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

    @abstractmethod
    def parse(self, link: str) -> Config | None:
        """Parse a single link into a Config object.

        Returns None if the link is malformed or doesn't match this parser's protocol.
        """
        ...

    def can_parse(self, link: str) -> bool:
        """Check if this parser handles the given link scheme."""
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


# Scheme alternation: vmess, vless, trojan, ss, hysteria2, hy2.
# "hysteria2" requires the literal "2" (Hysteria v1 is a different protocol
# with no parser here). "hy2" is the short alias and must be listed explicitly
# — otherwise hy2:// links in source text are silently dropped by
# find_all_links and never reach the parser.
PROTOCOL_PATTERN = re.compile(
    r"(?:vmess|vless|trojan|ss|hysteria2|hy2)://[^\s<>'\"]+",
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
