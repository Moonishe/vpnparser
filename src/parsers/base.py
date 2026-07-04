"""Base parser interface and Config dataclass.

Every parser (vmess, vless, trojan, ss, subscription) implements BaseParser.
Config is the unified internal representation of a proxy server.
"""

from __future__ import annotations

import base64
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
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
    def dedup_key(self) -> tuple[str, str, int, str]:
        """Key for deduplication: (protocol, host, port, credential)."""
        return (self.protocol, self.address, self.port, self.uuid_or_password)

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


PROTOCOL_PATTERN = re.compile(
    r"(?:vmess|vless|trojan|ss)://[^\s<>'\"]+",
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
    r"|\bSERVER_IP"  # SERVER_IP_1, SERVER_IP_2...
    r"|\bPUBLIC_KEY\b"  # PUBLIC_KEY_1
    r"|\bSHORT_ID\b"  # SHORT_ID_1
    r"|\bPASSWORD\b"  # literal "PASSWORD"
    r"|your[_-]?domain"  # yourdomain.com, your-domain.com
    r"|example\.com"  # example.com (IANA reserved)
    r"|SERVER_IP_\d"  # SERVER_IP_1
)


def is_garbage_config(link_or_config: str | Config) -> bool:
    """Check if a link or Config is a placeholder/template, not a real server.

    Detects:
    - Literal placeholders: UUID, SERVER_IP_1, PUBLIC_KEY, SHORT_ID, PASSWORD
    - Example domains: example.com, yourdomain.com
    - Template remarks: "Replace ... with your ..."
    """
    if isinstance(link_or_config, Config):
        cfg = link_or_config
        # Check address, uuid, sni, host, pbk, sid for placeholders.
        fields_to_check = [
            cfg.address,
            cfg.uuid_or_password,
            cfg.sni or "",
            cfg.host or "",
            cfg.pbk or "",
            cfg.sid or "",
            cfg.remark,
        ]
        combined = " ".join(str(f) for f in fields_to_check)
        if _PLACEHOLDER_PATTERNS.search(combined):
            return True
        # UUID must look like a real UUID (8-4-4-4-12 hex), not literal "UUID".
        if cfg.protocol in ("vless", "vmess") and cfg.uuid_or_password:
            if cfg.uuid_or_password.upper() == "UUID":
                return True
            if not re.match(
                r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
                cfg.uuid_or_password,
            ):
                return True
        return False

    # String link — check raw text for placeholders.
    return bool(_PLACEHOLDER_PATTERNS.search(str(link_or_config)))
