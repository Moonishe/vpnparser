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
