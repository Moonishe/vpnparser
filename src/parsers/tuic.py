"""TUIC protocol parser.

TUIC links look like:
    tuic://UUID:PASSWORD@HOST:PORT?params#REMARK   (v4)
    tuic://TOKEN@HOST:PORT?params#REMARK            (v5)

Query parameters:
    sni               — TLS SNI
    alpn              — TLS ALPN (usually h3)
    congestion_control — bbr / cubic / new_reno
    udp_relay_mode    — native / quic
    allow_insecure    — skip cert verification (0/1)
"""

from __future__ import annotations

from typing import ClassVar
from urllib.parse import unquote

from src.parsers.base import (
    BaseParser,
    Config,
    extract_remark,
    parse_qs_single,
    split_host_port,
)


class TuicParser(BaseParser):
    """Parser for tuic:// links (v4 and v5)."""

    protocol: ClassVar[str] = "tuic"

    def parse(self, link: str) -> Config | None:
        """Parse a tuic:// link into a Config object.

        Returns None if the link is malformed.
        """
        try:
            normalized = link.strip()
            low = normalized.lower()
            if not low.startswith("tuic://"):
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

            # Split userinfo FIRST — before stripping path.
            # If we strip path first, a credential containing "/" would be
            # truncated at the first "/" and lose the "@" separator.
            if "@" in hostport:
                userinfo, hostport = hostport.rsplit("@", 1)
                credential = unquote(userinfo)
            else:
                return None  # TUIC requires credentials

            # Reject empty / whitespace-only credentials.
            if not credential or not credential.strip():
                return None

            # v4 format (UUID:PASSWORD): both halves must be non-empty.
            # v5 format (TOKEN): a single token with no colon — already
            # validated above by the non-empty check.
            if ":" in credential:
                uuid_part, _, password_part = credential.partition(":")
                if not uuid_part.strip() or not password_part.strip():
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

            sni = query.get("sni")
            alpn = query.get("alpn")

            cfg = Config(
                protocol=self.protocol,
                address=host,
                port=port,
                uuid_or_password=credential,
                network="quic",
                security="tls",
                sni=sni,
                alpn=alpn,
                remark=remark,
                raw_link=link,
            )
            return cfg
        except Exception:
            return None
