"""TUIC protocol parser.

TUIC links look like:
    tuic://TOKEN@HOST:PORT?params#REMARK            (v4)
    tuic://UUID:PASSWORD@HOST:PORT?params#REMARK   (v5)

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
                credential = unquote(userinfo).strip()
            else:
                return None  # TUIC requires credentials

            # Reject empty / whitespace-only credentials (e.g. ``tuic://%20@…``
            # decodes to a single space, which is not a real credential).
            if not credential:
                return None

            # v4 format (TOKEN): a single opaque token — already validated
            # above by the non-empty check. A v4 token may legally contain
            # ":" (e.g. "%3A"-decoded): it is still one credential.
            # v5 format (UUID:PASSWORD): both halves must be non-empty; a
            # non-UUID head is not a v5 pair, so the whole credential stays
            # a v4 token instead of being dropped. The probe decides whether
            # the server accepts it.
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

            _sni_raw = query.get("sni")
            sni = _sni_raw.strip() if _sni_raw and _sni_raw.strip() else None
            _alpn_raw = query.get("alpn")
            alpn = _alpn_raw.strip() if _alpn_raw and _alpn_raw.strip() else None

            def _clean_opt(key: str) -> str | None:
                # Mihomo expects lowercase ("bbr", not " BBR ").
                raw = query.get(key)
                cleaned = raw.strip().lower() if raw and raw.strip() else ""
                return cleaned or None

            _cc = _clean_opt("congestion_control")
            if _cc is not None and _cc not in ("bbr", "cubic", "new_reno"):
                return None
            _urm = _clean_opt("udp_relay_mode")
            if _urm is not None and _urm not in ("native", "quic"):
                return None
            cfg = Config(
                protocol=self.protocol,
                address=host,
                port=port,
                uuid_or_password=credential,
                network="quic",
                security="tls",
                sni=sni,
                alpn=alpn,
                congestion_control=_cc,
                udp_relay_mode=_urm,
                remark=remark,
                raw_link=link.strip(),
            )
            return cfg
        except Exception:
            return None
