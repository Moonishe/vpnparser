"""Shadowsocks (ss://) link parser.

Handles three ss:// formats:

1. SIP002 (most common)::

       ss://BASE64(method:password)@host:port#remark

   The userinfo before ``@`` is base64-encoded ``method:password``;
   after ``@`` is the plaintext ``host:port``; after ``#`` is the
   URL-encoded remark. Query params (``?plugin=...``) are ignored.

2. Legacy::

       ss://BASE64(method:password@host:port)#remark

   The entire payload after ``ss://`` (before ``#``) is base64-encoded
   ``method:password@host:port``.

3. Plain (no base64, rare)::

       ss://method:password@host:port#remark

   Credentials appear in plaintext.
"""

from __future__ import annotations

from typing import ClassVar
from urllib.parse import unquote

from src.parsers.base import (
    BaseParser,
    Config,
    extract_remark,
    safe_b64decode,
    split_host_port,
)


class ShadowsocksParser(BaseParser):
    """Parser for ``ss://`` Shadowsocks links (SIP002, legacy, and plain)."""

    protocol: ClassVar[str] = "ss"

    def parse(self, link: str) -> Config | None:
        """Parse a single ``ss://`` link into a :class:`Config`.

        Returns ``None`` for malformed input — never raises.
        """
        try:
            raw = link.strip()
            if not raw.lower().startswith("ss://"):
                return None

            body = raw[5:]  # strip "ss://"

            # 1. Split off the remark fragment (#remark, URL-encoded).
            if "#" in body:
                main, remark_raw = body.split("#", 1)
            else:
                main, remark_raw = body, ""
            remark = extract_remark(remark_raw)

            # 2. Drop query params (?plugin=...). Plugins are unsupported.
            if "?" in main:
                main = main.split("?", 1)[0]

            method: str | None = None
            password: str | None = None
            host_port: str | None = None

            # 3. Try SIP002: BASE64(method:password)@host:port
            #    unquote first — some sources percent-encode base64 padding
            #    ("=" -> "%3D") which would otherwise be rejected by the
            #    validate=True check inside safe_b64decode.
            if "@" in main:
                left, right = main.rsplit("@", 1)
                decoded = safe_b64decode(unquote(left))
                if decoded and ":" in decoded:
                    method, password = decoded.split(":", 1)
                    host_port = right

            # 4. Try legacy: BASE64(method:password@host:port)
            if method is None:
                decoded = safe_b64decode(unquote(main))
                if decoded and "@" in decoded:
                    creds, hp = decoded.rsplit("@", 1)
                    if ":" in creds:
                        method, password = creds.split(":", 1)
                        host_port = hp

            # 5. Try plain: method:password@host:port (no base64)
            #    unquote the userinfo before splitting on ":" so that
            #    percent-encoded colons (%3A) in the password are decoded
            #    first and the split point is correct.
            if method is None and "@" in main:
                left, right = main.rsplit("@", 1)
                left = unquote(left)
                if ":" in left:
                    method, password = left.split(":", 1)
                    host_port = right

            if not method or not password or not host_port:
                return None

            # 6. Split host:port — use the shared split_host_port helper which
            #    correctly handles bracketed IPv6 ([2001:db8::1]:443) and
            #    rejects bare IPv6 (ambiguous port boundary).
            #    Strip a trailing path/slash that some links carry.
            host_port = host_port.strip()
            if "/" in host_port:
                host_port = host_port.split("/", 1)[0]
            parsed_hp = split_host_port(host_port)
            if parsed_hp is None:
                return None
            host, port = parsed_hp

            return Config(
                protocol="ss",
                address=host,
                port=port,
                uuid_or_password=password,
                ss_method=method,
                remark=remark,
                raw_link=raw,
            )
        except Exception:
            return None
