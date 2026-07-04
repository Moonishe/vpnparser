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

from src.parsers.base import BaseParser, Config, extract_remark, safe_b64decode


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
            if "@" in main:
                left, right = main.rsplit("@", 1)
                decoded = safe_b64decode(left)
                if decoded and ":" in decoded:
                    method, password = decoded.split(":", 1)
                    host_port = right

            # 4. Try legacy: BASE64(method:password@host:port)
            if method is None:
                decoded = safe_b64decode(main)
                if decoded and "@" in decoded:
                    creds, hp = decoded.rsplit("@", 1)
                    if ":" in creds:
                        method, password = creds.split(":", 1)
                        host_port = hp

            # 5. Try plain: method:password@host:port (no base64)
            if method is None and "@" in main:
                left, right = main.rsplit("@", 1)
                if ":" in left:
                    method, password = left.split(":", 1)
                    host_port = right

            if method is None or password is None or not host_port:
                return None

            # 6. Split host:port (rsplit handles bracketed IPv6 addresses).
            #    Strip a trailing path/slash that some links carry.
            host_port = host_port.strip().rstrip("/")
            if ":" not in host_port:
                return None
            host, port_str = host_port.rsplit(":", 1)
            host = host.strip()
            if not host:
                return None
            try:
                port = int(port_str)
            except ValueError:
                return None
            if port <= 0 or port > 65535:
                return None

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
