"""Trojan protocol parser.

Format: ``trojan://PASSWORD@HOST:PORT?QUERY_PARAMS#REMARK``

Parsed with :func:`urllib.parse.urlparse` and
:func:`src.parsers.base.parse_qs_single`. The password (URL userinfo) is
percent-decoded with :func:`urllib.parse.unquote` so passwords containing
special characters work correctly.

Trojan uses TLS by default: if no ``security`` query param is present,
``security`` is set to ``"tls"``. Query param mapping is the same as vless.

Query param mapping (see :class:`src.parsers.base.Config`):

==============  ====================  ==========================================
Param           Config field          Notes
==============  ====================  ==========================================
``type``        ``network``           tcp / ws / grpc / h2 (default ``"tcp"``)
``security``    ``security``          tls / reality / none (default ``"tls"``)
``path``        ``path``              URL-decoded
``host``        ``host``
``sni``         ``sni``
``alpn``        ``alpn``
``fp``          ``fp``                fingerprint
``pbk``         ``pbk``               reality public key
``sid``         ``sid``               reality shortId
``flow``        ``flow``              xtls flow
==============  ====================  ==========================================
"""

from __future__ import annotations

from typing import ClassVar
from urllib.parse import unquote, urlparse

from src.parsers.base import BaseParser, Config, extract_remark, parse_qs_single


class TrojanParser(BaseParser):
    """Parser for ``trojan://`` links (URL with query params, TLS by default)."""

    protocol: ClassVar[str] = "trojan"

    def parse(self, link: str) -> Config | None:
        """Parse a ``trojan://`` link into a :class:`Config`.

        Returns ``None`` if the link is malformed or missing required parts
        (password, host, port). Defaults ``security`` to ``"tls"`` when no
        ``security`` query param is supplied.
        """
        try:
            stripped = link.strip()
            if not stripped.lower().startswith("trojan://"):
                return None

            parsed = urlparse(stripped)
            if parsed.scheme.lower() != "trojan":
                return None

            password = parsed.username
            host = parsed.hostname
            port = parsed.port
            if not password or not host or port is None:
                return None

            password = unquote(password).strip()
            # Reject empty / whitespace-only passwords after percent-decoding
            # (e.g. ``trojan://%20@host:port`` decodes to a single space).
            if not password:
                return None
            # Explicit port range check (defence in depth). CPython's urlparse
            # raises for out-of-range ports, but that is implicit; vmess
            # validates the range explicitly, so we do too for consistency.
            if not (1 <= port <= 65535):
                return None

            query = parse_qs_single(parsed.query)

            # Trojan implies TLS; only an explicit ``security`` param overrides.
            security = query.get("security") or "tls"

            return Config(
                protocol=self.protocol,
                address=host,
                port=port,
                uuid_or_password=password,
                network=query.get("type") or "tcp",
                security=security,
                path=query.get("path") or None,
                host=query.get("host") or None,
                sni=query.get("sni") or None,
                alpn=query.get("alpn") or None,
                fp=query.get("fp") or None,
                pbk=query.get("pbk") or None,
                sid=query.get("sid") or None,
                flow=query.get("flow") or None,
                remark=extract_remark(parsed.fragment),
                raw_link=link,
            )
        except Exception:
            # Never raise on malformed input — fail soft to None.
            return None
