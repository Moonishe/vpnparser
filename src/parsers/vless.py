"""Vless protocol parser.

Format: ``vless://UUID@HOST:PORT?QUERY_PARAMS#REMARK``

Parsed with :func:`urllib.parse.urlparse` and
:func:`src.parsers.base.parse_qs_single`.

Query param mapping (see :class:`src.parsers.base.Config`):

==============  ====================  ==========================================
Param           Config field          Notes
==============  ====================  ==========================================
``type``        ``network``           tcp / ws / grpc / h2 (default ``"tcp"``)
``security``    ``security``          tls / reality / none (default ``"none"``)
``path``        ``path``              URL-decoded
``host``        ``host``
``sni``         ``sni``
``alpn``        ``alpn``
``fp``          ``fp``                fingerprint
``pbk``         ``pbk``               reality public key
``sid``         ``sid``               reality shortId
``flow``        ``flow``
``encryption``  —                     always ``"none"`` for vless; ignored
``headerType``  —                     not stored (no Config field)
==============  ====================  ==========================================
"""

from __future__ import annotations

from typing import ClassVar
from urllib.parse import urlparse

from src.parsers.base import (
    _UUID_RE,
    BaseParser,
    Config,
    extract_remark,
    parse_qs_single,
)


class VlessParser(BaseParser):
    """Parser for ``vless://`` links (URL with query params)."""

    protocol: ClassVar[str] = "vless"

    def parse(self, link: str) -> Config | None:
        """Parse a ``vless://`` link into a :class:`Config`.

        Returns ``None`` if the link is malformed or missing required parts
        (UUID, host, port).
        """
        try:
            stripped = link.strip()
            if not stripped.lower().startswith("vless://"):
                return None

            parsed = urlparse(stripped)
            uuid = (parsed.username or "").strip()
            host = parsed.hostname
            port = parsed.port
            if not uuid or not host or port is None:
                return None
            # Explicit port range check (defence in depth). CPython's urlparse
            # raises for out-of-range ports, but relying on that is implicit
            # and fragile; vmess validates the range explicitly, so we do too.
            if not (1 <= port <= 65535):
                return None
            # A vless userinfo must be a valid UUID (8-4-4-4-12 hex, hyphens
            # optional). Same regex as is_garbage_config — a non-UUID userinfo
            # is malformed and would be filtered as garbage downstream anyway,
            # so rejecting it here is safe and matches the documented contract.
            if not _UUID_RE.match(uuid):
                return None

            query = parse_qs_single(parsed.query)

            # ``headerType`` is intentionally not read: Config has no field for
            # the transport header type. ``encryption`` is always "none" for
            # vless and is therefore ignored.
            return Config(
                protocol=self.protocol,
                address=host,
                port=port,
                uuid_or_password=uuid,
                network=query.get("type") or "tcp",
                security=query.get("security") or "none",
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
