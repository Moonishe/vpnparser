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

import logging
from typing import ClassVar
from urllib.parse import unquote, urlparse

from src.parsers.base import (
    _ALLOWED_NETWORKS,
    _ALLOWED_SECURITIES,
    _UUID_RE,
    BaseParser,
    Config,
    extract_remark,
    is_valid_host,
    parse_qs_single,
)

logger = logging.getLogger(__name__)


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
            # Percent-decode before validating: some sources percent-encode the
            # uuid (``%31%31…``), and an encoded uuid failed the _UUID_RE check
            # below and dropped the link.  Same treatment as the trojan /
            # hysteria2 / tuic credentials.  A whitespace-only userinfo still
            # fails the emptiness check after decoding+stripping.
            uuid = unquote(parsed.username or "").strip()
            host = parsed.hostname
            port = parsed.port
            if not uuid or not host or port is None:
                return None
            if not is_valid_host(host):
                return None
            # A trailing ":garbage" userinfo means the link is malformed —
            # silently keeping the username part would publish a config whose
            # credential was truncated.
            if parsed.password is not None:
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
            def _clean(key: str) -> str | None:
                raw = query.get(key)
                return raw.strip() if raw and raw.strip() else None

            # Blank values fall back to defaults: "?type=%20" is a missing
            # type (tcp), not an empty-string network that no client knows.
            network = (query.get("type") or "").strip().lower() or "tcp"
            security = (query.get("security") or "").strip().lower() or "none"
            # Unknown transports/securities cannot be probed or expressed by
            # the writers: reset to the default with a warning instead of
            # dropping the server outright.
            if network not in _ALLOWED_NETWORKS:
                logger.warning("vless unknown network %r, reset to tcp.", network)
                network = "tcp"
            if security not in _ALLOWED_SECURITIES:
                logger.warning("vless unknown security %r, reset to none.", security)
                security = "none"
            return Config(
                protocol=self.protocol,
                address=host,
                port=port,
                uuid_or_password=uuid,
                network=network,
                security=security,
                path=((query.get("path") or query.get("servicename")) or "").strip()
                or None,
                host=_clean("host"),
                sni=_clean("sni"),
                alpn=_clean("alpn"),
                fp=_clean("fp"),
                pbk=_clean("pbk"),
                sid=_clean("sid"),
                flow=_clean("flow"),
                remark=extract_remark(parsed.fragment),
                raw_link=stripped,
            )
        except Exception:
            # Never raise on malformed input — fail soft to None.
            return None
