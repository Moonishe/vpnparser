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

import logging
from typing import ClassVar
from urllib.parse import unquote, urlparse

from src.parsers.base import (
    _ALLOWED_NETWORKS,
    _ALLOWED_SECURITIES,
    BaseParser,
    Config,
    extract_remark,
    is_valid_host,
    parse_qs_single,
)

logger = logging.getLogger(__name__)


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

            # The trojan userinfo is the password as a whole, but urlparse
            # splits it on the first ":" into username/password.  Rejoin the
            # halves so a password containing colons ("pa:ss:word") survives —
            # taking ``parsed.username`` alone silently truncated it to "pa"
            # and produced a Config with unusable credentials.  An empty
            # username ("trojan://:pass@…") must not glue a leading ":" onto
            # the credential: ":pass" is not the password and fails probing.
            userinfo = parsed.username or ""
            if parsed.password is not None:
                userinfo = (
                    f"{userinfo}:{parsed.password}" if userinfo else parsed.password
                )
            host = parsed.hostname
            port = parsed.port
            if not userinfo or not host or port is None:
                return None
            if not is_valid_host(host):
                return None

            password = unquote(userinfo).strip()
            # Reject empty / whitespace-only passwords after percent-decoding
            # (e.g. ``trojan://%20@host:port`` decodes to a single space).  A
            # userinfo made of bare ":" separators carries no credential either.
            if not password or not password.strip(":"):
                return None
            # Explicit port range check (defence in depth). CPython's urlparse
            # raises for out-of-range ports, but that is implicit; vmess
            # validates the range explicitly, so we do too for consistency.
            if not (1 <= port <= 65535):
                return None

            query = parse_qs_single(parsed.query)

            # Trojan implies TLS; only an explicit ``security`` param overrides.
            # A blank value ("?security=%20") is a missing value, not an
            # empty-string scheme — it must not silently drop TLS.
            security = (query.get("security") or "").strip().lower() or "tls"
            network = (query.get("type") or "").strip().lower() or "tcp"
            if network not in _ALLOWED_NETWORKS:
                logger.warning("trojan unknown network %r, reset to tcp.", network)
                network = "tcp"
            if security not in _ALLOWED_SECURITIES:
                logger.warning("trojan unknown security %r, reset to tls.", security)
                security = "tls"

            def _clean(key: str) -> str | None:
                raw = query.get(key)
                return raw.strip() if raw and raw.strip() else None

            return Config(
                protocol=self.protocol,
                address=host,
                port=port,
                uuid_or_password=password,
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
