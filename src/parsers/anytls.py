"""AnyTLS protocol parser.

AnyTLS links look like:
    anytls://PASSWORD@HOST:PORT?params#REMARK

Query parameters:
    sni      — TLS SNI
    alpn     — TLS ALPN
    insecure — skip cert verification (0/1)

Parsing is delegated to :func:`src.parsers.base.parse_password_host_port`,
which is shared with the structurally identical ShadowTLS parser.  Only
``sni`` and ``alpn`` are stored in the :class:`Config`; ``insecure`` and
other params stay encoded in ``raw_link``.
"""

from __future__ import annotations

from typing import ClassVar

from src.parsers.base import BaseParser, Config, parse_password_host_port


class AnyTlsParser(BaseParser):
    """Parser for ``anytls://`` links (password@host:port, TLS)."""

    protocol: ClassVar[str] = "anytls"

    def parse(self, link: str) -> Config | None:
        """Parse an ``anytls://`` link into a :class:`Config`.

        Returns ``None`` if the link is malformed.
        """
        return parse_password_host_port(link, self.protocol)
