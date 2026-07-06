"""ShadowTLS protocol parser.

ShadowTLS links look like:
    shadowtls://PASSWORD@HOST:PORT?params#REMARK

Query parameters:
    sni      — TLS SNI (required for ShadowTLS to work)
    version  — ShadowTLS version (2 or 3, default 3)
    password — password for v2 (usually in userinfo instead)

Parsing is delegated to :func:`src.parsers.base.parse_password_host_port`,
which is shared with the structurally identical AnyTLS parser.  Only
``sni`` and ``alpn`` are stored in the :class:`Config`; ``version`` and
other params stay encoded in ``raw_link``.
"""

from __future__ import annotations

from typing import ClassVar

from src.parsers.base import BaseParser, Config, parse_password_host_port


class ShadowTlsParser(BaseParser):
    """Parser for ``shadowtls://`` links (password@host:port, TLS)."""

    protocol: ClassVar[str] = "shadowtls"

    def parse(self, link: str) -> Config | None:
        """Parse a ``shadowtls://`` link into a :class:`Config`.

        Returns ``None`` if the link is malformed.
        """
        return parse_password_host_port(link, self.protocol)
