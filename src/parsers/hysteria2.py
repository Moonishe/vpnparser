"""Hysteria2 protocol parser.

Hysteria2 links look like:
    hysteria2://PASSWORD@HOST:PORT?params#REMARK
    hy2://PASSWORD@HOST:PORT?params#REMARK

Query parameters:
    sni       — TLS SNI
    insecure  — skip cert verification (0/1)
    alpn      — TLS ALPN
    obfs      — obfuscation type (salamander)
    obfs-password — obfuscation password
"""

from __future__ import annotations

from urllib.parse import urlparse, unquote

from src.parsers.base import BaseParser, Config, extract_remark, parse_qs_single


class Hysteria2Parser(BaseParser):
    """Parser for hysteria2:// and hy2:// links."""

    protocol: str = "hysteria2"

    def can_parse(self, link: str) -> bool:
        """Check if this parser handles the given link scheme."""
        low = link.strip().lower()
        return low.startswith("hysteria2://") or low.startswith("hy2://")

    def parse(self, link: str) -> Config | None:
        """Parse a hysteria2:// or hy2:// link into a Config object.

        Returns None if the link is malformed.
        """
        try:
            # Normalize hy2:// -> hysteria2://
            normalized = link.strip()
            if normalized.lower().startswith("hy2://"):
                normalized = "hysteria2://" + normalized[5:]

            # urlparse doesn't extract userinfo for non-standard schemes,
            # so we parse manually: hysteria2://PASS@HOST:PORT?QUERY#REMARK
            if "://" not in normalized:
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

            # Split userinfo (password)
            if "@" in hostport:
                userinfo, hostport = hostport.rsplit("@", 1)
                password = unquote(userinfo)
            else:
                password = ""

            if not password:
                return None

            # Split host:port
            if ":" not in hostport:
                return None
            host, port_str = hostport.rsplit(":", 1)
            host = host.strip("[]")  # IPv6 brackets
            if not host:
                return None
            try:
                port = int(port_str)
            except ValueError:
                return None
            if not (1 <= port <= 65535):
                return None

            query = parse_qs_single(query_str)

            sni = query.get("sni")
            alpn = query.get("alpn")
            insecure = query.get("insecure", "0")
            obfs = query.get("obfs")
            obfs_password = query.get("obfs-password")

            # Hysteria2 is always TLS-based.
            cfg = Config(
                protocol=self.protocol,
                address=host,
                port=port,
                uuid_or_password=password,
                network="tcp",
                security="tls",
                sni=sni,
                alpn=alpn,
                fp=None,
                pbk=None,
                sid=None,
                flow=None,
                ss_method=None,
                remark=remark,
                raw_link=link,
            )

            # Store obfs info in path/host fields if present.
            if obfs:
                cfg.path = obfs
            if obfs_password:
                cfg.host = obfs_password

            return cfg
        except Exception:
            return None
