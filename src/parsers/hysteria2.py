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

Hysteria2 also supports *port hopping*: the port component may be a range or a
comma-separated list (``host:443-500``, ``host:443,8443``).
"""

from __future__ import annotations

import re
from typing import ClassVar
from urllib.parse import unquote

from src.parsers.base import (
    BaseParser,
    Config,
    extract_remark,
    parse_qs_single,
    split_host_port,
)

# Port-hopping spec: at least two ports joined by "-" (range) or "," (list).
# ASCII digits only — ``\d`` would also match e.g. Arabic-Indic numerals, which
# no client accepts.
_PORT_HOPPING_RE = re.compile(r"[0-9]{1,5}(?:[-,][0-9]{1,5})+")


def _collapse_port_hopping(hostport: str) -> str:
    """Reduce a hysteria2 port-hopping ``host:port`` to its first port.

    Port hopping (``host:443-500``, ``host:443,8443``) is standard hysteria2 and
    appears in public subscriptions, but :func:`split_host_port` needs a single
    integer.  Clients connect to the first port of the spec, so that is what the
    :class:`Config` gets; ``raw_link`` keeps the full spec for the output files.

    Args:
        hostport: ``host:port`` component with the path/query already stripped.

    Returns:
        *hostport* with a port-hopping spec replaced by its first port, or
        *hostport* unchanged when the port is a plain number (or absent).
    """
    host_part, sep, port_part = hostport.rpartition(":")
    if not sep or not _PORT_HOPPING_RE.fullmatch(port_part):
        return hostport
    first_port = port_part.replace(",", "-").split("-", 1)[0]
    return f"{host_part}:{first_port}"


class Hysteria2Parser(BaseParser):
    """Parser for hysteria2:// and hy2:// links."""

    protocol: ClassVar[str] = "hysteria2"

    # Both "hysteria2://" and the short alias "hy2://" map to this parser.
    schemes: ClassVar[tuple[str, ...]] = ("hysteria2", "hy2")

    def can_parse(self, link: str) -> bool:
        """Check if this parser handles the given link scheme.

        Returns ``False`` (never raises) for ``None`` or empty input.
        """
        if not link:
            return False
        low = link.strip().lower()
        return low.startswith("hysteria2://") or low.startswith("hy2://")

    def parse(self, link: str) -> Config | None:
        """Parse a hysteria2:// or hy2:// link into a Config object.

        Returns None if the link is malformed.
        """
        try:
            # Normalize hy2:// -> hysteria2://.  "hy2://" is 6 chars
            # (h,y,2,:,/,/) so we slice [6:] to skip the whole scheme;
            # [5:] would leave the second "/" and corrupt the password
            # with a leading "/" (e.g. "pass" -> "/pass").
            normalized = link.strip()
            low = normalized.lower()
            # Validate scheme — parse() must be self-guarding even if
            # can_parse() was not called (defence in depth: prevents
            # http://, hysteria://, etc. from being silently accepted).
            if not (low.startswith("hysteria2://") or low.startswith("hy2://")):
                return None
            if low.startswith("hy2://"):
                normalized = "hysteria2://" + normalized[6:]

            # urlparse doesn't extract userinfo for non-standard schemes,
            # so we parse manually: hysteria2://PASS@HOST:PORT?QUERY#REMARK
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
                password = unquote(userinfo).strip()
            else:
                password = ""

            # Reject empty / whitespace-only passwords (``password`` is already
            # stripped above, so the emptiness check covers both).
            if not password:
                return None

            # Strip path component (e.g. trailing "/" or "/path").
            if "/" in hostport:
                hostport = hostport.split("/", 1)[0]

            # Split host:port (handles bracketed IPv6, rejects bare IPv6).
            parsed_hp = split_host_port(_collapse_port_hopping(hostport))
            if parsed_hp is None:
                return None
            host, port = parsed_hp

            query = parse_qs_single(query_str)

            sni = query.get("sni")
            alpn = query.get("alpn")
            # obfs/obfs-password/insecure stay in raw_link — not stored in Config.

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

            # obfs/obfs_password are NOT stored in Config fields — they stay
            # encoded in raw_link (used by output generator).  Storing them in
            # cfg.path/cfg.host would break is_garbage_config (false positive on
            # "password" in obfs_password) and detect_country (false country
            # from obfs-password substring).
            return cfg
        except Exception:
            return None
