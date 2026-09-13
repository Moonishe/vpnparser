"""Hysteria2 protocol parser.

Hysteria2 links look like:
    hysteria2://PASSWORD@HOST:PORT?params#REMARK
    hy2://PASSWORD@HOST:PORT?params#REMARK

Query parameters:
    sni       — TLS SNI
    insecure  — skip cert verification (0/1).  Accepted but NOT validated or
                stored: Config has no field for it, so the value only
                survives inside ``raw_link`` (the pipeline publishes links
                verbatim and clients apply it themselves).
    alpn      — TLS ALPN
    obfs      — obfuscation type (salamander)
    obfs-password — obfuscation password
    mport     — port-hopping spec (``443-500``), equivalent to an authority
                range (``host:443-500``)

Hysteria2 also supports *port hopping*: the port component may be a range or a
comma-separated list (``host:443-500``, ``host:443,8443``); panels that cannot
put the range into the authority emit the same spec as the ``mport`` query
param instead.
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


def _clean_obfs(value: str | None) -> str | None:
    """Strip obfs values; whitespace-only is missing, not a value."""
    return value.strip() if value and value.strip() else None


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


def _extract_hopping_range(hostport: str) -> str | None:
    """Return the original port-hopping spec from *hostport*, if any.

    Called on the authority *before* :func:`_collapse_port_hopping` so the
    full range/list (``443-500``, ``443,8443``) survives in
    ``Config.hopping_port_range`` and the dedup key. A plain port returns
    ``None``. Bracketed IPv6 is handled without rpartitioning inside ``[]``.
    """
    hp = (hostport or "").strip()
    if not hp:
        return None
    if hp.startswith("["):
        close = hp.find("]")
        if close == -1:
            return None
        rest = hp[close + 1 :]
        if not rest.startswith(":"):
            return None
        port_part = rest[1:]
        return port_part if _PORT_HOPPING_RE.fullmatch(port_part) else None
    if ":" not in hp:
        return None
    port_part = hp.rpartition(":")[2]
    return port_part if _PORT_HOPPING_RE.fullmatch(port_part) else None


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

            query = parse_qs_single(query_str)

            # ``mport`` is the query-param spelling of port hopping (some
            # panels cannot put a range into the authority).  It only fills
            # in a MISSING authority port: an explicit plain port in the
            # authority always wins, so ``host:8443?mport=443-500`` dials
            # 8443, not 443.  An explicit authority range keeps precedence;
            # a plain (non-range) ``mport`` is ignored.
            mport = (query.get("mport") or "").strip()
            if hostport.startswith("[") and hostport.endswith("]"):
                _has_authority_port = False
            elif hostport.startswith("["):
                _close = hostport.find("]")
                _rest = hostport[_close + 1 :] if _close != -1 else ""
                _has_authority_port = _rest.startswith(":") and len(_rest) > 1
            else:
                _has_authority_port = ":" in hostport
            if (
                mport
                and not _has_authority_port
                and not _PORT_HOPPING_RE.fullmatch(hostport.rpartition(":")[2])
                and _PORT_HOPPING_RE.fullmatch(mport)
            ):
                # Authority without a port (panels that cannot put a range
                # there): "host" + mport, not ":mport" (which lost the host).
                # Bracketed IPv6 without a port ("[::1]") contains ":" inside
                # the brackets — do not rpartition it.
                if hostport.startswith("[") and hostport.endswith("]"):
                    hostport = f"{hostport}:{mport}"
                elif ":" in hostport:
                    hostport = f"{hostport.rpartition(':')[0]}:{mport}"
                else:
                    hostport = f"{hostport}:{mport}"

            # Split host:port (handles bracketed IPv6, rejects bare IPv6).
            # Preserve the hopping spec before collapsing: the first port goes
            # to Config.port, the full range to hopping_port_range (dedup).
            hopping_range = _extract_hopping_range(hostport)
            parsed_hp = split_host_port(_collapse_port_hopping(hostport))
            if parsed_hp is None:
                return None
            host, port = parsed_hp

            _sni_raw = query.get("sni")
            sni = _sni_raw.strip() if _sni_raw and _sni_raw.strip() else None
            _alpn_raw = query.get("alpn")
            alpn = _alpn_raw.strip() if _alpn_raw and _alpn_raw.strip() else None

            _obfs = _clean_obfs(query.get("obfs"))
            if _obfs is not None and _obfs.lower() not in ("salamander", "none"):
                return None
            if _obfs is not None and _obfs.lower() == "none":
                # Explicit "no obfuscation": same as the parameter missing.
                # Rejecting it used to drop live configs.
                _obfs = None
            # Hysteria2 is always TLS-based.
            cfg = Config(
                protocol=self.protocol,
                address=host,
                port=port,
                uuid_or_password=password,
                network="quic",
                security="tls",
                sni=sni,
                alpn=alpn,
                fp=None,
                pbk=None,
                sid=None,
                flow=None,
                ss_method=None,
                # Salamander obfuscation: without these the Clash writer and
                # the sing-box probe dial an obfs-required server bare, and a
                # working config is recorded dead. is_garbage_config and
                # detect_country examine the authority/remark inputs, not
                # these dedicated fields, so the false positives that
                # motivated keeping the values only in raw_link cannot recur.
                obfs=_obfs,
                obfs_password=_clean_obfs(
                    query.get("obfs-password") or query.get("obfs_password")
                ),
                hopping_port_range=hopping_range,
                remark=remark,
                raw_link=link.strip(),
            )
            return cfg
        except Exception:
            return None
