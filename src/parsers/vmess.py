"""Vmess protocol parser.

Format: ``vmess://BASE64(JSON)`` — the payload after the scheme is
base64-encoded JSON describing the server.  An optional ``#remark`` fragment
may follow the payload (``vmess://BASE64#remark``); it is used as the display
name when the JSON ``ps`` field is empty.

JSON field mapping (see :class:`src.parsers.base.Config`):

============  ====================  ==========================================
JSON field    Config field          Notes
============  ====================  ==========================================
``add``       ``address``           server host
``port``      ``port``              cast to int
``id``        ``uuid_or_password``  vmess UUID
``ps``        ``remark``            display name (falls back to ``#remark``)
``net``       ``network``           default ``"tcp"``
``host``      ``host``              ws Host header / grpc authority
``path``      ``path``              ws path / grpc serviceName
``tls``       ``security``          ``"tls"`` if value is ``"tls"`` else ``"none"``
``sni``       ``sni``
``alpn``      ``alpn``
``fp``        ``fp``                fingerprint
``flow``      ``flow``              xtls-rprx-vision etc.
``type``      —                     header type; not stored (no Config field)
``aid``       —                     alterId; ignored
``scy``       —                     vmess encryption mode; ignored
``v``         —                     version; ignored
============  ====================  ==========================================
"""

from __future__ import annotations

import json
from typing import ClassVar

from src.parsers.base import (
    _UUID_RE,
    BaseParser,
    Config,
    extract_remark,
    safe_b64decode,
)


def _json_str_or_none(value: object) -> str | None:
    """Coerce an optional vmess JSON field to ``str | None``.

    The vmess JSON spec says these fields are strings, but panels emit numbers
    freely (``"ps": 2`` for an auto-numbered node, ``"path": 0``).  Storing the
    raw value put a non-``str`` into :class:`Config`, and the first consumer to
    call a string method on it (``is_garbage_config`` does ``remark.upper()``)
    raised, killing the whole pipeline run over a single link.

    Args:
        value: Raw JSON value (``str``, number, ``None``, ...).

    Returns:
        ``None`` for falsy values (matching the previous ``x or None``), the
        string itself when already a ``str``, else ``str(value)``.
    """
    if not value:
        return None
    return value if isinstance(value, str) else str(value)


class VmessParser(BaseParser):
    """Parser for ``vmess://`` links (base64-encoded JSON payload)."""

    protocol: ClassVar[str] = "vmess"

    def parse(self, link: str) -> Config | None:
        """Parse a ``vmess://`` link into a :class:`Config`.

        Returns ``None`` if the link is malformed, not vmess, contains
        invalid base64, or holds invalid/missing JSON fields.
        """
        try:
            stripped = link.strip()
            if not stripped.lower().startswith("vmess://"):
                return None

            payload = stripped[len("vmess://") :]
            # ``vmess://BASE64#remark`` occurs in the wild.  The fragment must
            # be removed BEFORE decoding: remark chars are valid base64 and
            # would otherwise be spliced into the stream, breaking the JSON.
            payload, _, fragment = payload.partition("#")
            if not payload:
                return None

            decoded = safe_b64decode(payload)
            if not decoded:
                return None

            try:
                obj = json.loads(decoded)
            except (json.JSONDecodeError, ValueError):
                return None
            if not isinstance(obj, dict):
                return None

            # ``add``/``id`` must be strings: they feed DNS lookups, the dedup
            # key and the UUID check, so a numeric value means this is not a
            # real vmess payload.  Checked explicitly instead of relying on
            # ``.strip()`` raising into the catch-all below.
            address_raw = obj.get("add")
            uuid_raw = obj.get("id")
            if not isinstance(address_raw, str) or not isinstance(uuid_raw, str):
                return None
            address = address_raw.strip()
            port_raw = obj.get("port")
            uuid = uuid_raw.strip()
            if not address or port_raw is None or not uuid:
                return None
            # An IPv6 ``add`` may be bracketed ("[2001:db8::1]").  Every other
            # parser goes through urlparse/split_host_port, which strip the
            # brackets, so strip them here too: otherwise the dedup key differs
            # from the same server seen via another protocol and getaddrinfo
            # rejects the bracketed form at connect time.
            if address.startswith("[") and address.endswith("]"):
                address = address[1:-1].strip()
                if not address:
                    return None
            # A vmess ``id`` must be a valid UUID (8-4-4-4-12 hex, hyphens
            # optional). Rejecting here honours the documented contract
            # ("invalid JSON fields → None") and stops garbage early. Uses
            # the same regex as is_garbage_config for consistency.
            if not _UUID_RE.match(uuid):
                return None

            # Reject bool ports: ``int(True) == 1`` would silently accept a
            # meaningless boolean as port 1. Reject non-integral floats too:
            # ``int(443.5) == 443`` silently truncates, corrupting the port.
            if isinstance(port_raw, bool):
                return None
            try:
                port = int(port_raw)
            except (TypeError, ValueError):
                return None
            if isinstance(port_raw, float) and not port_raw.is_integer():
                return None
            if not (1 <= port <= 65535):
                return None

            tls_field = obj.get("tls")
            security = "tls" if tls_field == "tls" else "none"

            # ``type`` is the transport header type ("none"/"http"). Config has
            # no header_type field, so it is intentionally not stored.
            # ``aid``, ``scy`` and ``v`` are vmess-specific and not needed.

            return Config(
                protocol=self.protocol,
                address=address,
                port=port,
                uuid_or_password=uuid,
                network=_json_str_or_none(obj.get("net")) or "tcp",
                security=security,
                path=_json_str_or_none(obj.get("path")),
                host=_json_str_or_none(obj.get("host")),
                sni=_json_str_or_none(obj.get("sni")),
                alpn=_json_str_or_none(obj.get("alpn")),
                fp=_json_str_or_none(obj.get("fp")),
                flow=_json_str_or_none(obj.get("flow")),
                remark=_json_str_or_none(obj.get("ps")) or extract_remark(fragment),
                raw_link=link,
            )
        except Exception:
            # Never raise on malformed input — fail soft to None.
            return None
