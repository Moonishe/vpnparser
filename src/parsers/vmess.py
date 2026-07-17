"""Vmess protocol parser.

Format: ``vmess://BASE64(JSON)`` — the entire payload after the scheme is
base64-encoded JSON describing the server.

JSON field mapping (see :class:`src.parsers.base.Config`):

============  ====================  ==========================================
JSON field    Config field          Notes
============  ====================  ==========================================
``add``       ``address``           server host
``port``      ``port``              cast to int
``id``        ``uuid_or_password``  vmess UUID
``ps``        ``remark``            display name
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

from src.parsers.base import _UUID_RE, BaseParser, Config, safe_b64decode


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

            address = (obj.get("add") or "").strip()
            port_raw = obj.get("port")
            uuid = (obj.get("id") or "").strip()
            if not address or port_raw is None or not uuid:
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
                network=obj.get("net") or "tcp",
                security=security,
                path=obj.get("path") or None,
                host=obj.get("host") or None,
                sni=obj.get("sni") or None,
                alpn=obj.get("alpn") or None,
                fp=obj.get("fp") or None,
                flow=obj.get("flow") or None,
                remark=obj.get("ps") or "",
                raw_link=link,
            )
        except Exception:
            # Never raise on malformed input — fail soft to None.
            return None
