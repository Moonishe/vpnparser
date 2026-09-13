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
``net``       ``network``           default ``"tcp"``; stripped/lower-cased
``host``      ``host``              ws Host header / grpc authority
``path``      ``path``              ws path / grpc serviceName
``tls``       ``security``          ``"tls"`` if value is ``"tls"`` else ``"none"``
``sni``       ``sni``
``alpn``      ``alpn``
``fp``        ``fp``                fingerprint
``flow``      ``flow``              xtls-rprx-vision etc.
``type``      —                     header type; not stored (no Config field)
``aid``       ``alter_id``          alterId; Xray >= 1.8.5 ignores it (AEAD-only)
``scy``       —                     vmess encryption mode; ignored
``v``         —                     version; ignored
============  ====================  ==========================================
"""

from __future__ import annotations

import json
import logging
from typing import ClassVar

from src.parsers.base import (
    _ALLOWED_NETWORKS,
    _UUID_RE,
    BaseParser,
    Config,
    cap_remark,
    extract_remark,
    is_valid_host,
    safe_b64decode,
)

logger = logging.getLogger(__name__)


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
    result = value if isinstance(value, str) else str(value)
    # json.loads accepts ``\uXXXX`` escapes for lone surrogates (``A\ud800B``),
    # which no downstream ``.encode()`` can serialize: dedup_key's hashlib
    # sha256 raised UnicodeEncodeError and one crafted link crashed the whole
    # run (and permanently disabled dedup in the filter stage). Drop the
    # surrogate bytes at the single entry point.
    try:
        result.encode("utf-8")
    except UnicodeEncodeError:
        result = result.encode("utf-8", "ignore").decode("utf-8")
    return result


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
            if not is_valid_host(address):
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
            # Panels emit "tls", "TLS", "true", "1" — all mean TLS enabled.
            security = (
                "tls"
                if str(tls_field).strip().lower() in ("tls", "true", "1")
                else "none"
            )

            # Xray-core >= 1.8.5 removed legacy vmess MD5 auth and ignores
            # ``aid`` (the client is AEAD-only; modern servers accept AEAD
            # for the primary UUID regardless of aid). Older cores still
            # need the panel's real value, so it is preserved, not dropped.
            aid_raw = obj.get("aid")
            alter_id: int | None = None
            if aid_raw is not None and not isinstance(aid_raw, bool):
                if isinstance(aid_raw, float) and not aid_raw.is_integer():
                    aid_int = None
                else:
                    try:
                        aid_int = int(aid_raw)
                    except (TypeError, ValueError):
                        aid_int = None
                if aid_int is not None and 0 <= aid_int <= 65535:
                    alter_id = aid_int

            # ``type`` is the transport header type ("none"/"http"). Config has
            # no header_type field, so it is intentionally not stored.
            # ``scy`` and ``v`` are vmess-specific and not needed.

            def _opt(key: str) -> str | None:
                raw = _json_str_or_none(obj.get(key))
                if raw is None:
                    return None
                cleaned = raw.strip()
                return cleaned or None

            ps_raw = _json_str_or_none(obj.get("ps"))

            network = (
                str(_json_str_or_none(obj.get("net")) or "")
            ).strip().lower() or "tcp"
            # Panels emit the transport with stray whitespace or uppercase
            # (``"ws "``, ``"WS"``). clash.py matches Config.network against
            # its supported set exactly, so a raw value silently published a
            # ws config as plain TCP — normalise once, here. Unknown values
            # reset to tcp with a warning instead of dropping the server.
            if network not in _ALLOWED_NETWORKS:
                logger.warning("vmess unknown network %r, reset to tcp.", network)
                network = "tcp"

            return Config(
                protocol=self.protocol,
                address=address,
                port=port,
                uuid_or_password=uuid,
                network=network,
                security=security,
                path=_opt("path"),
                host=_opt("host"),
                sni=_opt("sni"),
                alpn=_opt("alpn"),
                fp=_opt("fp"),
                flow=_opt("flow"),
                alter_id=alter_id,
                remark=cap_remark(ps_raw)
                if (ps_raw or "").strip()
                else extract_remark(fragment),
                raw_link=stripped,
            )
        except Exception:
            # Never raise on malformed input — fail soft to None.
            return None
