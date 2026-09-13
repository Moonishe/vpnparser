"""Subscription parser — decodes base64 subscription blobs into proxy links.

A *subscription* is NOT a single proxy link. It is a base64-encoded text
file containing multiple proxy links, one per line::

    subscription:BASE64_DATA
    BASE64_DATA            (raw blob, no scheme prefix — most common)

``SubscriptionParser`` does **not** extend :class:`BaseParser` because it
does not parse a single link into a :class:`Config`. Instead it decodes
the blob (handling optional zlib/gzip compression) and returns a list of
individual proxy link strings, which are then handled by the
protocol-specific parsers (vmess/vless/trojan/ss).
"""

from __future__ import annotations

import base64
import contextlib
import re
import zlib
from urllib.parse import unquote

from src.parsers.base import find_all_links

# Schemes that mark a single proxy link (not a subscription blob).
# Kept in sync with PROTOCOL_PATTERN in base.py.
_PROXY_SCHEMES: tuple[str, ...] = (
    "vmess://",
    "vless://",
    "trojan://",
    "ss://",
    "hysteria2://",
    "hy2://",
    "tuic://",
    "shadowtls://",
    "anytls://",
    "wireguard://",
)

_B64_NOISE_RE = re.compile(
    r"[\s\ufeff\u200b\u200c\u200d\u200e\u200f\u202a-\u202e\u2060]+"
)

#: Bound decompressed output so a malicious/crafted blob cannot OOM the
#: process. Subscription payloads are tiny; 32 MiB is far beyond any legit use.
_MAX_DECOMPRESSED_BYTES = 32 * 1024 * 1024


def _b64_to_bytes(data: str | None) -> bytes | None:
    """Best-effort base64 (incl. URL-safe, padded) decode to raw bytes."""
    # Percent-encoding is normalized before decoding (most visibly the
    # padding: "…fQ%3D%3D"), exactly like safe_b64decode in base.py handles
    # it.  Without this a percent-encoded padding made the strict decode
    # reject the WHOLE subscription, while the same body decoded fine as a
    # single link.  unquote() is safe here: the base64 alphabet contains no
    # "%", and unlike unquote_plus it does not turn "+" into a space.
    if data is None:
        return b""
    try:
        text = unquote(data)
    except Exception:
        return b""
    cleaned = _B64_NOISE_RE.sub("", text).replace("-", "+").replace("_", "/")
    padding = 4 - (len(cleaned) % 4)
    if padding != 4:
        cleaned += "=" * padding
    try:
        # validate=True rejects anything outside the base64 alphabet, so a
        # plain-text payload (links, not base64) is refused here and falls
        # through to the plain-text decode instead of yielding garbage bytes.
        return base64.b64decode(cleaned, validate=True)
    except Exception:
        return None


def _stream_decompress(raw: bytes, wbits: int) -> bytes:
    """Decompress with :class:`zlib.decompressobj`, capped at the safety limit.

    Uses ``max_length`` streaming so a decompression bomb (tiny input, huge
    expanded output) is stopped after ``_MAX_DECOMPRESSED_BYTES`` rather than
    allocating the whole output up front and OOM-ing the process.
    """
    out = bytearray()
    dec = zlib.decompressobj(wbits)
    data = raw
    while True:
        chunk = dec.decompress(data, 1 << 20)
        out += chunk
        if len(out) > _MAX_DECOMPRESSED_BYTES:
            raise ValueError
        data = dec.unconsumed_tail
        if not data:
            # Bound the flush too: unbounded flush() allocated past the cap
            # before the length check ran (decompression bomb via tail).
            remaining = _MAX_DECOMPRESSED_BYTES - len(out) + 1
            tail = dec.flush(remaining)
            out += tail
            if len(out) > _MAX_DECOMPRESSED_BYTES:
                raise ValueError
            break
    return bytes(out)


def _decompress_candidates(raw: bytes) -> list[bytes]:
    """Return ``raw`` plus gzip/zlib/raw-deflate decompressions, in order.

    Subscription payloads arrive in several wrapper flavours (plain, zlib,
    raw deflate, gzip). Trying each in turn avoids silently dropping a
    whole compressed subscription as "no links". Output is capped so a
    crafted payload cannot OOM the process: decompression is streamed with
    ``decompressobj(max_length=...)`` and aborts past the limit.
    """
    candidates: list[bytes] = [raw]
    for wbits in (15, -15, 31):  # zlib header, raw deflate, gzip
        with contextlib.suppress(Exception):
            candidates.append(_stream_decompress(raw, wbits))
    return candidates


def _links_from_bytes(raw: bytes) -> list[str]:
    """Decode (and, if needed, decompress) bytes, returning any proxy links."""
    best: list[str] = []
    for candidate in _decompress_candidates(raw):
        # Replacement characters instead of a strict decode: one stray
        # non-utf-8 byte (a latin-1 remark byte is enough) used to raise,
        # the whole candidate was discarded, and a two-link subscription
        # yielded zero links. find_all_links() below is the real gate —
        # garbage that still "decodes" simply yields no links.
        # Keep the candidate with the most links: a single false positive
        # in raw must not shadow a hundred real links in gzip.
        text = candidate.decode("utf-8", errors="replace")
        links = find_all_links(text)
        if len(links) > len(best):
            best = links
    return best


class SubscriptionParser:
    """Decode base64 (optionally compressed) subscription blobs into links."""

    def parse_subscription(self, data: str | None) -> list[str]:
        """Decode a subscription blob and return individual proxy links.

        Strategy:

        1. Strip an optional ``subscription:`` scheme prefix.
        2. Base64-decode the input to raw bytes.
        3. Try the raw bytes and gzip/zlib/raw-deflate decompressions; the
           first candidate that decodes to text containing proxy links wins.
        4. If decoding yields nothing, treat the input as plain text
           containing proxy links directly.

        Args:
            data: Raw subscription content — base64 (possibly compressed) or
                   plain text holding one or more proxy links.

        Returns:
            List of proxy link strings (``vmess://``, ``vless://``,
            ``trojan://``, ``ss://``). Empty list if none found.
        """
        if not data or not data.strip():
            return []

        text = data.strip()

        # Strip optional "subscription:" scheme prefix.
        if text.lower().startswith("subscription:"):
            text = text[len("subscription:") :].strip()
            if not text:
                return []

        # 1. Base64 decode → try raw + each decompression for proxy links.
        raw = _b64_to_bytes(text)
        if raw:
            links = _links_from_bytes(raw)
            if links:
                return links

        # 2. Fall back: input may already be plain text with proxy links.
        return find_all_links(text)

    def is_subscription(self, data: str | None) -> bool:
        """Detect whether a blob is likely a base64 subscription.

        A subscription blob starts with *non-scheme* characters (i.e. it
        is base64, not a direct proxy link) and decodes (possibly after
        decompression) to text containing proxy schemes.

        Args:
            data: Raw input string to inspect.

        Returns:
            ``True`` if the data looks like a base64 subscription blob
            (or plain text holding multiple proxy links without a leading
            scheme).
        """
        if not data or not data.strip():
            return False

        text = data.strip()
        lowered = text.lower()

        # A single proxy link is not a subscription.
        if lowered.startswith(_PROXY_SCHEMES):
            return False

        # Strip optional "subscription:" prefix before decoding.
        if lowered.startswith("subscription:"):
            text = text[len("subscription:") :].strip()
            if not text:
                return False

        # If base64-decoding (incl. decompression) reveals proxy links, treat
        # as subscription.
        raw = _b64_to_bytes(text)
        if raw and _links_from_bytes(raw):
            return True

        # Last resort: plain text with multiple proxy links and no
        # leading scheme — also treat as a subscription-style blob.
        return len(find_all_links(text)) > 1
