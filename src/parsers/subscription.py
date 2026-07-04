"""Subscription parser — decodes base64 subscription blobs into proxy links.

A *subscription* is NOT a single proxy link. It is a base64-encoded text
file containing multiple proxy links, one per line::

    subscription:BASE64_DATA
    BASE64_DATA            (raw blob, no scheme prefix — most common)

``SubscriptionParser`` does **not** extend :class:`BaseParser` because it
does not parse a single link into a :class:`Config`. Instead it decodes
the blob and returns a list of individual proxy link strings, which are
then handled by the protocol-specific parsers (vmess/vless/trojan/ss).
"""

from __future__ import annotations

from src.parsers.base import find_all_links, safe_b64decode

# Schemes that mark a single proxy link (not a subscription blob).
_PROXY_SCHEMES: tuple[str, ...] = (
    "vmess://",
    "vless://",
    "trojan://",
    "ss://",
)


class SubscriptionParser:
    """Decode base64 subscription blobs into lists of proxy links."""

    def parse_subscription(self, data: str) -> list[str]:
        """Decode a subscription blob and return individual proxy links.

        Strategy:

        1. Strip an optional ``subscription:`` scheme prefix.
        2. Try to base64-decode the input via :func:`safe_b64decode`.
        3. If decoding yields text containing proxy links, return them.
        4. If decoding fails (or yields no links), treat the input as
           plain text and extract any proxy links directly.

        Args:
            data: Raw subscription content — either a base64-encoded blob
                  or plain text containing one or more proxy links.

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

        # 1. Try base64 decode → look for proxy links in decoded text.
        decoded = safe_b64decode(text)
        if decoded:
            links = find_all_links(decoded)
            if links:
                return links

        # 2. Fall back: input may already be plain text with proxy links.
        return find_all_links(text)

    def is_subscription(self, data: str) -> bool:
        """Detect whether a blob is likely a base64 subscription.

        A subscription blob starts with *non-scheme* characters (i.e. it
        is base64, not a direct proxy link) and decodes to text containing
        proxy schemes.

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

        # If base64-decoding reveals proxy links, treat as subscription.
        decoded = safe_b64decode(text)
        if decoded:
            if find_all_links(decoded):
                return True

        # Last resort: plain text with multiple proxy links and no
        # leading scheme — also treat as a subscription-style blob.
        return len(find_all_links(text)) > 1
