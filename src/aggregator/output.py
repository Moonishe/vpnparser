"""Output generation for Happ and other VPN clients.

Happ (and most VPN clients) consume subscriptions in two formats:
- Base64 subscription: base64(all_links_joined_by_newline)
- Plain text: all links joined by newline (some clients prefer this)
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

from src.parsers.base import Config

# Watermark config — shown first in Happ as a "title" entry.
# Uses a dummy vmess link with LO's GitHub repo name as remark.
# The server (0.0.0.0:1) is not real — it's just a display marker.
_WATERMARK_REMARK = "Moonishe/vpnparser"
_WATERMARK_LINK = "vmess://" + base64.b64encode(
    json.dumps(
        {
            "v": "2",
            "ps": _WATERMARK_REMARK,
            "add": "0.0.0.0",
            "port": "1",
            "id": "00000000-0000-0000-0000-000000000000",
            "aid": 0,
            "scy": "auto",
            "net": "tcp",
            "type": "none",
            "tls": "none",
        }
    ).encode("utf-8")
).decode("utf-8")


def generate_plain(configs: list[Config]) -> str:
    """Generate plain text subscription (one link per line).

    Prepends a watermark entry (Moonishe/vpnparser) as the first line so
    it shows up first in Happ's server list.
    Joins raw_link fields with newline. Filters out configs with empty
    raw_link. Returns just the watermark for empty input.
    """
    links = [_WATERMARK_LINK]
    links.extend(config.raw_link for config in configs if config.raw_link)
    return "\n".join(links)


def generate_base64(configs: list[Config]) -> str:
    """Generate base64-encoded subscription (Happ format).

    Base64-encodes the plain text output (including watermark) and returns
    it as a utf-8 string.
    """
    plain = generate_plain(configs)
    return base64.b64encode(plain.encode("utf-8")).decode("utf-8")


def generate_output(configs: list[Config], fmt: str = "base64") -> str:
    """Generate subscription output.

    fmt: "base64" (default, Happ format) or "plain".
    Unknown fmt values fall back to base64.
    Never returns an empty string: the watermark entry is always the
    first line, even when *configs* is empty (the plain form is then
    just the single watermark link; the base64 form is its encoding).
    """
    if fmt == "plain":
        return generate_plain(configs)
    # "base64" or any unknown format → base64 (the Happ default).
    return generate_base64(configs)


def write_subscription(
    configs: list[Config], filepath: str, fmt: str = "base64"
) -> int:
    """Write subscription to file. Returns number of configs written.

    Generates output in the specified format and writes it to filepath.
    Creates parent directories if needed.

    The returned count is the number of configs that actually contributed
    a link to the output (i.e. those with a non-empty raw_link).
    """
    output = generate_output(configs, fmt=fmt)

    path = Path(filepath)
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)

    path.write_text(output, encoding="utf-8")

    return sum(1 for c in configs if c.raw_link)
