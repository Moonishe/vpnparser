"""Output generation for Happ and other VPN clients.

Happ (and most VPN clients) consume subscriptions in two formats:
- Base64 subscription: base64(all_links_joined_by_newline)
- Plain text: all links joined by newline (some clients prefer this)
"""

from __future__ import annotations

import base64
from pathlib import Path

from src.parsers.base import Config


def generate_plain(configs: list[Config]) -> str:
    """Generate plain text subscription (one link per line).

    Joins raw_link fields with newline. Filters out configs with empty
    raw_link. Returns an empty string for empty input or when no config
    has a raw_link.
    """
    if not configs:
        return ""

    links = [config.raw_link for config in configs if config.raw_link]
    return "\n".join(links)


def generate_base64(configs: list[Config]) -> str:
    """Generate base64-encoded subscription (Happ format).

    Base64-encodes the plain text output and returns it as a utf-8 string.
    Returns an empty string for empty input (no point encoding empty text).
    """
    plain = generate_plain(configs)
    if not plain:
        return ""

    return base64.b64encode(plain.encode("utf-8")).decode("utf-8")


def generate_output(configs: list[Config], fmt: str = "base64") -> str:
    """Generate subscription output.

    fmt: "base64" (default, Happ format) or "plain".
    Unknown fmt values fall back to base64.
    Returns an empty string for empty input.
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
