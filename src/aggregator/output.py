"""Output generation for Happ and other VPN clients.

Happ (and most VPN clients) consume subscriptions in two formats:
- Base64 subscription: base64(all_links_joined_by_newline)
- Plain text: all links joined by newline (some clients prefer this)
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import json
import logging
import os
import tempfile

from src.parsers.base import Config
from src.repo_info import github_repo_slug
from src.utils.paths import resolve_safe_output_path
from src.validators.country_filter import detect_country

logger = logging.getLogger(__name__)

# Watermark config — shown first in Happ as a "title" entry.
# Uses a dummy vmess link with the configured GitHub repo name as remark.
# The server (0.0.0.0:1) is not real — it's just a display marker.


def _repo_slug() -> str:
    """Return owner/repo for display in subscription clients."""
    return github_repo_slug()


def _watermark_payload() -> dict[str, object]:
    return {
        "v": "2",
        "ps": _repo_slug(),
        "add": "0.0.0.0",
        "port": "1",
        "id": "00000000-0000-0000-0000-000000000000",
        "aid": 0,
        "scy": "auto",
        "net": "tcp",
        "type": "none",
        "tls": "none",
    }


def _watermark_link() -> str:
    """Build the display-only vmess watermark from the current repo env.

    Computed on every call (cheap) so changes to GITHUB_OWNER/GITHUB_REPO
    after import — e.g. in tests — are reflected. Avoids import-time side
    effects.
    """
    return "vmess://" + base64.b64encode(
        json.dumps(_watermark_payload()).encode("utf-8"),
    ).decode("utf-8")


def _safe_raw_link(raw_link: str) -> str | None:
    """Return *raw_link* only when it is a single clean line.

    ``raw_link`` is rebuilt from untrusted source content (remarks, query
    parameters). A link carrying ``\\n``/``\\r`` or other control characters
    would inject arbitrary lines into the published subscription file, so it
    is dropped with a warning instead.
    """
    if not raw_link:
        return None
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in raw_link):
        logger.warning(
            "Dropped raw_link containing control characters (length %d).",
            len(raw_link),
        )
        return None
    return raw_link


def _vmess_with_country(link: str, code: str) -> str:
    """Stamp *code* into a vmess link's ``ps`` field, best effort.

    Vmess carries its display name in the base64 JSON payload rather than a
    URL fragment; some clients ignore fragments on vmess:// links entirely.
    Any payload that does not decode cleanly is returned unchanged — a lost
    country label is better than a corrupted subscription entry.
    """
    try:
        payload = link[len("vmess://") :].partition("#")[0]
        # The wild mixes standard and URL-safe alphabets and drops padding.
        normalized = payload.replace("-", "+").replace("_", "/")
        obj = json.loads(
            base64.b64decode(normalized + "=" * (-len(normalized) % 4)).decode(
                "utf-8",
                errors="replace",
            )
        )
        if not isinstance(obj, dict):
            return link
        ps = str(obj.get("ps") or "")
        if detect_country(ps) is not None:
            return link
        obj["ps"] = f"{ps}-{code}" if ps else code
        encoded = base64.b64encode(
            json.dumps(obj, ensure_ascii=False).encode("utf-8")
        ).decode("ascii")
        return "vmess://" + encoded
    except (binascii.Error, UnicodeDecodeError, ValueError, json.JSONDecodeError):
        return link


def _with_country_fragment(config: Config) -> str:
    """Return the config's raw_link with an explicit country label appended.

    The hourly fast-track revalidation reparses the published subscription,
    where the source's ``default_country`` hint no longer exists and remarks
    are often opaque numbers ("5777") that carry no country. Without a
    country the country filter drops the config before it is even probed,
    so every fast-track run shrank the published set (observed: 167 → 33
    within hours). Stamping the ISO code into the link makes the label
    survive the publish → reparse round-trip for clients as well.
    """
    link = config.raw_link
    country = config.country
    if not link or not country:
        return link
    code = str(country).upper()
    if detect_country(config.remark) is not None:
        return link
    scheme = link.split("://", 1)[0].lower()
    if scheme == "vmess":
        return _vmess_with_country(link, code)
    head, sep, frag = link.partition("#")
    if not sep or not frag:
        return f"{head}#{code}"
    # Append to the still-encoded fragment: an ASCII "-XX" suffix survives
    # any percent-encoding in front of it and extract_remark() unquotes after.
    return f"{head}#{frag}-{code}"


def generate_plain(configs: list[Config]) -> str:
    """Generate plain text subscription (one link per line).

    Prepends a watermark entry with the GitHub repo name as the first line so
    it shows up first in Happ's server list.
    Joins raw_link fields with newline. Filters out configs with empty
    raw_link. Returns just the watermark for empty input.
    """
    links = [_watermark_link()]
    for config in configs:
        safe = _safe_raw_link(_with_country_fragment(config))
        if safe:
            links.append(safe)
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
    configs: list[Config],
    filepath: str,
    fmt: str = "base64",
) -> int:
    """Write subscription to file. Returns number of configs written.

    Generates output in the specified format and writes it to filepath.
    Creates parent directories if needed.

    The returned count is the number of configs that actually contributed
    a link to the output: those with a non-empty raw_link that survived the
    control-character filter (see :func:`_safe_raw_link`).
    """
    written = sum(1 for c in configs if _safe_raw_link(c.raw_link))
    output = generate_output(configs, fmt=fmt)

    path = resolve_safe_output_path(filepath)
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)

    # Atomic write — write to temp file then rename.
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(output)
        os.replace(tmp, str(path))
    except Exception:
        with contextlib.suppress(Exception):
            os.unlink(tmp)
        raise

    return written
