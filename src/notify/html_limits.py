"""Telegram message limits: UTF-16 length, safe HTML truncation, flood waits.

Truncation is measured in UTF-16 code units — Telegram's actual limit — and
never cuts inside a tag or an entity, both of which make Telegram reject the
whole message. Extracted from telegram.py so the limits logic is testable
without the transport.
"""

from __future__ import annotations

import json

# Telegram bot tokens have format: <digits>:<alphanumeric_hash>
# e.g. "123456789:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"
_TOKEN_MIN_LEN = 20

# Characters http.client rejects inside a URL path (C0 controls, space, DEL,
# plus C1 controls 0x80-0x9F which some stacks also reject when quoting URLs).
# The token is interpolated into the sendMessage URL, and the rejection message
# quotes that whole path — so a token pasted into .env with an embedded newline
# would end up in the log verbatim.  Refuse it before it reaches urllib.
_URL_FORBIDDEN_CHARS = frozenset(
    chr(code) for code in (*range(0x21), 0x7F, *range(0x80, 0xA0))
)

# HTML tags used in the notification template that need closing when truncated.
_SELF_CLOSING_TAGS = {"br", "hr"}
_PAIRED_TAGS = ("b", "i", "u", "s", "a", "code", "pre", "blockquote", "tg-spoiler")

# Telegram sendMessage rejects text longer than this with a 400.
# The limit is measured in UTF-16 code units, not Python code points: every
# character outside the BMP (flag emoji are surrogate pairs = 4 units) counts
# twice, and this template is emoji-dense. Truncating by len() alone produced
# 4100+ unit messages that Telegram rejected with 400 "message is too long".
_TELEGRAM_MAX_TEXT = 4096

# Longest entity html.escape() can emit ("&quot;" / "&#x27;") plus slack.
_MAX_ENTITY_LEN = 8

_ELLIPSIS = "..."

# One retry is enough for the flood limit: two runs colliding (a manual
# workflow_dispatch on top of the hourly schedule) is the realistic case, and
# without it the "subscription updated" message is simply lost.
_SEND_ATTEMPTS = 2

# Used when a 429 body carries no usable ``retry_after``.
_DEFAULT_FLOOD_WAIT = 3.0

# Upper bound on an honoured ``retry_after`` — a bogus value must not park the
# pipeline for hours.
_MAX_FLOOD_WAIT = 30.0


def _utf16_len(text: str) -> int:
    """Length Telegram actually enforces: UTF-16 code units."""
    # surrogatepass: remarks come from untrusted source text, and a lone
    # surrogate there must not crash the notify step (it counts as 2 units).
    return len(text.encode("utf-16-le", errors="surrogatepass")) // 2


def _flood_wait_seconds(body: str) -> float:
    """Return the delay to honour before retrying a flood-limited send.

    Telegram answers a flood limit with HTTP 429 and
    ``{"parameters": {"retry_after": N}}``.

    Args:
        body: Decoded response body of the 429 answer.

    Returns:
        Seconds to wait, clamped to ``_MAX_FLOOD_WAIT``.
    """
    try:
        parameters = json.loads(body).get("parameters")
        raw = parameters.get("retry_after")
    except (AttributeError, TypeError, ValueError):
        return _DEFAULT_FLOOD_WAIT
    try:
        seconds = float(raw)
    except (TypeError, ValueError):
        return _DEFAULT_FLOOD_WAIT
    import math

    if not math.isfinite(seconds):
        return _DEFAULT_FLOOD_WAIT
    return min(max(0.0, seconds), _MAX_FLOOD_WAIT)


def _safe_cut_offset(text: str, limit: int) -> int:
    """Return an offset ``<= limit`` at which ``text`` can be split safely.

    ``text[:offset]`` never ends inside an HTML tag or a half-written
    ``&entity;`` — both would make Telegram reject the message with
    "can't parse entities".
    """
    cut = min(limit, len(text))
    # Avoid cutting inside an HTML entity (&...;) — back up to '&'.  The ';'
    # must land *inside* text[:cut], so the search bound is exclusive: a ';'
    # at index cut is not part of the slice.
    last_amp = text.rfind("&", max(0, cut - _MAX_ENTITY_LEN), cut)
    if last_amp != -1 and text.find(";", last_amp, cut) == -1:
        cut = last_amp
    # Avoid cutting between '<' and '>' (inside a tag).  Backing up once is not
    # enough: with runs like "a<<b" the new boundary lands right after another
    # '<', so the prefix would again end on an unclosed tag opener.  ``cut``
    # strictly decreases every round, so the loop always terminates.
    while True:
        last_open = text.rfind("<", 0, cut)
        if last_open == -1 or text.find(">", last_open, cut) != -1:
            break
        cut = last_open
    return max(0, cut)


def _open_tags(text: str) -> list[str]:
    """Return the paired tags left open in ``text``, outermost first."""
    open_stack: list[str] = []
    pos = 0
    while pos < len(text):
        lt = text.find("<", pos)
        if lt == -1:
            break
        gt = text.find(">", lt)
        if gt == -1:
            break
        tag_text = text[lt + 1 : gt].strip()
        pos = gt + 1
        if not tag_text:
            continue
        if tag_text.startswith("/"):
            # A nameless closing tag ("</>", "</ >") has nothing to pop, and
            # split() on the empty remainder yields no element to index.
            closing = tag_text[1:].split()
            if not closing:
                continue
            name = closing[0].lower()
            for i in range(len(open_stack) - 1, -1, -1):
                if open_stack[i] == name:
                    open_stack.pop(i)
                    break
            continue
        name = tag_text.split()[0].lower()
        if name in _SELF_CLOSING_TAGS or name not in _PAIRED_TAGS:
            continue
        open_stack.append(name)
    return open_stack


def _truncate_html_safe(text: str, limit: int) -> str:
    """Truncate Telegram HTML text so the *result* fits ``limit`` UTF-16 units.

    Telegram measures message length in UTF-16 code units, so the cut is
    measured with :func:`_utf16_len` — a plain ``len()`` over-counts astral
    characters once and under-counts them here, and both directions have
    produced 400 "message is too long".

    Cuts at a safe offset (never inside a <tag> or an entity), appends an
    ellipsis, and closes any tags left open by the cut. The ellipsis and the
    closing tags count against ``limit`` — a "</blockquote>" tail adds 13
    characters, and without reserving room for it the message would come back
    from Telegram as 400 "message is too long".
    """
    if _utf16_len(text) <= limit:
        return text
    # Huge emoji-dense texts overshoot when ``limit`` (UTF-16 units) is used
    # as a code-point index: pre-compute the first cut from the UTF-16 ratio
    # so the first iteration already lands close. Small messages keep the
    # legacy ``cut = limit`` start so maximal-prefix behaviour is unchanged.
    total_units = _utf16_len(text)
    if len(text) > 20000 and total_units > limit:
        cut = max(1, min(limit, int(len(text) * limit / max(1, total_units))))
    else:
        cut = limit
    while cut > 0:
        prefix = text[: _safe_cut_offset(text, cut)].rstrip()
        closing = "".join(f"</{name}>" for name in reversed(_open_tags(prefix)))
        result = f"{prefix}{_ELLIPSIS}{closing}"
        if _utf16_len(result) <= limit:
            return result
        # Shrink by exactly the overflow: the next attempt keeps as much text
        # as the reserved ellipsis/closing tags allow.
        cut -= max(1, _utf16_len(result) - limit)
    return ""
