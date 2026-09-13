"""HTTP body-reading helpers shared by the fetchers.

Both fetch paths pull text from hosts the pipeline does not control: the
``url-list`` sources point at arbitrary URLs, and even the trusted raw hosts can
serve a file far larger than anything worth parsing. Reading such a body with
``response.text`` buffers and decodes all of it before any limit can be
checked, so a single oversized (or slow-drip, endless) response is enough to
exhaust memory. Streaming with a byte budget is the only way to bound that.
"""

from __future__ import annotations

import codecs

import httpx


async def read_limited_text(
    response: httpx.Response,
    *,
    max_bytes: int,
) -> str | None:
    """Read an open streaming response, giving up past ``max_bytes``.

    The budget is enforced per chunk, so the read stops as soon as the limit is
    crossed instead of after the whole body has arrived.

    Args:
        response: Streaming :class:`httpx.Response` whose body is not read yet.
        max_bytes: Byte budget for the body.

    Returns:
        The decoded body, or ``None`` when the budget was exceeded (the caller
        discards the response and logs it).
    """
    # Decoded incrementally: buffering the raw chunks, joining them and THEN
    # decoding tripled the peak (12 MiB body -> ~36 MiB transient) — with 50
    # concurrent fetches that alone neared 1.8 GB.
    encoding = response.encoding or "utf-8"
    try:
        codecs.lookup(encoding)
    except LookupError:
        encoding = "utf-8"
    decoder = codecs.getincrementaldecoder(encoding)(errors="replace")
    parts: list[str] = []
    total = 0
    async for chunk in response.aiter_bytes():
        total += len(chunk)
        if total > max_bytes:
            return None
        parts.append(decoder.decode(chunk))
    parts.append(decoder.decode(b"", final=True))
    return "".join(parts)
