"""Fetch and validate free SOCKS5 proxies for liveness checks.

The pool is intentionally only for validator routing. Proxy addresses are
untrusted input, so only public IPv4 ``host:port`` candidates are accepted.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
import re
import time
from collections.abc import Iterable

import httpx

from src.validators.proxy_health import ProxyHealthHistory

logger = logging.getLogger(__name__)


DEFAULT_PROXY_SOURCES: tuple[str, ...] = (
    "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt",
    "https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/protocols/socks5/data.txt",
    "https://cdn.jsdelivr.net/gh/VPSLabCloud/VPSLab-Free-Proxy-List@main/socks5_all.txt",
    "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/socks5.txt",
)

_USER_AGENT = "vpn-config-parser/1.0"
_PROXY_RE = re.compile(
    r"(?:socks5h?://|socks://)?"
    r"(?P<host>(?:\d{1,3}\.){3}\d{1,3})"
    r"(?::|\s+)"
    r"(?P<port>\d{1,5})"
)


def _is_public_ipv4(host: str) -> bool:
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return addr.version == 4 and addr.is_global


def _normalize_proxy(host: str, port_raw: str) -> str | None:
    if not _is_public_ipv4(host):
        return None
    try:
        port = int(port_raw)
    except (TypeError, ValueError):
        return None
    if not (1 <= port <= 65535):
        return None
    return f"socks5://{host}:{port}"


def parse_proxy_candidates(text: str) -> list[str]:
    """Extract unique public SOCKS5 proxy URLs from arbitrary proxy-list text."""
    if not text:
        return []

    seen: set[str] = set()
    proxies: list[str] = []
    for line in text.splitlines():
        # Most proxy lists use comments/metadata after whitespace or #. The
        # regex still scans the full line so "socks5://ip:port" is supported.
        for match in _PROXY_RE.finditer(line):
            proxy = _normalize_proxy(match.group("host"), match.group("port"))
            if proxy and proxy not in seen:
                seen.add(proxy)
                proxies.append(proxy)
    return proxies


async def _fetch_source(client: httpx.AsyncClient, url: str) -> str:
    try:
        response = await client.get(
            url,
            headers={"User-Agent": _USER_AGENT, "Accept": "text/plain,*/*"},
        )
    except httpx.HTTPError as exc:
        logger.warning("Proxy source fetch failed for %s: %s", url, exc)
        return ""

    if response.status_code != 200:
        logger.warning("Proxy source %s returned HTTP %d", url, response.status_code)
        return ""
    return response.text


async def fetch_proxy_candidates(
    sources: Iterable[str] | None = None,
    *,
    timeout: float = 10.0,
    max_candidates: int = 200,
    max_candidates_per_source: int | None = None,
) -> list[str]:
    """Fetch proxy source files and return unique candidates, capped by count.

    Sources are fetched in order and stop once enough unique candidates are
    collected. ``max_candidates_per_source`` keeps one large source from
    monopolising the pool, so later sources still contribute candidates.
    """
    source_urls = [
        str(src).strip()
        for src in (DEFAULT_PROXY_SOURCES if sources is None else sources)
        if str(src).strip()
    ]
    if not source_urls or max_candidates <= 0:
        return []

    seen: set[str] = set()
    proxies: list[str] = []
    timeout_cfg = httpx.Timeout(timeout)
    async with httpx.AsyncClient(timeout=timeout_cfg, follow_redirects=True) as client:
        for url in source_urls:
            try:
                text = await _fetch_source(client, url)
            except Exception as exc:
                logger.warning("Proxy source fetch raised for %s: %s", url, exc)
                continue
            added_from_source = 0
            for proxy in parse_proxy_candidates(text):
                if proxy in seen:
                    continue
                seen.add(proxy)
                proxies.append(proxy)
                added_from_source += 1
                if len(proxies) >= max_candidates:
                    return proxies
                if (
                    max_candidates_per_source is not None
                    and max_candidates_per_source > 0
                    and added_from_source >= max_candidates_per_source
                ):
                    break
    return proxies


async def proxy_connects(
    proxy_url: str,
    *,
    probe_host: str = "api.github.com",
    probe_port: int = 443,
    timeout: float = 5.0,
) -> bool:
    """Return True when a SOCKS5 proxy can open a TCP connection to a probe."""
    try:
        from python_socks.async_.asyncio import Proxy

        proxy = Proxy.from_url(proxy_url)
        sock = await proxy.connect(
            dest_host=probe_host,
            dest_port=probe_port,
            timeout=timeout,
        )
    except Exception:
        return False

    with contextlib.suppress(Exception):
        sock.close()
    return True


async def validate_proxy_candidates(
    proxies: list[str],
    *,
    max_proxies: int = 20,
    timeout: float = 5.0,
    concurrency: int = 50,
    probe_host: str = "api.github.com",
    probe_port: int = 443,
    history: ProxyHealthHistory | None = None,
) -> list[str]:
    """Self-check proxy candidates and return the first working proxies.

    Records latency and success/failure in ``history`` when provided, and
    prefers proxies with a good recent track record.
    """
    if not proxies or max_proxies <= 0:
        return []

    semaphore = asyncio.Semaphore(max(1, concurrency))
    alive: list[str] = []
    alive_lock = asyncio.Lock()
    done_event = asyncio.Event()

    async def _check(proxy_url: str) -> None:
        if done_event.is_set():
            return
        async with semaphore:
            if done_event.is_set():
                return
            start = time.monotonic()
            ok = await proxy_connects(
                proxy_url,
                probe_host=probe_host,
                probe_port=probe_port,
                timeout=timeout,
            )
            latency_ms = (time.monotonic() - start) * 1000.0 if ok else None
            if history is not None:
                history.record(proxy_url, ok, latency_ms)
            if not ok:
                return
            async with alive_lock:
                if proxy_url not in alive:
                    alive.append(proxy_url)
                if len(alive) >= max_proxies:
                    done_event.set()

    tasks = [asyncio.create_task(_check(proxy)) for proxy in proxies]
    pending_tasks = set(tasks)
    done_task = asyncio.create_task(done_event.wait())
    while pending_tasks and not done_event.is_set():
        done, _pending = await asyncio.wait(
            [*pending_tasks, done_task],
            return_when=asyncio.FIRST_COMPLETED,
        )
        pending_tasks -= done

    if done_event.is_set():
        for task in pending_tasks:
            task.cancel()

    await asyncio.gather(*tasks, return_exceptions=True)
    if not done_task.done():
        done_task.cancel()
        await asyncio.gather(done_task, return_exceptions=True)
    return alive[:max_proxies]


async def load_proxy_pool(
    sources: Iterable[str] | None = None,
    *,
    fetch_timeout: float = 10.0,
    max_candidates: int = 200,
    max_candidates_per_source: int | None = None,
    max_proxies: int = 20,
    validate: bool = True,
    validation_timeout: float = 5.0,
    validation_concurrency: int = 50,
    probe_host: str = "api.github.com",
    probe_port: int = 443,
    history: ProxyHealthHistory | None = None,
) -> list[str]:
    """Load a SOCKS5 proxy pool from GitHub-hosted text lists."""
    candidates = await fetch_proxy_candidates(
        sources,
        timeout=fetch_timeout,
        max_candidates=max_candidates,
        max_candidates_per_source=max_candidates_per_source,
    )
    if not candidates:
        logger.warning("Proxy pool: no candidates fetched.")
        return []

    if not validate:
        pool = candidates[:max_proxies]
        logger.info("Proxy pool: using %d unvalidated proxies.", len(pool))
        return pool

    pool = await validate_proxy_candidates(
        candidates,
        max_proxies=max_proxies,
        timeout=validation_timeout,
        concurrency=validation_concurrency,
        probe_host=probe_host,
        probe_port=probe_port,
        history=history,
    )
    if history is not None:
        pool = history.rank(pool)
    logger.info(
        "Proxy pool: %d/%d candidates passed self-check.",
        len(pool),
        len(candidates),
    )
    return pool
