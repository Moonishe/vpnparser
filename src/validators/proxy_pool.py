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
from urllib.parse import urljoin, urlparse

import httpx

from src.validators.proxy_health import ProxyHealthHistory

logger = logging.getLogger(__name__)

#: Hard cap on the body accepted from one proxy source. The sources are third
#: parties; an endless stream must not buffer into memory unbounded.
_MAX_SOURCE_BODY_BYTES = 8 * 1024 * 1024

#: Wall-clock budget for one source fetch (the whole redirect chain and every
#: transient retry included) as a multiple of the per-operation ``timeout``.
#: httpx restarts its read timer on every chunk, so a slow-drip host holds one
#: stream open far past any single timeout while staying under the byte cap —
#: sources are fetched concurrently now, but an unbudgeted stream still pins
#: its worker and delays pool readiness. Mirrors
#: ``sources.manager.DOWNLOAD_TIMEOUT_FACTOR``.
_DOWNLOAD_BUDGET_FACTOR = 4.0

#: Transient statuses worth a retry (the raw-GitHub path retries these too):
#: CDNs throttle bursts with 429, 5xx are transient by definition.
_RETRIABLE_STATUSES = frozenset({429, 500, 502, 503, 504})
_MAX_SOURCE_ATTEMPTS = 3

#: How many passing candidates to collect relative to ``max_proxies`` so the
#: final selection can prefer distinct /16 networks instead of the first N
#: completions, which routinely come from one busy CIDR range.
_NETWORK_OVERSAMPLE = 3

#: Maximum redirect hops followed for one proxy source. Every hop is
#: re-validated: a client with ``follow_redirects=True`` would otherwise be
#: sent to an internal address without any SSRF check.
_MAX_REDIRECT_HOPS = 5


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
    r"(?P<port>\d{1,5})",
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


def _is_safe_public_http_url(url: str) -> bool:
    """True for an absolute http(s) URL whose host is a public address/name.

    Mirrors the SSRF stance of the source fetcher: a redirect hop pointing at
    loopback/RFC1918/link-local (or cloud metadata) must never be followed.
    Hostnames are accepted here and resolved by the connector; the proxy-list
    sources are operator-configured, so the per-hop check focuses on literals
    and scheme sanity.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return False
    try:
        addr = ipaddress.ip_address(parsed.hostname.strip("[]"))
    except ValueError:
        # A hostname: cannot judge without DNS; accept — same as operators'
        # configured sources, redirects included below are still bounded.
        return True
    return addr.is_global


async def _fetch_source(
    client: httpx.AsyncClient,
    url: str,
    *,
    timeout: float = 10.0,
) -> str | None:
    """Fetch one proxy-list source under SSRF, byte and wall-clock budgets.

    Transient statuses (429/5xx) and network errors are retried up to
    ``_MAX_SOURCE_ATTEMPTS`` times honouring ``Retry-After`` — the raw-GitHub
    path already did this, and without it one CDN hiccup skipped a source for
    the whole run. The wall-clock budget covers every attempt of the chain.

    Returns:
        The body text, ``None`` when the body exceeded the byte cap or the
        wall-clock budget (a truncated body must not be parsed — the missing
        tail silently skews the pool towards whatever happened to fit), or
        ``""`` on refusals/non-retriable HTTP/network errors.
    """
    headers = {"User-Agent": _USER_AGENT, "Accept": "text/plain,*/*"}
    try:
        async with asyncio.timeout(timeout * _DOWNLOAD_BUDGET_FACTOR):
            for attempt in range(1, _MAX_SOURCE_ATTEMPTS + 1):
                try:
                    text, retry_after = await _fetch_source_once(
                        client,
                        url,
                        headers,
                        attempt=attempt,
                    )
                except httpx.HTTPError as exc:
                    if attempt >= _MAX_SOURCE_ATTEMPTS:
                        logger.warning("Proxy source fetch failed for %s: %s", url, exc)
                        return ""
                    delay = 0.5 * attempt
                    logger.warning(
                        "Proxy source %s network error (attempt %d/%d) — "
                        "retrying in %.1fs.",
                        url,
                        attempt,
                        _MAX_SOURCE_ATTEMPTS,
                        delay,
                    )
                    await asyncio.sleep(delay)
                    continue
                if retry_after is not None and attempt < _MAX_SOURCE_ATTEMPTS:
                    logger.warning(
                        "Proxy source %s got a retriable failure "
                        "(attempt %d/%d) — retrying in %.1fs.",
                        url,
                        attempt,
                        _MAX_SOURCE_ATTEMPTS,
                        retry_after,
                    )
                    await asyncio.sleep(retry_after)
                    continue
                return text
            return ""
    except TimeoutError:
        logger.warning(
            "Proxy source %s exceeded its %.0fs wall-clock budget.",
            url,
            timeout * _DOWNLOAD_BUDGET_FACTOR,
        )
        return None


async def _fetch_source_once(
    client: httpx.AsyncClient,
    url: str,
    headers: dict[str, str],
    *,
    attempt: int = 1,
) -> tuple[str | None, float | None]:
    """One redirect-chain walk of :func:`_fetch_source`.

    Returns ``(text, retry_after)``.  A non-None ``retry_after`` marks a
    transient failure worth another attempt; ``text`` is then ignored.
    Network errors propagate to the caller's retry loop.
    """
    from src.sources.github import _retry_after_delay

    target = url
    for _hop in range(_MAX_REDIRECT_HOPS + 1):
        if not _is_safe_public_http_url(target):
            logger.warning(
                "Proxy source %s redirects to unsafe URL — refusing.",
                url,
            )
            return "", None
        async with client.stream(
            "GET",
            target,
            headers=headers,
        ) as response:
            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("location")
                if not location:
                    logger.warning(
                        "Proxy source %s redirected without Location — skipping.",
                        target,
                    )
                    return "", None
                # Resolve against the *logical* URL of this hop.
                target = urljoin(target, location.strip())
                continue
            if response.status_code in _RETRIABLE_STATUSES:
                delay = _retry_after_delay(
                    response.headers.get("Retry-After"),
                    float(attempt),
                )
                return "", delay
            if response.status_code != 200:
                logger.warning(
                    "Proxy source %s returned HTTP %d",
                    url,
                    response.status_code,
                )
                return "", None
            # Stream with a byte cap: response.text would buffer any size.
            body = bytearray()
            overflow = False
            async for chunk in response.aiter_bytes(64 * 1024):
                body.extend(chunk)
                if len(body) > _MAX_SOURCE_BODY_BYTES:
                    logger.warning(
                        "Proxy source %s exceeded %d bytes — discarded.",
                        url,
                        _MAX_SOURCE_BODY_BYTES,
                    )
                    overflow = True
                    break
            if overflow:
                return None, None
            return body.decode("utf-8", errors="replace"), None
    logger.warning(
        "Proxy source %s exceeded %d redirect hops.", url, _MAX_REDIRECT_HOPS
    )
    return "", None


async def fetch_proxy_candidates(
    sources: Iterable[str] | None = None,
    *,
    timeout: float = 10.0,
    max_candidates: int = 200,
    max_candidates_per_source: int | None = None,
) -> list[str]:
    """Fetch proxy source files and return unique candidates, capped by count.

    Sources are fetched **concurrently** (each under its own wall-clock
    budget), then parsed in the configured source order so earlier sources
    keep their priority; collection stops once enough unique candidates are
    gathered. ``max_candidates_per_source`` keeps one large source from
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
    # follow_redirects=False: _fetch_source walks hops manually and
    # re-validates each one against the SSRF stance above.
    async with httpx.AsyncClient(timeout=timeout_cfg, follow_redirects=False) as client:
        outcomes = await asyncio.gather(
            *(_fetch_source(client, url, timeout=timeout) for url in source_urls),
            return_exceptions=True,
        )
        for url, outcome in zip(source_urls, outcomes, strict=False):
            if isinstance(outcome, BaseException):
                logger.warning("Proxy source fetch raised for %s: %s", url, outcome)
                continue
            text = outcome
            if not text:
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


async def _proxy_connects_to(
    proxy_url: str,
    host: str,
    port: int,
    timeout: float,
) -> bool:
    """One SOCKS5 connect attempt; a failure just means "this target"."""
    try:
        from python_socks.async_.asyncio import Proxy

        proxy = Proxy.from_url(proxy_url)
        sock = await proxy.connect(dest_host=host, dest_port=port, timeout=timeout)
    except Exception:
        return False

    with contextlib.suppress(Exception):
        sock.close()
    return True


async def proxy_connects(
    proxy_url: str,
    *,
    probe_host: str = "api.github.com",
    probe_port: int = 443,
    timeout: float = 5.0,
    extra_probe_targets: list[tuple[str, int]] | None = None,
) -> bool:
    """Return True when a SOCKS5 proxy can open a TCP connection to a probe.

    Targets are tried in order until one connects: a network that filters
    GitHub but not Google would otherwise reject every living proxy during
    the self-check and leave the pool empty.
    """
    targets: list[tuple[str, int]] = [(probe_host, probe_port)]
    targets.extend(extra_probe_targets or [])
    for index, (host, port) in enumerate(targets):
        if await _proxy_connects_to(proxy_url, host, port, timeout):
            if index:
                # A proxy that only reaches Google will pass the pool
                # self-check and then fail every GitHub-targeted L3 probe;
                # the split is the first thing to check when the Xray stage
                # underperforms while the pool looks healthy.
                logger.debug(
                    "Proxy %s passed self-check via failover target %s:%d "
                    "(primary %s unreachable).",
                    proxy_url,
                    host,
                    port,
                    probe_host,
                )
            return True
    return False


def _proxy_network_key(proxy_url: str) -> str | None:
    """Return the network identity of a proxy: IPv4 /16, IPv6 /48, or host.

    A whole /16 is one network event away from dying together (one provider,
    one datacenter), so selection treats the prefix — not the address — as
    the diversity unit. Hostnames count as one network each (their addresses
    are unknown here).
    """
    host = (urlparse(str(proxy_url)).hostname or "").strip().lower()
    if not host:
        return None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host
    prefix = 16 if ip.version == 4 else 48
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


def select_diverse_proxies(proxies: list[str], limit: int) -> list[str]:
    """Pick up to *limit* proxies preferring distinct networks (greedy).

    The first pass takes every proxy whose /16 has not been seen yet; only
    when all represented networks are exhausted do same-network leftovers
    fill the remaining slots, preserving input order. Without this the pool
    was ``alive[:max_proxies]`` — completion order, which routinely put all
    working proxies inside one busy provider CIDR.
    """
    if limit <= 0:
        return []
    picked: list[str] = []
    deferred: list[str] = []
    seen_networks: set[str] = set()
    for proxy in proxies:
        key = _proxy_network_key(proxy)
        if key is not None and key not in seen_networks:
            seen_networks.add(key)
            picked.append(proxy)
            if len(picked) >= limit:
                return picked
        else:
            deferred.append(proxy)
    for proxy in deferred:
        if len(picked) >= limit:
            break
        picked.append(proxy)
    return picked


def count_proxy_networks(proxy_urls: list[str]) -> int:
    """Count distinct networks behind the pool (IPv4 /16, per-host otherwise)."""
    networks: set[str] = set()
    for url in proxy_urls:
        key = _proxy_network_key(url)
        if key is not None:
            networks.add(key)
    return len(networks)


async def validate_proxy_candidates(
    proxies: list[str],
    *,
    max_proxies: int = 20,
    timeout: float = 5.0,
    concurrency: int = 50,
    probe_host: str = "api.github.com",
    probe_port: int = 443,
    history: ProxyHealthHistory | None = None,
    extra_probe_targets: list[tuple[str, int]] | None = None,
) -> list[str]:
    """Self-check proxy candidates and return the first working proxies.

    Records latency and success/failure in ``history`` when provided, and
    prefers proxies with a good recent track record. Collection oversamples
    to ``max_proxies * _NETWORK_OVERSAMPLE`` completions so
    :func:`select_diverse_proxies` can hand back a pool spread across
    distinct /16 networks instead of whichever CIDR answered first.
    """
    if not proxies or max_proxies <= 0:
        return []

    collect_target = max_proxies * _NETWORK_OVERSAMPLE
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
                extra_probe_targets=extra_probe_targets,
            )
            latency_ms = (time.monotonic() - start) * 1000.0 if ok else None
            if history is not None:
                history.record(proxy_url, ok, latency_ms)
            if not ok:
                return
            async with alive_lock:
                if proxy_url not in alive:
                    alive.append(proxy_url)
                if len(alive) >= collect_target:
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
    return select_diverse_proxies(alive, max_proxies)


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
    extra_probe_targets: list[tuple[str, int]] | None = None,
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

    if history is not None:
        # Before the self-check, not after it: a proxy that fails the check is
        # given a fresh `consecutive_failures = 0` by ``record(success=True)``
        # only when it *passes*, so ranking the survivors can never drop a
        # banned one — the ban simply never applied, and every dead proxy was
        # re-probed at full cost on every run.
        healthy = history.rank(candidates)
        if healthy:
            logger.info(
                "Proxy pool: %d/%d candidates left after health history.",
                len(healthy),
                len(candidates),
            )
            candidates = healthy
        else:
            logger.warning(
                "Proxy pool: health history rejects all %d candidate(s); "
                "checking them anyway rather than running without a pool.",
                len(candidates),
            )

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
        extra_probe_targets=extra_probe_targets,
    )
    if history is not None:
        pool = history.rank(pool)
    logger.info(
        "Proxy pool: %d/%d candidates passed self-check.",
        len(pool),
        len(candidates),
    )
    return pool
