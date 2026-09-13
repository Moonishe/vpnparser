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
from dataclasses import dataclass
from typing import Any
from urllib.parse import SplitResult, urljoin, urlparse, urlsplit, urlunsplit

import httpx

from src.utils.net import redact_proxy_url, resolve_global_ips
from src.validators.proxy_health import ProxyHealthHistory

logger = logging.getLogger(__name__)

#: Hard cap on the body accepted from one proxy source. The sources are third
#: parties; an endless stream must not buffer into memory unbounded.
_MAX_SOURCE_BODY_BYTES = 8 * 1024 * 1024

#: Wall-clock budget for one source fetch (the whole redirect chain included)
#: as a multiple of the per-operation ``timeout``.  httpx restarts its read
#: timer on every chunk, so a slow-drip host holds one stream open far past
#: any single timeout while staying under the byte cap — and sources are
#: fetched sequentially, so pool building inherited that stall.  Mirrors
#: ``sources.manager.DOWNLOAD_TIMEOUT_FACTOR``.
_DOWNLOAD_BUDGET_FACTOR = 4.0

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
    r"^\s*(?:socks5h?://|socks://)?"
    r"(?P<host>(?:\d{1,3}\.){3}\d{1,3})"
    r"(?::|\s+)"
    r"(?P<port>\d{1,5})"
    r"\s*(?:#.*)?$",
)


def _line_chunks(line: str) -> list[str]:
    """Split a proxy-list line into matchable chunks.

    The common case is one proxy per line ("1.2.3.4:1080",
    "1.2.3.4 1080", "socks5://1.2.3.4:1080", "... # comment"). Some
    lists pack several proxies into one line ("a:1 b:2") — those fall
    back to whitespace tokens, stopping at a "#" comment token.
    """
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return []
    if _PROXY_RE.match(stripped):
        return [stripped]
    chunks: list[str] = []
    for token in stripped.split():
        if token.startswith("#"):
            break
        chunks.append(token)
    return chunks


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
        # Anchored per chunk: an unanchored finditer matched "1.2.3.4:8080"
        # embedded in garbage ("token=1.2.3.4:8080&x=1", "user:pass@…"),
        # minting pool candidates out of junk and burning the TCP
        # self-check budget on them. A trailing "# comment" is still
        # allowed — most proxy lists annotate entries that way. Octet and
        # port ranges are enforced by _normalize_proxy below.
        for chunk in _line_chunks(line):
            match = _PROXY_RE.match(chunk)
            if match is None:
                continue
            proxy = _normalize_proxy(match.group("host"), match.group("port"))
            if proxy and proxy not in seen:
                seen.add(proxy)
                proxies.append(proxy)
    return proxies


@dataclass(frozen=True)
class _PinnedTarget:
    """A source URL bound to the addresses its host was validated on.

    Resolving once and connecting to the approved address closes the
    check-to-connect window (DNS rebinding / TOCTOU): httpx would otherwise
    resolve independently at connect time, letting a TTL-0 record answer the
    guard with a public address and the socket with ``127.0.0.1`` /
    ``169.254.169.254``.  ``host_header`` and ``sni_hostname`` keep virtual
    hosting and TLS working against the original hostname, not the address.
    """

    connect_urls: tuple[str, ...]
    host_header: str
    extensions: dict[str, str]
    logical_url: str


#: Hostname suffixes that are private/internal by convention and must never be
#: followed on a redirect.
_BLOCKED_HOST_SUFFIXES = (
    ".local",
    ".internal",
    ".localhost",
    ".example",
    ".invalid",
    ".arpa",
)
#: Hostnames that resolve (or may resolve) to internal infrastructure.
_BLOCKED_HOSTS = frozenset(
    {"localhost", "metadata", "metadata.google.internal", "ip6-localhost"}
)

#: How many resolved addresses a single pinned target may connect to before the
#: rest are dropped (defence against a host answering with an enormous list).
_MAX_PINNED_ADDRESSES = 4


def _host_literal(host: str) -> str:
    """Return *host* as a URL authority literal, bracketing IPv6 addresses."""
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return host
    return f"[{addr}]" if addr.version == 6 else str(addr)


def _safe_source_url(url: str) -> tuple[SplitResult, str] | None:
    """Accept *url* only as an absolute http(s) URL with a non-blocked host.

    Hostnames are allowed (the pinning step resolves and judges their
    addresses); internal hostnames (``.local``, ``metadata``, …) are refused by
    name before any DNS lookup.  Returns the parsed URL and its lowercased host,
    or ``None`` when the URL is not fit to be a source.
    """
    try:
        parts = urlsplit((url or "").strip())
    except ValueError:
        return None
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        return None
    host = parts.hostname.lower()
    if host in _BLOCKED_HOSTS or any(host.endswith(s) for s in _BLOCKED_HOST_SUFFIXES):
        return None
    return parts, host


async def _pin_public_target(url: str) -> _PinnedTarget | None:
    """Validate *url* against the SSRF guard and pin it to its public addresses.

    Resolution happens exactly once; the connection goes to what was resolved,
    so a redirect controlled by a third party cannot be pointed at an internal
    address (DNS-rebinding TOCTOU).  Returns ``None`` when the URL is not a safe
    public http(s) URL or its host does not resolve exclusively to public
    addresses.
    """
    parsed = _safe_source_url(url)
    if parsed is None:
        return None
    parts, host = parsed
    addresses = await resolve_global_ips(host)
    if not addresses:
        return None
    userinfo = ""
    if parts.username or parts.password:
        # urlsplit() returns percent-ENCODED credentials (it does not decode
        # them), so they are rebuilt as-is: re-quoting turned "p%40ss" into
        # "p%2540ss" and the proxy refused the auth it had originally given.
        username = parts.username or ""
        password = parts.password or ""
        userinfo = f"{username}:{password}@" if password else f"{username}@"
    port = f":{parts.port}" if parts.port is not None else ""
    connect_urls = tuple(
        urlunsplit(
            (
                parts.scheme,
                f"{userinfo}{_host_literal(address)}{port}",
                parts.path,
                parts.query,
                parts.fragment,
            )
        )
        for address in addresses[:_MAX_PINNED_ADDRESSES]
    )
    return _PinnedTarget(
        connect_urls=connect_urls,
        host_header=f"{_host_literal(host)}{port}",
        extensions={"sni_hostname": host} if parts.scheme.lower() == "https" else {},
        logical_url=urlunsplit(
            (
                parts.scheme,
                f"{userinfo}{host}{port}",
                parts.path,
                parts.query,
                parts.fragment,
            )
        ),
    )


async def _fetch_source(
    client: httpx.AsyncClient,
    url: str,
    *,
    timeout: float = 10.0,
) -> str | None:
    """Fetch one proxy-list source under SSRF, byte and wall-clock budgets.

    Returns:
        The body text, ``None`` when the body exceeded the byte cap or the
        wall-clock budget (a truncated body must not be parsed — the missing
        tail silently skews the pool towards whatever happened to fit), or
        ``""`` on refusals/HTTP/network errors.
    """
    headers = {"User-Agent": _USER_AGENT, "Accept": "text/plain,*/*"}
    target = url
    # Operator-supplied source URLs may embed credentials (?token=, userinfo);
    # every log line below shows the redacted form only.
    log_url = redact_proxy_url(url)
    prior_scheme: str | None = None
    try:
        async with asyncio.timeout(timeout * _DOWNLOAD_BUDGET_FACTOR):
            for _hop in range(_MAX_REDIRECT_HOPS + 1):
                # Resolve once and connect to the approved address, so a
                # redirect controlled by a third party cannot be pointed at an
                # internal host (DNS-rebinding TOCTOU).  Hostnames are judged
                # only by the addresses they resolve to — never re-resolved by
                # httpx at connect time.
                pinned = await _pin_public_target(target)
                if pinned is None:
                    logger.warning(
                        "Proxy source %s refused (unsafe or unresolvable): %s",
                        log_url,
                        redact_proxy_url(target),
                    )
                    return ""
                scheme = urlsplit(target).scheme.lower()
                # A server-controlled redirect must not downgrade TLS.
                if prior_scheme == "https" and scheme == "http":
                    logger.warning(
                        "Proxy source %s https->http redirect refused: %s",
                        log_url,
                        redact_proxy_url(target),
                    )
                    return ""
                prior_scheme = scheme
                request_headers = {**headers, "Host": pinned.host_header}
                last_error: httpx.HTTPError | None = None
                for connect_url in pinned.connect_urls:
                    try:
                        async with client.stream(
                            "GET",
                            connect_url,
                            headers=request_headers,
                            extensions=pinned.extensions,
                        ) as response:
                            if response.status_code in (301, 302, 303, 307, 308):
                                location = response.headers.get("location")
                                if not location:
                                    logger.warning(
                                        "Proxy source %s redirected without "
                                        "Location — skipping.",
                                        redact_proxy_url(target),
                                    )
                                    return ""
                                # Resolve against the *logical* URL, never the
                                # pinned address, so relative redirects stay sane.
                                target = urljoin(pinned.logical_url, location.strip())
                                break
                            if response.status_code != 200:
                                logger.warning(
                                    "Proxy source %s returned HTTP %d",
                                    log_url,
                                    response.status_code,
                                )
                                return ""
                            # Byte cap so response.text cannot buffer the entire body.
                            body = bytearray()
                            overflow = False
                            async for chunk in response.aiter_bytes(64 * 1024):
                                body.extend(chunk)
                                if len(body) > _MAX_SOURCE_BODY_BYTES:
                                    logger.warning(
                                        "Proxy source %s exceeded %d bytes "
                                        "— discarded.",
                                        log_url,
                                        _MAX_SOURCE_BODY_BYTES,
                                    )
                                    overflow = True
                                    break
                            if overflow:
                                return None
                            return body.decode("utf-8", errors="replace")
                    except httpx.TransportError as exc:
                        # Any transport failure on one pinned address must
                        # still try the next one (mirrors sources/manager).
                        last_error = exc
                        continue
                else:
                    logger.warning(
                        "Proxy source %s connect failed: %s",
                        log_url,
                        # httpx connect errors embed the full request URL.
                        redact_proxy_url(str(last_error)),
                    )
                    return ""
                # A redirect broke the inner loop; follow it on the next hop.
                continue
            logger.warning(
                "Proxy source %s exceeded %d redirect hops.",
                log_url,
                _MAX_REDIRECT_HOPS,
            )
            return ""
    except TimeoutError:
        logger.warning(
            "Proxy source %s exceeded its %.0fs wall-clock budget.",
            log_url,
            timeout * _DOWNLOAD_BUDGET_FACTOR,
        )
        return None
    except httpx.HTTPError as exc:
        logger.warning(
            "Proxy source fetch failed for %s: %s",
            log_url,
            redact_proxy_url(str(exc)),
        )
        return ""


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
    # follow_redirects=False: _fetch_source walks hops manually and
    # re-validates each one against the SSRF stance above.
    async with httpx.AsyncClient(timeout=timeout_cfg, follow_redirects=False) as client:
        for url in source_urls:
            try:
                text = await _fetch_source(client, url, timeout=timeout)
            except Exception as exc:
                logger.warning(
                    "Proxy source fetch raised for %s: %s",
                    redact_proxy_url(url),
                    redact_proxy_url(str(exc)),
                )
                continue
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
                    redact_proxy_url(proxy_url),
                    host,
                    port,
                    probe_host,
                )
            return True
    return False


def count_proxy_networks(proxy_urls: list[str]) -> int:
    """Count distinct networks behind the pool (IPv4 /16, per-host otherwise).

    The whole L3 stage rides on this pool; when every proxy lives in one
    /16, a single network event empties the subscription. Hostnames count
    as one network each (their addresses are unknown here).
    """
    networks: set[str] = set()
    for url in proxy_urls:
        host = (urlparse(str(url)).hostname or "").strip().lower()
        if not host:
            continue
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            networks.add(host)
            continue
        prefix = 16 if ip.version == 4 else 48
        networks.add(str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False)))
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
                if len(alive) >= max_proxies:
                    done_event.set()

    tasks = [asyncio.create_task(_check(proxy)) for proxy in proxies]
    # Race gather against the max_proxies event instead of re-registering the
    # whole pending set on every completion (O(n²) in done-callbacks, and a
    # cancellation during the loop orphaned every in-flight lookup).
    gather_task: asyncio.Future[Any] = asyncio.gather(*tasks, return_exceptions=True)
    done_task = asyncio.ensure_future(done_event.wait())
    try:
        await asyncio.wait(
            [gather_task, done_task],
            return_when=asyncio.FIRST_COMPLETED,
        )
    except asyncio.CancelledError:
        for task in tasks:
            if not task.done():
                task.cancel()
        done_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await gather_task
        with contextlib.suppress(asyncio.CancelledError):
            await done_task
        raise
    finally:
        # Outer cancellation during the wait must still reap children.
        if done_task.done() and not done_event.is_set():
            done_event.set()
        for task in tasks:
            if not task.done():
                task.cancel()
        done_task.cancel()

    try:
        await gather_task
    except asyncio.CancelledError:
        for task in tasks:
            if not task.done():
                task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await gather_task
        raise
    # Reap the watcher: cancel() only requests cancellation.
    with contextlib.suppress(asyncio.CancelledError):
        await done_task
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
