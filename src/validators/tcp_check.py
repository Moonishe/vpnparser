"""L1 validator: TCP connect check.

Measures whether a proxy server's host:port accepts TCP connections
and how long the connect takes. This is the cheapest liveness check
and is run before the more expensive TLS handshake (L2) test.

Supports **early termination**: once enough alive configs with low
latency are found, remaining checks are cancelled to save time.

Supports **SOCKS5 proxy**: when a proxy URL is provided, TCP connections
are routed through it. This is essential when running from a data center
(GitHub Actions) where VPN servers may block data-center IPs.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import socket
import time
from typing import Any

from src.parsers.base import Config
from src.validators.address_guard import (
    filter_public_configs,
    is_blocked_literal,
    resolve_pinned_addresses,
)

logger = logging.getLogger(__name__)

#: Cap on the total connect attempts one config may cost when the whole proxy
#: pool is requested (``proxy_attempts_per_config=0``) — otherwise a large pool
#: keeps one semaphore slot busy for minutes.
_MAX_ATTEMPTS_PER_CONFIG = 12


async def _open_connection_direct(host: str, port: int) -> tuple[Any, Any]:
    """Direct TCP connection (no proxy)."""
    return await asyncio.open_connection(host, port)


async def _open_connection_via_socks(
    host: str,
    port: int,
    proxy_url: str,
    timeout: float | None = None,
) -> tuple[Any, Any]:
    """TCP connection routed through a SOCKS5 proxy.

    Uses python-socks which returns a raw socket; we wrap it into
    asyncio streams.
    """
    from python_socks.async_.asyncio import Proxy

    proxy = Proxy.from_url(proxy_url)
    # Timeout inside Proxy.connect, not only in the outer wait_for: the
    # outer cancellation abandoned the inner connect coroutine and leaked
    # its socket FD on every mass-timeout wave.
    sock = await proxy.connect(dest_host=host, dest_port=port, timeout=timeout)
    # python-socks returns a connected socket; wrap into streams.
    # If the wrap raises (cancel/timeout), close the raw socket — otherwise
    # long --continuous runs leak FDs on every mass-timeout wave.
    try:
        reader, writer = await asyncio.open_connection(sock=sock)
    except BaseException:
        with contextlib.suppress(Exception):
            sock.close()
        raise
    return reader, writer


#: Per-stage counters for the refusal log. A run can refuse tens of thousands
#: of dead/unresolvable addresses; one WARNING per address buried the useful
#: log lines, so refusals count here and the stage summary emits one line.
_refusals: dict[str, int] = {"non-public": 0, "unpinnable": 0}


def _log_refusal(kind: str, host: str, port: int) -> None:
    """Count a refused address; full detail goes to DEBUG only."""
    _refusals[kind] = _refusals.get(kind, 0) + 1
    logger.debug("Refusing %s TCP check of %s:%s.", kind, host, port)


def log_refusal_summary() -> None:
    """Emit one aggregate line for the refused addresses of this stage."""
    refused = sum(_refusals.values())
    if not refused:
        return
    logger.info(
        "TCP stage refused %d address(s) (%s).",
        refused,
        ", ".join(f"{kind}: {count}" for kind, count in _refusals.items()),
    )
    for kind in _refusals:
        _refusals[kind] = 0


def reset_refusal_counters() -> None:
    """Start a fresh refusal count — each stage invocation counts its own."""
    for kind in _refusals:
        _refusals[kind] = 0


async def tcp_check(
    host: str,
    port: int,
    timeout: float = 3.0,
    proxy_url: str | None = None,
    resolve_timeout: float = 5.0,
    pin_address: bool = True,
) -> tuple[bool | None, float | None]:
    """TCP connect to host:port, optionally through a SOCKS5 proxy.

    Args:
        host: Target hostname or IP.
        port: Target port.
        timeout: Connect timeout in seconds.
        proxy_url: Optional SOCKS5 proxy URL (e.g. ``socks5://host:port``).
            When provided, the connection is routed through the proxy.
        pin_address: Resolve the host once and connect to the validated
            literals (DNS rebinding guard). ``False`` honours the operator's
            ``check_hostnames: false`` opt-out and dials the hostname
            as-is — the OS/proxy resolves it, no DNS query is made here.

    Returns (is_alive, latency_ms) where is_alive None means no verdict
    (transient DNS-pin failure — must not count toward health bans,
    unlike a refused/dead connection).
    """
    if is_blocked_literal(host):
        _log_refusal("non-public", host, port)
        return (False, None)

    # Pin the connect target to the addresses the guard validated: connecting
    # to the hostname would let the OS resolve it a second time, reopening
    # the DNS-rebinding window between verdict and socket. The list is walked
    # in order — a dual-stack host whose first answer is an unroutable AAAA
    # used to die outright when only the first address survived.
    if pin_address:
        pinned = await resolve_pinned_addresses(host, timeout=resolve_timeout)
        if not pinned:
            _log_refusal("unpinnable", host, port)
            return (None, None)
    else:
        # check_hostnames=false skips DNS entirely (same contract as the
        # Xray stage's pin_address): no resolve, no pin, dial the name.
        pinned = [host]

    writer: asyncio.StreamWriter | None = None
    attempt_start = time.monotonic()
    try:
        for address in pinned:
            # The clock restarts per attempt: taken once before the loop, the
            # successful attempt's latency also carried the timeouts of every
            # earlier failed one (a dead AAAA eating 3 s before a fast A4
            # connected reported ~3050 ms and dropped live servers in the
            # quality stage).
            attempt_start = time.monotonic()
            try:
                if proxy_url:
                    # Inner timeout drives the SOCKS handshake; the outer
                    # wait_for is only a safety net (timeout+5) for the
                    # stream wrap, so a stuck handshake cannot leak an FD.
                    reader, writer = await asyncio.wait_for(
                        _open_connection_via_socks(
                            address, port, proxy_url, timeout=timeout
                        ),
                        timeout=timeout + 5.0,
                    )
                else:
                    reader, writer = await asyncio.wait_for(
                        _open_connection_direct(address, port),
                        timeout=timeout,
                    )
                break
            except (TimeoutError, ConnectionRefusedError, socket.gaierror, OSError):
                writer = None
                continue
            except Exception:
                writer = None
                continue
        if writer is None:
            return (False, None)
    except Exception:
        return (False, None)

    # attempt_start is the top of the iteration that connected: the successful
    # attempt is the last one, since the loop breaks on success.
    latency_ms = (time.monotonic() - attempt_start) * 1000.0
    # Exception covers everything the narrower names would: close()/wait_closed()
    # are best-effort teardown on a socket that just failed to connect.
    with contextlib.suppress(Exception):
        writer.close()
        await writer.wait_closed()

    return (True, latency_ms)


async def validate_configs_tcp(
    configs: list[Config],
    timeout: float = 3.0,
    concurrency: int = 200,
    max_alive: int = 0,
    proxy_url: str | None = None,
    proxy_urls: list[str] | None = None,
    proxy_attempts_per_config: int = 1,
    check_hostnames: bool = True,
    resolve_timeout: float = 5.0,
    proxy_latency_ms: dict[str, float] | None = None,
) -> list[Config]:
    """Check configs via TCP with optional early termination and SOCKS5 proxy.

    Args:
        configs: List of Config objects to check.
        timeout: TCP connect timeout in seconds.
        concurrency: Maximum concurrent connections.
        max_alive: Stop once this many alive configs are found.
            0 = no limit (check everything).
        proxy_url: Optional SOCKS5 proxy URL to route connections through.
        proxy_urls: Optional SOCKS5 proxy pool. When provided, configs are
            checked through the pool in round-robin order. Takes precedence
            over ``proxy_url``.
        proxy_attempts_per_config: Number of different proxies to try per
            config before marking it dead. ``0`` means try the whole pool.
        check_hostnames: Resolve hostnames to reject configs pointing at
            internal addresses. IP literals are rejected either way.
        proxy_latency_ms: Mean dial latency of each pool proxy (ms). A
            through-proxy measurement includes the proxy's own hop; without
            subtracting that baseline a fast server behind a congested free
            proxy is ranked as slow (and can bounce out of the subscription
            run over run) purely because of the proxy it happened to ride.

    Returns alive configs sorted by latency_ms ascending.
    """
    if not configs:
        return []

    configs = await filter_public_configs(
        configs,
        stage="TCP check",
        check_hostnames=check_hostnames,
        resolve_timeout=resolve_timeout,
    )
    if not configs:
        return []

    reset_refusal_counters()
    proxy_choices = [p for p in (proxy_urls or []) if p]
    if not proxy_choices and proxy_url:
        proxy_choices = [proxy_url]

    def _proxies_for(index: int) -> list[str | None]:
        if not proxy_choices:
            return [None]
        if proxy_attempts_per_config <= 0:
            attempts = len(proxy_choices)
        else:
            attempts = min(max(1, proxy_attempts_per_config), len(proxy_choices))
        start = index % len(proxy_choices)
        return [
            proxy_choices[(start + offset) % len(proxy_choices)]
            for offset in range(attempts)
        ]

    semaphore = asyncio.Semaphore(max(1, int(concurrency)))
    alive_list: list[Config] = []
    alive_lock = asyncio.Lock()
    done_event = asyncio.Event()

    async def _check_one(index: int, cfg: Config) -> None:
        if done_event.is_set():
            return
        async with semaphore:
            if done_event.is_set():
                return
            # tcp_check never raises for ordinary network failures, but a
            # bug or an unexpected OSError must not silently swallow the
            # config: without this handler gather(return_exceptions=True)
            # ate the exception and the config left the stage with neither
            # a verdict nor a log line (the TLS/Xray stages both guard).
            try:
                is_alive: bool | None = False
                latency_ms: float | None = None
                candidate_proxy: str | None = None
                candidates = _proxies_for(index)[:_MAX_ATTEMPTS_PER_CONFIG]
                for candidate_proxy in candidates:
                    is_alive, latency_ms = await tcp_check(
                        cfg.address,
                        cfg.port,
                        timeout=timeout,
                        proxy_url=candidate_proxy,
                        resolve_timeout=resolve_timeout,
                        pin_address=check_hostnames,
                    )
                    if is_alive is None:
                        # Transient DNS-pin failure is deterministic per host:
                        # retrying via the next proxy cannot help.
                        break
                    if is_alive:
                        break
            except asyncio.CancelledError:
                # Early-stop cancel reached no verdict: do not leave a stale
                # TCP True/False from a previous stage as a false verdict.
                cfg.is_alive = None
                raise
            except Exception as exc:
                logger.exception(
                    "TCP check of %s:%s failed unexpectedly: %s",
                    cfg.address,
                    cfg.port,
                    exc,
                )
                is_alive = False
                latency_ms = None
            cfg.is_alive = is_alive
            if latency_ms is not None:
                # Shed the proxy's own dial hop (mirrors validate_configs_xray):
                # the recorded latency must describe the SERVER, not whichever
                # congested free proxy carried the probe.
                baseline = (
                    float((proxy_latency_ms or {}).get(str(candidate_proxy), 0.0))
                    if candidate_proxy
                    else 0.0
                )
                cfg.latency_ms = max(latency_ms - baseline, 1.0)
            else:
                cfg.latency_ms = None
            if is_alive:
                async with alive_lock:
                    alive_list.append(cfg)
                    if max_alive > 0 and len(alive_list) >= max_alive:
                        done_event.set()

    tasks = [asyncio.create_task(_check_one(i, c)) for i, c in enumerate(configs)]

    # Race the checks against the max_alive event instead of re-registering
    # every pending task into asyncio.wait on each completion: the old loop
    # re-bound done callbacks O(n²) times, and a cancellation arriving during
    # the loop orphaned the per-config tasks entirely. gather() reaps the
    # cancelled children; nothing stays detached.
    gather_task: asyncio.Future[Any] = asyncio.gather(*tasks, return_exceptions=True)
    if max_alive > 0:
        done_task = asyncio.ensure_future(done_event.wait())
        try:
            await asyncio.wait(
                [gather_task, done_task],
                return_when=asyncio.FIRST_COMPLETED,
            )
        except asyncio.CancelledError:
            # Outer cancellation during the wait: reap children before
            # propagating, otherwise per-config tasks stay detached (FD leak).
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
            # Outer cancellation during the wait must still reap children
            # (subprocess/ports), not leave them detached.
            if done_task.done() and not done_event.is_set():
                done_event.set()
            for task in tasks:
                if not task.done():
                    task.cancel()
            # Cancelling an already-completed waiter is a no-op, so this is
            # safe on both race outcomes.
            done_task.cancel()
    try:
        results = await gather_task
    except asyncio.CancelledError:
        for task in tasks:
            if not task.done():
                task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await gather_task
        raise
    if max_alive > 0:
        # Reap the watcher: cancel() only requests cancellation.
        with contextlib.suppress(asyncio.CancelledError):
            await done_task
    for cfg, result in zip(configs, results, strict=False):
        # Cancelled mid-connect: no verdict was reached (mirrors TLS/Xray).
        if isinstance(result, asyncio.CancelledError):
            cfg.is_alive = None

    alive_list.sort(
        key=lambda c: c.latency_ms if c.latency_ms is not None else float("inf"),
    )
    # Contract parity with validate_configs_xray / singbox: racing tasks that
    # grabbed the semaphore before the stop event can overshoot the cap.
    if max_alive > 0 and len(alive_list) > max_alive:
        del alive_list[max_alive:]
    log_refusal_summary()
    return alive_list
