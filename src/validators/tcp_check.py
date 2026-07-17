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
import socket
import time
from typing import Any

from src.parsers.base import Config


async def _open_connection_direct(host: str, port: int) -> tuple[Any, Any]:
    """Direct TCP connection (no proxy)."""
    return await asyncio.open_connection(host, port)


async def _open_connection_via_socks(
    host: str,
    port: int,
    proxy_url: str,
) -> tuple[Any, Any]:
    """TCP connection routed through a SOCKS5 proxy.

    Uses python-socks which returns a raw socket; we wrap it into
    asyncio streams.
    """
    from python_socks.async_.asyncio import Proxy

    proxy = Proxy.from_url(proxy_url)
    sock = await proxy.connect(dest_host=host, dest_port=port, timeout=None)
    # python-socks returns a connected socket; wrap into streams.
    reader, writer = await asyncio.open_connection(sock=sock)
    return reader, writer


async def tcp_check(
    host: str,
    port: int,
    timeout: float = 3.0,
    proxy_url: str | None = None,
) -> tuple[bool, float | None]:
    """TCP connect to host:port, optionally through a SOCKS5 proxy.

    Args:
        host: Target hostname or IP.
        port: Target port.
        timeout: Connect timeout in seconds.
        proxy_url: Optional SOCKS5 proxy URL (e.g. ``socks5://host:port``).
            When provided, the connection is routed through the proxy.

    Returns (is_alive, latency_ms).
    """
    start = time.monotonic()
    try:
        if proxy_url:
            reader, writer = await asyncio.wait_for(
                _open_connection_via_socks(host, port, proxy_url),
                timeout=timeout,
            )
        else:
            reader, writer = await asyncio.wait_for(
                _open_connection_direct(host, port),
                timeout=timeout,
            )
    except (TimeoutError, ConnectionRefusedError, socket.gaierror, OSError):
        return (False, None)
    except Exception:
        return (False, None)

    latency_ms = (time.monotonic() - start) * 1000.0
    with contextlib.suppress(OSError, Exception):
        writer.close()
        with contextlib.suppress(OSError, Exception):
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

    Returns alive configs sorted by latency_ms ascending.
    """
    if not configs:
        return []

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
            is_alive = False
            latency_ms: float | None = None
            for candidate_proxy in _proxies_for(index):
                is_alive, latency_ms = await tcp_check(
                    cfg.address,
                    cfg.port,
                    timeout=timeout,
                    proxy_url=candidate_proxy,
                )
                if is_alive:
                    break
            cfg.is_alive = is_alive
            cfg.latency_ms = latency_ms
            if is_alive:
                async with alive_lock:
                    alive_list.append(cfg)
                    if max_alive > 0 and len(alive_list) >= max_alive:
                        done_event.set()

    tasks = [asyncio.create_task(_check_one(i, c)) for i, c in enumerate(configs)]

    if max_alive > 0:
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
        if not done_task.done():
            done_task.cancel()
            await asyncio.gather(done_task, return_exceptions=True)

    await asyncio.gather(*tasks, return_exceptions=True)

    alive_list.sort(
        key=lambda c: c.latency_ms if c.latency_ms is not None else float("inf"),
    )
    return alive_list
