"""L1 validator: TCP connect check.

Measures whether a proxy server's host:port accepts TCP connections
and how long the connect takes. This is the cheapest liveness check
and is run before the more expensive TLS handshake (L2) test.

Supports **early termination**: once enough alive configs with low
latency are found, remaining checks are cancelled to save time.
"""

from __future__ import annotations

import asyncio
import socket
import time

from src.parsers.base import Config


async def tcp_check(
    host: str, port: int, timeout: float = 3.0
) -> tuple[bool, float | None]:
    """TCP connect to host:port.

    Returns (is_alive, latency_ms).
    - latency_ms is measured from connect start to successful connect,
      using a monotonic clock.
    - Returns (False, None) on timeout, connection refused, DNS failure,
      or any other OSError.
    """
    start = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
    except (ConnectionRefusedError, asyncio.TimeoutError, socket.gaierror, OSError):
        return (False, None)
    except Exception:
        # Defensive: never raise from a validator.
        return (False, None)

    latency_ms = (time.monotonic() - start) * 1000.0
    # Close the connection cleanly, ignoring close-time errors.
    try:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, Exception):
            pass
    except (OSError, Exception):
        pass

    return (True, latency_ms)


async def validate_configs_tcp(
    configs: list[Config],
    timeout: float = 3.0,
    concurrency: int = 200,
    max_alive: int = 0,
) -> list[Config]:
    """Check configs via TCP with optional early termination.

    Args:
        configs: List of Config objects to check.
        timeout: TCP connect timeout in seconds.
        concurrency: Maximum concurrent connections.
        max_alive: Stop once this many alive configs are found.
            0 = no limit (check everything).

    Sets is_alive and latency_ms on each Config that was actually checked.
    Configs that were cancelled (not checked) remain unchanged.

    Returns alive configs sorted by latency_ms ascending.
    """
    if not configs:
        return []

    semaphore = asyncio.Semaphore(concurrency)
    alive_list: list[Config] = []
    alive_lock = asyncio.Lock()
    done_event = asyncio.Event()

    async def _check_one(cfg: Config) -> None:
        if done_event.is_set():
            return
        async with semaphore:
            if done_event.is_set():
                return
            is_alive, latency_ms = await tcp_check(cfg.address, cfg.port, timeout)
            cfg.is_alive = is_alive
            cfg.latency_ms = latency_ms
            if is_alive:
                async with alive_lock:
                    alive_list.append(cfg)
                    if max_alive > 0 and len(alive_list) >= max_alive:
                        done_event.set()

    tasks = [asyncio.create_task(_check_one(c)) for c in configs]

    # Wait until either all done or we have enough alive.
    # Use as_completed to check periodically.
    await asyncio.wait(
        [asyncio.create_task(done_event.wait()), *tasks],
        return_when=asyncio.FIRST_COMPLETED,
    )

    if done_event.is_set():
        # Cancel all remaining tasks.
        for t in tasks:
            if not t.done():
                t.cancel()
        # Wait for cancellations to settle.
        await asyncio.gather(*tasks, return_exceptions=True)

    alive_list.sort(
        key=lambda c: c.latency_ms if c.latency_ms is not None else float("inf")
    )
    return alive_list
