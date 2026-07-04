"""L1 validator: TCP connect check.

Measures whether a proxy server's host:port accepts TCP connections
and how long the connect takes. This is the cheapest liveness check
and is run before the more expensive TLS handshake (L2) test.
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
        # Don't await full drain — we only care that the connect succeeded.
        # Some transports raise on await after close; guard it.
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
) -> list[Config]:
    """Check all configs via TCP.

    Sets is_alive and latency_ms on each Config (even ones that fail,
    which get is_alive=False and latency_ms=None).

    Returns only alive configs, sorted by latency_ms ascending.
    Failed configs (latency_ms is None) are kept out of the returned list
    but remain mutated in the input list.
    """
    semaphore = asyncio.Semaphore(concurrency)

    async def _check_one(cfg: Config) -> None:
        async with semaphore:
            is_alive, latency_ms = await tcp_check(cfg.address, cfg.port, timeout)
            cfg.is_alive = is_alive
            cfg.latency_ms = latency_ms

    # Run all checks concurrently (bounded by the semaphore).
    await asyncio.gather(*(_check_one(c) for c in configs))

    alive = [c for c in configs if c.is_alive]
    # Sort by latency ascending; None should never appear here since alive
    # implies a measured latency, but guard defensively.
    alive.sort(key=lambda c: c.latency_ms if c.latency_ms is not None else float("inf"))
    return alive
