"""L2 validator: TLS handshake check.

For configs that use TLS or REALITY security, performs a real TLS
handshake against the server to confirm it is reachable and responds.
Configs with security='none' pass through unchanged.

Supports **SOCKS5 proxy**: when a proxy URL is provided, TLS handshakes
are routed through it (same rationale as TCP check).
"""

from __future__ import annotations

import asyncio
import logging
import ssl
from typing import Any

from src.parsers.base import Config

logger = logging.getLogger(__name__)


async def _open_connection_direct(
    host: str, port: int, ssl_context: ssl.SSLContext, server_hostname: str
) -> tuple[Any, Any]:
    """Direct TLS connection."""
    return await asyncio.open_connection(
        host, port, ssl=ssl_context, server_hostname=server_hostname
    )


async def _open_connection_via_socks(
    host: str,
    port: int,
    ssl_context: ssl.SSLContext,
    server_hostname: str,
    proxy_url: str,
) -> tuple[Any, Any]:
    """TLS connection routed through a SOCKS5 proxy."""
    from python_socks.async_.asyncio import Proxy

    proxy = Proxy.from_url(proxy_url)
    sock = await proxy.connect(dest_host=host, dest_port=port, timeout=None)
    # Wrap the raw socket into an SSL-wrapped asyncio connection.
    reader, writer = await asyncio.open_connection(
        sock=sock, ssl=ssl_context, server_hostname=server_hostname
    )
    return reader, writer


async def tls_check(
    host: str,
    port: int,
    sni: str | None = None,
    timeout: float = 5.0,
    proxy_url: str | None = None,
) -> bool:
    """TLS handshake to host:port, optionally through a SOCKS5 proxy.

    Returns True if the handshake completes successfully, False on any error.
    """
    server_hostname = sni if sni else host
    try:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
    except Exception:
        return False

    try:
        if proxy_url:
            reader, writer = await asyncio.wait_for(
                _open_connection_via_socks(
                    host, port, ssl_context, server_hostname, proxy_url
                ),
                timeout=timeout,
            )
        else:
            reader, writer = await asyncio.wait_for(
                _open_connection_direct(host, port, ssl_context, server_hostname),
                timeout=timeout,
            )
    except (ssl.SSLError, ConnectionRefusedError, asyncio.TimeoutError, OSError):
        return False
    except Exception:
        return False

    try:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ssl.SSLError, Exception):
            pass
    except (OSError, ssl.SSLError, Exception):
        pass

    return True


async def validate_configs_tls(
    configs: list[Config],
    timeout: float = 5.0,
    concurrency: int = 100,
    proxy_url: str | None = None,
) -> list[Config]:
    """Filter configs by TLS handshake.

    Only checks configs with security='tls' or 'reality'. Configs with
    security='none' pass through unchanged.

    Args:
        configs: List of Config objects.
        timeout: TLS handshake timeout.
        concurrency: Max concurrent checks.
        proxy_url: Optional SOCKS5 proxy URL.
    """
    semaphore = asyncio.Semaphore(concurrency)

    async def _check_one(cfg: Config) -> None:
        if cfg.security not in ("tls", "reality"):
            return
        async with semaphore:
            try:
                ok = await tls_check(
                    cfg.address,
                    cfg.port,
                    sni=cfg.sni,
                    timeout=timeout,
                    proxy_url=proxy_url,
                )
                cfg.is_alive = ok
            except Exception as exc:
                logger.debug(
                    "TLS check failed for %s:%d: %s — marking as dead.",
                    cfg.address,
                    cfg.port,
                    exc,
                )
                cfg.is_alive = False

    await asyncio.gather(*(_check_one(c) for c in configs), return_exceptions=True)

    return [
        c for c in configs if c.security not in ("tls", "reality") or c.is_alive is True
    ]
