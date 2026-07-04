"""L2 validator: TLS handshake check.

For configs that use TLS or REALITY security, performs a real TLS
handshake against the server to confirm it presents a valid certificate
chain (or at least completes a handshake against the configured SNI).
Configs with security='none' pass through unchanged — they don't claim
to use TLS so we don't penalize them.
"""

from __future__ import annotations

import asyncio
import ssl

from src.parsers.base import Config


async def tls_check(
    host: str,
    port: int,
    sni: str | None = None,
    timeout: float = 5.0,
) -> bool:
    """TLS handshake to host:port.

    Returns True if the handshake completes successfully, False on any
    error (timeout, refused, DNS failure, certificate error, etc.).

    The SNI (server_hostname) is set to `sni` if provided, otherwise `host`.
    """
    server_hostname = sni if sni else host
    try:
        ssl_context = ssl.create_default_context()
        # Liveness check, not a trust check: VPN servers (especially REALITY
        # and self-signed) would be incorrectly rejected with verify=True.
        # check_hostname must be False *before* setting CERT_NONE.
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
    except Exception:
        # Extremely unlikely, but never raise from a validator.
        return False

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host, port, ssl=ssl_context, server_hostname=server_hostname
            ),
            timeout=timeout,
        )
    except (ssl.SSLError, ConnectionRefusedError, asyncio.TimeoutError, OSError):
        return False
    except Exception:
        return False

    # Handshake already completed by open_connection with ssl=... — close cleanly.
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
) -> list[Config]:
    """Filter configs by TLS handshake.

    Only checks configs with security='tls' or 'reality'. Configs with
    security='none' (or any other value) pass through unchanged — their
    is_alive is left as-is (typically set by the preceding TCP check).

    For TLS/reality configs that fail the handshake, is_alive is set to
    False. Returns the list of configs that are still alive.
    """
    semaphore = asyncio.Semaphore(concurrency)

    async def _check_one(cfg: Config) -> None:
        # Non-TLS configs are not tested here.
        if cfg.security not in ("tls", "reality"):
            return
        async with semaphore:
            ok = await tls_check(cfg.address, cfg.port, sni=cfg.sni, timeout=timeout)
            if not ok:
                cfg.is_alive = False

    await asyncio.gather(*(_check_one(c) for c in configs))

    return [c for c in configs if c.is_alive]
