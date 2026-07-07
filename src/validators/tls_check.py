"""L2 validator: TLS handshake check.

For configs that use TLS or REALITY security, performs a real TLS
handshake against the server to confirm it is reachable and responds.
Configs with security='none' pass through unchanged.

Supports **SOCKS5 proxy**: when a proxy URL is provided, TLS handshakes
are routed through it (same rationale as TCP check).
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import ssl
from typing import Any
from urllib.parse import urlparse

from src.parsers.base import Config

logger = logging.getLogger(__name__)

_TLS_SECURITY_VALUES = {"tls", "reality"}
_EMPTY_SERVER_NAMES = {"", "none", "null", "false", "0", "-"}


async def _open_connection_direct(
    host: str, port: int, ssl_context: ssl.SSLContext, server_hostname: str | None
) -> tuple[Any, Any]:
    """Direct TLS connection."""
    return await asyncio.open_connection(
        host, port, ssl=ssl_context, server_hostname=server_hostname
    )


async def _open_connection_via_socks(
    host: str,
    port: int,
    ssl_context: ssl.SSLContext,
    server_hostname: str | None,
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


def _is_tls_security(security: str | None) -> bool:
    return str(security or "").strip().lower() in _TLS_SECURITY_VALUES


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return False
    return True


def _clean_server_name(value: str) -> str | None:
    cleaned = value.strip().strip("\"'")
    if not cleaned or cleaned.lower() in _EMPTY_SERVER_NAMES:
        return None

    if "://" in cleaned:
        parsed = urlparse(cleaned)
        cleaned = parsed.hostname or cleaned

    if "/" in cleaned:
        cleaned = cleaned.split("/", 1)[0]
    cleaned = cleaned.strip().strip("[]").strip()

    if cleaned.startswith("*."):
        cleaned = cleaned[2:]

    if cleaned.count(":") == 1:
        host, port = cleaned.rsplit(":", 1)
        if port.isdigit():
            cleaned = host.strip()

    if not cleaned or cleaned.lower() in _EMPTY_SERVER_NAMES:
        return None
    return cleaned


def _split_server_names(value: str | None) -> list[str]:
    if not value:
        return []
    names: list[str] = []
    for part in re.split(r"[,;]", str(value)):
        cleaned = _clean_server_name(part)
        if cleaned:
            names.append(cleaned)
    return names


def _tls_server_names(cfg: Config) -> list[str | None]:
    """Return SNI candidates matching how clients commonly interpret links."""
    names: list[str | None] = []
    seen: set[str | None] = set()

    def add(candidate: str | None) -> None:
        key = candidate.lower() if isinstance(candidate, str) else candidate
        if key in seen:
            return
        seen.add(key)
        names.append(candidate)

    explicit_names = [
        name
        for raw in (cfg.sni, cfg.host)
        for name in _split_server_names(raw)
        if name
    ]
    for name in explicit_names:
        add(name)

    if explicit_names:
        return names

    address = _clean_server_name(cfg.address)
    if address and not _is_ip_address(address):
        add(address)
    else:
        add(None)
    return names


def _alpn_protocols(value: str | None) -> list[str] | None:
    if not value:
        return None
    protocols = [part.strip() for part in re.split(r"[,;]", value) if part.strip()]
    return protocols or None


async def tls_check(
    host: str,
    port: int,
    sni: str | None = None,
    alpn: str | None = None,
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
        protocols = _alpn_protocols(alpn)
        if protocols:
            ssl_context.set_alpn_protocols(protocols)
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
    proxy_urls: list[str] | None = None,
    proxy_attempts_per_config: int = 1,
) -> list[Config]:
    """Filter configs by TLS handshake.

    Only checks configs with security='tls' or 'reality'. Configs with
    security='none' pass through unchanged.

    Args:
        configs: List of Config objects.
        timeout: TLS handshake timeout.
        concurrency: Max concurrent checks.
        proxy_url: Optional SOCKS5 proxy URL.
        proxy_urls: Optional SOCKS5 proxy pool. When provided, configs are
            checked through the pool in round-robin order. Takes precedence
            over ``proxy_url``.
        proxy_attempts_per_config: Number of different proxies to try per
            config before marking it dead. ``0`` means try the whole pool.
    """
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
        return [proxy_choices[(start + offset) % len(proxy_choices)] for offset in range(attempts)]

    semaphore = asyncio.Semaphore(concurrency)

    async def _check_one(index: int, cfg: Config) -> None:
        if not _is_tls_security(cfg.security):
            return
        async with semaphore:
            try:
                ok = False
                for candidate_proxy in _proxies_for(index):
                    for server_name in _tls_server_names(cfg):
                        ok = await tls_check(
                            cfg.address,
                            cfg.port,
                            sni=server_name,
                            alpn=cfg.alpn,
                            timeout=timeout,
                            proxy_url=candidate_proxy,
                        )
                        if ok:
                            break
                    if ok:
                        break
                cfg.is_alive = ok
            except Exception as exc:
                logger.debug(
                    "TLS check failed for %s:%d: %s — marking as dead.",
                    cfg.address,
                    cfg.port,
                    exc,
                )
                cfg.is_alive = False

    await asyncio.gather(
        *(_check_one(i, c) for i, c in enumerate(configs)),
        return_exceptions=True,
    )

    return [
        c for c in configs if not _is_tls_security(c.security) or c.is_alive is True
    ]
