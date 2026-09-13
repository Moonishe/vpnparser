"""L2 validator: TLS handshake check.

For configs that use TLS or REALITY security, performs a real TLS
handshake against the server to confirm it is reachable and responds.
Configs with security='none' pass through unchanged.

Supports **SOCKS5 proxy**: when a proxy URL is provided, TLS handshakes
are routed through it (same rationale as TCP check).
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import ipaddress
import logging
import re
import ssl
from typing import Any
from urllib.parse import urlparse

from src.parsers.base import Config
from src.validators.address_guard import (
    filter_public_configs,
    is_blocked_literal,
    resolve_pinned_addresses,
)

logger = logging.getLogger(__name__)

_TLS_SECURITY_VALUES = {"tls", "reality"}
_EMPTY_SERVER_NAMES = {"", "none", "null", "false", "0", "-"}
#: Cap on the SNI candidates one config may cost. ``sni``/``host`` come from an
#: untrusted subscription link and take a comma-separated list, so a single
#: config could otherwise demand hundreds of handshakes — each up to the full
#: TLS timeout, all inside one slot of the stage semaphore. Real links carry a
#: handful of names; the rest is either a typo or a deliberate stall.
_MAX_SERVER_NAME_CANDIDATES = 4
#: Cap on the TOTAL handshakes one config may cost (proxies x SNI names).
#: Without it, ``proxy_attempts_per_config=0`` ("whole pool") times four SNI
#: candidates could keep one semaphore slot busy for minutes — the same stall
#: the per-name cap above already prevents for a single dimension.
_MAX_ATTEMPTS_PER_CONFIG = 12

#: Per-stage counters for the refusal log (see tcp_check._log_refusal): one
#: aggregate line per stage instead of thousands of WARNINGs per run.
_refusals: dict[str, int] = {"non-public": 0, "unpinnable": 0}


def _log_refusal(kind: str, host: str, port: int) -> None:
    """Count a refused address; full detail goes to DEBUG only."""
    _refusals[kind] = _refusals.get(kind, 0) + 1
    logger.debug("Refusing %s TLS check of %s:%s.", kind, host, port)


def log_refusal_summary() -> None:
    """Emit one aggregate line for the refused addresses of this stage."""
    refused = sum(_refusals.values())
    if not refused:
        return
    logger.info(
        "TLS stage refused %d address(s) (%s).",
        refused,
        ", ".join(f"{kind}: {count}" for kind, count in _refusals.items()),
    )
    for kind in _refusals:
        _refusals[kind] = 0


def reset_refusal_counters() -> None:
    """Start a fresh refusal count — each stage invocation counts its own."""
    for kind in _refusals:
        _refusals[kind] = 0


async def _open_connection_direct(
    host: str,
    port: int,
    ssl_context: ssl.SSLContext,
    server_hostname: str | None,
) -> tuple[Any, Any]:
    """Direct TLS connection."""
    return await asyncio.open_connection(
        host,
        port,
        ssl=ssl_context,
        server_hostname=server_hostname,
    )


async def _open_connection_via_socks(
    host: str,
    port: int,
    ssl_context: ssl.SSLContext,
    server_hostname: str | None,
    proxy_url: str,
    timeout: float | None = None,
) -> tuple[Any, Any]:
    """TLS connection routed through a SOCKS5 proxy."""
    from python_socks.async_.asyncio import Proxy

    proxy = Proxy.from_url(proxy_url)
    # Timeout inside Proxy.connect (see tcp_check): an outer-only wait_for
    # leaked the SOCKS socket FD on every mass-timeout wave.
    sock = await proxy.connect(dest_host=host, dest_port=port, timeout=timeout)
    # Wrap the raw socket into an SSL-wrapped asyncio connection.
    # Close the raw socket if the wrap raises (see tcp_check).
    try:
        reader, writer = await asyncio.open_connection(
            sock=sock,
            ssl=ssl_context,
            server_hostname=server_hostname,
        )
    except BaseException:
        with contextlib.suppress(Exception):
            sock.close()
        raise
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

    cleaned = cleaned.removeprefix("*.")

    if cleaned.count(":") == 1:
        host, port = cleaned.rsplit(":", 1)
        if port.isdigit():
            cleaned = host.strip()

    # A bracketed IPv6 literal with a port ("[::1]:443") strips to garbage
    # ("::1]:443") via strip("[]"): anything bracket-shaped left is not a
    # hostname. Bare IP literals are not valid SNI either (RFC 6066 forbids
    # IP literals in server_name) — without SNI the handshake still proves
    # liveness, while garbage fails it (false dead). Mirrors xray's
    # _server_name, which drops the same inputs.
    if "[" in cleaned or "]" in cleaned:
        return None
    if _is_ip_address(cleaned):
        return None

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
    """Return SNI candidates matching how clients commonly interpret links.

    At most :data:`_MAX_SERVER_NAME_CANDIDATES` names are returned, in the order
    the link listed them.
    """
    names: list[str | None] = []
    seen: set[str | None] = set()

    def add(candidate: str | None) -> None:
        key = candidate.lower() if isinstance(candidate, str) else candidate
        if key in seen:
            return
        seen.add(key)
        names.append(candidate)

    explicit_names = [
        name for raw in (cfg.sni, cfg.host) for name in _split_server_names(raw) if name
    ]
    for name in explicit_names:
        add(name)

    if explicit_names:
        return names[:_MAX_SERVER_NAME_CANDIDATES]

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


#: ALPN names the cache accepts. ``cfg.alpn`` comes straight out of an
#: untrusted subscription link, and _tls_context is a process-lifetime
#: functools.cache keyed on it: an attacker-controlled source minting a
#: distinct alpn=... per config would otherwise hold one SSLContext (with a
#: loaded trust store, ~15ms of blocking work each) per key for the life of a
#: --continuous process. Anything outside this set is treated as "no ALPN".
_KNOWN_ALPN = frozenset({"h2", "http/1.1", "h3"})


def _alpn_cache_key(value: str | None) -> tuple[str, ...] | None:
    """Normalize an untrusted alpn string into a bounded cache key."""
    protocols = _alpn_protocols(value)
    if not protocols:
        return None
    known = tuple(sorted({p.lower() for p in protocols if p.lower() in _KNOWN_ALPN}))
    return known or None


@functools.cache
def _tls_context(verify_tls: bool, alpn_key: tuple[str, ...] | None) -> ssl.SSLContext:
    """Build (and cache) the TLS context for one verify/alpn combination.

    ``ssl.create_default_context()`` re-reads the system trust store — about
    15ms of *blocking* work on Windows — and this sits on the hot path of a
    stage running at concurrency 100: one context per attempt stalled the
    event loop for minutes over a large sweep. xray_probe caches the same
    call for the same reason. Contexts are immutable after setup, so the
    cache is safe; ALPN is part of the key because it mutates the context.
    The key cardinality is bounded (see ``_KNOWN_ALPN``): the input is
    attacker-controlled and a raw ``cfg.alpn`` would mint unlimited keys.
    """
    ssl_context = ssl.create_default_context()
    if not verify_tls:
        # Liveness-only mode: accept any certificate and any hostname.
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
    if alpn_key:
        ssl_context.set_alpn_protocols(list(alpn_key))
    return ssl_context


async def tls_check(
    host: str,
    port: int,
    sni: str | None = None,
    alpn: str | None = None,
    timeout: float = 5.0,
    proxy_url: str | None = None,
    verify_tls: bool = False,
    resolve_timeout: float = 5.0,
    pin_address: bool = True,
) -> bool | None:
    """TLS handshake to host:port, optionally through a SOCKS5 proxy.

    By default the handshake only proves that the server completes one — most
    VPN servers use self-signed certificates, so certificate validation would
    mark every one of them dead. Pass ``verify_tls=True`` to additionally
    require a certificate valid for the connection target; only meaningful
    when the checked servers are known to hold trusted certificates.

    ``pin_address=False`` honours the operator's ``check_hostnames: false``
    opt-out: the hostname is dialled as-is (OS/proxy resolves it) and no DNS
    query is made here, mirroring tcp_check and the Xray stage.

    Returns True on success, False on dead, None on no verdict (transient
    DNS-pin failure — must not count toward health bans).
    """
    if is_blocked_literal(host):
        _log_refusal("non-public", host, port)
        return False

    # Pin the connect target to the addresses the guard validated (DNS
    # rebinding); SNI/certificate identity still comes from server_hostname.
    # The list is walked in order: a dual-stack host whose first answer is an
    # unroutable AAAA used to die when only the first address survived.
    if pin_address:
        pinned_addresses = await resolve_pinned_addresses(host, timeout=resolve_timeout)
        if not pinned_addresses:
            _log_refusal("unpinnable", host, port)
            return None
    else:
        # check_hostnames=false skips DNS entirely (same contract as the
        # Xray stage's pin_address): no resolve, no pin, dial the name.
        pinned_addresses = [host]

    server_hostname = sni or host
    try:
        # Bounded key: untrusted ALPN input must not mint unlimited contexts.
        ssl_context = _tls_context(verify_tls, _alpn_cache_key(alpn))
    except Exception:
        return False

    writer = None
    for address in pinned_addresses:
        try:
            if proxy_url:
                # Inner timeout drives the handshake; outer is safety +5.
                reader, writer = await asyncio.wait_for(
                    _open_connection_via_socks(
                        address,
                        port,
                        ssl_context,
                        server_hostname,
                        proxy_url,
                        timeout=timeout,
                    ),
                    timeout=timeout + 5.0,
                )
            else:
                reader, writer = await asyncio.wait_for(
                    _open_connection_direct(
                        address,
                        port,
                        ssl_context,
                        server_hostname,
                    ),
                    timeout=timeout,
                )
            break
        except (TimeoutError, ssl.SSLError, ConnectionRefusedError, OSError):
            writer = None
            continue
        except Exception:
            writer = None
            continue
    if writer is None:
        return False

    # Exception covers everything the narrower names would: close()/wait_closed()
    # are best-effort teardown on a socket that just failed its handshake.
    with contextlib.suppress(Exception):
        writer.close()
        await writer.wait_closed()

    return True


async def validate_configs_tls(
    configs: list[Config],
    timeout: float = 5.0,
    concurrency: int = 100,
    proxy_url: str | None = None,
    proxy_urls: list[str] | None = None,
    proxy_attempts_per_config: int = 1,
    check_hostnames: bool = True,
    resolve_timeout: float = 5.0,
    verify_tls: bool = False,
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
        check_hostnames: Resolve hostnames to reject configs pointing at
            internal addresses. IP literals are rejected either way.
        verify_tls: Require a certificate valid for the connection target in
            the handshake probes. ``False`` (default) only checks that a
            handshake completes — see :func:`tls_check`.
    """
    configs = await filter_public_configs(
        configs,
        stage="TLS check",
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

    async def _check_one(index: int, cfg: Config) -> None:
        if not _is_tls_security(cfg.security):
            return
        async with semaphore:
            try:
                ok: bool | None = False
                # Flatten proxies x SNI names and cap the total: the product
                # used to be unbounded when the whole pool was requested.
                combos = [
                    (candidate_proxy, server_name)
                    for candidate_proxy in _proxies_for(index)
                    for server_name in _tls_server_names(cfg)
                ][:_MAX_ATTEMPTS_PER_CONFIG]
                for candidate_proxy, server_name in combos:
                    ok = await tls_check(
                        cfg.address,
                        cfg.port,
                        sni=server_name,
                        alpn=cfg.alpn,
                        timeout=timeout,
                        proxy_url=candidate_proxy,
                        verify_tls=verify_tls,
                        resolve_timeout=resolve_timeout,
                        pin_address=check_hostnames,
                    )
                    if ok is None:
                        # Transient DNS-pin failure: further combos cannot
                        # help (same hostname), stop as no-verdict.
                        break
                    if ok:
                        break
                cfg.is_alive = ok
            except asyncio.CancelledError:
                # Early-stop cancel reached no verdict: keep no TCP True as
                # a false TLS pass (see xray/singbox reset).
                cfg.is_alive = None
                raise
            except Exception as exc:
                logger.debug(
                    "TLS check failed for %s:%d: %s — marking as dead.",
                    cfg.address,
                    cfg.port,
                    exc,
                )
                cfg.is_alive = False

    results = await asyncio.gather(
        *(_check_one(i, c) for i, c in enumerate(configs)),
        return_exceptions=True,
    )
    for cfg, result in zip(configs, results, strict=False):
        # Cancelled mid-handshake: no TLS verdict was reached.
        if isinstance(result, asyncio.CancelledError) and _is_tls_security(
            cfg.security
        ):
            cfg.is_alive = None
    log_refusal_summary()

    return [
        c for c in configs if not _is_tls_security(c.security) or c.is_alive is True
    ]
