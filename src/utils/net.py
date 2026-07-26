"""Network-address safety helpers (SSRF guard).

The pipeline consumes two kinds of fully untrusted input:

- **Source indexes** — ``url-list`` sources hold arbitrary URLs written by a
  third party; every one of them gets fetched.
- **Proxy configs** — ``address``/``port`` pairs parsed out of public
  subscriptions; every one of them gets connected to by the validators.

Both must be filtered before a socket is opened, otherwise the runner becomes
an internal-network scanner (and, with the LLM fallback enabled, an
exfiltration channel) on behalf of whoever controls the upstream file.

All predicates here **fail closed**: an address that cannot be parsed or a
hostname that cannot be resolved is reported as unsafe.
"""

from __future__ import annotations

import asyncio
import functools
import ipaddress
import logging
import socket
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

#: URL schemes the fetchers are allowed to touch.
SAFE_URL_SCHEMES = frozenset({"http", "https"})

#: Well-known NAT64 prefix (RFC 6052): the low 32 bits carry the IPv4 address
#: the synthesized answer stands for.
_NAT64_WELL_KNOWN = ipaddress.IPv6Network("64:ff9b::/96")

#: Non-public ranges no standard predicate reports: deprecated IPv6 site-local
#: space (RFC 3879) is neither private nor reserved to Python, and ``is_global``
#: still calls it global.
_EXTRA_NON_PUBLIC = (ipaddress.IPv6Network("fec0::/10"),)

#: Width of the resolver thread pool — and therefore the maximum number of
#: lookups a caller may keep in flight, see :func:`_resolver_pool`.
RESOLVER_CONCURRENCY = 50

_IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


@functools.cache
def _resolver_pool() -> ThreadPoolExecutor:
    """Return the thread pool dedicated to blocking ``getaddrinfo`` calls.

    asyncio's default executor is ``min(32, cpu + 4)`` threads wide — six on a
    two-core CI runner — and is shared with every other thread offload in the
    process, so a lookup submitted to it can sit in the queue for longer than
    the resolve timeout. :func:`asyncio.wait_for` cannot tell queue time from
    DNS time: it would report a healthy resolver as timed out, and the SSRF
    guard reads a timeout as "unresolved" and lets the address through. A
    dedicated pool exactly :data:`RESOLVER_CONCURRENCY` wide keeps the timeout
    about DNS alone.
    """
    return ThreadPoolExecutor(
        max_workers=RESOLVER_CONCURRENCY,
        thread_name_prefix="net-resolve",
    )


def _nat64_embedded(addr: _IpAddress) -> _IpAddress:
    """Return the IPv4 address a well-known-prefix NAT64 answer stands for.

    In a DNS64/NAT64 network every A record comes back as ``64:ff9b::<ipv4>``.
    Python files that prefix under ``::/8`` and therefore calls it *reserved*,
    so judging it as-is marks every hostname internal and empties the pipeline;
    the embedded IPv4 address is what a connection would actually reach.
    """
    if isinstance(addr, ipaddress.IPv6Address) and addr in _NAT64_WELL_KNOWN:
        return ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
    return addr


def is_private_address(value: str) -> bool:
    """Return ``True`` when *value* is not a routable public IP address.

    Covers private (RFC 1918), loopback, link-local (including the cloud
    metadata endpoint ``169.254.169.254``), carrier-grade NAT (RFC 6598),
    reserved, multicast, unspecified and deprecated site-local ranges, for both
    IPv4 and IPv6. NAT64 answers are judged by the IPv4 address they embed.

    Unparseable input returns ``True`` (fail-closed) — callers pass hostnames
    and attacker-controlled strings here, and "not an IP literal" must never
    read as "safe".
    """
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return True
    addr = _nat64_embedded(addr)
    return (
        # is_global covers CGNAT (100.64.0.0/10), which none of the predicates
        # below classifies; the explicit ones cover what is_global still calls
        # global, such as multicast.
        not addr.is_global
        or addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
        or any(addr in network for network in _EXTRA_NON_PUBLIC)
    )


def _strip_brackets(host: str) -> str:
    """Remove the brackets around an IPv6 literal (``[::1]`` -> ``::1``)."""
    host = host.strip()
    if host.startswith("[") and host.endswith("]"):
        return host[1:-1].strip()
    return host


async def resolve_host_addresses(
    host: str,
    *,
    timeout: float = 5.0,
) -> list[str] | None:
    """Resolve *host* once and return every address it answers with.

    Args:
        host: Hostname to look up; IP literals are the caller's business.
        timeout: Lookup timeout in seconds.

    Returns:
        The distinct addresses ``getaddrinfo`` returned, or ``None`` when the
        lookup itself failed. "Did not resolve" and "resolved to nothing
        public" lead to opposite verdicts in the SSRF guard, so they must stay
        distinguishable — see
        :func:`src.validators.address_guard.classify_host`.
    """
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.run_in_executor(
                _resolver_pool(),
                socket.getaddrinfo,
                host,
                None,
                0,
                socket.SOCK_STREAM,
                0,
                0,
            ),
            timeout=timeout,
        )
    except (OSError, TimeoutError, UnicodeError):
        # UnicodeError is a ValueError, *not* an OSError: it is what the idna
        # codec raises for a DNS label over 63 bytes or an empty one, e.g. a
        # base64 blob parsed as a host. Public subscriptions are full of those,
        # and letting it escape kills the whole liveness stage.
        return None

    addresses: list[str] = []
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        candidate = sockaddr[0]
        if not isinstance(candidate, str):
            continue
        if candidate not in addresses:
            addresses.append(candidate)
    return addresses


async def resolve_global_ips(host: str, *, timeout: float = 5.0) -> list[str]:
    """Resolve *host* and return only its globally routable IP addresses.

    Accepts IPv4/IPv6 literals (returned as-is when public) and hostnames
    (resolved via ``getaddrinfo``, IPv4 and IPv6 alike). Returns an empty list
    when the host does not resolve, resolution times out, or every address is
    non-public.
    """
    bare = _strip_brackets(host)
    if not bare:
        return []

    # IP literal: no DNS needed.
    try:
        ipaddress.ip_address(bare)
    except ValueError:
        pass
    else:
        return [] if is_private_address(bare) else [bare]

    answers = await resolve_host_addresses(bare, timeout=timeout)
    if not answers:
        return []

    public: list[str] = []
    for candidate in answers:
        if is_private_address(candidate):
            # A single internal answer is enough to distrust the whole name:
            # a hostname resolving to 127.0.0.1 is an SSRF attempt, not a
            # partially healthy host.
            return []
        public.append(candidate)
    return public


async def is_public_host(host: str, *, timeout: float = 5.0) -> bool:
    """Return ``True`` only if *host* resolves exclusively to public addresses.

    Fail-closed: unresolvable hosts, timeouts, and hosts with any private,
    loopback, link-local or reserved answer all return ``False``.
    """
    return bool(await resolve_global_ips(host, timeout=timeout))


async def is_safe_public_url(url: str, *, timeout: float = 5.0) -> bool:
    """Return ``True`` when *url* is an http(s) URL pointing at a public host.

    Intended for URLs harvested from untrusted indexes. Rejects unknown
    schemes, missing hosts, and any host that resolves into a non-public
    range. Note that this validates a *single* hop — a client following
    redirects must re-validate every hop (see
    :func:`src.sources.manager.SourceManager._fetch_direct_url`).
    """
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return False
    if parts.scheme.lower() not in SAFE_URL_SCHEMES:
        return False
    host = parts.hostname
    if not host:
        return False
    return await is_public_host(host, timeout=timeout)
