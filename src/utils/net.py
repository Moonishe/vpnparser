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
import ipaddress
import logging
import socket
import threading
from concurrent.futures import Future
from typing import Any
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

#: How many lookups a caller is expected to keep in flight at once.
RESOLVER_CONCURRENCY = 50

#: Hard cap on lookup threads alive at once, including the ones a caller has
#: already given up on. Reaching it means DNS is black-holed rather than slow;
#: further lookups then wait for a thread instead of being submitted.
_MAX_LOOKUP_THREADS = 4 * RESOLVER_CONCURRENCY

#: How often a lookup re-checks for a free thread once the cap is reached.
_LOOKUP_SLOT_POLL_SECONDS = 0.05

_IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class _LookupSlots:
    """Process-wide count of threads currently inside ``getaddrinfo``.

    A slot is held for as long as the *thread* is busy, not for as long as the
    awaiting coroutine is: a lookup nobody waits for any more still occupies an
    OS thread until the resolver gives up on it.
    """

    def __init__(self, capacity: int) -> None:
        self._capacity = capacity
        self._lock = threading.Lock()
        self._active = 0

    def acquire(self) -> bool:
        """Claim a slot; ``False`` when every thread is already taken."""
        with self._lock:
            if self._active >= self._capacity:
                return False
            self._active += 1
            return True

    def release(self) -> None:
        """Give a slot back once its thread has left ``getaddrinfo``."""
        with self._lock:
            self._active = max(0, self._active - 1)

    @property
    def active(self) -> int:
        with self._lock:
            return self._active


_lookup_slots = _LookupSlots(_MAX_LOOKUP_THREADS)


def active_lookup_count() -> int:
    """Return how many lookup threads are still inside ``getaddrinfo``."""
    return _lookup_slots.active


def _start_lookup(host: str) -> Future[list[Any]]:
    """Run one blocking ``getaddrinfo`` on a thread of its own.

    A shared pool cannot be used here. ``getaddrinfo`` is not interruptible, so
    a lookup the caller timed out on keeps its worker until the resolver's own
    timeout expires (10-30s against a black-holed nameserver). With a pool, the
    next lookups queue behind those workers, time out *without ever asking
    DNS*, and are then read as "unresolved" — which the SSRF guard lets through
    (see :func:`src.validators.address_guard.classify_host`). One thread per
    lookup keeps :func:`asyncio.wait_for` timing DNS alone, and the thread is a
    daemon so a stuck lookup can never delay interpreter exit either.
    """
    future: Future[list[Any]] = Future()

    def _run() -> None:
        try:
            if not future.set_running_or_notify_cancel():
                return
            try:
                infos = socket.getaddrinfo(host, None, 0, socket.SOCK_STREAM, 0, 0)
            except Exception as exc:
                # Whatever the resolver raised belongs to the awaiter, which
                # knows that OSError/UnicodeError mean "did not resolve".
                future.set_exception(exc)
            else:
                future.set_result(infos)
        finally:
            _lookup_slots.release()

    thread = threading.Thread(target=_run, name="net-resolve", daemon=True)
    try:
        thread.start()
    except RuntimeError:
        _lookup_slots.release()
        raise
    return future


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
        timeout: Lookup timeout in seconds. It covers the lookup itself; when
            every lookup thread is stuck (see :data:`_MAX_LOOKUP_THREADS`) the
            call waits for one to free up first, because reporting a lookup
            that never ran as a failed one is what opens the SSRF guard.

    Returns:
        The distinct addresses ``getaddrinfo`` returned, or ``None`` when the
        lookup itself failed. "Did not resolve" and "resolved to nothing
        public" lead to opposite verdicts in the SSRF guard, so they must stay
        distinguishable — see
        :func:`src.validators.address_guard.classify_host`.
    """
    # Polled rather than event-driven on purpose: the slot is freed by a plain
    # thread, which cannot set an asyncio.Event safely, and the counter is
    # process-wide while an Event belongs to one event loop (``--continuous``
    # runs several). Waiting only happens once DNS is black-holed.
    while not _lookup_slots.acquire():  # noqa: ASYNC110
        await asyncio.sleep(_LOOKUP_SLOT_POLL_SECONDS)
    try:
        infos = await asyncio.wait_for(
            asyncio.wrap_future(_start_lookup(host)),
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


async def is_public_host(
    host: str,
    *,
    timeout: float = 5.0,
    attempts: int = 2,
    retry_delay: float = 0.25,
) -> bool:
    """Return ``True`` only if *host* resolves exclusively to public addresses.

    Fail-closed: unresolvable hosts, timeouts, and hosts with any private,
    loopback, link-local or reserved answer all return ``False``.

    A *failed* lookup is retried, a successful one never is. The verdict is
    final for the whole run — the source manager drops the URL and does not
    retry a ``ValueError`` — so one slow answer used to cost an entire upstream
    index. Retrying cannot loosen the guard: a name that resolves into private
    space answers on the first try and is rejected without a second lookup.

    Args:
        host: Hostname or IP literal taken from an untrusted index.
        timeout: Per-lookup resolution timeout in seconds.
        attempts: How many times a failed lookup is repeated.
        retry_delay: Pause between two lookups of the same host, in seconds.
    """
    bare = _strip_brackets(host)
    if not bare:
        return False

    try:
        ipaddress.ip_address(bare)
    except ValueError:
        pass
    else:
        return not is_private_address(bare)

    for attempt in range(max(1, attempts)):
        answers = await resolve_host_addresses(bare, timeout=timeout)
        if answers is not None:
            return bool(answers) and not any(
                is_private_address(answer) for answer in answers
            )
        if attempt + 1 < max(1, attempts):
            await asyncio.sleep(max(0.0, retry_delay))
    return False


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
