"""SSRF guard for validator connect targets.

``Config.address``/``Config.port`` come straight out of public subscriptions, so
a link like ``vless://<uuid>@10.0.0.5:22`` is enough to turn the pipeline into a
port scanner of the network it happens to run in — the garbage and country
filters have no reason to reject it. Every validator therefore runs its input
through :func:`filter_public_configs` before the first socket is opened, and the
low-level checks additionally refuse a non-public IP literal through
:func:`is_blocked_literal`.

Verdict policy for a target host:

- IP literal in public space -> allowed; any other literal -> dropped, decided
  synchronously so an internal address never even reaches the resolver;
- hostname with at least one public address -> allowed;
- hostname that resolves, but only into private/loopback/link-local/reserved
  space -> dropped; this is the actual SSRF attempt;
- hostname that does not resolve at all (NXDOMAIN, DNS timeout, offline
  runner) -> dropped (fail-closed). Only an explicit "public" verdict is
  connectable: resolving again at connect time would reopen the
  resolve-then-connect rebinding window, so an unvalidated name must not
  reach the socket at all.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import time
from typing import TYPE_CHECKING, Literal, TypeVar

from src.utils.net import (
    RESOLVER_CONCURRENCY,
    is_private_address,
    resolve_host_addresses,
)

if TYPE_CHECKING:
    from src.parsers.base import Config

logger = logging.getLogger(__name__)

#: Verdict returned by :func:`classify_host`.
HostVerdict = Literal["public", "blocked", "unresolved"]

#: Parallel hostname lookups. Kept at the resolver's own advertised width: a
#: timed-out lookup keeps its thread until the OS resolver gives up, and this
#: bound is what stops those threads from piling up faster than they retire.
_RESOLVE_CONCURRENCY = RESOLVER_CONCURRENCY

#: Pause between the two attempts of a transient (``None``) resolution —
#: mirrors ``is_public_host``'s retry pacing.
_TRANSIENT_RESOLVE_RETRY_DELAY = 0.25

#: How long a decided verdict may be reused. One run puts the same hosts through
#: the guard three times (TCP, TLS, Xray stages), so without reuse every run
#: pays for three full resolutions of the same list — and resolver starvation is
#: exactly what turned this guard fail-open twice before. Kept short so a
#: rebinding host cannot ride a stale "public" verdict for long.
_VERDICT_TTL_SECONDS = 300.0

#: host -> (expiry timestamp, verdict). Only decided verdicts are stored;
#: ``unresolved`` is never cached and therefore retried on the next stage.
_verdict_cache: dict[str, tuple[float, HostVerdict]] = {}

#: Verdicts and pins expire by TTL, but entries that are never re-queried are
#: never re-read either, so lazy eviction on access leaves them forever — in a
#: long-lived ``--continuous`` process the dict only grew. When a store pushes
#: a cache past this many entries, one pass drops everything already expired
#: (O(n), amortized over stores).
_CACHE_SWEEP_THRESHOLD = 1024

#: Any TTL-cache value shape used with :func:`_sweep_expired_cache_entries`;
#: the sweep only reads the expiry timestamp, so it is value-type agnostic.
_CacheValue = TypeVar("_CacheValue")


def _sweep_expired_cache_entries(cache: dict[str, tuple[float, _CacheValue]]) -> None:
    """Drop expired entries from *cache* once it outgrows the sweep threshold."""
    if len(cache) < _CACHE_SWEEP_THRESHOLD:
        return
    now = time.monotonic()
    expired = [k for k, (expires_at, _v) in cache.items() if expires_at <= now]
    for key in expired:
        del cache[key]


def clear_verdict_cache() -> None:
    """Forget every cached verdict and pinned address set (tests, new runs)."""
    _verdict_cache.clear()
    _pinned_cache.clear()


def _cached_verdict(host: str, *, now: float) -> HostVerdict | None:
    """Return a still-valid cached verdict for *host*, if there is one."""
    entry = _verdict_cache.get(host)
    if entry is None:
        return None
    expires_at, verdict = entry
    if expires_at <= now:
        del _verdict_cache[host]
        return None
    return verdict


def _store_verdict(host: str, verdict: HostVerdict, *, now: float) -> None:
    """Remember a decided verdict; ``unresolved`` is never cached."""
    if verdict == "unresolved":
        return
    _verdict_cache[host] = (now + _VERDICT_TTL_SECONDS, verdict)
    _sweep_expired_cache_entries(_verdict_cache)


def _bare_host(address: str | None) -> str:
    """Return *address* lowercased, trimmed and without IPv6 brackets."""
    host = str(address or "").strip().lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1].strip()
    return host


def _as_canonical_ip(host: str | None) -> str | None:
    """Return the canonical IP literal for *host*, or ``None`` if it is not an IP.

    ``ipaddress`` is strict, so non-canonical IPv4 spellings
    (``2130706433``, ``0x7f000001``, ``127.1``, ``127.0.0.1.``) are normalized
    through ``socket.inet_aton`` before being judged. Without this they fall
    through to DNS, fail to resolve, and slip through as "unresolved"
    (fail-open SSRF).
    """
    bare = _bare_host(host)
    if not bare:
        return None
    if bare.endswith("."):
        bare = bare[:-1]
    try:
        return str(ipaddress.ip_address(bare))
    except ValueError:
        pass
    # inet_aton also accepts short forms like "127.1" or "0x7f000001" that
    # ipaddress rejects. A bare all-digit token, though, is ambiguous: "1" is
    # far more likely a DNS search-suffix hostname than the address 0.0.0.1, so
    # short labels must reach real DNS. Only treat a bare decimal as an address
    # when it is large enough to be a full 32-bit IPv4 literal (>= 1.0.0.0),
    # which keeps decimal-encoded loopback (2130706433) blocked while letting
    # single-label hostnames through.
    if "." not in bare and not bare.lower().startswith("0x"):
        try:
            if int(bare) < 0x1000000:
                return None
        except ValueError:
            return None
    try:
        return socket.inet_ntoa(socket.inet_aton(bare))
    except OSError:
        return None


def _is_ip_literal(host: str) -> bool:
    return _as_canonical_ip(host) is not None


def is_blocked_literal(host: str | None) -> bool:
    """Return ``True`` when *host* is an IP literal outside public space.

    Hostnames always return ``False`` — they need DNS to judge and are handled
    by :func:`filter_public_configs`. Literals never trigger a lookup, so this
    predicate is safe to call on the hot path of every connect.
    """
    canonical = _as_canonical_ip(host)
    if not canonical:
        return False
    return is_private_address(canonical)


async def classify_host(host: str | None, *, timeout: float = 5.0) -> HostVerdict:
    """Classify a connect target as ``public``, ``blocked`` or ``unresolved``.

    Args:
        host: Address taken from an untrusted config (IP literal or hostname).
        timeout: Per-lookup resolution timeout in seconds.
    """
    bare = _bare_host(host)
    if not bare:
        return "blocked"
    canonical = _as_canonical_ip(bare)
    if canonical is not None:
        return "blocked" if is_private_address(canonical) else "public"
    # One lookup decides both halves of the verdict: whether the name resolves
    # at all separates the SSRF attempt from the offline resolver, and asking
    # twice doubled the DNS load of every dead or internal host.
    answers = await resolve_host_addresses(bare, timeout=timeout)
    if answers is None:
        # A ``None`` here is a *transient* lookup failure (timeout, resolver
        # outage), not a verdict: retry once, exactly like is_public_host —
        # a single 5-second resolver hiccup used to drop the whole hostname
        # batch for the run. The retry cannot loosen the guard: a name that
        # resolved into private space answers deterministically and is
        # rejected without a second lookup.
        await asyncio.sleep(_TRANSIENT_RESOLVE_RETRY_DELAY)
        answers = await resolve_host_addresses(bare, timeout=timeout)
        if answers is None:
            return "unresolved"
    if answers and all(not is_private_address(answer) for answer in answers):
        return "public"
    return "blocked"


#: Cap on validated addresses handed to a connect loop (mirrors the source
#: manager's pin cap): one dual-stack name rarely has more, and an unbounded
#: list lets one config cost a handshake per answer.
_MAX_PINNED_ADDRESSES = 4

#: How long a validated pin may be reused. ``resolve_pinned_addresses`` runs on
#: every attempt of every stage (TCP/TLS/Xray, proxy-pool rotation), so without
#: reuse one host cost dozens of DNS lookups per run. Only successful public
#: resolutions are cached — an empty answer keeps being retried, exactly like
#: the ``unresolved`` verdict — and the TTL stays an order of magnitude under
#: the verdict cache's, since a stale pin is a stale *connect target*.
_PINNED_TTL_SECONDS = 60.0

#: host -> (expiry timestamp, pinned public addresses).
_pinned_cache: dict[str, tuple[float, list[str]]] = {}


async def resolve_pinned_addresses(
    host: str | None,
    *,
    timeout: float = 5.0,
) -> list[str]:
    """Return the validated public IP literals for *host*, best answer first.

    The plural form is the real primitive: a dual-stack host whose first
    ``getaddrinfo`` answer is an unreachable AAAA used to die outright when
    only ``public[0]`` survived — the singular wrapper keeps its contract,
    and connect loops (tcp/tls) may walk the whole list.

    Closes the resolve-then-connect window (DNS rebinding): a verdict from
    :func:`classify_host` alone does not help when the socket then resolves
    the name again — an attacker with a short-TTL record can answer the guard
    with a public address and the connect with RFC1918/metadata. The check
    functions therefore connect to the literals returned here, which come
    from the SAME resolution that was validated.

    IP literals pass through unchanged (private ones return ``[]``). For a
    hostname, ``[]`` means "no validated public address" — callers must
    treat the config as dead (fail closed).
    """
    bare = _bare_host(host)
    if not bare:
        return []
    canonical = _as_canonical_ip(bare)
    if canonical is not None:
        return [] if is_private_address(canonical) else [canonical]
    now = time.monotonic()
    cached = _pinned_cache.get(bare)
    if cached is not None:
        expires_at, pinned = cached
        if expires_at > now:
            return list(pinned)
        del _pinned_cache[bare]
    answers = await resolve_host_addresses(bare, timeout=timeout)
    if answers is None:
        # resolve_host_addresses maps every failure mode (timeout, offline
        # moment, NXDOMAIN) to None, and the caller turns an empty result
        # into a dead verdict — so a living server could die on one unlucky
        # lookup under resolver load. One retry before failing closed; the
        # cost is a second lookup for genuinely dead hosts.
        answers = await resolve_host_addresses(bare, timeout=timeout)
    if not answers:
        # Unresolvable names cannot be pinned; connecting to the name would
        # reopen the rebinding window, so fail closed.
        return []
    public = [answer for answer in answers if not is_private_address(answer)][
        :_MAX_PINNED_ADDRESSES
    ]
    if not public:
        # Private-only answers stay uncached too: the pinned list must never
        # outlive the resolution it was validated against.
        return []
    _pinned_cache[bare] = (now + _PINNED_TTL_SECONDS, public)
    _sweep_expired_cache_entries(_pinned_cache)
    return list(public)


async def resolve_pinned_address(
    host: str | None,
    *,
    timeout: float = 5.0,
) -> str | None:
    """Return an IP literal that is safe to connect to for *host*.

    Thin wrapper over :func:`resolve_pinned_addresses` keeping the
    single-answer contract: ``None`` means "no validated public address" —
    callers must treat the config as dead (fail closed).
    """
    addresses = await resolve_pinned_addresses(host, timeout=timeout)
    return addresses[0] if addresses else None


def _verdict_or_unresolved(
    host: str,
    result: HostVerdict | BaseException,
) -> HostVerdict:
    """Turn a failed classification into a per-host verdict.

    A resolver error must cost one config, not the batch: without this the
    exception escapes :func:`filter_public_configs` and takes the whole
    liveness stage down with it.
    """
    if isinstance(result, BaseException):
        logger.warning(
            "Cannot classify address %r (%s: %s) — treating it as unresolved.",
            host,
            type(result).__name__,
            result,
        )
        return "unresolved"
    return result


async def filter_public_configs(
    configs: list[Config],
    *,
    stage: str,
    check_hostnames: bool = True,
    resolve_timeout: float = 5.0,
) -> list[Config]:
    """Drop configs whose address must never be connected to.

    Args:
        configs: Parsed configs, in the order they should be checked.
        stage: Validator name, used in the drop warning.
        check_hostnames: When ``False``, only IP literals are judged and no DNS
            query is made at all.
        resolve_timeout: Per-hostname resolution timeout in seconds.

    Returns the accepted configs, original order preserved. Dropped configs are
    reported once per batch at warning level.
    """
    if not configs:
        return []

    hosts = list(dict.fromkeys(_bare_host(cfg.address) for cfg in configs))
    if check_hostnames:
        semaphore = asyncio.Semaphore(_RESOLVE_CONCURRENCY)
        now = time.monotonic()

        async def _classify(host: str) -> HostVerdict:
            cached = _cached_verdict(host, now=now)
            if cached is not None:
                return cached
            async with semaphore:
                verdict = await classify_host(host, timeout=resolve_timeout)
            _store_verdict(host, verdict, now=now)
            return verdict

        classified = await asyncio.gather(
            *[_classify(host) for host in hosts],
            return_exceptions=True,
        )
        results: list[HostVerdict] = [
            _verdict_or_unresolved(host, result)
            for host, result in zip(hosts, classified, strict=False)
        ]
    else:
        results = [
            "blocked" if not host or is_blocked_literal(host) else "public"
            for host in hosts
        ]
    verdicts = dict(zip(hosts, results, strict=False))

    # Fail-closed: only an explicit "public" verdict is connectable. An
    # "unresolved" hostname (NXDOMAIN, DNS timeout, offline runner) is
    # dropped like "blocked": connecting to it would reopen the
    # resolve-then-connect rebinding window that resolve_pinned_addresses
    # was built to close.
    kept: list[Config] = [
        cfg for cfg in configs if verdicts.get(_bare_host(cfg.address)) == "public"
    ]
    # Guard-dropped configs never earned a verdict in this stage: reset any
    # previous-stage True so the shared probe_log does not record them as
    # a health-history pass without a real probe in this stage.
    if len(kept) != len(configs):
        kept_ids = {id(cfg) for cfg in kept}
        for cfg in configs:
            if id(cfg) not in kept_ids:
                cfg.is_alive = None
                cfg.xray_was_checked = False
    dropped = len(configs) - len(kept)
    if dropped:
        dropped_hosts = sorted(
            host for host, v in verdicts.items() if v in ("blocked", "unresolved")
        )
        logger.warning(
            "%s: dropped %d/%d config(s) targeting a non-public or unresolvable "
            "address (private/loopback/link-local/reserved/unresolved): %s",
            stage,
            dropped,
            len(configs),
            ", ".join(repr(host) for host in dropped_hosts[:5]),
        )
    return kept
