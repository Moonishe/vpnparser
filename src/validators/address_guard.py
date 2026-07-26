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
  runner) -> allowed. A name without an address cannot carry a connection
  anywhere, so keeping it costs nothing, while dropping it would empty the
  whole pipeline every time the resolver is unavailable.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from typing import TYPE_CHECKING, Literal

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

#: How long a decided verdict may be reused. One run puts the same hosts through
#: the guard three times (TCP, TLS, Xray stages), so without reuse every run
#: pays for three full resolutions of the same list — and resolver starvation is
#: exactly what turned this guard fail-open twice before. Kept short so a
#: rebinding host cannot ride a stale "public" verdict for long.
_VERDICT_TTL_SECONDS = 300.0

#: host -> (expiry timestamp, verdict). Only decided verdicts are stored;
#: ``unresolved`` must be retried, since it is the permissive answer.
_verdict_cache: dict[str, tuple[float, HostVerdict]] = {}


def clear_verdict_cache() -> None:
    """Forget every cached host verdict (used by tests and between runs)."""
    _verdict_cache.clear()


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


def _bare_host(address: str | None) -> str:
    """Return *address* lowercased, trimmed and without IPv6 brackets."""
    host = str(address or "").strip().lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1].strip()
    return host


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def is_blocked_literal(host: str | None) -> bool:
    """Return ``True`` when *host* is an IP literal outside public space.

    Hostnames always return ``False`` — they need DNS to judge and are handled
    by :func:`filter_public_configs`. Literals never trigger a lookup, so this
    predicate is safe to call on the hot path of every connect.
    """
    bare = _bare_host(host)
    return bool(bare) and _is_ip_literal(bare) and is_private_address(bare)


async def classify_host(host: str | None, *, timeout: float = 5.0) -> HostVerdict:
    """Classify a connect target as ``public``, ``blocked`` or ``unresolved``.

    Args:
        host: Address taken from an untrusted config (IP literal or hostname).
        timeout: Per-lookup resolution timeout in seconds.
    """
    bare = _bare_host(host)
    if not bare:
        return "blocked"
    if _is_ip_literal(bare):
        return "blocked" if is_private_address(bare) else "public"
    # One lookup decides both halves of the verdict: whether the name resolves
    # at all separates the SSRF attempt from the offline resolver, and asking
    # twice doubled the DNS load of every dead or internal host.
    answers = await resolve_host_addresses(bare, timeout=timeout)
    if answers is None:
        return "unresolved"
    if answers and all(not is_private_address(answer) for answer in answers):
        return "public"
    return "blocked"


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

    kept: list[Config] = [
        cfg for cfg in configs if verdicts.get(_bare_host(cfg.address)) != "blocked"
    ]
    dropped = len(configs) - len(kept)
    if dropped:
        blocked_hosts = sorted(host for host, v in verdicts.items() if v == "blocked")
        logger.warning(
            "%s: dropped %d/%d config(s) targeting a non-public address "
            "(private/loopback/link-local/reserved): %s",
            stage,
            dropped,
            len(configs),
            ", ".join(repr(host) for host in blocked_hosts[:5]),
        )
    return kept
