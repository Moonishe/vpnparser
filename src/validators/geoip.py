"""GeoIP enrichment: country lookup for proxy servers.

Uses the free ip-api.com JSON endpoint to resolve each server's address to a
2-letter country code. The free tier allows 45 requests/minute, which is a
*global* budget: a semaphore alone does not enforce it, so all lookups pass
through one :class:`_RateLimiter` and every address is queried at most once.
Rate-limit responses are tolerated by returning None rather than raising.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable

import httpx

from src.parsers.base import Config
from src.utils.net import is_private_address, resolve_global_ips

logger = logging.getLogger(__name__)

# In-flight lookups. The real throughput bound is _DEFAULT_REQUESTS_PER_MINUTE;
# this only caps how many slow responses may overlap.
_DEFAULT_CONCURRENCY = 8
# ip-api.com free tier allows 45 req/min. 40 leaves headroom for clock skew and
# for whatever else on the runner's IP talks to the same endpoint.
_DEFAULT_REQUESTS_PER_MINUTE = 40.0
_DEFAULT_API_URL = "https://ip-api.com/json/{ip}"

#: Injectable sleep, so tests can drive the limiter without real waiting.
SleepFunc = Callable[[float], Awaitable[None]]


def _is_private_ip(ip: str) -> bool:
    """Return ``True`` if *ip* is non-public or unparseable (fail-closed).

    Thin alias for :func:`src.utils.net.is_private_address`, kept because the
    SSRF rule ("never send an internal address to an external GeoIP API") is
    part of this module's contract.
    """
    return is_private_address(ip)


class _RateLimiter:
    """Serialize calls so the global rate stays under a per-minute cap.

    A semaphore bounds parallelism, not throughput: N slots with a sleep inside
    each slot still allow N requests per delay. This limiter instead hands out
    one slot per ``60 / requests_per_minute`` seconds, whatever the concurrency.
    """

    def __init__(
        self,
        requests_per_minute: float = _DEFAULT_REQUESTS_PER_MINUTE,
        *,
        sleep: SleepFunc | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.interval = 60.0 / max(1.0, float(requests_per_minute))
        self._sleep: SleepFunc = sleep or asyncio.sleep
        self._clock = clock
        self._lock = asyncio.Lock()
        self._next_at: float | None = None

    def _now(self) -> float:
        return self._clock() if self._clock else asyncio.get_running_loop().time()

    async def acquire(self) -> None:
        """Block until the next request slot is due, then claim it."""
        async with self._lock:
            now = self._now()
            if self._next_at is None:
                self._next_at = now
            wait = self._next_at - now
            if wait > 0:
                await self._sleep(wait)
                # Advance on the schedule, not on the clock: an injected no-op
                # sleep must not collapse the whole queue into one instant.
                now = self._next_at
            self._next_at = now + self.interval


async def lookup_country(
    ip: str,
    api_url: str = _DEFAULT_API_URL,
    timeout: float = 5.0,
) -> str | None:
    """Lookup the 2-letter country code for an IP address.

    Returns the country code (e.g. "US") or None on any error: timeout,
    rate limit, non-200 response, missing/invalid fields, network error.
    Never raises.
    """
    url = api_url.replace("{ip}", ip)
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(url)
    except (httpx.HTTPError, OSError, Exception):
        return None

    if resp.status_code != 200:
        # 429 = rate limited; treat as failure.
        return None

    try:
        data = resp.json()
    except (ValueError, Exception):
        return None

    # ip-api.com returns {"countryCode": "US", ...} on success,
    # or {"status": "fail", "message": "..."} on failure.
    if not isinstance(data, dict):
        return None
    if data.get("status") == "fail":
        return None

    country = data.get("countryCode")
    if isinstance(country, str) and len(country) == 2:
        return country.upper()
    return None


async def _resolve_to_ip(host: str) -> str | None:
    """Resolve a host to a single globally routable IP address.

    Handles IPv4 and IPv6 alike (a host with AAAA records only used to end up
    without a country) and drops private/reserved answers. Returns None when
    nothing public is left, including for a private IP literal.
    """
    public = await resolve_global_ips(host)
    return public[0] if public else None


def _warn_about_failures(results: list[object], action: str) -> None:
    """Report the failures ``gather(return_exceptions=True)`` collected.

    One unusable address must cost one config, not the batch: an escaping
    exception aborts the whole enrichment (up to a few hundred configs lose
    their country) and leaves the sibling tasks running as orphans.
    """
    failures = [result for result in results if isinstance(result, BaseException)]
    if not failures:
        return
    logger.warning(
        "GeoIP %s failed for %d/%d config(s); first error: %s: %s",
        action,
        len(failures),
        len(results),
        type(failures[0]).__name__,
        failures[0],
    )


async def enrich_configs_geoip(
    configs: list[Config],
    api_url: str = _DEFAULT_API_URL,
    concurrency: int = _DEFAULT_CONCURRENCY,
    *,
    requests_per_minute: float = _DEFAULT_REQUESTS_PER_MINUTE,
    sleep: SleepFunc | None = None,
) -> list[Config]:
    """Set the country field on all configs.

    Resolves each config's address to an IP (if it isn't already one), then
    looks up the country code. Each distinct IP is queried once and all lookups
    share one global rate limiter, so the free ip-api.com quota is respected
    even with hundreds of configs. Configs whose address can't be resolved or
    whose lookup fails keep country=None.

    Args:
        configs: Configs to enrich, mutated in place.
        api_url: Lookup endpoint template containing ``{ip}``.
        concurrency: Max overlapping HTTP lookups.
        requests_per_minute: Global lookup budget shared by all configs.
        sleep: Await-able delay used by the rate limiter; defaults to
            :func:`asyncio.sleep` and exists so tests can run without waiting.

    Returns the same list (mutated in place) for convenience.
    """
    if not configs:
        return configs

    semaphore = asyncio.Semaphore(max(1, int(concurrency)))
    limiter = _RateLimiter(requests_per_minute, sleep=sleep)
    by_ip: dict[str, list[Config]] = {}
    group_lock = asyncio.Lock()

    async def _resolve_one(cfg: Config) -> None:
        async with semaphore:
            ip = await _resolve_to_ip(cfg.address)
        cfg.country = None
        if ip is None:
            return
        async with group_lock:
            by_ip.setdefault(ip, []).append(cfg)

    resolved = await asyncio.gather(
        *(_resolve_one(c) for c in configs),
        return_exceptions=True,
    )
    _warn_about_failures(list(resolved), "address resolution")

    async def _lookup_one(ip: str, targets: list[Config]) -> None:
        await limiter.acquire()
        async with semaphore:
            country = await lookup_country(ip, api_url=api_url)
        for cfg in targets:
            cfg.country = country

    looked_up = await asyncio.gather(
        *(_lookup_one(ip, targets) for ip, targets in by_ip.items()),
        return_exceptions=True,
    )
    _warn_about_failures(list(looked_up), "country lookup")
    return configs
