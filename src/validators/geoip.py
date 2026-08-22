"""GeoIP enrichment: country lookup for proxy servers.

Two backends:

- **Offline** (preferred when ``geoip_mmdb_file`` is configured and usable):
  a pinned MaxMind-format database downloaded once via
  :func:`ensure_geoip_database`. Unlimited lookups, no network at enrich
  time — the ip-api rate limit is what kept 97% of unknown-country configs
  unenriched (300 lookups per run against thousands of addresses).
- **API**: the free ip-api.com JSON endpoint. The free tier allows 45
  requests/minute, which is a *global* budget: a semaphore alone does not
  enforce it, so all lookups pass through one :class:`_RateLimiter` and
  every address is queried at most once. Rate-limit responses are tolerated
  by returning None rather than raising.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import os
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import httpx

from src.parsers.base import Config
from src.utils.net import is_private_address, resolve_global_ips
from src.utils.paths import resolve_safe_output_path

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


# --- Offline (MaxMind database) backend ---

#: Hard cap on the downloaded database: the pinned GeoLite2-Country file is
#: ~9 MB; anything dramatically larger means the URL no longer points at the
#: pinned artifact.
_DEFAULT_MMDB_MAX_BYTES = 32 * 1024 * 1024

#: Callable opening an mmdb file into a reader with ``.get(ip)``/``.close()``.
#: Injectable so tests can enrich without a real database.
ReaderFactory = Callable[[str], Any]


def _open_mmdb(path: str) -> Any:
    import maxminddb

    return maxminddb.open_database(path)


def _file_sha256_matches(path: Path, expected: str | None) -> bool:
    if not path.is_file():
        return False
    if not expected:
        # Nothing pinned: the operator only asked for "use the file if there".
        return True
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest() == expected


async def ensure_geoip_database(
    *,
    path: str,
    url: str,
    sha256: str | None = None,
    timeout: float = 120.0,
    max_bytes: int = _DEFAULT_MMDB_MAX_BYTES,
) -> bool:
    """Make sure a usable offline database exists at *path*.

    The file is validated against *sha256* when one is pinned; a mismatch (or
    a missing file) triggers one streamed download from *url* — checksummed,
    size-capped and atomically renamed, so a broken download never replaces a
    working database. Downloads without a pinned checksum are refused: an
    unverified GeoIP database is an operator-controlled but still external
    artifact, and the checksum is one line of settings.

    Returns ``True`` when the database at *path* is usable.
    """
    try:
        target = resolve_safe_output_path(path)
    except ValueError as exc:
        logger.warning("Unsafe GeoIP database path %r: %s", path, exc)
        return False
    if _file_sha256_matches(target, sha256):
        return True
    if not url or not sha256:
        logger.warning(
            "GeoIP database %s is missing/invalid and no pinned url+sha256 "
            "is configured to fetch it.",
            path,
        )
        return False

    target.parent.mkdir(parents=True, exist_ok=True)
    part = target.with_name(target.name + ".part")
    digest = hashlib.sha256()
    size = 0
    too_large = False
    try:
        async with (
            httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client,
            client.stream("GET", url) as resp,
        ):
            if resp.status_code != 200:
                logger.warning(
                    "GeoIP database download returned HTTP %d.",
                    resp.status_code,
                )
                return False
            with part.open("wb") as fh:
                async for chunk in resp.aiter_bytes(64 * 1024):
                    size += len(chunk)
                    if size > max_bytes:
                        too_large = True
                        break
                    digest.update(chunk)
                    fh.write(chunk)
        if too_large:
            logger.warning(
                "GeoIP database at %s is larger than the size cap (%d bytes).",
                url,
                max_bytes,
            )
            with contextlib.suppress(OSError):
                part.unlink(missing_ok=True)
            return False
        if digest.hexdigest() != sha256:
            logger.warning(
                "GeoIP database checksum mismatch for %s — keeping the old "
                "file (if any).",
                url,
            )
            with contextlib.suppress(OSError):
                part.unlink(missing_ok=True)
            return False
        os.replace(part, target)
        logger.info("Downloaded GeoIP database to %s (%d bytes).", path, size)
        return True
    except Exception as exc:
        logger.warning("GeoIP database download failed: %s", exc)
        with contextlib.suppress(OSError):
            part.unlink(missing_ok=True)
        return False


def _country_from_mmdb_record(record: Any) -> str | None:
    """Read an ISO code out of a MaxMind lookup result, fail-soft to None."""
    if not isinstance(record, dict):
        return None
    for key in ("country", "registered_country"):
        node = record.get(key)
        if isinstance(node, dict):
            code = node.get("iso_code")
            if isinstance(code, str) and len(code) == 2:
                return code.upper()
    return None


async def enrich_configs_geoip_offline(
    configs: list[Config],
    db_path: str,
    *,
    concurrency: int = _DEFAULT_CONCURRENCY,
    reader_factory: ReaderFactory | None = None,
) -> list[Config]:
    """Set the country field on all configs using the offline database.

    Same address grouping as the API backend, but every lookup is a local
    microsecond-priced ``reader.get()`` — no rate limiter and no per-run cap,
    which is what makes enriching the whole unknown-country backlog viable.

    Args:
        configs: Configs to enrich, mutated in place.
        db_path: Path to the mmdb database.
        concurrency: Max overlapping DNS resolutions.
        reader_factory: Opens the database; defaults to maxminddb. Injectable
            for tests.

    Returns the same list (mutated in place) for convenience.
    """
    if not configs:
        return configs
    open_reader = reader_factory or _open_mmdb
    try:
        reader = open_reader(str(db_path))
    except Exception as exc:
        logger.warning("Cannot open GeoIP database %r: %s", db_path, exc)
        return configs

    semaphore = asyncio.Semaphore(max(1, int(concurrency)))
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

    try:
        for ip, targets in by_ip.items():
            country = _country_from_mmdb_record(reader.get(ip))
            for cfg in targets:
                cfg.country = country
    finally:
        close = getattr(reader, "close", None)
        if callable(close):
            with contextlib.suppress(Exception):
                close()
    return configs
