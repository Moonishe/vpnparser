"""GeoIP enrichment: country lookup for proxy servers.

Uses the free ip-api.com JSON endpoint to resolve each server's address
to a 2-letter country code. The free tier allows 45 requests/minute, so
we bound concurrency with a semaphore and tolerate rate-limit responses
by returning None rather than raising.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket

import httpx

from src.parsers.base import Config

# ip-api.com free tier: 45 req/min. Use 40 to stay safely under the limit.
_DEFAULT_CONCURRENCY = 40
_DEFAULT_API_URL = "http://ip-api.com/json/{ip}"


def _is_private_ip(ip: str) -> bool:
    """Check if an IP address is private, loopback, link-local, or reserved.

    Protects against SSRF: malicious proxy configs could point to internal
    services (e.g. AWS metadata endpoint 169.254.169.254, localhost, RFC 1918
    private ranges).  Such IPs must never be sent to external GeoIP APIs or
    used for validation connections.

    Returns ``True`` if the IP is non-public or unparseable (fail-closed).
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        # If we cannot parse it, treat it as unsafe (fail-closed).
        return True
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


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
    """Resolve a hostname to a single IPv4 address.

    Returns the first A-record result, or None on failure. If `host` is
    already an IP literal, it is returned unchanged.
    """
    # Fast path: already an IP literal (no DNS needed).
    try:
        socket.inet_aton(host)
        # SSRF protection: reject private/reserved IP literals.
        if _is_private_ip(host):
            return None
        return host
    except OSError:
        pass

    loop = asyncio.get_running_loop()
    try:
        # getaddrinfo returns a list of (family, type, proto, canonname, sockaddr)
        infos = await loop.getaddrinfo(host, None)
    except (socket.gaierror, OSError, Exception):
        return None

    for info in infos:
        if info[0] != socket.AF_INET:
            continue
        sockaddr = info[4]
        if not sockaddr:
            continue
        # sockaddr for IPv4 is (host, port); host is always a str IP literal.
        host_ip = sockaddr[0]
        if isinstance(host_ip, str):
            # SSRF protection: skip private/resolved internal IPs.
            if _is_private_ip(host_ip):
                continue
            return host_ip
    return None


async def enrich_configs_geoip(
    configs: list[Config],
    api_url: str = _DEFAULT_API_URL,
    concurrency: int = _DEFAULT_CONCURRENCY,
) -> list[Config]:
    """Set the country field on all configs.

    Resolves each config's address to an IP (if it isn't already one),
    then looks up the country code. Configs whose address can't be
    resolved or whose lookup fails keep country=None.

    Returns the same list (mutated in place) for convenience.
    """
    semaphore = asyncio.Semaphore(concurrency)

    async def _enrich_one(cfg: Config) -> None:
        async with semaphore:
            ip = await _resolve_to_ip(cfg.address)
            if ip is None:
                cfg.country = None
                return
            cfg.country = await lookup_country(ip, api_url=api_url)

    await asyncio.gather(*(_enrich_one(c) for c in configs))
    return configs
