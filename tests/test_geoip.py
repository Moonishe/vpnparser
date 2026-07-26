"""Tests for src/validators/geoip.py — SSRF guard, country lookup, DNS resolve,
and batch enrichment. httpx and getaddrinfo are mocked inline (no network).
"""

from __future__ import annotations

import socket

import httpx
import pytest

from src.parsers.base import Config
from src.validators import geoip

# --- _is_private_ip --------------------------------------------------------


def test_is_private_ip_rfc1918_ranges() -> None:
    assert geoip._is_private_ip("10.0.0.1") is True
    assert geoip._is_private_ip("172.16.0.1") is True
    assert geoip._is_private_ip("192.168.1.1") is True


def test_is_private_ip_special_ranges() -> None:
    assert geoip._is_private_ip("127.0.0.1") is True  # loopback
    assert geoip._is_private_ip("169.254.169.254") is True  # link-local / metadata
    assert geoip._is_private_ip("240.0.0.1") is True  # reserved
    assert geoip._is_private_ip("224.0.0.1") is True  # multicast
    assert geoip._is_private_ip("0.0.0.0") is True  # unspecified


def test_is_private_ip_public_addresses() -> None:
    assert geoip._is_private_ip("8.8.8.8") is False
    assert geoip._is_private_ip("1.1.1.1") is False
    # 203.0.113.10 is TEST-NET-3 (RFC 5737) — reserved, not public
    assert geoip._is_private_ip("203.0.113.10") is True


def test_is_private_ip_unparseable_is_fail_closed() -> None:
    # Fail-closed: unparseable input is treated as unsafe.
    assert geoip._is_private_ip("not-an-ip") is True
    assert geoip._is_private_ip("") is True


# --- lookup_country --------------------------------------------------------


class _FakeResp:
    def __init__(self, status: int, json_data: object | None = None) -> None:
        self.status_code = status
        self._json = json_data

    def json(self):
        if self._json is None:
            raise ValueError("no json")
        return self._json


class _FakeHttpClient:
    def __init__(self, result) -> None:
        self._result = result

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return None

    async def get(self, url):
        if isinstance(self._result, Exception):
            raise self._result
        return self._result


def _patch_geoip_httpx(monkeypatch, result) -> None:
    monkeypatch.setattr(
        "src.validators.geoip.httpx.AsyncClient",
        lambda *a, **kw: _FakeHttpClient(result),
    )


async def test_lookup_country_success_uppercases(monkeypatch) -> None:
    _patch_geoip_httpx(monkeypatch, _FakeResp(200, {"countryCode": "us"}))
    assert await geoip.lookup_country("8.8.8.8") == "US"


async def test_lookup_country_fail_status(monkeypatch) -> None:
    _patch_geoip_httpx(monkeypatch, _FakeResp(200, {"status": "fail"}))
    assert await geoip.lookup_country("8.8.8.8") is None


async def test_lookup_country_rate_limited(monkeypatch) -> None:
    _patch_geoip_httpx(monkeypatch, _FakeResp(429))
    assert await geoip.lookup_country("8.8.8.8") is None


async def test_lookup_country_non_200(monkeypatch) -> None:
    _patch_geoip_httpx(monkeypatch, _FakeResp(500))
    assert await geoip.lookup_country("8.8.8.8") is None


async def test_lookup_country_network_error(monkeypatch) -> None:
    _patch_geoip_httpx(monkeypatch, httpx.ConnectError("boom"))
    assert await geoip.lookup_country("8.8.8.8") is None


async def test_lookup_country_missing_country_code(monkeypatch) -> None:
    _patch_geoip_httpx(monkeypatch, _FakeResp(200, {}))
    assert await geoip.lookup_country("8.8.8.8") is None


async def test_lookup_country_wrong_length(monkeypatch) -> None:
    _patch_geoip_httpx(monkeypatch, _FakeResp(200, {"countryCode": "USA"}))
    assert await geoip.lookup_country("8.8.8.8") is None


async def test_lookup_country_non_dict(monkeypatch) -> None:
    _patch_geoip_httpx(monkeypatch, _FakeResp(200, ["not", "dict"]))
    assert await geoip.lookup_country("8.8.8.8") is None


async def test_lookup_country_json_decode_error(monkeypatch) -> None:
    _patch_geoip_httpx(monkeypatch, _FakeResp(200, json_data=None))
    assert await geoip.lookup_country("8.8.8.8") is None


# --- _resolve_to_ip --------------------------------------------------------


def _fake_getaddrinfo(host, *_args, **_kwargs):
    table = {
        "good.example": [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))
        ],
        "private.example": [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 0))
        ],
        "ipv6.example": [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 0, 0, 0))
        ],
        "ipv6-public.example": [
            (
                socket.AF_INET6,
                socket.SOCK_STREAM,
                6,
                "",
                ("2606:4700:4700::1111", 0, 0, 0),
            )
        ],
    }
    if host in table:
        return table[host]
    raise socket.gaierror("no such host")


async def test_resolve_to_ip_public_literal_returned_directly() -> None:
    # Fast path: already an IPv4 literal, public -> returned unchanged.
    assert await geoip._resolve_to_ip("8.8.8.8") == "8.8.8.8"


async def test_resolve_to_ip_private_literal_rejected() -> None:
    assert await geoip._resolve_to_ip("10.0.0.1") is None


async def test_resolve_to_ip_hostname_resolves_to_public(monkeypatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)
    assert await geoip._resolve_to_ip("good.example") == "93.184.216.34"


async def test_resolve_to_ip_hostname_resolves_to_private_returns_none(
    monkeypatch,
) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)
    assert await geoip._resolve_to_ip("private.example") is None


async def test_resolve_to_ip_documentation_ipv6_rejected(monkeypatch) -> None:
    # 2001:db8::/32 is the documentation range — non-public, so no country.
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)
    assert await geoip._resolve_to_ip("ipv6.example") is None


async def test_resolve_to_ip_public_ipv6_is_used(monkeypatch) -> None:
    """A host with AAAA records only must still get a country lookup."""
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)
    assert await geoip._resolve_to_ip("ipv6-public.example") == "2606:4700:4700::1111"


async def test_resolve_to_ip_ipv6_literal_is_used() -> None:
    assert await geoip._resolve_to_ip("2606:4700:4700::1111") == "2606:4700:4700::1111"


async def test_resolve_to_ip_private_ipv6_literal_rejected() -> None:
    assert await geoip._resolve_to_ip("::1") is None


async def test_resolve_to_ip_hostname_gaierror(monkeypatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)
    assert await geoip._resolve_to_ip("bad.example") is None


async def test_resolve_to_ip_empty_sockaddr_skipped(monkeypatch) -> None:
    """Line 117: ``if not sockaddr: continue`` covers empty/None sockaddr."""

    def _fake_getaddrinfo_empty(host, port, *args, **kwargs):
        return [
            # First entry has AF_INET but empty sockaddr -> continue (line 117)
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ()),
            # Second entry is valid -> returned
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo_empty)
    assert await geoip._resolve_to_ip("some.host") == "93.184.216.34"


# --- enrich_configs_geoip --------------------------------------------------


async def test_enrich_configs_geoip_sets_countries(monkeypatch) -> None:
    cfg_ip = Config("vless", "1.1.1.1", 443, "u")
    cfg_unresolvable = Config("vless", "bad.example", 443, "u")

    async def fake_resolve(host):
        return "1.1.1.1" if host == "1.1.1.1" else None

    async def fake_lookup(ip, **_kwargs):
        return "US" if ip == "1.1.1.1" else None

    monkeypatch.setattr(geoip, "_resolve_to_ip", fake_resolve)
    monkeypatch.setattr(geoip, "lookup_country", fake_lookup)

    result = await geoip.enrich_configs_geoip([cfg_ip, cfg_unresolvable])

    assert result == [cfg_ip, cfg_unresolvable]
    assert cfg_ip.country == "US"
    assert cfg_unresolvable.country is None


async def test_enrich_configs_geoip_empty_list() -> None:
    assert await geoip.enrich_configs_geoip([]) == []


async def test_enrich_configs_geoip_concurrency_floor(monkeypatch) -> None:
    # concurrency=0 must be floored to 1 (no crash).
    cfg = Config("vless", "8.8.8.8", 443, "u")

    async def fake_resolve(host):
        return host

    async def fake_lookup(ip, **_kwargs):
        return None

    monkeypatch.setattr(geoip, "_resolve_to_ip", fake_resolve)
    monkeypatch.setattr(geoip, "lookup_country", fake_lookup)

    result = await geoip.enrich_configs_geoip([cfg], concurrency=0)
    assert result == [cfg]
    assert cfg.country is None


# --- global rate limiting --------------------------------------------------


async def test_rate_limiter_spaces_requests_by_interval() -> None:
    waits: list[float] = []
    clock = {"now": 100.0}

    async def fake_sleep(delay: float) -> None:
        waits.append(delay)
        clock["now"] += delay

    limiter = geoip._RateLimiter(  # 1 request/second
        60.0,
        sleep=fake_sleep,
        clock=lambda: clock["now"],
    )
    for _ in range(4):
        await limiter.acquire()

    # First slot is free; every later slot waits one full interval.
    assert waits == [pytest.approx(1.0), pytest.approx(1.0), pytest.approx(1.0)]
    assert clock["now"] == pytest.approx(103.0)


async def test_enrich_configs_geoip_rate_limits_all_lookups(monkeypatch) -> None:
    """The limiter must bound the whole batch, not each semaphore slot."""
    configs = [Config("vless", f"8.8.8.{i}", 443, "u") for i in range(1, 6)]
    waits: list[float] = []

    async def fake_sleep(delay: float) -> None:
        waits.append(delay)

    async def fake_resolve(host):
        return host

    async def fake_lookup(ip, **_kwargs):
        return "US"

    monkeypatch.setattr(geoip, "_resolve_to_ip", fake_resolve)
    monkeypatch.setattr(geoip, "lookup_country", fake_lookup)

    result = await geoip.enrich_configs_geoip(
        configs,
        concurrency=40,
        requests_per_minute=45.0,
        sleep=fake_sleep,
    )

    assert all(cfg.country == "US" for cfg in result)
    # 5 unique IPs -> 4 enforced gaps, even with concurrency=40. The old code
    # slept inside each of the 40 semaphore slots, so nothing was serialized.
    assert len(waits) == 4
    assert sum(waits) >= 4 * (60.0 / 45.0)


async def test_enrich_configs_geoip_queries_each_ip_once(monkeypatch) -> None:
    """Configs sharing an address must not spend the quota twice."""
    configs = [Config("vless", "same.example", 443, "u") for _ in range(3)]
    looked_up: list[str] = []
    waits: list[float] = []

    async def fake_sleep(delay: float) -> None:
        waits.append(delay)

    async def fake_resolve(host):
        return "93.184.216.34"

    async def fake_lookup(ip, **_kwargs):
        looked_up.append(ip)
        return "DE"

    monkeypatch.setattr(geoip, "_resolve_to_ip", fake_resolve)
    monkeypatch.setattr(geoip, "lookup_country", fake_lookup)

    await geoip.enrich_configs_geoip(configs, sleep=fake_sleep)

    assert looked_up == ["93.184.216.34"]
    assert waits == []
    assert [cfg.country for cfg in configs] == ["DE", "DE", "DE"]


async def test_enrich_configs_geoip_survives_a_failing_resolve(
    monkeypatch,
    caplog,
) -> None:
    """One unusable address must cost one config, not the whole batch.

    ``gather`` without ``return_exceptions`` re-raised the first error out of
    the stage ("GeoIP enrichment failed"), left every other config without a
    country and abandoned the sibling tasks as orphans.
    """
    caplog.set_level("WARNING")
    broken = Config("vless", "broken.example", 443, "u")
    good = Config("vless", "good.example", 443, "u")

    async def fake_resolve(host):
        if host == "broken.example":
            raise AttributeError("'NoneType' object has no attribute 'strip'")
        return "93.184.216.34"

    async def fake_lookup(ip, **_kwargs):
        return "DE"

    async def fake_sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr(geoip, "_resolve_to_ip", fake_resolve)
    monkeypatch.setattr(geoip, "lookup_country", fake_lookup)

    await geoip.enrich_configs_geoip([broken, good], sleep=fake_sleep)

    assert good.country == "DE"
    assert broken.country is None
    assert "GeoIP address resolution failed for 1/2" in caplog.text


async def test_enrich_configs_geoip_survives_a_failing_lookup(
    monkeypatch,
    caplog,
) -> None:
    caplog.set_level("WARNING")
    configs = [Config("vless", "a.example", 443, "u")]

    async def fake_resolve(host):
        return "93.184.216.34"

    async def fake_lookup(ip, **_kwargs):
        raise RuntimeError("event loop is closed")

    async def fake_sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr(geoip, "_resolve_to_ip", fake_resolve)
    monkeypatch.setattr(geoip, "lookup_country", fake_lookup)

    await geoip.enrich_configs_geoip(configs, sleep=fake_sleep)

    assert configs[0].country is None
    assert "GeoIP country lookup failed for 1/1" in caplog.text
