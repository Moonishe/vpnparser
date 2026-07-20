"""Tests for proxy pool fetching, parsing, and validation — 100% coverage."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from src.validators.proxy_health import ProxyHealthHistory
from src.validators.proxy_pool import (
    _fetch_source,
    _is_public_ipv4,
    _normalize_proxy,
    fetch_proxy_candidates,
    load_proxy_pool,
    parse_proxy_candidates,
    proxy_connects,
    validate_proxy_candidates,
)

# ---------------------------------------------------------------------------
# _is_public_ipv4
# ---------------------------------------------------------------------------


def test_is_public_ipv4_valid() -> None:
    assert _is_public_ipv4("8.8.8.8") is True
    assert _is_public_ipv4("1.2.3.4") is True
    assert _is_public_ipv4("4.4.4.4") is True


def test_is_public_ipv4_private() -> None:
    assert _is_public_ipv4("192.168.1.1") is False
    assert _is_public_ipv4("10.0.0.1") is False
    assert _is_public_ipv4("172.16.0.1") is False


def test_is_public_ipv4_invalid() -> None:
    assert _is_public_ipv4("not-an-ip") is False
    assert _is_public_ipv4("") is False
    assert _is_public_ipv4("::1") is False  # IPv6


# ---------------------------------------------------------------------------
# _normalize_proxy
# ---------------------------------------------------------------------------


def test_normalize_proxy_valid() -> None:
    assert _normalize_proxy("1.2.3.4", "1080") == "socks5://1.2.3.4:1080"


def test_normalize_proxy_invalid_host() -> None:
    assert _normalize_proxy("192.168.1.1", "1080") is None
    assert _normalize_proxy("not-ip", "1080") is None


def test_normalize_proxy_bad_port() -> None:
    """Non-numeric port returns None."""
    assert _normalize_proxy("1.2.3.4", "not-a-port") is None


def test_normalize_proxy_port_out_of_range() -> None:
    """Port outside 1-65535 returns None."""
    assert _normalize_proxy("1.2.3.4", "0") is None
    assert _normalize_proxy("1.2.3.4", "65536") is None


# ---------------------------------------------------------------------------
# parse_proxy_candidates
# ---------------------------------------------------------------------------


def test_parse_proxy_candidates_empty_text() -> None:
    assert parse_proxy_candidates("") == []
    assert parse_proxy_candidates("   ") == []


def test_parse_proxy_candidates_no_matches() -> None:
    text = "this text has no proxy addresses"
    assert parse_proxy_candidates(text) == []


def test_parse_proxy_candidates_with_socks5_scheme() -> None:
    text = "socks5://1.2.3.4:1080"
    result = parse_proxy_candidates(text)
    assert result == ["socks5://1.2.3.4:1080"]


def test_parse_proxy_candidates_with_socks5h_scheme() -> None:
    text = "socks5h://1.2.3.4:1080"
    result = parse_proxy_candidates(text)
    assert result == ["socks5://1.2.3.4:1080"]


def test_parse_proxy_candidates_ip_port_only() -> None:
    """IP:port format without scheme is accepted."""
    text = "1.2.3.4:1080"
    result = parse_proxy_candidates(text)
    assert result == ["socks5://1.2.3.4:1080"]


def test_parse_proxy_candidates_ip_space_port() -> None:
    """IP space port format is accepted."""
    text = "1.2.3.4 1080"
    result = parse_proxy_candidates(text)
    assert result == ["socks5://1.2.3.4:1080"]


def test_parse_proxy_candidates_private_ip_skipped() -> None:
    text = "192.168.1.1:1080\n1.2.3.4:1080"
    result = parse_proxy_candidates(text)
    assert result == ["socks5://1.2.3.4:1080"]


def test_parse_proxy_candidates_dedup() -> None:
    text = "1.2.3.4:1080\n1.2.3.4:1080"
    result = parse_proxy_candidates(text)
    assert result == ["socks5://1.2.3.4:1080"]


def test_parse_proxy_candidates_mixed_lines() -> None:
    text = """# proxy list
1.2.3.4:1080
socks5://5.6.7.8:1080
# comment
9.10.11.12 3130"""
    result = parse_proxy_candidates(text)
    assert result == [
        "socks5://1.2.3.4:1080",
        "socks5://5.6.7.8:1080",
        "socks5://9.10.11.12:3130",
    ]


# ---------------------------------------------------------------------------
# _fetch_source
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fetch_source_success() -> None:
    client = AsyncMock(spec=httpx.AsyncClient)
    response = MagicMock(spec=httpx.Response)
    response.status_code = 200
    response.text = "1.2.3.4:1080"
    client.get.return_value = response

    text = await _fetch_source(client, "https://example.com/proxies.txt")
    assert text == "1.2.3.4:1080"
    client.get.assert_awaited_once()


@pytest.mark.asyncio
async def test_fetch_source_http_error() -> None:
    client = AsyncMock(spec=httpx.AsyncClient)
    client.get.side_effect = httpx.HTTPError("connection failed")

    text = await _fetch_source(client, "https://example.com/proxies.txt")
    assert text == ""


@pytest.mark.asyncio
async def test_fetch_source_non_200() -> None:
    client = AsyncMock(spec=httpx.AsyncClient)
    response = MagicMock(spec=httpx.Response)
    response.status_code = 404
    client.get.return_value = response

    text = await _fetch_source(client, "https://example.com/proxies.txt")
    assert text == ""


# ---------------------------------------------------------------------------
# fetch_proxy_candidates
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fetch_proxy_candidates_empty_sources() -> None:
    result = await fetch_proxy_candidates([])
    assert result == []


@pytest.mark.asyncio
async def test_fetch_proxy_candidates_max_candidates_zero() -> None:
    result = await fetch_proxy_candidates(
        ["https://example.com/list.txt"], max_candidates=0
    )
    assert result == []


@pytest.mark.asyncio
async def test_fetch_proxy_candidates_with_mocked_source() -> None:
    with patch(
        "src.validators.proxy_pool._fetch_source", new_callable=AsyncMock
    ) as mock_fetch:
        mock_fetch.return_value = "1.2.3.4:1080\n5.6.7.8:1080"
        result = await fetch_proxy_candidates(
            ["https://example.com/list.txt"],
            max_candidates=10,
        )
        assert result == ["socks5://1.2.3.4:1080", "socks5://5.6.7.8:1080"]


@pytest.mark.asyncio
async def test_fetch_proxy_candidates_exception_on_fetch() -> None:
    with patch(
        "src.validators.proxy_pool._fetch_source", new_callable=AsyncMock
    ) as mock_fetch:
        mock_fetch.side_effect = Exception("unexpected error")
        result = await fetch_proxy_candidates(
            ["https://example.com/list.txt"],
            max_candidates=10,
        )
        assert result == []


@pytest.mark.asyncio
async def test_fetch_proxy_candidates_max_candidates_limit() -> None:
    text = "\n".join(f"{i}.{i}.{i}.{i}:1080" for i in range(1, 11))
    with patch(
        "src.validators.proxy_pool._fetch_source", new_callable=AsyncMock
    ) as mock_fetch:
        mock_fetch.return_value = text
        result = await fetch_proxy_candidates(
            ["https://example.com/list.txt"],
            max_candidates=3,
        )
        assert len(result) == 3


@pytest.mark.asyncio
async def test_fetch_proxy_candidates_max_per_source() -> None:
    text = "\n".join(f"{i}.{i}.{i}.{i}:1080" for i in range(1, 11))
    with patch(
        "src.validators.proxy_pool._fetch_source", new_callable=AsyncMock
    ) as mock_fetch:
        mock_fetch.return_value = text
        result = await fetch_proxy_candidates(
            ["https://example.com/list.txt"],
            max_candidates=10,
            max_candidates_per_source=3,
        )
        assert len(result) == 3


@pytest.mark.asyncio
async def test_fetch_proxy_candidates_dedup_across_sources() -> None:
    with patch(
        "src.validators.proxy_pool._fetch_source", new_callable=AsyncMock
    ) as mock_fetch:
        mock_fetch.return_value = "1.2.3.4:1080"
        result = await fetch_proxy_candidates(
            ["https://a.com/list.txt", "https://b.com/list.txt"],
            max_candidates=10,
        )
        assert result == ["socks5://1.2.3.4:1080"]


# ---------------------------------------------------------------------------
# proxy_connects
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_proxy_connects_success() -> None:
    with patch("python_socks.async_.asyncio.Proxy") as MockProxy:
        proxy_instance = MagicMock()
        MockProxy.from_url.return_value = proxy_instance
        mock_sock = MagicMock()
        proxy_instance.connect = AsyncMock(return_value=mock_sock)

        result = await proxy_connects("socks5://1.2.3.4:1080")
        assert result is True


@pytest.mark.asyncio
async def test_proxy_connects_failure() -> None:
    with patch("python_socks.async_.asyncio.Proxy") as MockProxy:
        proxy_instance = MagicMock()
        MockProxy.from_url.return_value = proxy_instance
        proxy_instance.connect = AsyncMock(side_effect=Exception("connection refused"))

        result = await proxy_connects("socks5://1.2.3.4:1080")
        assert result is False


# ---------------------------------------------------------------------------
# validate_proxy_candidates
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_validate_proxy_candidates_empty() -> None:
    result = await validate_proxy_candidates([])
    assert result == []


@pytest.mark.asyncio
async def test_validate_proxy_candidates_max_proxies_zero() -> None:
    result = await validate_proxy_candidates(["socks5://1.2.3.4:1080"], max_proxies=0)
    assert result == []


@pytest.mark.asyncio
async def test_validate_proxy_candidates_all_fail() -> None:
    with patch(
        "src.validators.proxy_pool.proxy_connects", new_callable=AsyncMock
    ) as mock_pc:
        mock_pc.return_value = False
        result = await validate_proxy_candidates(
            ["socks5://1.2.3.4:1080", "socks5://5.6.7.8:1080"],
            max_proxies=5,
        )
        assert result == []


@pytest.mark.asyncio
async def test_validate_proxy_candidates_some_pass() -> None:
    with patch(
        "src.validators.proxy_pool.proxy_connects", new_callable=AsyncMock
    ) as mock_pc:
        mock_pc.side_effect = [True, False, True]
        result = await validate_proxy_candidates(
            [
                "socks5://1.2.3.4:1080",
                "socks5://5.6.7.8:1080",
                "socks5://9.10.11.12:1080",
            ],
            max_proxies=5,
        )
        assert result == ["socks5://1.2.3.4:1080", "socks5://9.10.11.12:1080"]


@pytest.mark.asyncio
async def test_validate_proxy_candidates_with_history() -> None:
    history = ProxyHealthHistory()
    with patch(
        "src.validators.proxy_pool.proxy_connects", new_callable=AsyncMock
    ) as mock_pc:
        mock_pc.return_value = True
        result = await validate_proxy_candidates(
            ["socks5://1.2.3.4:1080"],
            max_proxies=5,
            history=history,
        )
        assert result == ["socks5://1.2.3.4:1080"]
        assert "socks5://1.2.3.4:1080" in history.records


@pytest.mark.asyncio
async def test_validate_proxy_candidates_max_proxies_reached() -> None:
    with patch(
        "src.validators.proxy_pool.proxy_connects", new_callable=AsyncMock
    ) as mock_pc:
        mock_pc.return_value = True
        result = await validate_proxy_candidates(
            [
                "socks5://1.2.3.4:1080",
                "socks5://5.6.7.8:1080",
                "socks5://9.10.11.12:1080",
            ],
            max_proxies=2,
        )
        assert len(result) == 2


# ---------------------------------------------------------------------------
# load_proxy_pool
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_load_proxy_pool_no_candidates() -> None:
    with patch(
        "src.validators.proxy_pool.fetch_proxy_candidates",
        new_callable=AsyncMock,
    ) as mock_fetch:
        mock_fetch.return_value = []
        result = await load_proxy_pool(sources=["https://example.com/list.txt"])
        assert result == []


@pytest.mark.asyncio
async def test_load_proxy_pool_unvalidated() -> None:
    with patch(
        "src.validators.proxy_pool.fetch_proxy_candidates",
        new_callable=AsyncMock,
    ) as mock_fetch:
        mock_fetch.return_value = [
            "socks5://1.2.3.4:1080",
            "socks5://5.6.7.8:1080",
        ]
        result = await load_proxy_pool(
            sources=["https://example.com/list.txt"],
            validate=False,
            max_proxies=1,
        )
        assert result == ["socks5://1.2.3.4:1080"]


@pytest.mark.asyncio
async def test_load_proxy_pool_validated() -> None:
    with (
        patch(
            "src.validators.proxy_pool.fetch_proxy_candidates",
            new_callable=AsyncMock,
        ) as mock_fetch,
        patch(
            "src.validators.proxy_pool.validate_proxy_candidates",
            new_callable=AsyncMock,
        ) as mock_validate,
    ):
        mock_fetch.return_value = [
            "socks5://1.2.3.4:1080",
            "socks5://5.6.7.8:1080",
        ]
        mock_validate.return_value = ["socks5://1.2.3.4:1080"]
        result = await load_proxy_pool(
            sources=["https://example.com/list.txt"],
            validate=True,
        )
        assert result == ["socks5://1.2.3.4:1080"]


@pytest.mark.asyncio
async def test_load_proxy_pool_with_history() -> None:
    history = ProxyHealthHistory()
    history.record("socks5://5.6.7.8:1080", True, latency_ms=50)
    with (
        patch(
            "src.validators.proxy_pool.fetch_proxy_candidates",
            new_callable=AsyncMock,
        ) as mock_fetch,
        patch(
            "src.validators.proxy_pool.validate_proxy_candidates",
            new_callable=AsyncMock,
        ) as mock_validate,
    ):
        mock_fetch.return_value = [
            "socks5://1.2.3.4:1080",
            "socks5://5.6.7.8:1080",
        ]
        mock_validate.return_value = ["socks5://1.2.3.4:1080", "socks5://5.6.7.8:1080"]
        result = await load_proxy_pool(
            sources=["https://example.com/list.txt"],
            validate=True,
            history=history,
        )
        # After validation, should be ranked - 5.6.7.8 has good history
        assert "socks5://5.6.7.8:1080" in result
        assert "socks5://1.2.3.4:1080" in result


# ---------------------------------------------------------------------------
# validate_proxy_candidates — cancellation edge cases
# (coverage for lines 196, 227: done_event race + task cancellation)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_validate_candidates_cancels_remaining_tasks() -> None:
    """When max_proxies is reached early, remaining tasks hit done_event or get cancelled."""
    connect_count = 0

    async def _delayed_connect(proxy_url: str, **kwargs: object) -> bool:
        nonlocal connect_count
        connect_count += 1
        if connect_count == 1:
            # First task yields so other tasks can start and queue up
            await asyncio.sleep(0)
        return True

    with patch(
        "src.validators.proxy_pool.proxy_connects",
        side_effect=_delayed_connect,
    ):
        result = await validate_proxy_candidates(
            [f"socks5://{i}.{i}.{i}.{i}:1080" for i in range(1, 6)],
            max_proxies=1,
            concurrency=1,
        )
        assert len(result) == 1


# ---------------------------------------------------------------------------
# parse_proxy_candidates — edge: already-seen proxy skipped in second source
# (coverage for line 128: "if proxy in seen")
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fetch_proxy_candidates_duplicate_in_second_source() -> None:
    """When the same proxy appears in a second source, it's skipped (seen set)."""
    side_effect = ["1.2.3.4:1080", "1.2.3.4:1080"]
    with patch(
        "src.validators.proxy_pool._fetch_source", new_callable=AsyncMock
    ) as mock_fetch:
        mock_fetch.side_effect = side_effect
        result = await fetch_proxy_candidates(
            ["https://a.com/list.txt", "https://b.com/list.txt"],
            max_candidates=10,
        )
        assert result == ["socks5://1.2.3.4:1080"]
