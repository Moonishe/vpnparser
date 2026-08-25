"""Tests for proxy pool fetching, parsing, and validation — 100% coverage."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

import src.validators.proxy_pool as proxy_pool_module
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


def _stream_client(
    responses: list[tuple[int, bytes, dict[str, str]]],
) -> AsyncMock:
    """Build an httpx.AsyncClient mock whose .stream() replays *responses*."""
    client = AsyncMock(spec=httpx.AsyncClient)
    calls = 0

    def stream(method: str, url: str, **kwargs: object) -> MagicMock:
        nonlocal calls
        status_code, body, headers = responses[min(calls, len(responses) - 1)]
        calls += 1
        response = MagicMock(spec=httpx.Response)
        response.status_code = status_code
        response.headers = headers

        async def aiter_bytes(chunk_size: int) -> AsyncIterator[bytes]:
            for start in range(0, len(body), chunk_size or 1):
                yield body[start : start + chunk_size]

        response.aiter_bytes = aiter_bytes
        ctx = MagicMock()
        ctx.__aenter__ = AsyncMock(return_value=response)
        ctx.__aexit__ = AsyncMock(return_value=False)
        return ctx

    client.stream = MagicMock(side_effect=stream)
    return client


@pytest.mark.asyncio
async def test_fetch_source_success() -> None:
    client = _stream_client([(200, b"1.2.3.4:1080", {})])

    text = await _fetch_source(client, "https://example.com/proxies.txt")
    assert text == "1.2.3.4:1080"
    client.stream.assert_called_once()


@pytest.mark.asyncio
async def test_fetch_source_http_error() -> None:
    client = AsyncMock(spec=httpx.AsyncClient)
    client.stream.side_effect = httpx.HTTPError("connection failed")

    text = await _fetch_source(client, "https://example.com/proxies.txt")
    assert text == ""


@pytest.mark.asyncio
async def test_fetch_source_non_200() -> None:
    client = _stream_client([(404, b"", {})])

    text = await _fetch_source(client, "https://example.com/proxies.txt")
    assert text == ""


@pytest.mark.asyncio
async def test_fetch_source_follows_safe_redirect() -> None:
    client = _stream_client(
        [
            (301, b"", {"location": "https://mirror.example.com/list.txt"}),
            (200, b"1.2.3.4:1080", {}),
        ],
    )

    text = await _fetch_source(client, "https://example.com/proxies.txt")
    assert text == "1.2.3.4:1080"
    # Second hop went to the redirect target.
    second_url = client.stream.call_args_list[1][0][1]
    assert second_url == "https://mirror.example.com/list.txt"


@pytest.mark.asyncio
async def test_fetch_source_refuses_private_redirect() -> None:
    client = _stream_client(
        [(302, b"", {"location": "http://169.254.169.254/latest/meta-data"})],
    )

    text = await _fetch_source(client, "https://example.com/proxies.txt")
    assert text == ""
    # Only the initial request was made — the private hop was refused.
    assert client.stream.call_count == 1


@pytest.mark.asyncio
async def test_fetch_source_discards_oversized_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(proxy_pool_module, "_MAX_SOURCE_BODY_BYTES", 10)
    # Two chunks of 64 KiB each: once the byte cap is exceeded the whole body
    # is discarded (None) — a truncated list would silently skew the pool.
    client = _stream_client([(200, b"a" * 65536 + b"b" * 65536, {})])

    text = await _fetch_source(client, "https://example.com/proxies.txt")
    assert text is None


@pytest.mark.asyncio
async def test_fetch_source_wall_clock_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A slow-drip stream must hit the overall deadline, not read-timeout forever.

    httpx restarts its read timer on every chunk; without a wall-clock budget
    one dripping source stalled sequential pool construction indefinitely.
    """
    import asyncio as _asyncio

    monkeypatch.setattr(proxy_pool_module, "_DOWNLOAD_BUDGET_FACTOR", 0.0)

    async def drip_forever(chunk_size: int):
        while True:
            yield b"x"
            await _asyncio.sleep(0.01)

    client = AsyncMock(spec=httpx.AsyncClient)
    response = MagicMock(spec=httpx.Response)
    response.status_code = 200
    response.headers = {}
    response.aiter_bytes = drip_forever
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=response)
    ctx.__aexit__ = AsyncMock(return_value=False)
    client.stream = MagicMock(return_value=ctx)

    text = await _fetch_source(client, "https://example.com/proxies.txt")
    assert text is None


@pytest.mark.asyncio
async def test_fetch_source_redirect_without_location() -> None:
    client = _stream_client([(301, b"", {})])

    text = await _fetch_source(client, "https://example.com/proxies.txt")
    assert text == ""
    assert client.stream.call_count == 1


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


@pytest.mark.asyncio
async def test_load_proxy_pool_skips_banned_candidates_before_probing() -> None:
    """Banned proxies must never reach the self-check.

    Ranking after validation cannot drop them: a proxy only reaches the ranked
    list by passing the check, and passing resets ``consecutive_failures``. So
    every dead proxy was re-probed at full cost, run after run, while the
    settings promise "banned/dead proxies are skipped on the next run".
    """
    history = ProxyHealthHistory(ban_after_consecutive_failures=3)
    for _ in range(3):
        history.record("socks5://1.2.3.4:1080", False)
    history.record("socks5://5.6.7.8:1080", True, latency_ms=50)
    probed: list[list[str]] = []

    async def _fake_validate(proxies: list[str], **_kwargs: object) -> list[str]:
        probed.append(list(proxies))
        return list(proxies)

    with (
        patch(
            "src.validators.proxy_pool.fetch_proxy_candidates",
            new_callable=AsyncMock,
        ) as mock_fetch,
        patch(
            "src.validators.proxy_pool.validate_proxy_candidates",
            new=_fake_validate,
        ),
    ):
        mock_fetch.return_value = [
            "socks5://1.2.3.4:1080",
            "socks5://5.6.7.8:1080",
        ]
        result = await load_proxy_pool(
            sources=["https://example.com/list.txt"],
            validate=True,
            history=history,
        )

    assert probed == [["socks5://5.6.7.8:1080"]]
    assert result == ["socks5://5.6.7.8:1080"]


@pytest.mark.asyncio
async def test_load_proxy_pool_keeps_candidates_when_all_are_banned(caplog) -> None:
    """A history that bans everything must not leave the run without a pool."""
    caplog.set_level("WARNING")
    history = ProxyHealthHistory(ban_after_consecutive_failures=1)
    history.record("socks5://1.2.3.4:1080", False)
    probed: list[list[str]] = []

    async def _fake_validate(proxies: list[str], **_kwargs: object) -> list[str]:
        probed.append(list(proxies))
        # What the real self-check does for a proxy that answers.
        for proxy in proxies:
            history.record(proxy, True, latency_ms=50)
        return list(proxies)

    with (
        patch(
            "src.validators.proxy_pool.fetch_proxy_candidates",
            new_callable=AsyncMock,
        ) as mock_fetch,
        patch(
            "src.validators.proxy_pool.validate_proxy_candidates",
            new=_fake_validate,
        ),
    ):
        mock_fetch.return_value = ["socks5://1.2.3.4:1080"]
        result = await load_proxy_pool(
            sources=["https://example.com/list.txt"],
            validate=True,
            history=history,
        )

    assert probed == [["socks5://1.2.3.4:1080"]]
    assert result == ["socks5://1.2.3.4:1080"]
    assert "rejects all 1 candidate(s)" in caplog.text


# --- failover probe targets & network diversity ------------------------------


async def test_proxy_connects_fails_over_to_extra_target(monkeypatch) -> None:
    """A proxy that cannot reach GitHub still passes via gstatic."""
    from src.validators import proxy_pool

    attempted: list[str] = []

    class _Sock:
        def close(self) -> None:
            return None

    def _proxy_from_url(_url: str):
        class _Proxy:
            async def connect(self, *, dest_host, dest_port, timeout=1.0):
                attempted.append(dest_host)
                if dest_host == "api.github.com":
                    raise OSError("filtered")
                return _Sock()

        return _Proxy()

    import python_socks.async_.asyncio as psi

    monkeypatch.setattr(
        psi, "Proxy", type("P", (), {"from_url": staticmethod(_proxy_from_url)})
    )
    monkeypatch.setattr(
        "sys.modules",
        {**__import__("sys").modules},
    )
    ok = await proxy_pool.proxy_connects(
        "socks5://1.2.3.4:1080",
        extra_probe_targets=[("www.gstatic.com", 443)],
    )
    assert ok is True
    assert attempted == ["api.github.com", "www.gstatic.com"]


async def test_proxy_connects_all_targets_dead(monkeypatch) -> None:
    from src.validators import proxy_pool

    class _Nope:
        async def connect(self, **_kw):
            raise OSError("dead")

    import python_socks.async_.asyncio as psi

    monkeypatch.setattr(
        psi.Proxy,
        "from_url",
        staticmethod(lambda _url: _Nope()),
    )
    ok = await proxy_pool.proxy_connects(
        "socks5://1.2.3.4:1080",
        extra_probe_targets=[("www.gstatic.com", 443)],
    )
    assert ok is False


def test_count_proxy_networks_groups_by_prefix16() -> None:
    from src.validators.proxy_pool import count_proxy_networks

    urls = [
        "socks5://10.1.1.1:1080",
        "socks5://10.1.9.9:1080",  # same /16
        "socks5://10.2.0.1:1080",  # different /16
        "socks5://proxy.example:1080",  # hostname — its own bucket
        "socks5://[2001:db8:1::1]:1080",
        "socks5://[2001:db8:1::2]:1080",  # same /48
    ]
    assert count_proxy_networks(urls) == 4
    assert count_proxy_networks([]) == 0


# ---------------------------------------------------------------------------
# _fetch_source: transient network errors and redirect-loop cap
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fetch_source_retries_network_error_then_succeeds() -> None:
    """A transient network error retries instead of dropping the source."""
    import httpx as _httpx

    calls = {"n": 0}

    class _FlakyClient:
        async def __aenter__(self) -> _FlakyClient:
            return self

        async def __aexit__(self, *exc: object) -> None:
            return None

        def stream(self, *a: object, **kw: object):
            calls["n"] += 1
            if calls["n"] == 1:
                raise _httpx.ConnectError("blip")

            class _Resp:
                status_code = 200
                headers = {}

                @staticmethod
                async def aiter_bytes(size: int):
                    yield b"1.2.3.4:1080"

            ctx = MagicMock()
            ctx.__aenter__ = AsyncMock(return_value=_Resp())
            ctx.__aexit__ = AsyncMock(return_value=False)
            return ctx

    text = await _fetch_source(_FlakyClient(), "https://example.com/list.txt")
    assert text == "1.2.3.4:1080"
    assert calls["n"] == 2


@pytest.mark.asyncio
async def test_fetch_source_network_error_exhausts_attempts() -> None:
    """Every attempt failing leaves the source skipped (empty string)."""
    import httpx as _httpx

    calls = {"n": 0}

    class _DeadClient:
        async def __aenter__(self) -> _DeadClient:
            return self

        async def __aexit__(self, *exc: object) -> None:
            return None

        def stream(self, *a: object, **kw: object):
            calls["n"] += 1
            raise _httpx.ConnectError("down")

    text = await _fetch_source(
        _DeadClient(),
        "https://example.com/list.txt",
        timeout=10.0,
    )
    assert text == ""
    assert calls["n"] == 3


@pytest.mark.asyncio
async def test_fetch_source_redirect_hops_exhausted() -> None:
    """An endless same-host redirect chain gives up after the hop budget."""
    client = _stream_client([(301, b"", {"location": "https://example.com/next"})])

    text = await _fetch_source(client, "https://example.com/list.txt")
    assert text == ""


def test_fetch_proxy_candidates_swallows_raising_source(monkeypatch) -> None:
    """A raising source is skipped without killing the concurrent gather."""
    import httpx as _httpx

    async def raiser(_client, url, **kwargs):
        raise _httpx.ConnectError("nope")

    async def ok(_client, url, **kwargs):
        return "9.9.9.9:1080"

    monkeypatch.setattr(
        proxy_pool_module,
        "_fetch_source",
        lambda c, u, **k: raiser(c, u) if "bad" in u else ok(c, u),
    )
    result = asyncio.run(
        proxy_pool_module.fetch_proxy_candidates(
            ["https://bad.example/x", "https://ok.example/x"],
            max_candidates=10,
        ),
    )
    assert result == ["socks5://9.9.9.9:1080"]


def test_fetch_proxy_candidates_swallows_base_exception_source(
    monkeypatch,
) -> None:
    """gather(return_exceptions=True) results are type-checked, not truthy."""

    async def raiser(_client, url, **kwargs):
        raise ValueError("unexpected")

    monkeypatch.setattr(proxy_pool_module, "_fetch_source", raiser)
    result = asyncio.run(
        proxy_pool_module.fetch_proxy_candidates(
            ["https://bad.example/x"],
            max_candidates=5,
        ),
    )
    assert result == []
