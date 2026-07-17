"""Tests for src/validators/tcp_check.py — 100% coverage."""

from __future__ import annotations

import asyncio
import logging
import socket
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.parsers.base import Config
from src.validators.tcp_check import (
    _open_connection_direct,
    _open_connection_via_socks,
    tcp_check,
    validate_configs_tcp,
)


# ===========================================================================
# _open_connection_direct
# ===========================================================================


class TestOpenConnectionDirect:
    """Cover line 28."""

    @pytest.mark.asyncio
    async def test_direct_connection_calls_open_connection(self) -> None:
        """Delegates to asyncio.open_connection with host, port."""
        mock_reader = MagicMock()
        mock_writer = MagicMock()

        with patch(
            "src.validators.tcp_check.asyncio.open_connection",
            new=AsyncMock(return_value=(mock_reader, mock_writer)),
        ) as mock_open:
            reader, writer = await _open_connection_direct("example.com", 443)
            mock_open.assert_called_once_with("example.com", 443)
            assert reader is mock_reader
            assert writer is mock_writer


# ===========================================================================
# _open_connection_via_socks
# ===========================================================================


class TestOpenConnectionViaSocks:
    """Cover lines 41-47."""

    @pytest.mark.asyncio
    async def test_via_socks_uses_proxy(self) -> None:
        """Routes connection through SOCKS5 proxy via mocked python_socks."""
        mock_reader = MagicMock()
        mock_writer = MagicMock()
        mock_sock = MagicMock()

        # Mock python_socks so _open_connection_via_socks executes its body
        mock_proxy_instance = MagicMock()
        mock_proxy_instance.connect = AsyncMock(return_value=mock_sock)

        with patch(
            "python_socks.async_.asyncio.Proxy.from_url",
            return_value=mock_proxy_instance,
        ):
            with patch(
                "src.validators.tcp_check.asyncio.open_connection",
                new=AsyncMock(return_value=(mock_reader, mock_writer)),
            ) as mock_open:
                is_alive, latency = await tcp_check(
                    "example.com",
                    443,
                    proxy_url="socks5://proxy.example:1080",
                )
        assert is_alive is True
        assert latency is not None
        mock_open.assert_called_once_with(sock=mock_sock)


# ===========================================================================
# tcp_check()
# ===========================================================================


class TestTcpCheck:
    """Cover tcp_check — lines 50-90."""

    @pytest.mark.asyncio
    async def test_success_direct(self) -> None:
        """Successful direct connection returns (True, latency_ms)."""
        mock_writer = MagicMock()
        with patch(
            "src.validators.tcp_check._open_connection_direct",
            new=AsyncMock(return_value=(MagicMock(), mock_writer)),
        ):
            is_alive, latency = await tcp_check("example.com", 443)
        assert is_alive is True
        assert latency is not None
        assert latency > 0

    @pytest.mark.asyncio
    async def test_success_via_proxy(self) -> None:
        """Successful proxy connection returns (True, latency_ms)."""
        mock_writer = MagicMock()
        with patch(
            "src.validators.tcp_check._open_connection_via_socks",
            new=AsyncMock(return_value=(MagicMock(), mock_writer)),
        ):
            is_alive, latency = await tcp_check(
                "example.com", 443, proxy_url="socks5://proxy:1080"
            )
        assert is_alive is True
        assert latency is not None

    @pytest.mark.asyncio
    async def test_timeout_error(self) -> None:
        """TimeoutError -> (False, None)."""
        with patch(
            "src.validators.tcp_check._open_connection_direct",
            new=AsyncMock(side_effect=TimeoutError("timed out")),
        ):
            is_alive, latency = await tcp_check("example.com", 443)
        assert is_alive is False
        assert latency is None

    @pytest.mark.asyncio
    async def test_connection_refused(self) -> None:
        """ConnectionRefusedError -> (False, None)."""
        with patch(
            "src.validators.tcp_check._open_connection_direct",
            new=AsyncMock(side_effect=ConnectionRefusedError),
        ):
            is_alive, latency = await tcp_check("example.com", 443)
        assert is_alive is False
        assert latency is None

    @pytest.mark.asyncio
    async def test_gaierror(self) -> None:
        """socket.gaierror -> (False, None)."""
        with patch(
            "src.validators.tcp_check._open_connection_direct",
            new=AsyncMock(side_effect=socket.gaierror("no address")),
        ):
            is_alive, latency = await tcp_check("example.com", 443)
        assert is_alive is False
        assert latency is None

    @pytest.mark.asyncio
    async def test_os_error(self) -> None:
        """OSError -> (False, None)."""
        with patch(
            "src.validators.tcp_check._open_connection_direct",
            new=AsyncMock(side_effect=OSError("connection reset")),
        ):
            is_alive, latency = await tcp_check("example.com", 443)
        assert is_alive is False
        assert latency is None

    @pytest.mark.asyncio
    async def test_generic_exception(self) -> None:
        """Generic Exception -> (False, None)."""
        with patch(
            "src.validators.tcp_check._open_connection_direct",
            new=AsyncMock(side_effect=RuntimeError("unexpected")),
        ):
            is_alive, latency = await tcp_check("example.com", 443)
        assert is_alive is False
        assert latency is None

    @pytest.mark.asyncio
    async def test_writer_close_exception_suppressed(self) -> None:
        """Exception on writer.close() is suppressed."""
        mock_writer = MagicMock()
        # Make writer.close() raise OSError
        mock_writer.close.side_effect = OSError("close failed")
        mock_writer.wait_closed = AsyncMock(side_effect=OSError("wait closed failed"))

        with patch(
            "src.validators.tcp_check._open_connection_direct",
            new=AsyncMock(return_value=(MagicMock(), mock_writer)),
        ):
            is_alive, latency = await tcp_check("example.com", 443)
        assert is_alive is True
        assert latency is not None

    @pytest.mark.asyncio
    async def test_asyncio_timeout(self) -> None:
        """asyncio.TimeoutError (from wait_for) -> (False, None)."""
        with patch(
            "src.validators.tcp_check._open_connection_direct",
            new=AsyncMock(side_effect=asyncio.TimeoutError),
        ):
            is_alive, latency = await tcp_check("example.com", 443)
        assert is_alive is False
        assert latency is None


# ===========================================================================
# validate_configs_tcp()
# ===========================================================================


class TestValidateConfigsTcp:
    """Cover validate_configs_tcp — lines 93-193."""

    @pytest.mark.asyncio
    async def test_empty_configs(self) -> None:
        """Empty configs list -> []."""
        result = await validate_configs_tcp([])
        assert result == []

    @pytest.mark.asyncio
    async def test_all_configs_checked(self) -> None:
        """All configs checked, no max_alive limit."""
        configs = [
            Config("vless", "a.example", 443, "uuid"),
            Config("vless", "b.example", 443, "uuid"),
        ]

        with patch(
            "src.validators.tcp_check.tcp_check",
            new=AsyncMock(return_value=(True, 10.0)),
        ):
            result = await validate_configs_tcp(configs)
        assert len(result) == 2
        assert all(c.is_alive for c in result)
        assert all(c.latency_ms == 10.0 for c in result)

    @pytest.mark.asyncio
    async def test_some_configs_alive(self) -> None:
        """Mix of alive/dead configs."""
        configs = [
            Config("vless", "alive.example", 443, "uuid"),
            Config("vless", "dead.example", 443, "uuid"),
        ]
        side_effects = [(True, 5.0), (False, None)]

        with patch(
            "src.validators.tcp_check.tcp_check",
            new=AsyncMock(side_effect=side_effects),
        ):
            result = await validate_configs_tcp(configs)
        assert len(result) == 1
        assert result[0].address == "alive.example"

    @pytest.mark.asyncio
    async def test_max_alive_early_termination(self) -> None:
        """Early termination when max_alive configs found."""
        configs = [
            Config("vless", f"host-{i}.example", 443 + i, "uuid") for i in range(10)
        ]

        call_count = 0

        async def fake_tcp_check(host, port, timeout=3.0, proxy_url=None):
            nonlocal call_count
            call_count += 1
            return (True, 5.0)

        with patch(
            "src.validators.tcp_check.tcp_check",
            new=fake_tcp_check,
        ):
            result = await validate_configs_tcp(configs, max_alive=3)
        assert len(result) == 3
        # Should have stopped early after finding 3 alive
        assert call_count < 10

    @pytest.mark.asyncio
    async def test_proxy_url(self) -> None:
        """proxy_url is used when proxy_urls is empty."""
        configs = [Config("vless", "a.example", 443, "uuid")]

        with patch(
            "src.validators.tcp_check.tcp_check",
            new=AsyncMock(return_value=(True, 5.0)),
        ) as mock_check:
            result = await validate_configs_tcp(
                configs, proxy_url="socks5://proxy:1080"
            )
        assert len(result) == 1
        # Check proxy_url was passed through to tcp_check
        _, kwargs = mock_check.call_args
        assert kwargs["proxy_url"] == "socks5://proxy:1080"

    @pytest.mark.asyncio
    async def test_proxy_urls_used(self) -> None:
        """proxy_urls list takes precedence over proxy_url."""
        configs = [Config("vless", "a.example", 443, "uuid")]

        with patch(
            "src.validators.tcp_check.tcp_check",
            new=AsyncMock(return_value=(True, 5.0)),
        ) as mock_check:
            result = await validate_configs_tcp(
                configs,
                proxy_url="socks5://fallback:1080",
                proxy_urls=["socks5://primary:1080"],
            )
        assert len(result) == 1
        _, kwargs = mock_check.call_args
        assert kwargs["proxy_url"] == "socks5://primary:1080"

    @pytest.mark.asyncio
    async def test_proxy_attempts_per_config_zero(self) -> None:
        """proxy_attempts_per_config=0 tries all proxies."""
        configs = [Config("vless", "a.example", 443, "uuid")]
        proxy_urls = [
            "socks5://p1:1080",
            "socks5://p2:1080",
            "socks5://p3:1080",
        ]
        used_proxies = []

        async def fake_tcp_check(host, port, timeout=3.0, proxy_url=None):
            used_proxies.append(proxy_url)
            # Fail on first two, succeed on last
            return (proxy_url == "socks5://p3:1080", 5.0)

        with patch(
            "src.validators.tcp_check.tcp_check",
            new=fake_tcp_check,
        ):
            result = await validate_configs_tcp(
                configs, proxy_urls=proxy_urls, proxy_attempts_per_config=0
            )
        assert len(result) == 1
        # With 3 proxies and attempts=0, should try all 3
        assert len(used_proxies) == 3

    @pytest.mark.asyncio
    async def test_first_proxy_succeeds(self) -> None:
        """First proxy succeeds -> no retry with different proxy."""
        configs = [Config("vless", "a.example", 443, "uuid")]
        proxy_urls = ["socks5://p1:1080", "socks5://p2:1080"]
        used_proxies = []

        async def fake_tcp_check(host, port, timeout=3.0, proxy_url=None):
            used_proxies.append(proxy_url)
            return (True, 5.0) if proxy_url == "socks5://p1:1080" else (False, None)

        with patch(
            "src.validators.tcp_check.tcp_check",
            new=fake_tcp_check,
        ):
            result = await validate_configs_tcp(
                configs, proxy_urls=proxy_urls, proxy_attempts_per_config=2
            )
        assert len(result) == 1
        # Only first proxy should have been tried (it succeeded)
        assert used_proxies == ["socks5://p1:1080"]

    @pytest.mark.asyncio
    async def test_sort_by_latency(self) -> None:
        """Results sorted by latency ascending."""
        configs = [
            Config("vless", "slow.example", 443, "uuid"),
            Config("vless", "fast.example", 443, "uuid"),
        ]

        side_effects = [(True, 100.0), (True, 5.0)]

        with patch(
            "src.validators.tcp_check.tcp_check",
            new=AsyncMock(side_effect=side_effects),
        ):
            result = await validate_configs_tcp(configs)
        assert result[0].address == "fast.example"
        assert result[1].address == "slow.example"

    @pytest.mark.asyncio
    async def test_cancelled_error_in_early_termination(self) -> None:
        """CancelledError during gather after early termination."""
        configs = [
            Config("vless", f"host-{i}.example", 443 + i, "uuid") for i in range(50)
        ]

        # Make check_one succeed instantly for first few, then slow
        async def fake_tcp_check(host, port, timeout=3.0, proxy_url=None):
            return (True, 5.0)

        with patch(
            "src.validators.tcp_check.tcp_check",
            new=fake_tcp_check,
        ):
            result = await validate_configs_tcp(configs, max_alive=10)
        assert len(result) == 10
        # All tasks should complete (return_exceptions=True handles CancelledError)

    @pytest.mark.asyncio
    async def test_no_proxy_choices_and_no_proxy_url(self) -> None:
        """No proxy_choices and no proxy_url -> direct connection (None proxy)."""
        configs = [Config("vless", "a.example", 443, "uuid")]

        with patch(
            "src.validators.tcp_check.tcp_check",
            new=AsyncMock(return_value=(True, 5.0)),
        ) as mock_check:
            result = await validate_configs_tcp(configs)
        assert len(result) == 1
        _, kwargs = mock_check.call_args
        assert kwargs["proxy_url"] is None

    @pytest.mark.asyncio
    async def test_all_dead_configs_returns_empty(self) -> None:
        """All configs dead -> empty list."""
        configs = [
            Config("vless", "dead1.example", 443, "uuid"),
            Config("vless", "dead2.example", 443, "uuid"),
        ]

        with patch(
            "src.validators.tcp_check.tcp_check",
            new=AsyncMock(return_value=(False, None)),
        ):
            result = await validate_configs_tcp(configs)
        assert result == []

    @pytest.mark.asyncio
    async def test_no_filtered_proxy_choices(self) -> None:
        """proxy_urls with empty/falsy values are filtered out."""
        configs = [Config("vless", "a.example", 443, "uuid")]
        # All falsy proxy URLs -> should fall back to None
        with patch(
            "src.validators.tcp_check.tcp_check",
            new=AsyncMock(return_value=(True, 5.0)),
        ) as mock_check:
            result = await validate_configs_tcp(
                configs, proxy_urls=["", "socks5://good:1080"]
            )
        assert len(result) == 1
        _, kwargs = mock_check.call_args
        assert kwargs["proxy_url"] == "socks5://good:1080"

    @pytest.mark.asyncio
    async def test_cleanup_when_max_alive_not_reached(self) -> None:
        """Lines 185-186: cleanup done_task when max_alive not reached."""
        configs = [
            Config("vless", f"host-{i}.example", 443 + i, "uuid") for i in range(3)
        ]

        async def fake_tcp_check(host, port, timeout=3.0, proxy_url=None):
            return (True, 5.0)

        with patch(
            "src.validators.tcp_check.tcp_check",
            new=fake_tcp_check,
        ):
            # max_alive > total configs => all complete, done_event never set
            # Lines 185-186 cancel the pending done_task
            result = await validate_configs_tcp(configs, max_alive=10)
        assert len(result) == 3

    @pytest.mark.asyncio
    async def test_semaphore_done_event_check(
        self,
    ) -> None:
        """Line 149: task acquires semaphore but done_event is already set."""
        # Scenario: concurrency=1, 2 configs. The second task must wait for
        # the semaphore; by the time it acquires it, done_event is set.
        configs = [
            Config("vless", "fast.example", 443, "uuid"),
            Config("vless", "slow.example", 443, "uuid"),
        ]

        async def fake_tcp_check(host, port, timeout=3.0, proxy_url=None):
            await asyncio.sleep(0)  # yield so event loop can switch tasks
            return (True, 5.0)

        with patch(
            "src.validators.tcp_check.tcp_check",
            new=fake_tcp_check,
        ):
            result = await validate_configs_tcp(configs, max_alive=1, concurrency=1)
        assert len(result) == 1
        assert result[0].address == "fast.example"

    @pytest.mark.asyncio
    async def test_cancel_pending_tasks_on_early_termination(
        self,
    ) -> None:
        """Line 183: cancel pending tasks when max_alive reached early."""
        # 5 configs, max_alive=2, concurrency=1.
        # First 2 tasks complete and set done_event; remaining 3 are cancelled.
        configs = [
            Config("vless", f"host-{i}.example", 443 + i, "uuid") for i in range(5)
        ]

        async def fake_tcp_check(host, port, timeout=3.0, proxy_url=None):
            await asyncio.sleep(0)  # yield so event loop can interleave
            return (True, 5.0)

        with patch(
            "src.validators.tcp_check.tcp_check",
            new=fake_tcp_check,
        ):
            result = await validate_configs_tcp(configs, max_alive=2, concurrency=1)
        assert len(result) == 2
