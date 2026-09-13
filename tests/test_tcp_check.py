"""Tests for src/validators/tcp_check.py — 100% coverage."""

from __future__ import annotations

import asyncio
import contextlib
import socket
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.parsers.base import Config
from src.validators import address_guard
from src.validators.tcp_check import (
    _open_connection_direct,
    tcp_check,
    validate_configs_tcp,
)


@pytest.fixture(autouse=True)
def _no_real_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Resolve every hostname to a public IP so no test touches real DNS."""

    async def _resolve(host: str, *, timeout: float = 5.0) -> list[str]:
        return ["93.184.216.34"]

    monkeypatch.setattr(address_guard, "resolve_host_addresses", _resolve)


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

        with (
            patch(
                "python_socks.async_.asyncio.Proxy.from_url",
                return_value=mock_proxy_instance,
            ),
            patch(
                "src.validators.tcp_check.asyncio.open_connection",
                new=AsyncMock(return_value=(mock_reader, mock_writer)),
            ) as mock_open,
        ):
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
        assert isinstance(latency, float)
        assert latency >= 0

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

    @pytest.mark.asyncio
    async def test_latency_measures_only_the_successful_attempt(self) -> None:
        """A dead first pinned address must not inflate the recorded latency.

        The clock used to start once before the pinned loop, so a AAAA that
        ate its full timeout before a fast A4 connected reported ~timeout+epsilon
        and dropped live servers in the quality stage.
        """
        attempts: list[str] = []

        async def fake_direct(host: str, port: int):
            attempts.append(host)
            if host == "2606:4700:4700::1111":
                await asyncio.sleep(0.2)  # the dead answer burns its timeout
                raise TimeoutError("unroutable aaaa")
            return MagicMock(), MagicMock()

        with (
            patch.object(
                address_guard,
                "resolve_host_addresses",
                AsyncMock(return_value=["2606:4700:4700::1111", "93.184.216.34"]),
            ),
            patch(
                "src.validators.tcp_check._open_connection_direct",
                new=fake_direct,
            ),
        ):
            is_alive, latency = await tcp_check("dual.example", 443)
        assert is_alive is True
        assert attempts == ["2606:4700:4700::1111", "93.184.216.34"]
        assert latency is not None
        # Only the successful (second) attempt is measured; the ~200 ms spent
        # on the failed AAAA must not appear in the result.
        assert latency < 150.0


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
    async def test_proxy_baseline_subtracted_from_latency(self) -> None:
        """Recorded latency describes the server, not the proxy's dial hop.

        Without the subtraction a fast server behind a congested free proxy
        was ranked slow (and bounced out of the subscription) on proxy noise.
        """
        configs = [Config("vless", "fast.example", 443, "uuid")]

        with patch(
            "src.validators.tcp_check.tcp_check",
            new=AsyncMock(return_value=(True, 3000.0)),
        ):
            result = await validate_configs_tcp(
                configs,
                proxy_urls=["socks5://proxy:1080"],
                proxy_latency_ms={"socks5://proxy:1080": 2900.0},
            )
        assert len(result) == 1
        # 3000ms measured through the proxy minus its 2900ms dial baseline.
        assert result[0].latency_ms == 100.0

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

        async def fake_tcp_check(
            host, port, timeout=3.0, proxy_url=None, resolve_timeout=5.0, **_kw
        ):
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

        async def fake_tcp_check(
            host, port, timeout=3.0, proxy_url=None, resolve_timeout=5.0, **_kw
        ):
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

        async def fake_tcp_check(
            host, port, timeout=3.0, proxy_url=None, resolve_timeout=5.0, **_kw
        ):
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
        async def fake_tcp_check(
            host, port, timeout=3.0, proxy_url=None, resolve_timeout=5.0, **_kw
        ):
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

        async def fake_tcp_check(
            host, port, timeout=3.0, proxy_url=None, resolve_timeout=5.0, **_kw
        ):
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

        async def fake_tcp_check(
            host, port, timeout=3.0, proxy_url=None, resolve_timeout=5.0, **_kw
        ):
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
    async def test_private_literal_never_reaches_open_connection(self) -> None:
        """SSRF guard: internal literals are dropped before any connect."""
        configs = [
            Config("vless", "10.0.0.5", 22, "uuid"),
            Config("vless", "127.0.0.1", 5432, "uuid"),
            Config("vless", "169.254.169.254", 80, "uuid"),
            Config("vless", "[::1]", 443, "uuid"),
        ]

        with patch(
            "src.validators.tcp_check.asyncio.open_connection",
            new=AsyncMock(return_value=(MagicMock(), MagicMock())),
        ) as mock_open:
            result = await validate_configs_tcp(configs)
        assert result == []
        mock_open.assert_not_called()

    @pytest.mark.asyncio
    async def test_public_literal_reaches_open_connection(self) -> None:
        """A public literal is checked normally."""
        cfg = Config("vless", "93.184.216.34", 443, "uuid")
        mock_writer = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch(
            "src.validators.tcp_check.asyncio.open_connection",
            new=AsyncMock(return_value=(MagicMock(), mock_writer)),
        ) as mock_open:
            result = await validate_configs_tcp([cfg])
        assert result == [cfg]
        mock_open.assert_called_once_with("93.184.216.34", 443)

    @pytest.mark.asyncio
    async def test_hostname_resolving_to_private_is_dropped(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A hostname pointing into internal space is dropped, without connect."""

        async def _resolve(host: str, *, timeout: float = 5.0) -> list[str]:
            return ["10.0.0.1"]  # the name resolves, but only into RFC 1918

        monkeypatch.setattr(address_guard, "resolve_host_addresses", _resolve)
        cfg = Config("vless", "internal.example", 443, "uuid")

        with patch(
            "src.validators.tcp_check.asyncio.open_connection",
            new=AsyncMock(return_value=(MagicMock(), MagicMock())),
        ) as mock_open:
            result = await validate_configs_tcp([cfg])
        assert result == []
        mock_open.assert_not_called()

    @pytest.mark.asyncio
    async def test_unresolvable_hostname_is_dropped(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Fail-closed: an unresolvable hostname never reaches a socket."""

        async def _resolve(host: str, *, timeout: float = 5.0) -> list[str] | None:
            return None  # resolver down / NXDOMAIN

        monkeypatch.setattr(address_guard, "resolve_host_addresses", _resolve)
        cfg = Config("vless", "offline.example", 443, "uuid")

        with patch(
            "src.validators.tcp_check.tcp_check",
            new=AsyncMock(return_value=(True, 5.0)),
        ) as mock_open:
            result = await validate_configs_tcp([cfg])
        assert result == []
        mock_open.assert_not_called()

    @pytest.mark.asyncio
    async def test_tcp_check_refuses_private_literal_without_dns(self) -> None:
        """The low-level check is a second line of defence."""
        with patch(
            "src.validators.tcp_check._open_connection_direct",
            new=AsyncMock(return_value=(MagicMock(), MagicMock())),
        ) as mock_open:
            is_alive, latency = await tcp_check("192.168.1.1", 8080)
        assert (is_alive, latency) == (False, None)
        mock_open.assert_not_called()

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

        async def fake_tcp_check(
            host, port, timeout=3.0, proxy_url=None, resolve_timeout=5.0, **_kw
        ):
            await asyncio.sleep(0)  # yield so event loop can interleave
            return (True, 5.0)

        with patch(
            "src.validators.tcp_check.tcp_check",
            new=fake_tcp_check,
        ):
            result = await validate_configs_tcp(configs, max_alive=2, concurrency=1)
        assert len(result) == 2

    @pytest.mark.asyncio
    async def test_tcp_check_exception_marks_config_dead(self, caplog) -> None:
        """An unexpected exception marks the config dead and logs it.

        gather(return_exceptions=True) used to eat the exception, leaving the
        config with neither a verdict nor a log line.
        """
        import logging

        configs = [Config("vless", "boom.example", 443, "uuid")]
        caplog.set_level(logging.ERROR)

        with patch(
            "src.validators.tcp_check.tcp_check",
            new=AsyncMock(side_effect=RuntimeError("unexpected blow-up")),
        ):
            result = await validate_configs_tcp(configs)
        assert result == []
        assert configs[0].is_alive is False
        assert configs[0].latency_ms is None
        assert "failed unexpectedly" in caplog.text
        assert "boom.example" in caplog.text

    @pytest.mark.asyncio
    async def test_tcp_check_exception_then_alive_config_survives(self) -> None:
        """A raising config must not poison the rest of the batch."""
        configs = [
            Config("vless", "boom.example", 443, "uuid"),
            Config("vless", "fine.example", 443, "uuid"),
        ]

        async def fake_tcp_check(
            host, port, timeout=3.0, proxy_url=None, resolve_timeout=5.0, **_kw
        ):
            if host == "boom.example":
                raise RuntimeError("unexpected blow-up")
            return (True, 5.0)

        with patch(
            "src.validators.tcp_check.tcp_check",
            new=fake_tcp_check,
        ):
            result = await validate_configs_tcp(configs)
        assert [c.address for c in result] == ["fine.example"]
        assert configs[0].is_alive is False
        assert configs[0].latency_ms is None
        assert configs[1].is_alive is True

    @pytest.mark.asyncio
    async def test_tcp_check_cancelled_error_not_swallowed(self) -> None:
        """CancelledError is re-raised by _check_one, not turned into a verdict."""
        configs = [Config("vless", "slow.example", 443, "uuid")]

        with patch(
            "src.validators.tcp_check.tcp_check",
            new=AsyncMock(side_effect=asyncio.CancelledError()),
        ):
            result = await validate_configs_tcp(configs)
        assert result == []
        # No verdict was recorded: the exception short-circuited the check.
        assert configs[0].is_alive is None
        assert configs[0].latency_ms is None

    @pytest.mark.asyncio
    async def test_max_alive_overshoot_is_trimmed(self) -> None:
        """Racing tasks past the stop-event check overshoot; list is trimmed."""
        configs = [
            Config("vless", f"host-{i}.example", 443 + i, "uuid") for i in range(4)
        ]

        async def fake_tcp_check(
            host, port, timeout=3.0, proxy_url=None, resolve_timeout=5.0, **_kw
        ):
            await asyncio.sleep(0)  # everyone reaches the alive-append
            return (True, 5.0)

        with patch(
            "src.validators.tcp_check.tcp_check",
            new=fake_tcp_check,
        ):
            result = await validate_configs_tcp(configs, max_alive=2, concurrency=4)
        assert len(result) == 2

    @pytest.mark.asyncio
    async def test_done_watcher_race_sets_event(self) -> None:
        """A completed watcher with the event unset still sets the event
        (the post-wait guard), then the watcher is reaped."""
        configs = [
            Config("vless", f"host-{i}.example", 443 + i, "uuid") for i in range(2)
        ]

        async def fake_tcp_check(
            host, port, timeout=3.0, proxy_url=None, resolve_timeout=5.0, **_kw
        ):
            return (True, 5.0)

        async def racy_wait(fs, *, return_when=None):
            gather_task, done_task = fs
            await gather_task
            done_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await done_task
            return ({done_task}, set())

        with (
            patch(
                "src.validators.tcp_check.tcp_check",
                new=fake_tcp_check,
            ),
            patch("src.validators.tcp_check.asyncio.wait", new=racy_wait),
        ):
            result = await validate_configs_tcp(configs, max_alive=5)
        assert len(result) == 2


@pytest.mark.asyncio
async def test_tcp_check_connects_to_pinned_ip_not_hostname() -> None:
    """The socket target is the resolved literal — DNS rebinding is closed."""
    captured: dict[str, object] = {}

    async def fake_direct(host: str, port: int) -> tuple[MagicMock, MagicMock]:
        captured["host"] = host
        return MagicMock(), MagicMock()

    with (
        patch.object(
            address_guard,
            "resolve_host_addresses",
            AsyncMock(return_value=["9.9.9.9"]),
        ),
        patch(
            "src.validators.tcp_check._open_connection_direct",
            new=fake_direct,
        ),
    ):
        is_alive, _latency = await tcp_check("example.com", 443)
    assert is_alive is True
    assert captured["host"] == "9.9.9.9"


@pytest.mark.asyncio
async def test_tcp_check_unpinnable_host_is_dead() -> None:
    """A hostname that cannot be pinned is no verdict (not dead, no ban)."""
    opener = AsyncMock()
    with (
        patch.object(
            address_guard,
            "resolve_host_addresses",
            AsyncMock(return_value=None),
        ),
        patch(
            "src.validators.tcp_check._open_connection_direct",
            new=opener,
        ),
    ):
        is_alive, latency = await tcp_check("example.com", 443)
    assert is_alive is None
    assert latency is None
    opener.assert_not_awaited()


@pytest.mark.asyncio
async def test_refusals_aggregate_into_one_summary(caplog) -> None:
    """Refused addresses count per stage; one INFO line, details at DEBUG."""
    import logging

    from src.validators import tcp_check as tcp_check_module

    # Module-level counters leak across direct tcp_check() calls in other
    # tests; this test counts only its own three refusals.
    tcp_check_module.reset_refusal_counters()
    caplog.set_level(logging.DEBUG)
    opener = AsyncMock()
    with (
        patch.object(
            address_guard,
            "resolve_host_addresses",
            AsyncMock(return_value=None),
        ),
        patch(
            "src.validators.tcp_check._open_connection_direct",
            new=opener,
        ),
    ):
        for i in range(3):
            await tcp_check(f"unpinnable-{i}.example", 443)
    # DEBUG carries per-address detail; WARNING must stay silent (the old
    # behavior logged thousands of these per run).
    assert caplog.text.count("unpinnable-") == 3
    refusal_records = [r for r in caplog.records if "Refusing" in r.getMessage()]
    assert refusal_records and all(r.levelno < logging.WARNING for r in refusal_records)

    tcp_check_module.log_refusal_summary()
    summary_records = [
        r for r in caplog.records if "TCP stage refused" in r.getMessage()
    ]
    assert len(summary_records) == 1
    assert "unpinnable: 3" in summary_records[0].getMessage()
    # Counters reset: a second summary is silent.
    tcp_check_module.log_refusal_summary()
    assert (
        len([r for r in caplog.records if "TCP stage refused" in r.getMessage()]) == 1
    )


# ===========================================================================
# pin_address=False: check_hostnames=false skips DNS entirely
# ===========================================================================


class TestTcpCheckPinAddressFalse:
    @pytest.mark.asyncio
    async def test_pin_address_false_dials_the_hostname(self) -> None:
        """pin_address=False must not resolve or pin: dial the name as-is."""
        opener = AsyncMock(
            return_value=(MagicMock(), MagicMock(wait_closed=AsyncMock()))
        )
        with (
            patch(
                "src.validators.tcp_check.resolve_pinned_addresses",
                new=AsyncMock(side_effect=AssertionError("DNS pin must not run")),
            ),
            patch("src.validators.tcp_check._open_connection_direct", new=opener),
        ):
            alive, latency = await tcp_check("host.example", 443, pin_address=False)
        assert alive is True
        assert latency is not None
        opener.assert_awaited_once_with("host.example", 443)

    @pytest.mark.asyncio
    async def test_validate_configs_tcp_threads_check_hostnames(self) -> None:
        """check_hostnames reaches tcp_check as pin_address."""
        cfg = Config("vless", "host.example", 443, "uuid")
        probe = AsyncMock(return_value=(True, 1.0))
        with (
            patch("src.validators.tcp_check.tcp_check", new=probe),
            patch(
                "src.validators.tcp_check.filter_public_configs",
                new=AsyncMock(return_value=[cfg]),
            ),
        ):
            await validate_configs_tcp([cfg], check_hostnames=False)
            assert probe.await_args.kwargs["pin_address"] is False
            await validate_configs_tcp([cfg], check_hostnames=True)
            assert probe.await_args.kwargs["pin_address"] is True
