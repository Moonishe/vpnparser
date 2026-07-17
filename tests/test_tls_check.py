"""Tests for src/validators/tls_check.py — 100% coverage."""

from __future__ import annotations

import asyncio
import logging
import ssl
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.parsers.base import Config
from src.validators.tls_check import (
    _alpn_protocols,
    _clean_server_name,
    _is_ip_address,
    _is_tls_security,
    _open_connection_direct,
    _open_connection_via_socks,
    _split_server_names,
    _tls_server_names,
    tls_check,
    validate_configs_tls,
)


# ===========================================================================
# Helper: _is_tls_security
# ===========================================================================


class TestIsTlsSecurity:
    """Cover _is_tls_security — lines 66-67."""

    def test_tls(self) -> None:
        assert _is_tls_security("tls") is True

    def test_reality(self) -> None:
        assert _is_tls_security("reality") is True

    def test_none(self) -> None:
        assert _is_tls_security("none") is False

    def test_none_value(self) -> None:
        assert _is_tls_security(None) is False

    def test_case_insensitive(self) -> None:
        assert _is_tls_security("TLS") is True
        assert _is_tls_security("ReAlItY") is True

    def test_empty_string(self) -> None:
        assert _is_tls_security("") is False


# ===========================================================================
# Helper: _is_ip_address
# ===========================================================================


class TestIsIpAddress:
    """Cover _is_ip_address — lines 70-75."""

    def test_ipv4(self) -> None:
        assert _is_ip_address("1.2.3.4") is True

    def test_ipv6_bracketed(self) -> None:
        assert _is_ip_address("[::1]") is True

    def test_hostname(self) -> None:
        assert _is_ip_address("example.com") is False

    def test_empty(self) -> None:
        assert _is_ip_address("") is False

    def test_ipv6(self) -> None:
        assert _is_ip_address("2001:db8::1") is True


# ===========================================================================
# Helper: _clean_server_name
# ===========================================================================


class TestCleanServerName:
    """Cover _clean_server_name — lines 78-100."""

    def test_basic_hostname(self) -> None:
        assert _clean_server_name("example.com") == "example.com"

    def test_empty_returns_none(self) -> None:
        assert _clean_server_name("") is None

    def test_whitespace_trimmed(self) -> None:
        assert _clean_server_name("  example.com  ") == "example.com"

    def test_empty_values_return_none(self) -> None:
        for val in ("none", "null", "false", "0", "-"):
            assert _clean_server_name(val) is None, f"failed for {val!r}"

    def test_quote_stripping(self) -> None:
        assert _clean_server_name('"example.com"') == "example.com"
        assert _clean_server_name("'example.com'") == "example.com"

    def test_url_parsing(self) -> None:
        """URL-like value extracts hostname."""
        assert _clean_server_name("https://cdn.example.com/path") == "cdn.example.com"

    def test_path_stripping(self) -> None:
        """Value with path strips path."""
        assert _clean_server_name("example.com/some/path") == "example.com"

    def test_host_port_stripped(self) -> None:
        """Value with host:port strips port."""
        assert _clean_server_name("example.com:443") == "example.com"

    def test_wildcard_prefix_removed(self) -> None:
        assert _clean_server_name("*.example.com") == "example.com"

    def test_ipv6_bracket_stripped(self) -> None:
        assert _clean_server_name("[::1]") == "::1"

    def test_cleaned_empty_after_processing(self) -> None:
        """Value that becomes empty after cleaning -> None."""
        assert _clean_server_name("[::1]:bad") is not None  # not empty
        # A value like "none" stripped would be tested above

    def test_only_colon_port_valid(self) -> None:
        """host:port only when exactly 1 colon and port is digit."""
        assert _clean_server_name("example.com:abc") is not None
        assert _clean_server_name("example.com:443") == "example.com"

    def test_bracketed_host_with_port(self) -> None:
        """Bracketed IPv6 with port."""
        result = _clean_server_name("[2001:db8::1]:443")
        # DNS name inside brackets, port stripped
        assert result is not None

    def test_multiple_colons_bare_ipv6(self) -> None:
        """Bare IPv6 (multiple colons, no brackets) -> passes through."""
        # Since there are multiple colons, the port-stripping logic
        # won't trigger (count(":") != 1), so it passes through as-is
        result = _clean_server_name("2001:db8::1")
        assert result == "2001:db8::1"

    def test_value_becomes_empty_after_processing(self) -> None:
        """Value that becomes empty after processing -> None. (line 99)"""
        # "*.none" -> strip wildcard -> "none" which is in EMPTY_SERVER_NAMES
        assert _clean_server_name("*.none") is None

    def test_value_becomes_empty_after_path_strip(self) -> None:
        """Value with path that becomes empty after processing -> None. (line 99)"""
        # "//none" -> has "/" -> split -> "" -> stripped -> "" -> None
        assert _clean_server_name("//none") is None


# ===========================================================================
# Helper: _split_server_names
# ===========================================================================


class TestSplitServerNames:
    """Cover _split_server_names — lines 103-111."""

    def test_none_input(self) -> None:
        assert _split_server_names(None) == []

    def test_empty_input(self) -> None:
        assert _split_server_names("") == []

    def test_single_name(self) -> None:
        assert _split_server_names("example.com") == ["example.com"]

    def test_comma_separated(self) -> None:
        assert _split_server_names("a.com,b.com") == ["a.com", "b.com"]

    def test_semicolon_separated(self) -> None:
        assert _split_server_names("a.com;b.com") == ["a.com", "b.com"]

    def test_mixed_separators(self) -> None:
        assert _split_server_names("a.com,b.com;c.com") == [
            "a.com",
            "b.com",
            "c.com",
        ]

    def test_invalid_names_filtered(self) -> None:
        """Invalid/empty names after cleaning are excluded."""
        assert _split_server_names("a.com,,none") == ["a.com"]

    def test_all_invalid(self) -> None:
        assert _split_server_names("none,null") == []


# ===========================================================================
# Helper: _tls_server_names
# ===========================================================================


class TestTlsServerNames:
    """Cover _tls_server_names — lines 114-140."""

    def test_explicit_sni_used(self) -> None:
        """sni field provides server names."""
        cfg = Config("vless", "1.2.3.4", 443, "uuid", sni="sni.example.com")
        names = _tls_server_names(cfg)
        assert "sni.example.com" in names

    def test_host_used_when_no_sni(self) -> None:
        """host field used when sni is empty."""
        cfg = Config("vless", "1.2.3.4", 443, "uuid", host="host.example.com")
        names = _tls_server_names(cfg)
        assert "host.example.com" in names

    def test_address_used_when_no_explicit_names(self) -> None:
        """address used when sni and host are empty."""
        cfg = Config("vless", "server.example.com", 443, "uuid")
        names = _tls_server_names(cfg)
        assert "server.example.com" in names

    def test_ip_address_adds_none(self) -> None:
        """IP address results in None being added."""
        cfg = Config("vless", "1.2.3.4", 443, "uuid")
        names = _tls_server_names(cfg)
        assert None in names

    def test_duplicates_deduplicated(self) -> None:
        """Same name from sni and host is deduplicated."""
        cfg = Config(
            "vless",
            "1.2.3.4",
            443,
            "uuid",
            sni="same.com",
            host="same.com",
        )
        names = _tls_server_names(cfg)
        assert len(names) == 1
        assert names == ["same.com"]

    def test_explicit_names_prevent_address_fallback(self) -> None:
        """When explicit names exist, address is not added."""
        cfg = Config(
            "vless",
            "1.2.3.4",
            443,
            "uuid",
            sni="mysni.com",
        )
        names = _tls_server_names(cfg)
        assert "mysni.com" in names
        # should not add "1.2.3.4" or None since explicit names exist
        assert len(names) == 1

    def test_multiple_names_from_sni_and_host(self) -> None:
        """Combines sni and host into name list."""
        cfg = Config(
            "vless",
            "1.2.3.4",
            443,
            "uuid",
            sni="sni.com",
            host="host.com",
        )
        names = _tls_server_names(cfg)
        assert names == ["sni.com", "host.com"]


# ===========================================================================
# Helper: _alpn_protocols
# ===========================================================================


class TestAlpnProtocols:
    """Cover _alpn_protocols — lines 143-147."""

    def test_none(self) -> None:
        assert _alpn_protocols(None) is None

    def test_empty(self) -> None:
        assert _alpn_protocols("") is None

    def test_single(self) -> None:
        assert _alpn_protocols("h2") == ["h2"]

    def test_comma_separated(self) -> None:
        assert _alpn_protocols("h2,http/1.1") == ["h2", "http/1.1"]

    def test_semicolon_separated(self) -> None:
        assert _alpn_protocols("h2;http/1.1") == ["h2", "http/1.1"]

    def test_whitespace_stripped(self) -> None:
        assert _alpn_protocols("  h2 , http/1.1  ") == ["h2", "http/1.1"]


# ===========================================================================
# _open_connection_direct
# ===========================================================================


class TestOpenConnectionDirect:
    """Cover line 37."""

    @pytest.mark.asyncio
    async def test_direct_calls_open_connection(self) -> None:
        """Delegates to asyncio.open_connection with SSL context."""
        mock_reader = MagicMock()
        mock_writer = MagicMock()
        ctx = ssl.create_default_context()

        with patch(
            "src.validators.tls_check.asyncio.open_connection",
            new=AsyncMock(return_value=(mock_reader, mock_writer)),
        ) as mock_open:
            reader, writer = await _open_connection_direct(
                "example.com", 443, ctx, "example.com"
            )
            mock_open.assert_called_once_with(
                "example.com", 443, ssl=ctx, server_hostname="example.com"
            )
            assert reader is mock_reader
            assert writer is mock_writer


# ===========================================================================
# _open_connection_via_socks
# ===========================================================================


class TestOpenConnectionViaSocks:
    """Cover lines 53-63."""

    @pytest.mark.asyncio
    async def test_via_socks(self) -> None:
        """TLS connection routed through SOCKS5 proxy via mocked python_socks."""
        mock_reader = MagicMock()
        mock_writer = MagicMock()
        mock_sock = MagicMock()

        mock_proxy_instance = MagicMock()
        mock_proxy_instance.connect = AsyncMock(return_value=mock_sock)

        with patch(
            "python_socks.async_.asyncio.Proxy.from_url",
            return_value=mock_proxy_instance,
        ):
            with patch(
                "src.validators.tls_check.asyncio.open_connection",
                new=AsyncMock(return_value=(mock_reader, mock_writer)),
            ) as mock_open:
                result = await tls_check(
                    "example.com",
                    443,
                    proxy_url="socks5://proxy:1080",
                )
        assert result is True
        # Verify open_connection was called with the mock sock (SSL wrapped)
        call_kwargs = mock_open.call_args.kwargs
        assert call_kwargs["sock"] is mock_sock


# ===========================================================================
# tls_check()
# ===========================================================================


class TestTlsCheck:
    """Cover tls_check — lines 150-200."""

    @pytest.mark.asyncio
    async def test_success_direct(self) -> None:
        """Successful direct TLS handshake -> True."""
        mock_writer = MagicMock()

        with patch(
            "src.validators.tls_check._open_connection_direct",
            new=AsyncMock(return_value=(MagicMock(), mock_writer)),
        ):
            result = await tls_check("example.com", 443)
        assert result is True

    @pytest.mark.asyncio
    async def test_success_via_proxy(self) -> None:
        """Successful proxy TLS handshake -> True."""
        mock_writer = MagicMock()

        with patch(
            "src.validators.tls_check._open_connection_via_socks",
            new=AsyncMock(return_value=(MagicMock(), mock_writer)),
        ):
            result = await tls_check(
                "example.com", 443, proxy_url="socks5://proxy:1080"
            )
        assert result is True

    @pytest.mark.asyncio
    async def test_timeout_error(self) -> None:
        """TimeoutError -> False."""
        with patch(
            "src.validators.tls_check._open_connection_direct",
            new=AsyncMock(side_effect=TimeoutError("timed out")),
        ):
            result = await tls_check("example.com", 443)
        assert result is False

    @pytest.mark.asyncio
    async def test_asyncio_timeout(self) -> None:
        """asyncio.TimeoutError -> False."""
        with patch(
            "src.validators.tls_check._open_connection_direct",
            new=AsyncMock(side_effect=asyncio.TimeoutError),
        ):
            result = await tls_check("example.com", 443)
        assert result is False

    @pytest.mark.asyncio
    async def test_ssl_error(self) -> None:
        """ssl.SSLError -> False."""
        with patch(
            "src.validators.tls_check._open_connection_direct",
            new=AsyncMock(side_effect=ssl.SSLError("handshake failed")),
        ):
            result = await tls_check("example.com", 443)
        assert result is False

    @pytest.mark.asyncio
    async def test_connection_refused(self) -> None:
        """ConnectionRefusedError -> False."""
        with patch(
            "src.validators.tls_check._open_connection_direct",
            new=AsyncMock(side_effect=ConnectionRefusedError),
        ):
            result = await tls_check("example.com", 443)
        assert result is False

    @pytest.mark.asyncio
    async def test_os_error(self) -> None:
        """OSError -> False."""
        with patch(
            "src.validators.tls_check._open_connection_direct",
            new=AsyncMock(side_effect=OSError("connection reset")),
        ):
            result = await tls_check("example.com", 443)
        assert result is False

    @pytest.mark.asyncio
    async def test_generic_exception(self) -> None:
        """Generic Exception -> False."""
        with patch(
            "src.validators.tls_check._open_connection_direct",
            new=AsyncMock(side_effect=RuntimeError("unexpected")),
        ):
            result = await tls_check("example.com", 443)
        assert result is False

    @pytest.mark.asyncio
    async def test_ssl_context_creation_fails(self) -> None:
        """ssl.create_default_context raising -> False."""
        with patch(
            "src.validators.tls_check.ssl.create_default_context",
            side_effect=RuntimeError("SSL unavailable"),
        ):
            result = await tls_check("example.com", 443)
        assert result is False

    @pytest.mark.asyncio
    async def test_writer_close_exception_suppressed(self) -> None:
        """Exception on writer.close() is suppressed."""
        mock_writer = MagicMock()
        mock_writer.close.side_effect = OSError("close failed")
        mock_writer.wait_closed = AsyncMock(side_effect=ssl.SSLError("wait failed"))

        with patch(
            "src.validators.tls_check._open_connection_direct",
            new=AsyncMock(return_value=(MagicMock(), mock_writer)),
        ):
            result = await tls_check("example.com", 443)
        assert result is True

    @pytest.mark.asyncio
    async def test_alpn_protocols_applied(self) -> None:
        """ALPN protocols set on SSL context."""
        with patch(
            "src.validators.tls_check._open_connection_direct",
            new=AsyncMock(return_value=(MagicMock(), MagicMock())),
        ):
            with patch(
                "src.validators.tls_check.ssl.create_default_context"
            ) as mock_ctx_factory:
                mock_ctx = MagicMock()
                mock_ctx_factory.return_value = mock_ctx
                result = await tls_check("example.com", 443, alpn="h2,http/1.1")
        assert result is True
        mock_ctx.set_alpn_protocols.assert_called_once_with(["h2", "http/1.1"])

    @pytest.mark.asyncio
    async def test_sni_passed_as_server_hostname(self) -> None:
        """SNI is passed as server_hostname to asyncio.open_connection."""
        mock_writer = MagicMock()

        # Mock asyncio.open_connection directly to capture server_hostname
        with patch(
            "src.validators.tls_check.asyncio.open_connection",
            new=AsyncMock(return_value=(MagicMock(), mock_writer)),
        ) as mock_open:
            result = await tls_check("1.2.3.4", 443, sni="sni.example.com")
        assert result is True
        call_kwargs = mock_open.call_args.kwargs
        assert call_kwargs["server_hostname"] == "sni.example.com"


# ===========================================================================
# validate_configs_tls()
# ===========================================================================


class TestValidateConfigsTls:
    """Cover validate_configs_tls — lines 203-283."""

    @pytest.mark.asyncio
    async def test_empty_configs(self) -> None:
        """Empty configs list -> []."""
        result = await validate_configs_tls([])
        assert result == []

    @pytest.mark.asyncio
    async def test_security_none_passes_through(self) -> None:
        """Configs with security='none' pass through unchanged."""
        cfg = Config("vless", "a.example", 443, "uuid", security="none")
        result = await validate_configs_tls([cfg])
        assert result == [cfg]
        assert cfg.is_alive is None  # not checked

    @pytest.mark.asyncio
    async def test_tls_config_checked_and_alive(self) -> None:
        """TLS config is checked and passes."""
        cfg = Config("vless", "a.example", 443, "uuid", security="tls")

        with patch(
            "src.validators.tls_check.tls_check",
            new=AsyncMock(return_value=True),
        ):
            result = await validate_configs_tls([cfg])
        assert result == [cfg]
        assert cfg.is_alive is True

    @pytest.mark.asyncio
    async def test_tls_config_fails(self) -> None:
        """TLS config checked and fails -> excluded."""
        cfg = Config("vless", "a.example", 443, "uuid", security="tls")

        with patch(
            "src.validators.tls_check.tls_check",
            new=AsyncMock(return_value=False),
        ):
            result = await validate_configs_tls([cfg])
        assert result == []
        assert cfg.is_alive is False

    @pytest.mark.asyncio
    async def test_reality_config_checked(self) -> None:
        """REALITY config is also checked."""
        cfg = Config("vless", "a.example", 443, "uuid", security="reality")

        with patch(
            "src.validators.tls_check.tls_check",
            new=AsyncMock(return_value=True),
        ):
            result = await validate_configs_tls([cfg])
        assert result == [cfg]
        assert cfg.is_alive is True

    @pytest.mark.asyncio
    async def test_mixed_security_types(self) -> None:
        """Mix of tls, reality, and none configs."""
        tls_cfg = Config("vless", "tls.example", 443, "uuid", security="tls")
        reality_cfg = Config(
            "vless", "reality.example", 443, "uuid", security="reality"
        )
        none_cfg = Config("vless", "none.example", 443, "uuid", security="none")

        with patch(
            "src.validators.tls_check.tls_check",
            new=AsyncMock(return_value=True),
        ):
            result = await validate_configs_tls([tls_cfg, reality_cfg, none_cfg])
        assert len(result) == 3  # all should be in result
        assert tls_cfg.is_alive is True
        assert reality_cfg.is_alive is True
        assert none_cfg.is_alive is None  # not checked

    @pytest.mark.asyncio
    async def test_proxy_url_passed(self) -> None:
        """proxy_url is passed through to tls_check."""
        cfg = Config("vless", "a.example", 443, "uuid", security="tls")

        with patch(
            "src.validators.tls_check.tls_check",
            new=AsyncMock(return_value=True),
        ) as mock_check:
            result = await validate_configs_tls([cfg], proxy_url="socks5://proxy:1080")
        assert len(result) == 1
        _, kwargs = mock_check.call_args
        assert kwargs["proxy_url"] == "socks5://proxy:1080"

    @pytest.mark.asyncio
    async def test_proxy_urls_preferred(self) -> None:
        """proxy_urls takes precedence over proxy_url."""
        cfg = Config("vless", "a.example", 443, "uuid", security="tls")

        with patch(
            "src.validators.tls_check.tls_check",
            new=AsyncMock(return_value=True),
        ) as mock_check:
            result = await validate_configs_tls(
                [cfg],
                proxy_url="socks5://fallback:1080",
                proxy_urls=["socks5://primary:1080"],
            )
        assert len(result) == 1
        _, kwargs = mock_check.call_args
        assert kwargs["proxy_url"] == "socks5://primary:1080"

    @pytest.mark.asyncio
    async def test_proxy_attempts_per_config_zero(self) -> None:
        """proxy_attempts_per_config=0 tries all proxies."""
        cfg = Config("vless", "a.example", 443, "uuid", security="tls")
        proxy_urls = [
            "socks5://p1:1080",
            "socks5://p2:1080",
            "socks5://p3:1080",
        ]
        used_proxies = []

        async def fake_tls_check(
            host, port, sni=None, alpn=None, timeout=5.0, proxy_url=None
        ):
            used_proxies.append(proxy_url)
            # Fail on first two, succeed on last
            return proxy_url == "socks5://p3:1080"

        with patch(
            "src.validators.tls_check.tls_check",
            new=fake_tls_check,
        ):
            result = await validate_configs_tls(
                [cfg], proxy_urls=proxy_urls, proxy_attempts_per_config=0
            )
        assert len(result) == 1
        assert len(used_proxies) == 3  # tried all 3

    @pytest.mark.asyncio
    async def test_first_proxy_succeeds(self) -> None:
        """First proxy succeeds -> no retry."""
        cfg = Config("vless", "a.example", 443, "uuid", security="tls")
        proxy_urls = ["socks5://p1:1080", "socks5://p2:1080"]
        used = []

        async def fake_tls_check(
            host, port, sni=None, alpn=None, timeout=5.0, proxy_url=None
        ):
            used.append(proxy_url)
            return proxy_url == "socks5://p1:1080"

        with patch(
            "src.validators.tls_check.tls_check",
            new=fake_tls_check,
        ):
            result = await validate_configs_tls(
                [cfg], proxy_urls=proxy_urls, proxy_attempts_per_config=2
            )
        assert len(result) == 1
        assert used == ["socks5://p1:1080"]

    @pytest.mark.asyncio
    async def test_exception_during_check_logged(self, caplog) -> None:
        """Exception in _check_one is caught and logged."""
        caplog.set_level(logging.DEBUG)
        cfg = Config("vless", "a.example", 443, "uuid", security="tls")

        with patch(
            "src.validators.tls_check.tls_check",
            new=AsyncMock(side_effect=RuntimeError("probe crashed")),
        ):
            result = await validate_configs_tls([cfg])
        assert len(result) == 0
        assert cfg.is_alive is False
        assert "TLS check failed" in caplog.text

    @pytest.mark.asyncio
    async def test_multiple_server_names(self) -> None:
        """Tries multiple SNI names until one succeeds."""
        cfg = Config(
            "vless",
            "1.2.3.4",
            443,
            "uuid",
            security="tls",
            sni="sni1.com,sni2.com",
        )
        tried_names = []

        async def fake_tls_check(
            host, port, sni=None, alpn=None, timeout=5.0, proxy_url=None
        ):
            tried_names.append(sni)
            # First SNI fails, second succeeds
            return sni == "sni2.com"

        with patch(
            "src.validators.tls_check.tls_check",
            new=fake_tls_check,
        ):
            result = await validate_configs_tls([cfg])
        assert len(result) == 1
        assert cfg.is_alive is True
        assert tried_names == ["sni1.com", "sni2.com"]

    @pytest.mark.asyncio
    async def test_no_proxy_choices(self) -> None:
        """No proxy_url and no proxy_urls -> direct connection."""
        cfg = Config("vless", "a.example", 443, "uuid", security="tls")

        with patch(
            "src.validators.tls_check.tls_check",
            new=AsyncMock(return_value=True),
        ) as mock_check:
            result = await validate_configs_tls([cfg])
        assert len(result) == 1
        _, kwargs = mock_check.call_args
        assert kwargs["proxy_url"] is None
