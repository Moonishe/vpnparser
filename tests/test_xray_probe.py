"""Tests for Xray probe validator — 100% coverage."""

from __future__ import annotations

import asyncio
import json
import os
import socket
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

import pytest

from src.parsers.base import Config
from src.validators.xray_probe import (
    _alpn,
    _extract_probe_ip,
    _first_csv,
    _free_local_port,
    _http_status_code,
    _https_probe_response,
    _https_probe_via_socks,
    _is_ip,
    _normalize_probe_urls,
    _proxy_outbound,
    _rotated_proxy_urls_for_config,
    _server_name,
    _stream_settings,
    _wait_for_port,
    build_xray_config,
    discover_public_ip,
    find_xray_executable,
    is_xray_supported,
    validate_configs_xray,
    xray_probe_check,
)

# ===================== _first_csv ======================


def test_first_csv_none() -> None:
    assert _first_csv(None) is None


def test_first_csv_empty() -> None:
    assert _first_csv("") is None


def test_first_csv_single() -> None:
    assert _first_csv("hello") == "hello"


def test_first_csv_comma() -> None:
    assert _first_csv("a, b, c") == "a"


def test_first_csv_semicolon() -> None:
    assert _first_csv("x; y; z") == "x"


def test_first_csv_quotes() -> None:
    assert _first_csv('"quoted"') == "quoted"
    assert _first_csv("'single'") == "single"


def test_first_csv_all_empty() -> None:
    assert _first_csv(" ; ") is None


def test_first_csv_mixed() -> None:
    assert _first_csv("a;b,c") == "a"


# ===================== _is_ip ======================


def test_is_ip_valid() -> None:
    assert _is_ip("8.8.8.8") is True
    assert _is_ip("::1") is True
    assert _is_ip("[::1]") is True


def test_is_ip_invalid() -> None:
    assert _is_ip("") is False
    assert _is_ip(None) is False
    assert _is_ip("notanip") is False


# ===================== _server_name ======================


def _make_cfg(**overrides: object) -> Config:
    defaults: dict[str, object] = dict(
        protocol="vless",
        address="1.2.3.4",
        port=443,
        uuid_or_password="uuid",
        network="tcp",
        security="none",
        sni=None,
        host=None,
        alpn=None,
        fp=None,
        pbk=None,
        sid=None,
        path=None,
        flow=None,
        ss_method=None,
    )
    defaults.update(overrides)
    return Config(**defaults)  # type: ignore[arg-type]


def test_server_name_from_sni() -> None:
    cfg = _make_cfg(sni="example.com", address="1.2.3.4")
    assert _server_name(cfg) == "example.com"


def test_server_name_from_host() -> None:
    cfg = _make_cfg(sni="1.2.3.4", host="host.example.com", address="10.0.0.1")
    assert _server_name(cfg) == "host.example.com"


def test_server_name_from_address() -> None:
    cfg = _make_cfg(sni=None, host=None, address="server.example.com")
    assert _server_name(cfg) == "server.example.com"


def test_server_name_all_ips() -> None:
    cfg = _make_cfg(sni="8.8.8.8", address="1.2.3.4")
    assert _server_name(cfg) is None


# ===================== _alpn ======================


def test_alpn_none() -> None:
    assert _alpn(None) is None


def test_alpn_empty() -> None:
    assert _alpn("") is None


def test_alpn_single() -> None:
    assert _alpn("h2") == ["h2"]


def test_alpn_multiple() -> None:
    assert _alpn("h2, http/1.1") == ["h2", "http/1.1"]


def test_alpn_semicolon() -> None:
    assert _alpn("h2;http/1.1") == ["h2", "http/1.1"]


# ===================== _stream_settings ======================


def test_stream_settings_basic_tcp() -> None:
    cfg = _make_cfg(network="tcp", security="none")
    result = _stream_settings(cfg)
    assert result == {"network": "tcp"}


def test_stream_settings_unsupported_network() -> None:
    cfg = _make_cfg(network="quic", security="none")
    assert _stream_settings(cfg) is None


def test_stream_settings_ws() -> None:
    cfg = _make_cfg(network="ws", security="none", path="/ws", host="example.com")
    result = _stream_settings(cfg)
    assert result is not None
    assert result["network"] == "ws"
    assert result["wsSettings"]["path"] == "/ws"
    assert result["wsSettings"]["headers"]["Host"] == "example.com"


def test_stream_settings_ws_no_path() -> None:
    cfg = _make_cfg(network="ws", security="none", path=None, host=None)
    result = _stream_settings(cfg)
    assert result is not None
    assert result["network"] == "ws"
    assert "wsSettings" in result


def test_stream_settings_grpc() -> None:
    cfg = _make_cfg(
        network="grpc", security="none", path="/service", host="auth.example.com"
    )
    result = _stream_settings(cfg)
    assert result is not None
    assert result["network"] == "grpc"
    assert result["grpcSettings"]["serviceName"] == "service"
    assert result["grpcSettings"]["authority"] == "auth.example.com"


def test_stream_settings_reality() -> None:
    cfg = _make_cfg(
        network="tcp",
        security="reality",
        pbk="pubkey123",
        fp="firefox",
        sni="real.example.com",
        sid="abc",
    )
    result = _stream_settings(cfg)
    assert result is not None
    assert result["security"] == "reality"
    assert result["realitySettings"]["publicKey"] == "pubkey123"
    assert result["realitySettings"]["fingerprint"] == "firefox"
    assert result["realitySettings"]["serverName"] == "real.example.com"
    assert result["realitySettings"]["shortId"] == "abc"


def test_stream_settings_reality_no_pbk() -> None:
    cfg = _make_cfg(network="tcp", security="reality", pbk=None)
    assert _stream_settings(cfg) is None


def test_stream_settings_tls() -> None:
    cfg = _make_cfg(
        network="tcp",
        security="tls",
        sni="tls.example.com",
        fp="chrome",
        alpn="h2,http/1.1",
    )
    result = _stream_settings(cfg)
    assert result is not None
    assert result["security"] == "tls"
    assert result["tlsSettings"]["serverName"] == "tls.example.com"
    assert result["tlsSettings"]["fingerprint"] == "chrome"
    assert result["tlsSettings"]["alpn"] == ["h2", "http/1.1"]


def test_stream_settings_tls_no_sni() -> None:
    cfg = _make_cfg(network="tcp", security="tls", sni=None, fp=None, alpn=None)
    result = _stream_settings(cfg)
    assert result is not None
    assert result["security"] == "tls"
    assert "serverName" not in result["tlsSettings"]


def test_stream_settings_unknown_security() -> None:
    cfg = _make_cfg(network="tcp", security="xtls")
    assert _stream_settings(cfg) is None


# ===================== _proxy_outbound ======================


def test_proxy_outbound_socks5() -> None:
    r = _proxy_outbound("socks5://user:pass@1.2.3.4:1080")
    assert r is not None and r["protocol"] == "socks"
    assert r["settings"]["servers"][0]["address"] == "1.2.3.4"


def test_proxy_outbound_no_auth() -> None:
    r = _proxy_outbound("socks5://1.2.3.4:1080")
    assert r is not None and "users" not in r["settings"]["servers"][0]


def test_proxy_outbound_http() -> None:
    r = _proxy_outbound("http://1.2.3.4:8080")
    assert r is not None and r["protocol"] == "http"


def test_proxy_outbound_default_port_socks() -> None:
    r = _proxy_outbound("socks5://1.2.3.4")
    assert r is not None and r["settings"]["servers"][0]["port"] == 1080


def test_proxy_outbound_default_port_http() -> None:
    r = _proxy_outbound("http://1.2.3.4")
    assert r is not None and r["settings"]["servers"][0]["port"] == 8080


def test_proxy_outbound_unsupported() -> None:
    assert _proxy_outbound("https://1.2.3.4") is None
    assert _proxy_outbound("socks5://") is None


# ===================== build_xray_config ======================


@pytest.fixture
def cfg_vless() -> Config:
    return _make_cfg(
        protocol="vless",
        address="1.2.3.4",
        port=443,
        uuid_or_password="11111111-1111-4111-8111-111111111111",
        network="tcp",
        security="none",
    )


def test_build_xray_config_vless(cfg_vless: Config) -> None:
    r = build_xray_config(cfg_vless, socks_port=10800)
    assert r is not None
    assert r["outbounds"][0]["protocol"] == "vless"
    assert r["inbounds"][0]["port"] == 10800


def test_build_xray_config_vless_with_flow(cfg_vless: Config) -> None:
    cfg_vless.flow = "xtls-rprx-vision"
    r = build_xray_config(cfg_vless, socks_port=10800)
    assert r is not None
    assert (
        r["outbounds"][0]["settings"]["vnext"][0]["users"][0]["flow"]
        == "xtls-rprx-vision"
    )


def test_build_xray_config_trojan() -> None:
    cfg = _make_cfg(
        protocol="trojan",
        address="5.6.7.8",
        port=443,
        uuid_or_password="mypass",
        network="tcp",
        security="tls",
    )
    r = build_xray_config(cfg, socks_port=10800)
    assert r is not None and r["outbounds"][0]["protocol"] == "trojan"
    assert r["outbounds"][0]["settings"]["servers"][0]["password"] == "mypass"


def test_build_xray_config_vmess() -> None:
    cfg = _make_cfg(
        protocol="vmess",
        address="9.10.11.12",
        port=443,
        uuid_or_password="11111111-1111-4111-8111-111111111111",
    )
    r = build_xray_config(cfg, socks_port=10800)
    assert r is not None and r["outbounds"][0]["protocol"] == "vmess"
    assert r["outbounds"][0]["settings"]["vnext"][0]["users"][0]["security"] == "auto"


def test_build_xray_config_ss() -> None:
    cfg = _make_cfg(
        protocol="ss",
        address="1.2.3.4",
        port=8443,
        uuid_or_password="mypass",
        ss_method="aes-256-gcm",
    )
    r = build_xray_config(cfg, socks_port=10800)
    assert r is not None and r["outbounds"][0]["protocol"] == "ss"
    assert r["outbounds"][0]["settings"]["servers"][0]["method"] == "aes-256-gcm"


def test_build_xray_config_ss_no_method() -> None:
    cfg = _make_cfg(
        protocol="ss",
        address="1.2.3.4",
        port=8443,
        uuid_or_password="mypass",
        ss_method=None,
    )
    assert build_xray_config(cfg, socks_port=10800) is None


def test_build_xray_config_unsupported_protocol(cfg_vless: Config) -> None:
    cfg_vless.protocol = "unknown"
    assert build_xray_config(cfg_vless, socks_port=10800) is None


def test_build_xray_config_no_stream(cfg_vless: Config) -> None:
    cfg_vless.network = "quic"
    assert build_xray_config(cfg_vless, socks_port=10800) is None


def test_build_xray_config_with_dial_proxy(cfg_vless: Config) -> None:
    r = build_xray_config(
        cfg_vless, socks_port=10800, dial_proxy_url="socks5://10.0.0.1:1080"
    )
    assert r is not None and len(r["outbounds"]) == 2
    assert r["outbounds"][0]["proxySettings"]["tag"] == "dial-proxy"


def test_build_xray_config_bad_proxy(cfg_vless: Config) -> None:
    assert (
        build_xray_config(cfg_vless, socks_port=10800, dial_proxy_url="https://bad")
        is None
    )


# ===================== is_xray_supported ======================


def test_is_xray_supported_true(cfg_vless: Config) -> None:
    assert is_xray_supported(cfg_vless) is True


def test_is_xray_supported_false() -> None:
    cfg = _make_cfg(protocol="unknown")
    assert is_xray_supported(cfg) is False


# ===================== find_xray_executable ======================


def test_find_xray_explicit(monkeypatch) -> None:
    monkeypatch.setattr(Path, "exists", lambda self: True)
    r = find_xray_executable(explicit_path="/usr/local/bin/xray")
    assert r is not None and "xray" in r


def test_find_xray_from_env(monkeypatch) -> None:
    monkeypatch.setattr(Path, "exists", lambda self: True)
    monkeypatch.setenv("XRAY_EXECUTABLE", "/env/bin/xray")
    assert find_xray_executable() is not None


def test_find_xray_from_path(monkeypatch) -> None:
    monkeypatch.setattr(Path, "exists", lambda self: True)
    monkeypatch.delenv("XRAY_EXECUTABLE", raising=False)
    monkeypatch.setattr(
        "shutil.which", lambda name: "/usr/bin/xray" if "xray" in str(name) else None
    )
    assert find_xray_executable() is not None


def test_find_xray_not_found(monkeypatch) -> None:
    monkeypatch.setattr(Path, "exists", lambda self: False)
    monkeypatch.setattr("shutil.which", lambda name: None)
    monkeypatch.delenv("XRAY_EXECUTABLE", raising=False)
    assert find_xray_executable() is None


def test_find_xray_abs_not_found(monkeypatch) -> None:
    monkeypatch.setattr(Path, "exists", lambda self: False)
    assert find_xray_executable(explicit_path="/nonexistent/xray") is None


def test_find_xray_abs_path_continue() -> None:
    """Absolute candidate that doesn't exist -> continue to next (line 58)."""
    with (
        patch("pathlib.Path.exists", return_value=False),
        patch(
            "src.validators.xray_probe.os.environ.get",
            return_value="C:\\nonexistent\\xray",
        ),
        patch("src.validators.xray_probe.shutil.which", return_value=None),
    ):
        assert find_xray_executable() is None


def test_find_xray_relative_path_resolved() -> None:
    """Relative candidate resolved via shutil.which -> return (line 61)."""
    with (
        patch("pathlib.Path.exists", return_value=False),
        patch(
            "src.validators.xray_probe.os.environ.get",
            return_value="nonexistent_rel\\xray",
        ),
    ):
        # Build candidates: [None, "nonexistent_rel\xray", which("xray"), which("xray.exe")]
        # The second candidate is NOT absolute on Windows, so it falls through
        # to shutil.which(str(candidate)). We need that to succeed.
        # But shutil.which is called both for the candidate list AND for resolution.
        # Use a side_effect: first 2 calls (candidates list) return None,
        # third call (resolution) returns a path.
        call_count = 0
        orig_which = __import__("shutil").which

        def _mock_which(name: str) -> str | None:
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                return None
            if "xray" in name:
                return "C:\\found\\xray.exe"
            return orig_which(name)

        with patch("src.validators.xray_probe.shutil.which", side_effect=_mock_which):
            r = find_xray_executable()
            assert r == "C:\\found\\xray.exe"


# ===================== _free_local_port ======================


def test_free_local_port(monkeypatch) -> None:
    mock_sock = MagicMock()
    mock_sock.getsockname.return_value = ("127.0.0.1", 12345)
    monkeypatch.setattr(socket, "socket", lambda *a, **kw: mock_sock)
    assert _free_local_port() == 12345
    mock_sock.close.assert_called_once()


# ===================== _wait_for_port ======================


@pytest.mark.asyncio
async def test_wait_for_port_success(monkeypatch) -> None:
    mock_writer = MagicMock()
    mock_writer.wait_closed = AsyncMock()

    async def _open(*args, **kwargs):
        return MagicMock(), mock_writer

    monkeypatch.setattr(asyncio, "open_connection", _open)
    assert await _wait_for_port(10800, 1.0) is True
    mock_writer.close.assert_called_once()
    mock_writer.wait_closed.assert_awaited_once()


@pytest.mark.asyncio
async def test_wait_for_port_timeout(monkeypatch) -> None:
    async def _open(*args, **kwargs):
        raise OSError("refused")

    monkeypatch.setattr(asyncio, "open_connection", _open)
    assert await _wait_for_port(10800, 0.01) is False


# ===================== _http_status_code ======================


def test_http_status_code_ok() -> None:
    assert _http_status_code(b"HTTP/1.1 200 OK\r\n...") == 200
    assert _http_status_code(b"HTTP/1.1 404 Not Found") == 404


def test_http_status_code_no_prefix() -> None:
    assert _http_status_code(b"garbage") is None


def test_http_status_code_short() -> None:
    assert _http_status_code(b"HTTP/") is None
    assert _http_status_code(b"HTTP/1.1 ") is None


def test_http_status_code_bad_int() -> None:
    assert _http_status_code(b"HTTP/1.1 ABC") is None


# ===================== _extract_probe_ip ======================


def test_extract_ip_direct() -> None:
    assert _extract_probe_ip("1.2.3.4") == "1.2.3.4"


def test_extract_ip_kv() -> None:
    assert _extract_probe_ip("ip=5.6.7.8\nother=stuff") == "5.6.7.8"


def test_extract_ip_ip_addr() -> None:
    assert _extract_probe_ip("ip_addr=9.10.11.12") == "9.10.11.12"


def test_extract_ip_query() -> None:
    assert _extract_probe_ip("query=1.2.3.4") == "1.2.3.4"


def test_extract_ip_empty() -> None:
    assert _extract_probe_ip("") is None


def test_extract_ip_no_ip() -> None:
    assert _extract_probe_ip("hello world") is None


def test_extract_ip_cf_trace() -> None:
    body = "fl=123\nip=1.2.3.4\nts=456"
    assert _extract_probe_ip(body) == "1.2.3.4"


# ===================== _normalize_probe_urls ======================


def test_normalize_default() -> None:
    assert _normalize_probe_urls() == ["https://www.gstatic.com/generate_204"]


def test_normalize_with_url() -> None:
    urls = _normalize_probe_urls(probe_url="https://example.com/test")
    # When only probe_url is given, the result is just [probe_url]
    assert urls == ["https://example.com/test"]


def test_normalize_with_list() -> None:
    urls = _normalize_probe_urls(probe_urls=["https://a.com", "https://b.com"])
    assert urls == ["https://a.com", "https://b.com"]


def test_normalize_dedup() -> None:
    urls = _normalize_probe_urls(
        probe_url="https://a.com", probe_urls=["https://a.com"]
    )
    assert urls == ["https://a.com"]


def test_normalize_clean_empty() -> None:
    urls = _normalize_probe_urls(probe_url="https://a.com", probe_urls=["", "  "])
    assert urls == ["https://a.com"]


# ===================== _https_probe_response ======================


@pytest.mark.asyncio
async def test_https_probe_bad_scheme() -> None:
    with pytest.raises(ValueError, match="probe_url must be HTTPS"):
        await _https_probe_response(probe_url="http://example.com", timeout=1.0)


@pytest.mark.asyncio
async def test_https_probe_direct(monkeypatch) -> None:
    reader = AsyncMock()
    reader.read = AsyncMock(return_value=b"HTTP/1.1 200 OK\r\n\r\nbody")
    writer = MagicMock()
    writer.drain = AsyncMock()
    writer.wait_closed = AsyncMock()

    async def _open(host=None, port=None, ssl=None, server_hostname=None):
        return reader, writer

    monkeypatch.setattr(asyncio, "open_connection", _open)
    code, body = await _https_probe_response(
        probe_url="https://example.com/test?q=1", timeout=5.0
    )
    assert code == 200
    assert body == "body"


@pytest.mark.asyncio
async def test_https_probe_via_socks_port(monkeypatch) -> None:
    reader = AsyncMock()
    reader.read = AsyncMock(return_value=b"HTTP/1.1 204 No Content\r\n\r\n")
    writer = MagicMock()
    writer.drain = AsyncMock()
    writer.wait_closed = AsyncMock()
    mock_sock = MagicMock()

    async def _open_conn(sock=None, ssl=None, server_hostname=None):
        return reader, writer

    monkeypatch.setattr(asyncio, "open_connection", _open_conn)

    with patch("python_socks.async_.asyncio.Proxy") as MockProxy:
        inst = MagicMock()
        MockProxy.from_url.return_value = inst
        inst.connect = AsyncMock(return_value=mock_sock)
        code, body = await _https_probe_response(
            probe_url="https://example.com", timeout=5.0, socks_port=10800
        )
        assert code == 204
        assert body == ""


@pytest.mark.asyncio
async def test_https_probe_via_proxy_url(monkeypatch) -> None:
    reader = AsyncMock()
    reader.read = AsyncMock(return_value=b"HTTP/1.1 200 OK\r\n\r\nok")
    writer = MagicMock()
    writer.drain = AsyncMock()
    writer.wait_closed = AsyncMock()
    mock_sock = MagicMock()

    async def _open_conn(sock=None, ssl=None, server_hostname=None):
        return reader, writer

    monkeypatch.setattr(asyncio, "open_connection", _open_conn)
    with patch("python_socks.async_.asyncio.Proxy") as MockProxy:
        inst = MagicMock()
        MockProxy.from_url.return_value = inst
        inst.connect = AsyncMock(return_value=mock_sock)
        code, body = await _https_probe_response(
            probe_url="https://example.com",
            timeout=5.0,
            proxy_url="socks5://10.0.0.1:1080",
        )
        assert code == 200


@pytest.mark.asyncio
async def test_https_probe_exception(monkeypatch) -> None:
    async def _open(*args, **kwargs):
        raise ConnectionError("fail")

    monkeypatch.setattr(asyncio, "open_connection", _open)
    code, body = await _https_probe_response(
        probe_url="https://example.com", timeout=1.0
    )
    assert code is None and body == ""


@pytest.mark.asyncio
async def test_https_probe_cleanup(monkeypatch) -> None:
    """Writer.close is called even on exception."""
    writer = MagicMock()
    writer.close.side_effect = Exception("close_err")
    writer.wait_closed = AsyncMock()
    reader = AsyncMock()
    reader.read = AsyncMock(side_effect=ConnectionError("read_err"))

    async def _open(*args, **kwargs):
        return reader, writer

    monkeypatch.setattr(asyncio, "open_connection", _open)
    code, _ = await _https_probe_response(probe_url="https://example.com", timeout=1.0)
    assert code is None
    writer.close.assert_called_once()


# ===================== _https_probe_via_socks ======================


@pytest.mark.asyncio
async def test_https_probe_via_socks(monkeypatch) -> None:
    reader = AsyncMock()
    reader.read = AsyncMock(return_value=b"HTTP/1.1 200 OK\r\n\r\n")
    writer = MagicMock()
    writer.drain = AsyncMock()
    writer.wait_closed = AsyncMock()
    mock_sock = MagicMock()

    async def _open_conn(sock=None, ssl=None, server_hostname=None):
        return reader, writer

    monkeypatch.setattr(asyncio, "open_connection", _open_conn)
    with patch("python_socks.async_.asyncio.Proxy") as MockProxy:
        inst = MagicMock()
        MockProxy.from_url.return_value = inst
        inst.connect = AsyncMock(return_value=mock_sock)
        assert (
            await _https_probe_via_socks(
                10800, probe_url="https://example.com", timeout=5.0
            )
            == 200
        )


# ===================== discover_public_ip ======================


@pytest.mark.asyncio
async def test_discover_ip_found() -> None:
    with patch(
        "src.validators.xray_probe._https_probe_response", new_callable=AsyncMock
    ) as m:
        m.return_value = (200, "1.2.3.4")
        r = await discover_public_ip(probe_urls=["https://api.ipify.org"], timeout=5.0)
        assert r == "1.2.3.4"


@pytest.mark.asyncio
async def test_discover_ip_none() -> None:
    with patch(
        "src.validators.xray_probe._https_probe_response", new_callable=AsyncMock
    ) as m:
        m.return_value = (200, "no-ip")
        r = await discover_public_ip(probe_urls=["https://api.ipify.org"], timeout=5.0)
        assert r is None


@pytest.mark.asyncio
async def test_discover_ip_skip_non_accepted() -> None:
    calls = 0

    async def _probe(**kw: object) -> tuple[int, str]:
        nonlocal calls
        calls += 1
        return (500, "") if calls == 1 else (200, "5.6.7.8")

    with patch("src.validators.xray_probe._https_probe_response", side_effect=_probe):
        r = await discover_public_ip(
            probe_urls=["https://a.com", "https://b.com"], timeout=5.0
        )
        assert r == "5.6.7.8"


# ===================== _rotated_proxy_urls_for_config ======================


def test_rotated_proxy_urls_single() -> None:
    cfg = _make_cfg()
    assert _rotated_proxy_urls_for_config(cfg, ["socks5://a:1080"]) == [
        "socks5://a:1080"
    ]


def test_rotated_proxy_urls_empty() -> None:
    cfg = _make_cfg()
    assert _rotated_proxy_urls_for_config(cfg, []) == []


def test_rotated_proxy_urls_multiple() -> None:
    cfg = _make_cfg()
    urls = ["socks5://a:1080", "socks5://b:1080", "socks5://c:1080"]
    result = _rotated_proxy_urls_for_config(cfg, urls)
    assert len(result) == 3
    assert set(result) == set(urls)


# ===================== xray_probe_check ======================


@pytest.mark.asyncio
async def test_probe_check_success(cfg_vless: Config) -> None:
    """xray_probe_check returns True when everything succeeds."""
    with tempfile.TemporaryDirectory() as tmpdir:
        with (
            patch("src.validators.xray_probe._free_local_port", return_value=12345),
            patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_sub,
            patch(
                "src.validators.xray_probe._wait_for_port", new_callable=AsyncMock
            ) as mock_wait,
            patch(
                "src.validators.xray_probe._https_probe_response",
                new_callable=AsyncMock,
            ) as mock_probe,
        ):
            proc = MagicMock()
            proc.returncode = None
            proc.terminate = MagicMock()
            proc.kill = MagicMock()
            proc.wait = AsyncMock(return_value=0)
            mock_sub.return_value = proc
            mock_wait.return_value = True
            mock_probe.return_value = (204, "")

            # Use the real tempfile context manager by passing tmpdir as the dir
            with patch("tempfile.TemporaryDirectory") as mock_tmp:
                mock_tmp.return_value.__enter__.return_value = tmpdir
                r = await xray_probe_check(
                    cfg_vless,
                    xray_path="/usr/bin/xray",
                    timeout=5.0,
                    startup_timeout=2.0,
                )
                assert r is True


@pytest.mark.asyncio
async def test_probe_check_config_none(cfg_vless: Config) -> None:
    with patch("src.validators.xray_probe.build_xray_config", return_value=None):
        assert (
            await xray_probe_check(cfg_vless, xray_path="/usr/bin/xray", timeout=5.0)
            is False
        )


@pytest.mark.asyncio
async def test_probe_check_startup_timeout(cfg_vless: Config) -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        with (
            patch("src.validators.xray_probe._free_local_port", return_value=12345),
            patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_sub,
            patch(
                "src.validators.xray_probe._wait_for_port", new_callable=AsyncMock
            ) as mock_wait,
        ):
            proc = MagicMock()
            proc.returncode = None
            proc.terminate = MagicMock()
            proc.wait = AsyncMock(return_value=0)
            mock_sub.return_value = proc
            mock_wait.return_value = False

            with patch("tempfile.TemporaryDirectory") as mock_tmp:
                mock_tmp.return_value.__enter__.return_value = tmpdir
                r = await xray_probe_check(
                    cfg_vless,
                    xray_path="/usr/bin/xray",
                    startup_timeout=1.0,
                    timeout=5.0,
                )
                assert r is False


@pytest.mark.asyncio
async def test_probe_check_too_many_failures(cfg_vless: Config) -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        with (
            patch("src.validators.xray_probe._free_local_port", return_value=12345),
            patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_sub,
            patch(
                "src.validators.xray_probe._wait_for_port", new_callable=AsyncMock
            ) as mock_wait,
            patch(
                "src.validators.xray_probe._https_probe_response",
                new_callable=AsyncMock,
            ) as mock_probe,
        ):
            proc = MagicMock()
            proc.returncode = None
            proc.terminate = MagicMock()
            proc.wait = AsyncMock(return_value=0)
            mock_sub.return_value = proc
            mock_wait.return_value = True
            mock_probe.return_value = (500, "")  # not accepted

            with patch("tempfile.TemporaryDirectory") as mock_tmp:
                mock_tmp.return_value.__enter__.return_value = tmpdir
                r = await xray_probe_check(
                    cfg_vless,
                    xray_path="/usr/bin/xray",
                    timeout=5.0,
                    startup_timeout=2.0,
                )
                assert r is False


@pytest.mark.asyncio
async def test_probe_check_reject_ip(cfg_vless: Config) -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        with (
            patch("src.validators.xray_probe._free_local_port", return_value=12345),
            patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_sub,
            patch(
                "src.validators.xray_probe._wait_for_port", new_callable=AsyncMock
            ) as mock_wait,
            patch(
                "src.validators.xray_probe._https_probe_response",
                new_callable=AsyncMock,
            ) as mock_probe,
        ):
            proc = MagicMock()
            proc.returncode = None
            proc.terminate = MagicMock()
            proc.wait = AsyncMock(return_value=0)
            mock_sub.return_value = proc
            mock_wait.return_value = True
            mock_probe.return_value = (204, "ip=1.2.3.4")

            with patch("tempfile.TemporaryDirectory") as mock_tmp:
                mock_tmp.return_value.__enter__.return_value = tmpdir
                r = await xray_probe_check(
                    cfg_vless,
                    xray_path="/usr/bin/xray",
                    timeout=5.0,
                    startup_timeout=2.0,
                    require_distinct_outbound_ip=True,
                    reject_outbound_ips={"1.2.3.4"},
                )
                assert r is False


@pytest.mark.asyncio
async def test_probe_check_final_return(cfg_vless: Config) -> None:
    """When loop ends naturally, the final return at line 536 is used."""
    with tempfile.TemporaryDirectory() as tmpdir:
        with (
            patch("src.validators.xray_probe._free_local_port", return_value=12345),
            patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_sub,
            patch(
                "src.validators.xray_probe._wait_for_port", new_callable=AsyncMock
            ) as mock_wait,
            patch(
                "src.validators.xray_probe._https_probe_response",
                new_callable=AsyncMock,
            ) as mock_probe,
        ):
            proc = MagicMock()
            proc.returncode = None
            proc.terminate = MagicMock()
            proc.wait = AsyncMock(return_value=0)
            mock_sub.return_value = proc
            mock_wait.return_value = True
            # Multiple URLs: first succeeds but identity check fails; second succeeds with good IP
            mock_probe.side_effect = [(200, "no-ip"), (200, "ip=5.6.7.8")]

            with patch("tempfile.TemporaryDirectory") as mock_tmp:
                mock_tmp.return_value.__enter__.return_value = tmpdir
                r = await xray_probe_check(
                    cfg_vless,
                    xray_path="/usr/bin/xray",
                    timeout=5.0,
                    startup_timeout=2.0,
                    require_distinct_outbound_ip=True,
                    probe_urls=["https://a.com", "https://b.com"],
                )
                assert r is True


@pytest.mark.asyncio
async def test_probe_check_timeout_then_kill(cfg_vless: Config) -> None:
    """TimeoutError on proc.wait() triggers proc.kill()."""
    with tempfile.TemporaryDirectory() as tmpdir:
        with (
            patch("src.validators.xray_probe._free_local_port", return_value=12345),
            patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_sub,
            patch(
                "src.validators.xray_probe._wait_for_port", new_callable=AsyncMock
            ) as mock_wait,
            patch(
                "src.validators.xray_probe._https_probe_response",
                new_callable=AsyncMock,
            ) as mock_probe,
        ):
            proc = MagicMock()
            proc.returncode = None
            proc.terminate = MagicMock()
            proc.kill = MagicMock()
            proc.wait = AsyncMock(side_effect=[TimeoutError, 0])
            mock_sub.return_value = proc
            mock_wait.return_value = True
            mock_probe.return_value = (204, "")

            with patch("tempfile.TemporaryDirectory") as mock_tmp:
                mock_tmp.return_value.__enter__.return_value = tmpdir
                r = await xray_probe_check(
                    cfg_vless,
                    xray_path="/usr/bin/xray",
                    timeout=5.0,
                    startup_timeout=2.0,
                )
                assert r is True
            proc.kill.assert_called_once()


# ===================== validate_configs_xray ======================


@pytest.mark.asyncio
async def test_validate_empty() -> None:
    assert await validate_configs_xray([], xray_path="/usr/bin/xray") == []


@pytest.mark.asyncio
async def test_validate_all_pass() -> None:
    cfg1 = _make_cfg(address="1.2.3.4", port=443)
    cfg2 = _make_cfg(address="5.6.7.8", port=443)
    with patch(
        "src.validators.xray_probe.xray_probe_check", new_callable=AsyncMock
    ) as m:
        m.return_value = True
        result = await validate_configs_xray(
            [cfg1, cfg2], xray_path="/usr/bin/xray", timeout=5.0
        )
        assert len(result) == 2
        assert cfg1.is_alive is True
        assert cfg1.xray_was_checked is True


@pytest.mark.asyncio
async def test_validate_some_fail() -> None:
    cfg1 = _make_cfg(address="1.2.3.4", port=443)
    cfg2 = _make_cfg(address="5.6.7.8", port=443)
    with patch(
        "src.validators.xray_probe.xray_probe_check", new_callable=AsyncMock
    ) as m:
        m.side_effect = [True, False]
        result = await validate_configs_xray(
            [cfg1, cfg2], xray_path="/usr/bin/xray", timeout=5.0
        )
        assert len(result) == 1 and result[0] is cfg1


@pytest.mark.asyncio
async def test_validate_attempts_retry() -> None:
    cfg = _make_cfg()
    with patch(
        "src.validators.xray_probe.xray_probe_check", new_callable=AsyncMock
    ) as m:
        m.side_effect = [False, True]
        result = await validate_configs_xray(
            [cfg],
            xray_path="/usr/bin/xray",
            timeout=5.0,
            attempts_per_config=2,
            min_attempt_successes=1,
        )
        assert len(result) == 1
        assert cfg.xray_attempt_successes == 1


@pytest.mark.asyncio
async def test_validate_attempts_exhausted() -> None:
    cfg = _make_cfg()
    with patch(
        "src.validators.xray_probe.xray_probe_check", new_callable=AsyncMock
    ) as m:
        m.return_value = False
        result = await validate_configs_xray(
            [cfg],
            xray_path="/usr/bin/xray",
            timeout=5.0,
            attempts_per_config=2,
            min_attempt_successes=2,
        )
        assert len(result) == 0


@pytest.mark.asyncio
async def test_validate_with_proxies() -> None:
    cfg = _make_cfg()
    with patch(
        "src.validators.xray_probe.xray_probe_check", new_callable=AsyncMock
    ) as m:
        # 1 direct call + 2 proxy calls; all succeed
        # min_proxy_successes=1 => breaks after first proxy success
        m.return_value = True
        result = await validate_configs_xray(
            [cfg],
            xray_path="/usr/bin/xray",
            timeout=5.0,
            probe_proxy_urls=["socks5://p1:1080", "socks5://p2:1080"],
            min_proxy_successes=1,
        )
        assert len(result) == 1
        assert cfg.xray_proxy_successes == 1  # breaks after 1st proxy success
        assert cfg.xray_proxy_checks == 2


@pytest.mark.asyncio
async def test_validate_proxies_fail() -> None:
    cfg = _make_cfg()
    with patch(
        "src.validators.xray_probe.xray_probe_check", new_callable=AsyncMock
    ) as m:
        m.side_effect = [True, False, False]  # direct ok, both proxies fail
        result = await validate_configs_xray(
            [cfg],
            xray_path="/usr/bin/xray",
            timeout=5.0,
            probe_proxy_urls=["socks5://p1:1080", "socks5://p2:1080"],
            min_proxy_successes=1,
        )
        assert len(result) == 0


@pytest.mark.asyncio
async def test_validate_proxies_min_zero() -> None:
    cfg = _make_cfg()
    with patch(
        "src.validators.xray_probe.xray_probe_check", new_callable=AsyncMock
    ) as m:
        m.return_value = True
        result = await validate_configs_xray(
            [cfg],
            xray_path="/usr/bin/xray",
            timeout=5.0,
            probe_proxy_urls=["socks5://p1:1080"],
            min_proxy_successes=0,
        )
        assert len(result) == 1


@pytest.mark.asyncio
async def test_validate_max_alive() -> None:
    cfgs = [_make_cfg(address=f"10.0.0.{i}", port=443) for i in range(1, 6)]
    with patch(
        "src.validators.xray_probe.xray_probe_check", new_callable=AsyncMock
    ) as m:
        m.return_value = True
        result = await validate_configs_xray(
            cfgs, xray_path="/usr/bin/xray", timeout=5.0, max_alive=2
        )
        assert len(result) == 2


@pytest.mark.asyncio
async def test_validate_distinct_ip() -> None:
    cfg = _make_cfg()
    with (
        patch(
            "src.validators.xray_probe.discover_public_ip", new_callable=AsyncMock
        ) as md,
        patch(
            "src.validators.xray_probe.xray_probe_check", new_callable=AsyncMock
        ) as mc,
    ):
        md.return_value = "1.1.1.1"
        mc.return_value = True
        result = await validate_configs_xray(
            [cfg],
            xray_path="/usr/bin/xray",
            timeout=5.0,
            require_distinct_outbound_ip=True,
        )
        assert len(result) == 1


@pytest.mark.asyncio
async def test_validate_distinct_ip_with_proxies() -> None:
    cfg = _make_cfg()
    with (
        patch(
            "src.validators.xray_probe.discover_public_ip", new_callable=AsyncMock
        ) as md,
        patch(
            "src.validators.xray_probe.xray_probe_check", new_callable=AsyncMock
        ) as mc,
    ):
        md.side_effect = ["1.1.1.1", "2.2.2.2"]
        mc.return_value = True
        result = await validate_configs_xray(
            [cfg],
            xray_path="/usr/bin/xray",
            timeout=5.0,
            require_distinct_outbound_ip=True,
            probe_proxy_urls=["socks5://p1:1080"],
        )
        assert len(result) == 1


@pytest.mark.asyncio
async def test_validate_distinct_ip_no_direct() -> None:
    cfg = _make_cfg()
    with (
        patch(
            "src.validators.xray_probe.discover_public_ip", new_callable=AsyncMock
        ) as md,
        patch(
            "src.validators.xray_probe.xray_probe_check", new_callable=AsyncMock
        ) as mc,
    ):
        md.return_value = None
        mc.return_value = True
        result = await validate_configs_xray(
            [cfg],
            xray_path="/usr/bin/xray",
            timeout=5.0,
            require_distinct_outbound_ip=True,
        )
        # Fail-closed: require_distinct_outbound_ip=True + None direct IP = empty.
        assert len(result) == 0


@pytest.mark.asyncio
async def test_validate_done_event_stops_early() -> None:
    cfgs = [_make_cfg(address=f"10.0.0.{i}", port=443) for i in range(1, 4)]
    with patch(
        "src.validators.xray_probe.xray_probe_check", new_callable=AsyncMock
    ) as m:
        m.return_value = True
        result = await validate_configs_xray(
            cfgs, xray_path="/usr/bin/xray", timeout=5.0, max_alive=1
        )
        assert len(result) == 1
        checked = sum(1 for c in cfgs if c.xray_was_checked)
        assert checked <= 2  # at most 2 started before max_alive stopped


@pytest.mark.asyncio
async def test_validate_done_event_inside_semaphore() -> None:
    """When done_event fires while waiting on semaphore with concurrency=1 (line 618)."""
    cfgs = [_make_cfg(address=f"10.0.0.{i}", port=443) for i in range(1, 3)]
    with patch(
        "src.validators.xray_probe.xray_probe_check", new_callable=AsyncMock
    ) as m:

        async def _side_effect(*args: object, **kwargs: object) -> bool:
            await asyncio.sleep(0.05)
            return True

        m.side_effect = _side_effect
        result = await validate_configs_xray(
            cfgs,
            xray_path="/usr/bin/xray",
            timeout=5.0,
            concurrency=1,
            max_alive=1,
        )
        assert len(result) == 1


@pytest.mark.asyncio
async def test_validate_attempt_continue_insufficient_successes() -> None:
    """Continue when ok but attempt_successes < required_attempts (line 644)."""
    cfg = _make_cfg()
    with patch(
        "src.validators.xray_probe.xray_probe_check", new_callable=AsyncMock
    ) as m:
        m.return_value = True
        result = await validate_configs_xray(
            [cfg],
            xray_path="/usr/bin/xray",
            timeout=5.0,
            attempts_per_config=3,
            min_attempt_successes=2,
        )
        assert len(result) == 1
        assert cfg.xray_attempt_successes == 2


@pytest.mark.asyncio
async def test_validate_cancelled_error_handled() -> None:
    cfg = _make_cfg()
    with patch(
        "src.validators.xray_probe.xray_probe_check", new_callable=AsyncMock
    ) as m:
        m.side_effect = asyncio.CancelledError()
        result = await validate_configs_xray(
            [cfg], xray_path="/usr/bin/xray", timeout=5.0
        )
        # CancelledError propagates, but gather returns exceptions
        assert len(result) == 0
