"""Tests for Xray probe validator — 100% coverage."""

from __future__ import annotations

import asyncio
import logging
import os
import socket
import ssl
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.parsers.base import Config
from src.validators import address_guard, xray_probe
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
    _release_local_port,
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


@pytest.fixture(autouse=True)
def _no_real_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Resolve every hostname to a public IP so no test touches real DNS."""

    async def _resolve(host: str, *, timeout: float = 5.0) -> list[str]:
        return ["93.184.216.34"]

    monkeypatch.setattr(address_guard, "resolve_host_addresses", _resolve)


def _fake_xray_proc() -> MagicMock:
    """Stand-in for a live ``asyncio.subprocess.Process``."""
    proc = MagicMock()
    proc.returncode = None
    proc.terminate = MagicMock()
    proc.kill = MagicMock()
    proc.wait = AsyncMock(return_value=0)
    return proc


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
    # Both fallbacks have to be silenced, otherwise the result depends on the
    # developer's machine: a real xray on PATH (or XRAY_EXECUTABLE exported in
    # the shell) would be returned after the missing explicit path is rejected.
    monkeypatch.delenv("XRAY_EXECUTABLE", raising=False)
    monkeypatch.setattr("shutil.which", lambda name: None)
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


def test_find_xray_relative_path_resolved(monkeypatch) -> None:
    """A configured bare name is resolved through PATH, ahead of the defaults."""
    # Rooted means "not resolved against the CWD", which is spelled differently
    # per platform — hard-coding a Windows path made this test pass only there.
    rooted = "C:\\tools\\xray.exe" if os.name == "nt" else "/opt/bin/xray"
    monkeypatch.setenv("XRAY_EXECUTABLE", "xray-custom")
    monkeypatch.setattr(Path, "exists", lambda self: False)
    looked_up: list[str] = []

    def fake_which(name: str) -> str | None:
        looked_up.append(name)
        return rooted if name == "xray-custom" else None

    monkeypatch.setattr("shutil.which", fake_which)

    assert find_xray_executable() == rooted
    # The configured name wins over the built-in "xray"/"xray.exe" candidates.
    assert looked_up[0] == "xray-custom"


def test_find_xray_rejects_current_directory_hit(monkeypatch) -> None:
    """A stray ./xray.exe next to the CWD must never be executed."""
    monkeypatch.delenv("XRAY_EXECUTABLE", raising=False)
    monkeypatch.setattr(Path, "exists", lambda self: False)
    monkeypatch.setattr("shutil.which", lambda name: ".\\xray.exe")
    assert find_xray_executable() is None


def test_find_xray_rejects_relative_path_only_present_in_cwd(monkeypatch) -> None:
    """A relative candidate must not be resolved against the working directory."""
    monkeypatch.delenv("XRAY_EXECUTABLE", raising=False)
    # Path.exists() is True for everything, so a CWD-relative lookup would
    # "find" the binary; only the project-root anchor and PATH may be trusted.
    monkeypatch.setattr(Path, "exists", lambda self: True)
    monkeypatch.setattr("shutil.which", lambda name: None)
    assert find_xray_executable(explicit_path="xray.exe") is None


def test_find_xray_accepts_configured_path_relative_to_project_root(
    tmp_path,
    monkeypatch,
) -> None:
    """The shipped ``XRAY_EXECUTABLE=bin/xray/xray.exe`` layout must resolve.

    The lookup has to work from any working directory, so the result is the
    project-root-anchored absolute path rather than the relative input.
    """
    binary = tmp_path / "bin" / "xray" / "xray.exe"
    binary.parent.mkdir(parents=True)
    binary.write_text("", encoding="utf-8")
    monkeypatch.setattr(xray_probe, "_PROJECT_ROOT", tmp_path)
    monkeypatch.setattr("shutil.which", lambda name: None)
    monkeypatch.setenv("XRAY_EXECUTABLE", "bin/xray/xray.exe")
    monkeypatch.chdir(tmp_path.parent)

    assert find_xray_executable() == str(binary)


# ===================== _free_local_port ======================


def test_free_local_port(monkeypatch) -> None:
    monkeypatch.setattr(xray_probe, "_reserved_ports", set())
    mock_sock = MagicMock()
    mock_sock.getsockname.return_value = ("127.0.0.1", 12345)
    monkeypatch.setattr(socket, "socket", lambda *a, **kw: mock_sock)
    assert _free_local_port() == 12345
    mock_sock.close.assert_called_once()


def test_free_local_port_skips_already_reserved(monkeypatch) -> None:
    """Two probes must never be handed the same port number."""
    monkeypatch.setattr(xray_probe, "_reserved_ports", set())
    numbers = iter([5000, 5000, 5001])

    class _Sock:
        def bind(self, _addr: object) -> None:
            return None

        def getsockname(self) -> tuple[str, int]:
            return ("127.0.0.1", next(numbers))

        def close(self) -> None:
            return None

    monkeypatch.setattr(socket, "socket", lambda *a, **kw: _Sock())
    first = _free_local_port()
    second = _free_local_port()
    assert (first, second) == (5000, 5001)
    _release_local_port(first)
    assert first not in xray_probe._reserved_ports


def test_free_local_port_refuses_a_port_it_could_not_reserve(monkeypatch) -> None:
    """Exhausted attempts must fail, not hand out a running probe's port.

    Returning the colliding number left it unreserved, and the caller's
    ``finally: _release_local_port(...)`` then dropped the *other* probe's
    reservation — after which a third probe could legally take the same port
    and both Xray instances would fight over one SOCKS listener.
    """
    monkeypatch.setattr(xray_probe, "_reserved_ports", set())

    class _Sock:
        def bind(self, _addr: object) -> None:
            return None

        def getsockname(self) -> tuple[str, int]:
            return ("127.0.0.1", 51000)

        def close(self) -> None:
            return None

    monkeypatch.setattr(socket, "socket", lambda *a, **kw: _Sock())
    reserved = _free_local_port()
    with pytest.raises(OSError, match="no unreserved loopback port"):
        _free_local_port(attempts=3)
    assert xray_probe._reserved_ports == {reserved}


def test_free_local_port_propagates_a_failing_bind(monkeypatch) -> None:
    """A failed bind must not turn into port 0, which Xray cannot listen on."""
    monkeypatch.setattr(xray_probe, "_reserved_ports", set())

    class _Sock:
        def bind(self, _addr: object) -> None:
            raise OSError(10013, "permission denied")

        def getsockname(self) -> tuple[str, int]:  # pragma: no cover - unreachable
            return ("127.0.0.1", 0)

        def close(self) -> None:
            return None

    monkeypatch.setattr(socket, "socket", lambda *a, **kw: _Sock())
    with pytest.raises(OSError, match="permission denied"):
        _free_local_port()
    assert xray_probe._reserved_ports == set()


@pytest.mark.asyncio
async def test_probe_check_fails_when_no_port_can_be_reserved(
    monkeypatch,
    caplog,
) -> None:
    caplog.set_level(logging.WARNING)

    def _no_port(**_kwargs: object) -> int:
        msg = "no unreserved loopback port after 20 attempt(s)"
        raise OSError(msg)

    monkeypatch.setattr(xray_probe, "_reserved_ports", {51000})
    monkeypatch.setattr(xray_probe, "_free_local_port", _no_port)
    cfg = _make_cfg(address="93.184.216.34", port=443)
    assert await xray_probe_check(cfg, xray_path="/usr/bin/xray") is False
    # The reservation of the probe that owns 51000 must survive.
    assert xray_probe._reserved_ports == {51000}
    assert "Cannot reserve a local SOCKS port" in caplog.text


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


@pytest.mark.asyncio
async def test_wait_for_port_fails_when_process_died(monkeypatch) -> None:
    """A dead Xray must fail the wait instead of adopting a stranger's port."""
    connects = 0

    async def _open(*args, **kwargs):
        nonlocal connects
        connects += 1
        writer = MagicMock()
        writer.wait_closed = AsyncMock()
        return MagicMock(), writer

    monkeypatch.setattr(asyncio, "open_connection", _open)
    proc = MagicMock()
    proc.returncode = 23  # "address already in use"
    assert await _wait_for_port(10800, 1.0, proc=proc) is False
    assert connects == 0


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
    reader.read = AsyncMock(side_effect=[b"HTTP/1.1 200 OK\r\n\r\nbody", b""])
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
    reader.read = AsyncMock(side_effect=[b"HTTP/1.1 204 No Content\r\n\r\n", b""])
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
    reader.read = AsyncMock(side_effect=[b"HTTP/1.1 200 OK\r\n\r\nok", b""])
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


@pytest.mark.asyncio
async def test_https_probe_reads_body_arriving_in_second_chunk(monkeypatch) -> None:
    """Headers and body often arrive in separate TLS records."""
    reader = AsyncMock()
    reader.read = AsyncMock(
        side_effect=[
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n",
            b"ip=203.0.113.7\n",
            b"",
        ],
    )
    writer = MagicMock()
    writer.drain = AsyncMock()
    writer.wait_closed = AsyncMock()

    async def _open(host=None, port=None, ssl=None, server_hostname=None):
        return reader, writer

    monkeypatch.setattr(asyncio, "open_connection", _open)
    code, body = await _https_probe_response(
        probe_url="https://api.ipify.org",
        timeout=5.0,
    )
    assert code == 200
    assert body == "ip=203.0.113.7\n"
    assert _extract_probe_ip(body) == "203.0.113.7"


@pytest.mark.asyncio
async def test_https_probe_stops_reading_at_size_cap(monkeypatch) -> None:
    """A server that never closes the stream cannot stall the probe."""
    reader = AsyncMock()
    reader.read = AsyncMock(return_value=b"x" * 4096)
    writer = MagicMock()
    writer.drain = AsyncMock()
    writer.wait_closed = AsyncMock()

    async def _open(host=None, port=None, ssl=None, server_hostname=None):
        return reader, writer

    monkeypatch.setattr(asyncio, "open_connection", _open)
    code, body = await _https_probe_response(
        probe_url="https://example.com",
        timeout=5.0,
    )
    assert code is None  # no HTTP/ prefix in the garbage stream
    assert len(body) <= xray_probe._MAX_PROBE_RESPONSE_BYTES


@pytest.mark.asyncio
async def test_https_probe_verifies_certificate_by_default(monkeypatch) -> None:
    """Probe traffic goes through the untrusted server — verify the endpoint."""
    captured: dict[str, object] = {}
    reader = AsyncMock()
    reader.read = AsyncMock(side_effect=[b"HTTP/1.1 204 No Content\r\n\r\n", b""])
    writer = MagicMock()
    writer.drain = AsyncMock()
    writer.wait_closed = AsyncMock()

    async def _open(host=None, port=None, ssl=None, server_hostname=None):
        captured["context"] = ssl
        captured["server_hostname"] = server_hostname
        return reader, writer

    monkeypatch.setattr(asyncio, "open_connection", _open)
    code, _body = await _https_probe_response(
        probe_url="https://www.gstatic.com/generate_204",
        timeout=5.0,
    )
    assert code == 204
    context = captured["context"]
    assert isinstance(context, ssl.SSLContext)
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert captured["server_hostname"] == "www.gstatic.com"


@pytest.mark.asyncio
async def test_https_probe_verification_can_be_disabled(monkeypatch) -> None:
    captured: dict[str, object] = {}
    reader = AsyncMock()
    reader.read = AsyncMock(side_effect=[b"HTTP/1.1 204 No Content\r\n\r\n", b""])
    writer = MagicMock()
    writer.drain = AsyncMock()
    writer.wait_closed = AsyncMock()

    async def _open(host=None, port=None, ssl=None, server_hostname=None):
        captured["context"] = ssl
        return reader, writer

    monkeypatch.setattr(asyncio, "open_connection", _open)
    await _https_probe_response(
        probe_url="https://www.gstatic.com/generate_204",
        timeout=5.0,
        verify_tls=False,
    )
    context = captured["context"]
    assert isinstance(context, ssl.SSLContext)
    assert context.check_hostname is False
    assert context.verify_mode == ssl.CERT_NONE


# ===================== _https_probe_via_socks ======================


@pytest.mark.asyncio
async def test_https_probe_via_socks(monkeypatch) -> None:
    reader = AsyncMock()
    reader.read = AsyncMock(side_effect=[b"HTTP/1.1 200 OK\r\n\r\n", b""])
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
async def test_probe_check_survives_a_failing_temp_dir_cleanup(
    cfg_vless: Config,
    monkeypatch,
) -> None:
    """A cleanup race must not turn a working config into a dead one.

    On Windows the killed Xray still holds the directory for a moment, so
    ``TemporaryDirectory.__exit__`` raised ERROR_DIR_NOT_EMPTY out of
    ``xray_probe_check`` — before ``cfg.is_alive`` was set, and after
    ``xray_was_checked`` was, so a config that had just passed its probe was
    recorded as a failure in the health history.
    """
    real_temporary_directory = tempfile.TemporaryDirectory

    class _RacingTempDir:
        def __init__(self, **kwargs: object) -> None:
            self._ignore = bool(kwargs.pop("ignore_cleanup_errors", False))
            self._inner = real_temporary_directory(**kwargs)  # type: ignore[arg-type]

        def __enter__(self) -> str:
            return self._inner.__enter__()

        def __exit__(self, *exc_info: object) -> bool:
            self._inner.cleanup()
            if not self._ignore:
                raise OSError(145, "The directory is not empty")
            return False

    monkeypatch.setattr(tempfile, "TemporaryDirectory", _RacingTempDir)
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
        mock_sub.return_value = _fake_xray_proc()
        mock_wait.return_value = True
        mock_probe.return_value = (204, "")
        assert (
            await xray_probe_check(
                cfg_vless,
                xray_path="/usr/bin/xray",
                timeout=5.0,
                startup_timeout=2.0,
            )
            is True
        )
    assert xray_probe._reserved_ports == set()


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
    cfgs = [_make_cfg(address=f"93.184.216.{i}", port=443) for i in range(1, 6)]
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
    cfgs = [_make_cfg(address=f"93.184.216.{i}", port=443) for i in range(1, 4)]
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
async def test_validate_max_alive_cancels_in_flight_probes() -> None:
    """Reaching max_alive must stop the stage, not wait for the slowest probe.

    Without cancelling the pending tasks the stage waited out one hung probe
    (up to attempts * (startup + probes) seconds per list) and the probes still
    in flight appended their results, so ``xray_alive`` could exceed
    ``xray_max_alive`` in run-summary.json.
    """
    cfgs = [_make_cfg(address=f"93.184.216.{i}", port=443) for i in range(1, 21)]
    slow_used = False

    async def _probe(_cfg: Config, **_kwargs: object) -> bool:
        nonlocal slow_used
        if not slow_used:
            slow_used = True
            await asyncio.sleep(30.0)
        else:
            await asyncio.sleep(0)
        return True

    with patch("src.validators.xray_probe.xray_probe_check", new=_probe):
        started = asyncio.get_running_loop().time()
        result = await validate_configs_xray(
            cfgs,
            xray_path="/usr/bin/xray",
            timeout=5.0,
            concurrency=5,
            max_alive=3,
        )
    assert len(result) == 3
    assert asyncio.get_running_loop().time() - started < 10.0
    # A probe the early stop cancelled reached no verdict, so it must not be
    # reported to the health history as an attempted-and-failed check: every
    # probe here succeeds, so "checked but not alive" can only be a phantom.
    phantom_failures = [c for c in cfgs if c.xray_was_checked and not c.is_alive]
    assert phantom_failures == []


@pytest.mark.asyncio
async def test_validate_stops_between_attempts_without_recording_a_failure() -> None:
    """A config the early stop interrupts must not be recorded as checked.

    Its attempt loop is abandoned halfway, so it has no verdict — reporting it
    as an attempted probe would feed the health history a failure it never
    earned and push the config towards a ban.
    """
    slow, fast = (_make_cfg(address=f"93.184.216.{i}", port=443) for i in (1, 2))

    async def _probe(cfg: Config, **_kwargs: object) -> bool:
        # The slow config needs two loop turns per attempt, the fast one needs
        # one, so the fast config reaches max_alive while the slow config sits
        # between two attempts.
        await asyncio.sleep(0)
        if cfg is slow:
            await asyncio.sleep(0)
        return True

    with patch("src.validators.xray_probe.xray_probe_check", new=_probe):
        result = await validate_configs_xray(
            [slow, fast],
            xray_path="/usr/bin/xray",
            timeout=5.0,
            concurrency=2,
            attempts_per_config=4,
            min_attempt_successes=4,
            max_alive=1,
        )

    assert result == [fast]
    assert fast.xray_was_checked is True
    assert slow.xray_was_checked is False
    assert slow.is_alive is False


@pytest.mark.asyncio
async def test_validate_max_alive_never_reached_cleans_up_its_watcher() -> None:
    """All probes may finish before max_alive; the watcher must not leak."""
    cfgs = [_make_cfg(address=f"93.184.216.{i}", port=443) for i in range(1, 3)]
    with patch(
        "src.validators.xray_probe.xray_probe_check", new_callable=AsyncMock
    ) as m:
        m.return_value = True
        result = await validate_configs_xray(
            cfgs,
            xray_path="/usr/bin/xray",
            timeout=5.0,
            max_alive=10,
        )
    assert len(result) == 2
    assert all(task.done() for task in asyncio.all_tasks() - {asyncio.current_task()})


@pytest.mark.asyncio
async def test_validate_done_event_inside_semaphore() -> None:
    """When done_event fires while waiting on semaphore with concurrency=1 (line 618)."""
    cfgs = [_make_cfg(address=f"93.184.216.{i}", port=443) for i in range(1, 3)]
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


# ============ SSRF guard / identity probe / failure reporting ============


@pytest.mark.asyncio
async def test_probe_check_refuses_private_literal() -> None:
    """A private literal must not reach Xray at all (no DNS, no subprocess)."""
    cfg = _make_cfg(address="10.0.0.5", port=22)
    with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_sub:
        assert (
            await xray_probe_check(cfg, xray_path="/usr/bin/xray", timeout=1.0) is False
        )
    mock_sub.assert_not_called()


@pytest.mark.asyncio
async def test_validate_drops_non_public_addresses() -> None:
    private_cfg = _make_cfg(address="127.0.0.1", port=5432)
    metadata_cfg = _make_cfg(address="169.254.169.254", port=80)
    public_cfg = _make_cfg(address="93.184.216.34", port=443)
    with patch(
        "src.validators.xray_probe.xray_probe_check", new_callable=AsyncMock
    ) as m:
        m.return_value = True
        result = await validate_configs_xray(
            [private_cfg, metadata_cfg, public_cfg],
            xray_path="/usr/bin/xray",
            timeout=5.0,
        )
    assert result == [public_cfg]
    assert m.await_count == 1


@pytest.mark.asyncio
async def test_validate_distinct_ip_probes_identity_endpoint() -> None:
    """The default probe URL has no body, so identity URLs must be probed too."""
    cfg = _make_cfg()
    probed: list[str] = []

    async def _probe(**kwargs: object) -> tuple[int, str]:
        url = str(kwargs["probe_url"])
        probed.append(url)
        if "ipify" in url or "cdn-cgi/trace" in url:
            return (200, "ip=9.9.9.9")
        return (204, "")

    with (
        patch("src.validators.xray_probe._free_local_port", return_value=12345),
        patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_sub,
        patch(
            "src.validators.xray_probe._wait_for_port", new_callable=AsyncMock
        ) as mock_wait,
        patch("src.validators.xray_probe._https_probe_response", side_effect=_probe),
        patch(
            "src.validators.xray_probe.discover_public_ip", new_callable=AsyncMock
        ) as mock_direct,
    ):
        mock_sub.return_value = _fake_xray_proc()
        mock_wait.return_value = True
        mock_direct.return_value = "1.1.1.1"
        result = await validate_configs_xray(
            [cfg],
            xray_path="/usr/bin/xray",
            timeout=5.0,
            require_distinct_outbound_ip=True,
        )
    assert len(result) == 1
    assert any("ipify" in url or "cdn-cgi/trace" in url for url in probed)


@pytest.mark.asyncio
async def test_probe_check_reports_process_start_failure(caplog) -> None:
    """A missing/locked binary must be reported, not silently marked dead."""
    caplog.set_level(logging.WARNING)
    cfg = _make_cfg()
    with patch(
        "asyncio.create_subprocess_exec",
        side_effect=FileNotFoundError("xray is gone"),
    ):
        assert (
            await xray_probe_check(cfg, xray_path="/usr/bin/xray", timeout=1.0) is False
        )
    assert "Cannot start Xray" in caplog.text
    assert "xray is gone" in caplog.text


@pytest.mark.asyncio
async def test_validate_logs_task_exceptions(caplog) -> None:
    caplog.set_level(logging.WARNING)
    cfg = _make_cfg()
    with patch(
        "src.validators.xray_probe.xray_probe_check", new_callable=AsyncMock
    ) as m:
        m.side_effect = PermissionError("access denied")
        result = await validate_configs_xray(
            [cfg], xray_path="/usr/bin/xray", timeout=5.0
        )
    assert result == []
    assert "access denied" in caplog.text


@pytest.mark.asyncio
async def test_validate_skips_proxy_probes_when_none_required() -> None:
    """min_proxy_successes=0 is satisfied before the loop — do not probe."""
    cfg = _make_cfg()
    with patch(
        "src.validators.xray_probe.xray_probe_check", new_callable=AsyncMock
    ) as m:
        m.return_value = True
        result = await validate_configs_xray(
            [cfg],
            xray_path="/usr/bin/xray",
            timeout=5.0,
            probe_proxy_urls=["socks5://p1:1080", "socks5://p2:1080"],
            min_proxy_successes=0,
        )
    assert len(result) == 1
    assert m.await_count == 1
    assert cfg.xray_proxy_successes == 0
    assert cfg.xray_proxy_checks == 2


# ============ response framing / probe-URL hygiene / port bookkeeping ============


def _reader_returning_once(payload: bytes) -> AsyncMock:
    """Reader that yields *payload* once, then fails if read again."""
    reader = AsyncMock()
    reader.read = AsyncMock(
        side_effect=[payload, AssertionError("response was already complete")],
    )
    return reader


@pytest.mark.asyncio
async def test_https_probe_stops_at_content_length(monkeypatch) -> None:
    """A keep-alive server must not hold the probe until the timeout."""
    reader = _reader_returning_once(
        b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n1.2.3.4",
    )
    writer = MagicMock()
    writer.drain = AsyncMock()
    writer.wait_closed = AsyncMock()

    async def _open(host=None, port=None, ssl=None, server_hostname=None):
        return reader, writer

    monkeypatch.setattr(asyncio, "open_connection", _open)
    code, body = await _https_probe_response(
        probe_url="https://api.ipify.org",
        timeout=5.0,
    )
    assert (code, body) == (200, "1.2.3.4")
    assert reader.read.await_count == 1


@pytest.mark.asyncio
async def test_https_probe_stops_on_bodiless_status(monkeypatch) -> None:
    """204 carries no body, so the headers already are the whole response."""
    reader = _reader_returning_once(b"HTTP/1.1 204 No Content\r\n\r\n")
    writer = MagicMock()
    writer.drain = AsyncMock()
    writer.wait_closed = AsyncMock()

    async def _open(host=None, port=None, ssl=None, server_hostname=None):
        return reader, writer

    monkeypatch.setattr(asyncio, "open_connection", _open)
    code, body = await _https_probe_response(
        probe_url="https://www.gstatic.com/generate_204",
        timeout=5.0,
    )
    assert (code, body) == (204, "")
    assert reader.read.await_count == 1


def test_probe_response_completeness_needs_a_usable_content_length() -> None:
    """Without a trustworthy length the reader must keep going until EOF."""
    complete = xray_probe._probe_response_is_complete
    assert complete(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n") is False
    assert complete(b"HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\nx") is False
    assert complete(b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\nx") is False
    assert complete(b"HTTP/1.1 200 OK\r\n\r\nx") is False
    assert complete(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx") is True


def test_probe_response_completeness_understands_chunked_bodies() -> None:
    """A chunked body ends at its terminating chunk, not at the timeout."""
    complete = xray_probe._probe_response_is_complete
    head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
    assert complete(head + b"7\r\n1.2.3.4\r\n") is False
    assert complete(head + b"7\r\n1.2.3.4\r\n0\r\n\r\n") is True


def test_probe_response_unframed_only_when_nothing_bounds_the_body() -> None:
    unframed = xray_probe._probe_response_is_unframed
    assert unframed(b"HTTP/1.1 200 OK\r\n") is False  # headers still incomplete
    assert unframed(b"HTTP/1.1 204 No Content\r\n\r\n") is False  # bodiless
    assert unframed(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx") is False
    assert (
        unframed(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
        is False
    )
    assert unframed(b"HTTP/1.1 200 OK\r\n\r\n1.2.3.4") is True


@pytest.mark.asyncio
async def test_https_probe_does_not_burn_the_timeout_on_an_unframed_body(
    monkeypatch,
) -> None:
    """A body with neither length nor chunking may only cost the idle window.

    Such a response ends at EOF, which a server ignoring ``Connection: close``
    never sends — one such probe URL used to multiply the stage time by the
    full probe timeout for every config.
    """
    monkeypatch.setattr(xray_probe, "_UNFRAMED_BODY_IDLE_SECONDS", 0.05)
    reads = iter([b"HTTP/1.1 200 OK\r\n\r\n1.2.3.4"])

    class _Reader:
        async def read(self, _size: int) -> bytes:
            try:
                return next(reads)
            except StopIteration:
                await asyncio.sleep(30.0)
                return b""

    writer = MagicMock()
    writer.drain = AsyncMock()
    writer.wait_closed = AsyncMock()

    async def _open(host=None, port=None, ssl=None, server_hostname=None):
        return _Reader(), writer

    monkeypatch.setattr(asyncio, "open_connection", _open)
    started = asyncio.get_running_loop().time()
    code, body = await _https_probe_response(
        probe_url="https://api.ipify.org",
        timeout=30.0,
    )
    assert (code, body) == (200, "1.2.3.4")
    assert asyncio.get_running_loop().time() - started < 5.0


@pytest.mark.asyncio
async def test_https_probe_stops_at_the_last_chunk(monkeypatch) -> None:
    reader = _reader_returning_once(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"7\r\n1.2.3.4\r\n0\r\n\r\n",
    )
    writer = MagicMock()
    writer.drain = AsyncMock()
    writer.wait_closed = AsyncMock()

    async def _open(host=None, port=None, ssl=None, server_hostname=None):
        return reader, writer

    monkeypatch.setattr(asyncio, "open_connection", _open)
    code, _body = await _https_probe_response(
        probe_url="https://api.ipify.org",
        timeout=5.0,
    )
    assert code == 200
    assert reader.read.await_count == 1


def test_probe_ssl_context_is_reused(monkeypatch) -> None:
    """Rebuilding the verifying context blocks the loop for ~15ms each time."""
    builds = 0
    real_create = ssl.create_default_context

    def _counting_create(*args: object, **kwargs: object) -> ssl.SSLContext:
        nonlocal builds
        builds += 1
        return real_create(*args, **kwargs)

    xray_probe._probe_ssl_context.cache_clear()
    monkeypatch.setattr(ssl, "create_default_context", _counting_create)
    try:
        first = xray_probe._probe_ssl_context(True)
        second = xray_probe._probe_ssl_context(True)
    finally:
        xray_probe._probe_ssl_context.cache_clear()
    assert first is second
    assert builds == 1


@pytest.mark.asyncio
async def test_https_probe_gives_up_when_a_read_times_out(monkeypatch) -> None:
    reader = AsyncMock()
    reader.read = AsyncMock(side_effect=TimeoutError)
    writer = MagicMock()
    writer.drain = AsyncMock()
    writer.wait_closed = AsyncMock()

    async def _open(host=None, port=None, ssl=None, server_hostname=None):
        return reader, writer

    monkeypatch.setattr(asyncio, "open_connection", _open)
    code, body = await _https_probe_response(
        probe_url="https://example.com",
        timeout=1.0,
    )
    assert (code, body) == (None, "")


def test_normalize_probe_urls_dedupes_and_skips_blanks() -> None:
    urls = _normalize_probe_urls(
        probe_urls=["https://a.example", "  ", "https://a.example"],
    )
    assert urls == ["https://a.example"]


def test_normalize_probe_urls_drops_unparsable_url() -> None:
    assert _normalize_probe_urls(probe_urls=["https://[oops"]) == [
        "https://www.gstatic.com/generate_204",
    ]


def test_normalize_probe_urls_drops_non_https(caplog) -> None:
    caplog.set_level(logging.WARNING)
    urls = _normalize_probe_urls(
        probe_urls=["http://a.example", "https://b.example", "https://"],
    )
    assert urls == ["https://b.example"]
    assert "not an HTTPS URL" in caplog.text


def test_normalize_probe_urls_falls_back_when_all_invalid() -> None:
    assert _normalize_probe_urls(probe_urls=["http://a.example"]) == [
        "https://www.gstatic.com/generate_204",
    ]


def test_normalize_probe_urls_configured_list_wins_over_single_url() -> None:
    """The operator's list is authoritative: no built-in target is appended."""
    assert _normalize_probe_urls(
        probe_url="https://www.gstatic.com/generate_204",
        probe_urls=["https://cp.cloudflare.com/generate_204"],
    ) == ["https://cp.cloudflare.com/generate_204"]


@pytest.mark.asyncio
async def test_discover_public_ip_ignores_non_https_url(monkeypatch) -> None:
    """A typo in the settings must not raise out of the identity probe."""
    probed: list[str] = []

    async def _probe(*, probe_url: str, **_kwargs: object) -> tuple[int, str]:
        probed.append(probe_url)
        return (200, "no-ip")

    monkeypatch.setattr(xray_probe, "_https_probe_response", _probe)
    assert await discover_public_ip(probe_urls=["http://api.ipify.org"]) is None
    assert all(url.startswith("https://") for url in probed)


@pytest.mark.asyncio
async def test_validate_configs_xray_survives_non_https_probe_url(monkeypatch) -> None:
    """One bad probe URL must be skipped, not abort the whole liveness stage.

    ``discover_public_ip`` runs for real here — that is where the ValueError
    used to escape — while the socket layer is stubbed out so nothing dials.
    """

    async def _offline(*_args: object, **_kwargs: object) -> tuple[object, object]:
        raise ConnectionError("offline")

    monkeypatch.setattr(asyncio, "open_connection", _offline)
    cfg = _make_cfg(address="93.184.216.34", port=443)
    result = await validate_configs_xray(
        [cfg],
        xray_path="/usr/bin/xray",
        probe_urls=["http://api.ipify.org"],
        require_distinct_outbound_ip=True,
    )
    assert result == []


@pytest.mark.asyncio
async def test_validate_configs_xray_uses_only_configured_probe_urls() -> None:
    cfg = _make_cfg(address="93.184.216.34", port=443)
    with patch(
        "src.validators.xray_probe.xray_probe_check", new_callable=AsyncMock
    ) as m:
        m.return_value = True
        await validate_configs_xray(
            [cfg],
            xray_path="/usr/bin/xray",
            probe_urls=["https://cp.cloudflare.com/generate_204"],
        )
    assert m.await_args is not None
    assert m.await_args.kwargs["probe_urls"] == [
        "https://cp.cloudflare.com/generate_204",
    ]


@pytest.mark.asyncio
async def test_probe_check_releases_port_when_config_cannot_be_written(
    monkeypatch,
) -> None:
    """A failure before the subprocess starts must not burn the port number."""
    monkeypatch.setattr(xray_probe, "_reserved_ports", set())
    monkeypatch.setattr(xray_probe, "_free_local_port", lambda: 12345)

    def _boom(*_args: object, **_kwargs: object) -> int:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(Path, "write_text", _boom)
    cfg = _make_cfg(address="93.184.216.34", port=443)
    with pytest.raises(OSError, match="No space left"):
        await xray_probe_check(cfg, xray_path="/usr/bin/xray", timeout=1.0)
    assert xray_probe._reserved_ports == set()


@pytest.mark.asyncio
async def test_probe_check_releases_port_for_unsupported_config(monkeypatch) -> None:
    monkeypatch.setattr(xray_probe, "_reserved_ports", set())
    monkeypatch.setattr(xray_probe, "_free_local_port", lambda: 12345)
    cfg = _make_cfg(address="93.184.216.34", port=443)
    cfg.protocol = "unknown"
    assert await xray_probe_check(cfg, xray_path="/usr/bin/xray") is False
    assert xray_probe._reserved_ports == set()
