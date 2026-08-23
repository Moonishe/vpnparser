"""Tests for the sing-box L3 validator (hysteria2/tuic)."""

from __future__ import annotations

import asyncio
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.parsers.base import Config
from src.validators.singbox_probe import (
    build_singbox_config,
    find_singbox_executable,
    is_singbox_supported,
    singbox_probe_check,
    validate_configs_singbox,
)


def _hy2(address: str = "hy.example", secret: str | None = None) -> Config:
    return Config(
        protocol="hysteria2",
        address=address,
        port=443,
        uuid_or_password=secret or "test-password",
        network="quic",
        security="tls",
        sni="hy.example",
    )


def _tuic(address: str = "tuic.example") -> Config:
    return Config(
        protocol="tuic",
        address=address,
        port=443,
        uuid_or_password="11111111-1111-4111-8111-111111111111:secret",
        network="quic",
        security="tls",
        sni="tuic.example",
        alpn="h3",
    )


# --- build_singbox_config ---------------------------------------------------


def test_build_config_hysteria2_shape() -> None:
    config = build_singbox_config(_hy2(), 10800)
    assert config is not None
    outbound = config["outbounds"][0]
    assert outbound["type"] == "hysteria2"
    assert outbound["server"] == "hy.example"
    assert outbound["server_port"] == 443
    assert outbound["password"] == "test-password"
    assert outbound["tls"]["enabled"] is True
    assert outbound["tls"]["insecure"] is True
    assert outbound["tls"]["server_name"] == "hy.example"
    assert config["inbounds"][0]["listen"] == "127.0.0.1"
    assert config["inbounds"][0]["listen_port"] == 10800


def test_build_config_tuic_splits_credentials() -> None:
    outbound = build_singbox_config(_tuic(), 10800)["outbounds"][0]
    assert outbound["type"] == "tuic"
    assert outbound["uuid"] == "11111111-1111-4111-8111-111111111111"
    assert outbound["password"] == "secret"
    assert outbound["congestion_control"] == "bbr"
    assert outbound["tls"]["alpn"] == ["h3"]


def test_build_config_tuic_token_only_unsupported() -> None:
    cfg = _tuic()
    cfg.uuid_or_password = "just-a-token"
    assert build_singbox_config(cfg, 10800) is None


def test_build_config_rejects_other_protocols() -> None:
    assert build_singbox_config(Config("vless", "a.example", 443, "u"), 10800) is None


def test_build_config_dial_proxy_detour() -> None:
    config = build_singbox_config(
        _hy2(),
        10800,
        dial_proxy_url="socks5://p.example:1080",
    )
    assert config is not None
    vpn, dial = config["outbounds"]
    assert vpn["detour"] == "dial-proxy"
    assert dial["tag"] == "dial-proxy"
    assert dial["type"] == "socks"
    assert dial["version"] == "5"
    assert dial["server"] == "p.example"
    assert dial["server_port"] == 1080


def test_build_config_dial_proxy_bad_url() -> None:
    assert (
        build_singbox_config(_hy2(), 10800, dial_proxy_url="socks5://x:notaport")
        is None
    )


def test_is_singbox_supported() -> None:
    assert is_singbox_supported(_hy2()) is True
    assert is_singbox_supported(_tuic()) is True
    assert is_singbox_supported(Config("vless", "a.example", 443, "u")) is False


# --- find_singbox_executable ------------------------------------------------


def test_find_singbox_executable_none(monkeypatch) -> None:
    monkeypatch.delenv("SINGBOX_EXECUTABLE", raising=False)
    with patch("shutil.which", return_value=None):
        assert find_singbox_executable(None) is None


def test_find_singbox_executable_from_env(monkeypatch, tmp_path) -> None:
    binary = tmp_path / "sing-box.exe"
    binary.write_bytes(b"stub")
    monkeypatch.setenv("SINGBOX_EXECUTABLE", str(binary))
    assert find_singbox_executable(None) == str(binary)


# --- singbox_probe_check ----------------------------------------------------


@pytest.mark.asyncio
async def test_probe_check_success_returns_latency() -> None:
    cfg = _hy2()
    with tempfile.TemporaryDirectory() as tmpdir:
        with (
            patch("src.validators.singbox_probe._free_local_port", return_value=12345),
            patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_sub,
            patch(
                "src.validators.singbox_probe._wait_for_port",
                new_callable=AsyncMock,
                return_value=True,
            ),
            patch(
                "src.validators.singbox_probe._https_probe_response",
                new_callable=AsyncMock,
                return_value=(204, ""),
            ) as mock_probe,
            patch("tempfile.TemporaryDirectory") as mock_tmp,
        ):
            proc = MagicMock()
            proc.returncode = None
            proc.terminate = MagicMock()
            proc.wait = AsyncMock(return_value=0)
            mock_sub.return_value = proc
            mock_tmp.return_value.__enter__.return_value = tmpdir
            result = await singbox_probe_check(
                cfg,
                singbox_path="/usr/bin/sing-box",
                probe_urls=["https://gstatic.example/generate_204"],
                timeout=5.0,
            )
    assert result is not None
    assert result >= 0.0
    assert mock_probe.await_count == 1


@pytest.mark.asyncio
async def test_probe_check_refuses_private_literal() -> None:
    cfg = _hy2(address="10.0.0.5")
    assert (
        await singbox_probe_check(
            cfg, singbox_path="/usr/bin/sing-box", probe_urls=["https://a.example"]
        )
        is None
    )


@pytest.mark.asyncio
async def test_probe_check_unsupported_config() -> None:
    cfg = _tuic()
    cfg.uuid_or_password = "no-colon"
    assert (
        await singbox_probe_check(
            cfg, singbox_path="/usr/bin/sing-box", probe_urls=["https://a.example"]
        )
        is None
    )


# --- validate_configs_singbox -----------------------------------------------


@pytest.mark.asyncio
async def test_validate_singbox_alive_via_proxies() -> None:
    cfg = _hy2()
    seen_dials: list[str | None] = []

    async def fake_check(_cfg, **kwargs):
        seen_dials.append(kwargs.get("dial_proxy_url"))
        return 0.4

    with patch("src.validators.singbox_probe.singbox_probe_check", fake_check):
        result = await validate_configs_singbox(
            [cfg],
            singbox_path="/usr/bin/sing-box",
            probe_urls=["https://a.example"],
            probe_proxy_urls=["socks5://p1:1080"],
            attempts_per_config=2,
            min_attempt_successes=2,
        )
    assert result == [cfg]
    assert cfg.is_alive is True
    assert cfg.xray_was_checked is True
    assert seen_dials == ["socks5://p1:1080", "socks5://p1:1080"]
    assert cfg.latency_ms == 400.0


@pytest.mark.asyncio
async def test_validate_singbox_latency_compensated() -> None:
    cfg = _hy2()

    async def fake_check(_cfg, **_kwargs):
        return 0.5

    with patch("src.validators.singbox_probe.singbox_probe_check", fake_check):
        await validate_configs_singbox(
            [cfg],
            singbox_path="/usr/bin/sing-box",
            probe_urls=["https://a.example"],
            probe_proxy_urls=["socks5://p1:1080"],
            proxy_latency_ms={"socks5://p1:1080": 200.0},
        )
    assert cfg.latency_ms == 300.0


@pytest.mark.asyncio
async def test_validate_singbox_dead() -> None:
    cfg = _hy2()

    async def fake_check(_cfg, **_kwargs):
        return None

    with patch("src.validators.singbox_probe.singbox_probe_check", fake_check):
        result = await validate_configs_singbox(
            [cfg],
            singbox_path="/usr/bin/sing-box",
            probe_urls=["https://a.example"],
        )
    assert result == []
    assert cfg.is_alive is False


@pytest.mark.asyncio
async def test_validate_singbox_empty() -> None:
    assert (
        await validate_configs_singbox(
            [], singbox_path="/usr/bin/sing-box", probe_urls=["https://a.example"]
        )
        == []
    )


@pytest.mark.asyncio
async def test_validate_singbox_max_alive_stops_early() -> None:
    cfgs = [_hy2(address=f"h{i}.example") for i in range(5)]

    async def fake_check(_cfg, **_kwargs):
        return 0.1

    with patch("src.validators.singbox_probe.singbox_probe_check", fake_check):
        result = await validate_configs_singbox(
            cfgs,
            singbox_path="/usr/bin/sing-box",
            probe_urls=["https://a.example"],
            max_alive=2,
        )
    assert len(result) == 2


def test_validate_singbox_is_async() -> None:
    assert asyncio.iscoroutinefunction(validate_configs_singbox)
