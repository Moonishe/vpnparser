"""Tests for the sing-box L3 validator (hysteria2/tuic)."""

from __future__ import annotations

import asyncio
import tempfile
from typing import Any
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


# --- uncovered branches ------------------------------------------------------


def test_find_singbox_executable_from_path(monkeypatch) -> None:
    """PATH fallback: `which` hit with an absolute path is returned."""
    import os

    import src.validators.singbox_probe as sb

    monkeypatch.delenv("SINGBOX_EXECUTABLE", raising=False)
    abs_path = os.path.abspath("sing-box-under-test")
    monkeypatch.setattr(sb.shutil, "which", lambda name: abs_path)
    assert sb.find_singbox_executable() == abs_path


def test_find_singbox_executable_relative_which_ignored(monkeypatch) -> None:
    """A relative `which` hit is rejected (CWD-dependent binaries are unsafe)."""
    import src.validators.singbox_probe as sb

    monkeypatch.delenv("SINGBOX_EXECUTABLE", raising=False)
    monkeypatch.setattr(sb.shutil, "which", lambda name: "sing-box")
    assert sb.find_singbox_executable() is None


def test_socks_dial_proxy_rejects_non_socks_scheme() -> None:
    assert sb_mod()._socks_dial_proxy("http://proxy.example:8080") is None


def sb_mod():
    import src.validators.singbox_probe as sb

    return sb


def test_build_config_bad_dial_proxy_port() -> None:
    cfg = _hy2()
    assert (
        sb_mod().build_singbox_config(
            cfg,
            1080,
            dial_proxy_url="socks5://host:notaport",
        )
        is None
    )


@pytest.mark.asyncio
async def test_probe_check_no_free_port(monkeypatch) -> None:
    import src.validators.singbox_probe as sb

    def boom() -> int:
        raise OSError("no ports left")

    monkeypatch.setattr(sb, "_free_local_port", boom)
    result = await sb.singbox_probe_check(
        _hy2(),
        singbox_path="/usr/bin/sing-box",
        probe_urls=["https://a.example"],
    )
    assert result is None


@pytest.mark.asyncio
async def test_probe_check_subprocess_spawn_failure(monkeypatch) -> None:
    import src.validators.singbox_probe as sb

    monkeypatch.setattr(sb, "_free_local_port", lambda: 12345)

    async def spawn_fail(*a: object, **kw: object) -> None:
        raise OSError("binary missing")

    monkeypatch.setattr(sb.asyncio, "create_subprocess_exec", spawn_fail)
    released: list[int] = []
    monkeypatch.setattr(sb, "_release_local_port", lambda port: released.append(port))
    result = await sb.singbox_probe_check(
        _hy2(),
        singbox_path="/missing/sing-box",
        probe_urls=["https://a.example"],
    )
    assert result is None
    assert released == [12345]


@pytest.mark.asyncio
async def test_probe_check_startup_timeout(monkeypatch) -> None:
    import src.validators.singbox_probe as sb

    monkeypatch.setattr(sb, "_free_local_port", lambda: 12345)
    mock_sub = AsyncMock()
    proc = MagicMock()
    proc.returncode = None
    proc.terminate = MagicMock()
    proc.wait = AsyncMock(return_value=0)
    mock_sub.return_value = proc
    monkeypatch.setattr(sb.asyncio, "create_subprocess_exec", mock_sub)
    monkeypatch.setattr(sb, "_wait_for_port", AsyncMock(return_value=False))
    released: list[int] = []
    monkeypatch.setattr(sb, "_release_local_port", lambda port: released.append(port))

    result = await sb.singbox_probe_check(
        _hy2(),
        singbox_path="/usr/bin/sing-box",
        probe_urls=["https://a.example"],
    )
    assert result is None
    assert released == [12345]


@pytest.mark.asyncio
async def test_probe_check_second_success_after_one_failure() -> None:
    """failures_allowed budget: one bad URL must not kill a 1-of-2 probe."""
    responses = [(503, ""), (204, "")]
    calls = {"n": 0}

    async def fake_probe(**kwargs: object) -> tuple[int, str]:
        idx = min(calls["n"], len(responses) - 1)
        calls["n"] += 1
        return responses[idx]

    with tempfile.TemporaryDirectory() as tmpdir:
        with (
            patch(
                "src.validators.singbox_probe._free_local_port",
                return_value=12345,
            ),
            patch(
                "asyncio.create_subprocess_exec",
                new_callable=AsyncMock,
            ) as mock_sub,
            patch(
                "src.validators.singbox_probe._wait_for_port",
                new_callable=AsyncMock,
                return_value=True,
            ),
            patch(
                "src.validators.singbox_probe._https_probe_response",
                new=fake_probe,
            ),
            patch("tempfile.TemporaryDirectory") as mock_tmp,
        ):
            proc = MagicMock()
            proc.returncode = None
            proc.terminate = MagicMock()
            proc.wait = AsyncMock(return_value=0)
            mock_sub.return_value = proc
            mock_tmp.return_value.__enter__.return_value = tmpdir
            result = await singbox_probe_check(
                _hy2(),
                singbox_path="/usr/bin/sing-box",
                probe_urls=[
                    "https://a.example/generate_204",
                    "https://b.example/generate_204",
                ],
                timeout=5.0,
            )
    assert result is not None


@pytest.mark.asyncio
async def test_probe_check_two_full_timeouts_abort() -> None:
    """Two back-to-back full-timeout probes abort without burning the rest."""
    calls = {"n": 0}

    async def fake_slow_timeout(**kwargs: object) -> tuple[int, str]:
        # The caller measures elapsed around this call; sleeping past the
        # 0.9*timeout mark marks it a "full timeout".
        await asyncio.sleep(0.05)
        calls["n"] += 1
        return (0, "")

    with tempfile.TemporaryDirectory() as tmpdir:
        with (
            patch(
                "src.validators.singbox_probe._free_local_port",
                return_value=12345,
            ),
            patch("asyncio.create_subprocess_exec", new_callable=AsyncMock),
            patch(
                "src.validators.singbox_probe._wait_for_port",
                new_callable=AsyncMock,
                return_value=True,
            ),
            patch(
                "src.validators.singbox_probe._https_probe_response",
                new=fake_slow_timeout,
            ),
            patch("tempfile.TemporaryDirectory") as mock_tmp,
        ):
            proc = MagicMock()
            proc.returncode = None
            proc.terminate = MagicMock()
            proc.wait = AsyncMock(return_value=0)
            mock_tmp.return_value.__enter__.return_value = tmpdir
            result = await singbox_probe_check(
                _hy2(),
                singbox_path="/usr/bin/sing-box",
                probe_urls=[
                    f"https://{i}.example" for i in range(4)
                ],  # more URLs than the 2-timeout abort needs
                timeout=0.05,
            )
    assert result is None
    assert calls["n"] == 2


@pytest.mark.asyncio
async def test_probe_check_grace_wait_kills_on_termination_timeout() -> None:
    """proc.wait() exceeding the 2s grace forces kill()."""
    with tempfile.TemporaryDirectory() as tmpdir:
        with (
            patch(
                "src.validators.singbox_probe._free_local_port",
                return_value=12345,
            ),
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
            ),
            patch("tempfile.TemporaryDirectory") as mock_tmp,
        ):
            proc = MagicMock()
            proc.returncode = None
            killed = {"n": 0}

            def do_kill() -> None:
                killed["n"] += 1

            proc.kill = do_kill
            waits = {"n": 0}

            async def slow_wait() -> int:
                waits["n"] += 1
                await asyncio.sleep(0.01)
                return 0

            proc.wait = slow_wait

            async def hang_then_return(coro: Any, timeout: float) -> int:
                # First grace wait exceeds its budget; the post-kill one passes.
                result = await coro
                if waits["n"] == 1 and killed["n"] == 0:
                    raise TimeoutError()
                return result

            monkeypatch_target = "src.validators.singbox_probe.asyncio"
            with patch(f"{monkeypatch_target}.wait_for", new=hang_then_return):
                proc.terminate = MagicMock()
                mock_sub.return_value = proc
                mock_tmp.return_value.__enter__.return_value = tmpdir
                result = await singbox_probe_check(
                    _hy2(),
                    singbox_path="/usr/bin/sing-box",
                    probe_urls=["https://a.example"],
                )
    assert result is not None
    assert killed["n"] >= 1


@pytest.mark.asyncio
async def test_validate_singbox_all_filtered_out(monkeypatch) -> None:
    import src.validators.singbox_probe as sb

    async def drop_all(*a: object, **kw: object) -> list[Config]:
        return []

    monkeypatch.setattr(sb, "filter_public_configs", drop_all)
    result = await sb.validate_configs_singbox(
        [_hy2()],
        singbox_path="/usr/bin/sing-box",
    )
    assert result == []


@pytest.mark.asyncio
async def test_validate_singbox_task_exception_marks_unchecked(monkeypatch) -> None:
    """A crashing probe leaves the config unchecked, not falsely dead."""
    import src.validators.singbox_probe as sb

    async def explode(cfg: Config, **kw: object) -> float:
        raise ValueError("boom")

    async def pass_through(*a: object, **kw: object) -> list[Config]:
        return list(a[0])

    monkeypatch.setattr(sb, "filter_public_configs", pass_through)
    monkeypatch.setattr(sb, "singbox_probe_check", explode)
    cfg = _hy2(address="ok.example")
    result = await sb.validate_configs_singbox(
        [cfg],
        singbox_path="/usr/bin/sing-box",
    )
    assert result == []
    assert cfg.is_alive is False
    assert cfg.xray_was_checked is False


@pytest.mark.asyncio
async def test_validate_singbox_trims_overshoot_and_skips_done(monkeypatch) -> None:
    """max_alive trims late finishers; queued tasks exit via done_event."""
    import src.validators.singbox_probe as sb

    async def instant_ok(cfg: Config, **kw: object) -> float:
        # A tiny stagger lets several probes finish before the done_event is
        # observed, so `alive` genuinely overshoots max_alive and the
        # post-gather trim (`del alive[max_alive:]`) executes.
        await asyncio.sleep(0.01)
        cfg.xray_was_checked = True
        return 0.05

    async def pass_through(*a: object, **kw: object) -> list[Config]:
        return list(a[0])

    monkeypatch.setattr(sb, "filter_public_configs", pass_through)
    monkeypatch.setattr(sb, "singbox_probe_check", instant_ok)
    configs = [_hy2(address=f"h{i}.example") for i in range(6)]
    result = await sb.validate_configs_singbox(
        configs,
        singbox_path="/usr/bin/sing-box",
        concurrency=6,
        max_alive=2,
    )
    assert 1 <= len(result) <= 2
    assert all(c.is_alive for c in result)


@pytest.mark.asyncio
async def test_probe_check_multi_url_required_and_fail_budget() -> None:
    """required=2 needs two successes; the failure budget aborts at excess."""
    # Case A: two successes -> latency returned (covers the mid-loop continue).
    seq = [(204, ""), (204, "")]
    calls = {"n": 0}

    async def fake_ok(**kw):
        i = min(calls["n"], len(seq) - 1)
        calls["n"] += 1
        return seq[i]

    with tempfile.TemporaryDirectory() as tmpdir:
        with (
            patch("src.validators.singbox_probe._free_local_port", return_value=12345),
            patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_sub,
            patch(
                "src.validators.singbox_probe._wait_for_port",
                new_callable=AsyncMock,
                return_value=True,
            ),
            patch("src.validators.singbox_probe._https_probe_response", new=fake_ok),
            patch("tempfile.TemporaryDirectory") as mock_tmp,
        ):
            proc = MagicMock()
            proc.returncode = None
            proc.terminate = MagicMock()
            proc.wait = AsyncMock(return_value=0)
            mock_sub.return_value = proc
            mock_tmp.return_value.__enter__.return_value = tmpdir
            result = await singbox_probe_check(
                _hy2(),
                singbox_path="/usr/bin/sing-box",
                probe_urls=["https://a.example", "https://b.example"],
                min_probe_successes=2,
            )
    assert result is not None

    # Case B: more failures than the budget allows -> None before the last URL.
    fails = {"n": 0}

    async def fake_fail(**kw):
        fails["n"] += 1
        return (500, "")

    with tempfile.TemporaryDirectory() as tmpdir:
        with (
            patch("src.validators.singbox_probe._free_local_port", return_value=12345),
            patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_sub,
            patch(
                "src.validators.singbox_probe._wait_for_port",
                new_callable=AsyncMock,
                return_value=True,
            ),
            patch("src.validators.singbox_probe._https_probe_response", new=fake_fail),
            patch("tempfile.TemporaryDirectory") as mock_tmp,
        ):
            proc = MagicMock()
            proc.returncode = None
            proc.terminate = MagicMock()
            proc.wait = AsyncMock(return_value=0)
            mock_sub.return_value = proc
            mock_tmp.return_value.__enter__.return_value = tmpdir
            result = await singbox_probe_check(
                _hy2(),
                singbox_path="/usr/bin/sing-box",
                probe_urls=[f"https://{i}.example" for i in range(3)],
                min_probe_successes=1,
            )
    assert result is None
