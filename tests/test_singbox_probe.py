"""Tests for src/validators/singbox_probe.py pure helpers (no subprocess)."""

from __future__ import annotations

import asyncio
import contextlib
import shutil
from unittest.mock import AsyncMock

import pytest

from src.parsers.base import Config
from src.validators import singbox_probe as sb


def _cfg(
    protocol: str,
    password: str = "secret",  # noqa: S107 - dummy test password, not a secret
    sni: str | None = None,
    alpn: str | None = None,
) -> Config:
    return Config(protocol, "203.0.113.10", 443, password, sni=sni, alpn=alpn)


def test_is_singbox_supported_protocols() -> None:
    assert sb.is_singbox_supported(_cfg("hysteria2"))
    assert sb.is_singbox_supported(_cfg("tuic", "uuid:password"))
    assert not sb.is_singbox_supported(_cfg("vless"))
    assert not sb.is_singbox_supported(_cfg("vmess"))


def test_build_singbox_config_hysteria2() -> None:
    out = sb.build_singbox_config(_cfg("hysteria2"), 18080)
    assert out is not None
    vpn = out["outbounds"][0]
    assert vpn["type"] == "hysteria2"
    assert vpn["password"] == "secret"
    assert out["inbounds"][0]["listen_port"] == 18080


def test_build_singbox_config_tuic_valid_and_invalid() -> None:
    good = sb.build_singbox_config(_cfg("tuic", "uuid:password"), 18080)
    assert good is not None
    vpn = good["outbounds"][0]
    assert vpn["uuid"] == "uuid"
    assert vpn["password"] == "password"
    assert vpn["congestion_control"] == "bbr"

    bad = sb.build_singbox_config(_cfg("tuic", "no-colon-token"), 18080)
    assert bad is None


def test_build_singbox_config_unsupported() -> None:
    assert sb.build_singbox_config(_cfg("vless"), 18080) is None


def test_build_singbox_config_sni_and_alpn() -> None:
    out = sb.build_singbox_config(
        _cfg("hysteria2", sni="example.com", alpn="h3"), 18080
    )
    assert out is not None
    tls = out["outbounds"][0]["tls"]
    assert tls["server_name"] == "example.com"
    assert tls["alpn"] == ["h3"]


def test_build_singbox_config_pinned_address_keeps_sni() -> None:
    """pinned_address replaces the connect address; the hostname stays in SNI."""
    cfg = _cfg("hysteria2", sni="example.com")
    out = sb.build_singbox_config(cfg, 18080, pinned_address="203.0.113.9")
    assert out is not None
    vpn = out["outbounds"][0]
    assert vpn["server"] == "203.0.113.9"
    assert vpn["tls"]["server_name"] == "example.com"
    # Without a pin the config address is used as-is.
    direct = sb.build_singbox_config(cfg, 18080)
    assert direct is not None
    assert direct["outbounds"][0]["server"] == "203.0.113.10"


def test_build_singbox_config_forwards_obfs() -> None:
    """Salamander obfuscation must reach the sing-box outbound."""
    cfg = Config(
        "hysteria2",
        "203.0.113.10",
        443,
        "secret",
        obfs="salamander",
        obfs_password="obfs-secret",
    )
    out = sb.build_singbox_config(cfg, 18080)
    assert out is not None
    vpn = out["outbounds"][0]
    assert vpn["obfs"] == "salamander"
    assert vpn["obfs_password"] == "obfs-secret"


def test_build_singbox_config_dial_proxy() -> None:
    out = sb.build_singbox_config(
        _cfg("hysteria2"), 18080, dial_proxy_url="socks5://1.2.3.4:1080"
    )
    assert out is not None
    tags = {o["tag"] for o in out["outbounds"]}
    assert {"vpn", "dial-proxy"} <= tags
    assert out["outbounds"][0]["detour"] == "dial-proxy"


def test_build_singbox_config_dial_proxy_invalid() -> None:
    assert (
        sb.build_singbox_config(
            _cfg("hysteria2"), 18080, dial_proxy_url="ftp://1.2.3.4:1080"
        )
        is None
    )
    assert (
        sb.build_singbox_config(
            _cfg("hysteria2"), 18080, dial_proxy_url="socks5://bad:port"
        )
        is None
    )


def test_socks_dial_proxy_valid_and_invalid() -> None:
    assert sb._socks_dial_proxy("socks5://1.2.3.4:1080") == {
        "tag": "dial-proxy",
        "type": "socks",
        "version": "5",
        "server": "1.2.3.4",
        "server_port": 1080,
    }
    # http proxies are dialled too (parity with xray_probe._proxy_outbound):
    # rejecting them made every QUIC probe behind an http proxy fail.
    assert sb._socks_dial_proxy("http://1.2.3.4:8080") == {
        "tag": "dial-proxy",
        "type": "http",
        "server": "1.2.3.4",
        "server_port": 8080,
    }
    assert sb._socks_dial_proxy("socks5://bad:port") is None
    assert sb._socks_dial_proxy("ftp://1.2.3.4:21") is None


def test_socks_dial_proxy_forwards_credentials() -> None:
    # Credentials used to be dropped: an authenticated pool entry was dialled
    # anonymously, so every hysteria2/tuic config behind it recorded dead.
    assert sb._socks_dial_proxy("socks5://user:p%40ss@1.2.3.4:1080") == {
        "tag": "dial-proxy",
        "type": "socks",
        "version": "5",
        "server": "1.2.3.4",
        "server_port": 1080,
        "username": "user",
        "password": "p@ss",
    }


def test_find_singbox_executable_none(monkeypatch) -> None:
    monkeypatch.delenv("SINGBOX_EXECUTABLE", raising=False)
    monkeypatch.setattr(shutil, "which", lambda name: None)
    assert sb.find_singbox_executable() is None
    assert sb.find_singbox_executable("C:\\nonexistent\\sing-box.exe") is None


def test_find_singbox_executable_explicit(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("SINGBOX_EXECUTABLE", raising=False)
    monkeypatch.setattr(shutil, "which", lambda name: None)
    fake = tmp_path / "sing-box.exe"
    fake.write_text("")
    assert sb.find_singbox_executable(str(fake)) == str(fake)


def test_find_singbox_executable_env(tmp_path, monkeypatch) -> None:
    fake = tmp_path / "sing-box.exe"
    fake.write_text("")
    monkeypatch.setenv("SINGBOX_EXECUTABLE", str(fake))
    monkeypatch.setattr(shutil, "which", lambda name: None)
    assert sb.find_singbox_executable() == str(fake)


def test_find_singbox_executable_from_path(tmp_path, monkeypatch) -> None:
    """A sing-box discovered via shutil.which is returned."""
    monkeypatch.delenv("SINGBOX_EXECUTABLE", raising=False)
    found = tmp_path / "sing-box.exe"
    monkeypatch.setattr(shutil, "which", lambda name: str(found))
    assert sb.find_singbox_executable() == str(found)


def test_find_singbox_executable_rejects_drive_relative(monkeypatch) -> None:
    """``C:sing-box.exe`` resolves against the current directory — the same
    rooted-path guard the Xray lookup uses must reject it."""
    monkeypatch.delenv("SINGBOX_EXECUTABLE", raising=False)
    monkeypatch.setattr(shutil, "which", lambda name: "C:sing-box.exe")
    assert sb.find_singbox_executable() is None


class _DummySingboxProc:
    returncode = None

    def terminate(self) -> None:
        self.returncode = 0

    async def wait(self) -> None:
        return None

    def kill(self) -> None:
        self.returncode = -9


def _patch_singbox_subprocess(
    monkeypatch, status: int = 204, body: str = "ip=203.0.113.10\n"
) -> None:
    monkeypatch.setattr(sb, "_free_local_port", lambda *a, **k: 18080)
    monkeypatch.setattr(sb, "_wait_for_port", AsyncMock(return_value=True))
    monkeypatch.setattr(
        asyncio,
        "create_subprocess_exec",
        AsyncMock(return_value=_DummySingboxProc()),
    )

    async def _probe(*, socks_port: int, probe_url: str, timeout: float, **_kw):
        return (status, body)

    monkeypatch.setattr(sb, "_https_probe_response", _probe)


async def test_singbox_probe_check_success(monkeypatch) -> None:
    _patch_singbox_subprocess(monkeypatch, status=204, body="ip=203.0.113.10\n")
    cfg = Config("hysteria2", "93.184.216.34", 443, "secret")
    result = await sb.singbox_probe_check(
        cfg, singbox_path="/usr/bin/sing-box", min_probe_successes=1
    )
    assert result is not None
    assert isinstance(result, float)
    assert result >= 0


async def test_singbox_probe_check_failure(monkeypatch) -> None:
    _patch_singbox_subprocess(monkeypatch, status=503, body="")
    cfg = Config("hysteria2", "93.184.216.34", 443, "secret")
    result = await sb.singbox_probe_check(
        cfg, singbox_path="/usr/bin/sing-box", min_probe_successes=1
    )
    assert result is None


async def test_singbox_probe_check_blocked_literal() -> None:
    cfg = Config("hysteria2", "127.0.0.1", 443, "secret")
    assert await sb.singbox_probe_check(cfg, singbox_path="/x") is None


async def test_validate_configs_singbox_empty() -> None:
    assert await sb.validate_configs_singbox([], singbox_path="/x") == []


async def test_validate_configs_singbox_marks_alive(monkeypatch) -> None:
    monkeypatch.setattr(
        sb,
        "filter_public_configs",
        AsyncMock(side_effect=lambda configs, **kw: configs),
    )
    monkeypatch.setattr(sb, "singbox_probe_check", AsyncMock(return_value=0.5))
    cfg = Config("hysteria2", "93.184.216.34", 443, "secret")
    out = await sb.validate_configs_singbox(
        [cfg], singbox_path="/x", probe_urls=["https://www.gstatic.com/generate_204"]
    )
    assert out == [cfg]
    assert cfg.is_alive is True
    assert cfg.xray_was_checked is True
    assert cfg.latency_ms is not None


async def test_validate_configs_singbox_forwards_verify_probe_tls(monkeypatch) -> None:
    """validate_configs_singbox must pass verify_probe_tls down to the probe."""
    monkeypatch.setattr(
        sb,
        "filter_public_configs",
        AsyncMock(side_effect=lambda configs, **kw: configs),
    )
    mock_check = AsyncMock(return_value=0.5)
    monkeypatch.setattr(sb, "singbox_probe_check", mock_check)
    cfg = Config("hysteria2", "93.184.216.34", 443, "secret")
    await sb.validate_configs_singbox(
        [cfg],
        singbox_path="/x",
        probe_urls=["https://www.gstatic.com/generate_204"],
        verify_probe_tls=False,
    )
    assert mock_check.await_args.kwargs.get("verify_probe_tls") is False


async def test_validate_configs_singbox_dead(monkeypatch) -> None:
    monkeypatch.setattr(
        sb,
        "filter_public_configs",
        AsyncMock(side_effect=lambda configs, **kw: configs),
    )
    monkeypatch.setattr(sb, "singbox_probe_check", AsyncMock(return_value=None))
    cfg = Config("hysteria2", "93.184.216.34", 443, "secret")
    out = await sb.validate_configs_singbox(
        [cfg], singbox_path="/x", probe_urls=["https://www.gstatic.com/generate_204"]
    )
    assert out == []
    assert cfg.is_alive is False


async def test_validate_configs_singbox_reports_proxy_pool_stats(monkeypatch) -> None:
    """The QUIC stage must fill the same proxy bookkeeping the Xray stage
    writes — reports showed nothing for every hysteria2/tuic config otherwise."""
    monkeypatch.setattr(
        sb,
        "filter_public_configs",
        AsyncMock(side_effect=lambda configs, **kw: configs),
    )
    monkeypatch.setattr(sb, "singbox_probe_check", AsyncMock(return_value=0.5))
    cfg = Config("hysteria2", "93.184.216.34", 443, "secret")
    await sb.validate_configs_singbox(
        [cfg],
        singbox_path="/x",
        probe_urls=["https://www.gstatic.com/generate_204"],
        probe_proxy_urls=["socks5://p1:1080", "socks5://p2:1080"],
    )
    # Same numbers xray_probe writes in via-proxy mode: the pool is dialled
    # inside the attempt loop, so there is no separate proxy-success count.
    assert cfg.xray_proxy_successes == 0
    assert cfg.xray_proxy_checks == 2


async def test_validate_configs_singbox_max_alive(monkeypatch) -> None:
    monkeypatch.setattr(
        sb,
        "filter_public_configs",
        AsyncMock(side_effect=lambda configs, **kw: configs),
    )
    monkeypatch.setattr(sb, "singbox_probe_check", AsyncMock(return_value=0.5))
    cfgs = [Config("hysteria2", "93.184.216.34", 443, f"secret{i}") for i in range(3)]
    out = await sb.validate_configs_singbox(
        cfgs,
        singbox_path="/x",
        probe_urls=["https://www.gstatic.com/generate_204"],
        max_alive=2,
    )
    assert len(out) == 2


# ===========================================================================
# singbox_probe_check — guard paths before and around the subprocess
# ===========================================================================


def _patch_probe_prelude(monkeypatch) -> None:
    """Pin the DNS guard and port reservation so no real network is touched."""
    monkeypatch.setattr(
        sb, "resolve_pinned_address", AsyncMock(return_value="93.184.216.34")
    )
    monkeypatch.setattr(sb, "_free_local_port", lambda *a, **k: 18080)


async def test_singbox_probe_check_skipped_when_dns_pin_fails(monkeypatch) -> None:
    """No validated public address -> no verdict (not a dead server)."""
    monkeypatch.setattr(sb, "resolve_pinned_address", AsyncMock(return_value=None))
    spawn = AsyncMock()
    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    cfg = Config("hysteria2", "93.184.216.34", 443, "secret")
    with pytest.raises(sb._NoVerdictError):
        await sb.singbox_probe_check(cfg, singbox_path="/x")
    spawn.assert_not_awaited()


async def test_singbox_probe_check_port_reservation_os_error(monkeypatch) -> None:
    """OSError while reserving the local SOCKS port -> no verdict."""

    def _raise(*_a, **_k):
        raise OSError("no free ports")

    monkeypatch.setattr(
        sb, "resolve_pinned_address", AsyncMock(return_value="93.184.216.34")
    )
    monkeypatch.setattr(sb, "_free_local_port", _raise)
    cfg = Config("hysteria2", "93.184.216.34", 443, "secret")
    with pytest.raises(sb._NoVerdictError):
        await sb.singbox_probe_check(cfg, singbox_path="/x")


async def test_singbox_probe_check_unsupported_protocol(monkeypatch) -> None:
    """A config sing-box cannot express is no verdict (not dead)."""
    _patch_probe_prelude(monkeypatch)
    spawn = AsyncMock()
    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    cfg = Config("vless", "93.184.216.34", 443, "uuid")
    with pytest.raises(sb._NoVerdictError):
        await sb.singbox_probe_check(cfg, singbox_path="/x", pin_address=False)
    spawn.assert_not_awaited()


async def test_singbox_probe_check_subprocess_os_error(monkeypatch) -> None:
    """A missing sing-box binary is no verdict, not a crash."""
    _patch_probe_prelude(monkeypatch)
    monkeypatch.setattr(
        asyncio,
        "create_subprocess_exec",
        AsyncMock(side_effect=OSError("binary missing")),
    )
    cfg = Config("hysteria2", "93.184.216.34", 443, "secret")
    with pytest.raises(sb._NoVerdictError):
        await sb.singbox_probe_check(cfg, singbox_path="/x")


async def test_singbox_probe_check_startup_port_never_ready(monkeypatch) -> None:
    """_wait_for_port False -> no verdict; the process is still torn down."""
    _patch_probe_prelude(monkeypatch)
    proc = _DummySingboxProc()
    monkeypatch.setattr(asyncio, "create_subprocess_exec", AsyncMock(return_value=proc))
    monkeypatch.setattr(sb, "_wait_for_port", AsyncMock(return_value=False))
    cfg = Config("hysteria2", "93.184.216.34", 443, "secret")
    with pytest.raises(sb._NoVerdictError):
        await sb.singbox_probe_check(cfg, singbox_path="/x")
    assert proc.returncode == 0  # terminate() ran


async def test_singbox_probe_check_second_success_reaches_required(monkeypatch) -> None:
    """min_probe_successes=2: the first success must not short-circuit."""
    _patch_singbox_subprocess(monkeypatch, status=204, body="ip=93.184.216.34\n")
    cfg = Config("hysteria2", "93.184.216.34", 443, "secret")
    result = await sb.singbox_probe_check(
        cfg,
        singbox_path="/usr/bin/sing-box",
        probe_urls=["https://a.example/204", "https://b.example/204"],
        min_probe_successes=2,
    )
    assert result is not None


class _FakeMonotonic:
    """Deterministic time.monotonic stand-in for the timeout heuristics."""

    def __init__(self, values: list[float]) -> None:
        self._values = list(values)
        self._calls = 0

    def monotonic(self) -> float:
        value = self._values[min(self._calls, len(self._values) - 1)]
        self._calls += 1
        return value


async def test_singbox_probe_check_consecutive_full_timeouts_bail(monkeypatch) -> None:
    """Two probes that burn the whole timeout in a row abort the probe."""
    _patch_singbox_subprocess(monkeypatch, status=503, body="")
    # probe_started/elapsed pairs: 100s elapsed on both probes >= 0.9 * 12s.
    monkeypatch.setattr(sb, "time", _FakeMonotonic([0.0, 100.0, 100.0, 200.0]))
    cfg = Config("hysteria2", "93.184.216.34", 443, "secret")
    result = await sb.singbox_probe_check(
        cfg,
        singbox_path="/usr/bin/sing-box",
        probe_urls=["https://a.example/204", "https://b.example/204"],
    )
    assert result is None


async def test_singbox_probe_check_without_probe_urls(monkeypatch) -> None:
    """No usable probe targets -> nothing to probe, None verdict."""
    _patch_probe_prelude(monkeypatch)
    monkeypatch.setattr(sb, "_normalize_probe_urls", lambda *a, **k: [])
    monkeypatch.setattr(
        asyncio,
        "create_subprocess_exec",
        AsyncMock(return_value=_DummySingboxProc()),
    )
    monkeypatch.setattr(sb, "_wait_for_port", AsyncMock(return_value=True))
    cfg = Config("hysteria2", "93.184.216.34", 443, "secret")
    assert await sb.singbox_probe_check(cfg, singbox_path="/x") is None


class _GraceTimeoutProc:
    """wait() raises TimeoutError: the grace wait expires, kill must follow."""

    def __init__(self) -> None:
        self.returncode: int | None = None

    def terminate(self) -> None:
        pass

    def kill(self) -> None:
        self.returncode = -9

    async def wait(self) -> None:
        raise TimeoutError


class _CancelledGraceProc:
    """wait() raises CancelledError, then wait() succeeds: the stage-shutdown
    cancellation must not skip the kill, and the kill is awaited before the
    original cancellation is re-raised."""

    def __init__(self) -> None:
        self.returncode: int | None = None
        self._waits = 0

    def terminate(self) -> None:
        pass

    def kill(self) -> None:
        self.returncode = -9

    async def wait(self) -> None:
        self._waits += 1
        if self._waits == 1:
            raise asyncio.CancelledError


async def test_singbox_probe_check_kills_after_grace_timeout(monkeypatch) -> None:
    """A process surviving the 2s terminate grace window is killed."""
    _patch_probe_prelude(monkeypatch)
    proc = _GraceTimeoutProc()
    monkeypatch.setattr(asyncio, "create_subprocess_exec", AsyncMock(return_value=proc))
    monkeypatch.setattr(sb, "_wait_for_port", AsyncMock(return_value=True))
    monkeypatch.setattr(sb, "_https_probe_response", AsyncMock(return_value=(204, "")))
    cfg = Config("hysteria2", "93.184.216.34", 443, "secret")
    result = await sb.singbox_probe_check(cfg, singbox_path="/usr/bin/sing-box")
    assert result is not None
    assert proc.returncode == -9


async def test_singbox_probe_check_kills_on_cancelled_grace_wait(monkeypatch) -> None:
    """A second cancellation during the grace wait still kills the process."""
    _patch_probe_prelude(monkeypatch)
    proc = _CancelledGraceProc()
    monkeypatch.setattr(asyncio, "create_subprocess_exec", AsyncMock(return_value=proc))
    monkeypatch.setattr(sb, "_wait_for_port", AsyncMock(return_value=True))
    monkeypatch.setattr(sb, "_https_probe_response", AsyncMock(return_value=(204, "")))
    cfg = Config("hysteria2", "93.184.216.34", 443, "secret")
    with pytest.raises(asyncio.CancelledError):
        await sb.singbox_probe_check(cfg, singbox_path="/usr/bin/sing-box")
    assert proc.returncode == -9


# ===========================================================================
# validate_configs_singbox — early-stop race, cancellation bookkeeping
# ===========================================================================


def _patch_validate_prelude(monkeypatch) -> None:
    """Skip the network-facing public-address filter, pass configs through."""
    monkeypatch.setattr(
        sb,
        "filter_public_configs",
        AsyncMock(side_effect=lambda configs, **kw: configs),
    )


async def test_validate_configs_singbox_all_filtered_out(monkeypatch) -> None:
    """A batch the guard rejects entirely -> no probes, empty result."""
    monkeypatch.setattr(sb, "filter_public_configs", AsyncMock(return_value=[]))
    cfg = Config("hysteria2", "93.184.216.34", 443, "secret")
    assert await sb.validate_configs_singbox([cfg], singbox_path="/x") == []


async def test_validate_configs_singbox_stop_event_after_semaphore(monkeypatch) -> None:
    """A task queued on the semaphore exits at its post-acquire event check."""
    _patch_validate_prelude(monkeypatch)

    async def fake_probe(_cfg, **_kw):
        await asyncio.sleep(0.01)
        return 0.5

    monkeypatch.setattr(sb, "singbox_probe_check", fake_probe)
    cfgs = [Config("hysteria2", "93.184.216.34", 443, f"secret{i}") for i in range(3)]
    out = await sb.validate_configs_singbox(
        cfgs, singbox_path="/x", concurrency=1, max_alive=1
    )
    assert out == [cfgs[0]]
    # It observed the stop event before recording any bookkeeping.
    assert cfgs[1].xray_was_checked is False
    assert cfgs[1].is_alive is None


async def test_validate_configs_singbox_cancels_pending_tasks(monkeypatch) -> None:
    """max_alive stop cancels the still-probing task and resets its flags.

    The first config's probe finishes quickly; the second is still sleeping
    when the stop event fires, so the stage must cancel it (its port and
    subprocess with it) instead of waiting.
    """
    _patch_validate_prelude(monkeypatch)

    async def fake_probe(cfg, **_kw):
        if cfg.address == "slow.example":
            await asyncio.sleep(0.05)
        else:
            await asyncio.sleep(0.01)
        return 0.5

    monkeypatch.setattr(sb, "singbox_probe_check", fake_probe)
    fast = Config("hysteria2", "fast.example", 443, "secret")
    slow = Config("hysteria2", "slow.example", 443, "secret")
    queued = Config("hysteria2", "queued.example", 443, "secret")
    out = await sb.validate_configs_singbox(
        [fast, slow, queued], singbox_path="/x", concurrency=2, max_alive=1
    )
    assert out == [fast]
    # Cancelled mid-probe: the bookkeeping flag is reset via the result scan.
    assert slow.xray_was_checked is False
    assert slow.is_alive is None
    # The queued task observed the stop event at the semaphore check instead.
    assert queued.xray_was_checked is False
    assert queued.is_alive is None


async def test_validate_configs_singbox_exception_results_logged(
    monkeypatch, caplog
) -> None:
    """A probe that raises must reset the config's bookkeeping and log."""
    _patch_validate_prelude(monkeypatch)

    async def fake_probe(cfg, **_kw):
        if cfg.address == "boom.example":
            raise RuntimeError("probe exploded")
        return 0.5

    monkeypatch.setattr(sb, "singbox_probe_check", fake_probe)
    bad = Config("hysteria2", "boom.example", 443, "secret")
    good = Config("hysteria2", "93.184.216.34", 443, "secret")
    out = await sb.validate_configs_singbox([bad, good], singbox_path="/x")
    assert out == [good]
    assert bad.is_alive is None
    assert bad.xray_was_checked is False
    assert "raised RuntimeError" in caplog.text


async def _racy_wait(fs, *, return_when=None):
    """Simulate the watcher finishing without the stop event (the race the
    post-wait guard covers): await the gather, then cancel the watcher."""
    gather_task, done_task = fs
    await gather_task
    done_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await done_task
    return ({done_task}, set())


async def test_validate_configs_singbox_done_watcher_race(monkeypatch) -> None:
    """A completed watcher with the event unset still sets the event."""
    _patch_validate_prelude(monkeypatch)
    monkeypatch.setattr(sb, "singbox_probe_check", AsyncMock(return_value=0.5))
    monkeypatch.setattr(asyncio, "wait", _racy_wait)
    cfgs = [Config("hysteria2", "93.184.216.34", 443, f"secret{i}") for i in range(3)]
    out = await sb.validate_configs_singbox(cfgs, singbox_path="/x", max_alive=5)
    assert out == cfgs


async def test_validate_configs_singbox_attempt_loop_stops_on_event(
    monkeypatch,
) -> None:
    """A first success below min_attempt_successes continues the attempt loop;
    the next iteration bails once the stop event fires mid-attempts."""
    _patch_validate_prelude(monkeypatch)
    gate = asyncio.Event()
    calls: dict[str, int] = {}

    async def fake_probe(cfg, **_kw):
        n = calls.get(cfg.address, 0) + 1
        calls[cfg.address] = n
        if cfg.address == "fast.example":
            if n == 1:
                await asyncio.sleep(0)  # let the slow task enter its attempt
                return 0.5
            gate.set()  # unblock slow; the stop event lands right after
            return 0.5
        await gate.wait()  # slow sits inside its first attempt until then
        return 0.5

    monkeypatch.setattr(sb, "singbox_probe_check", fake_probe)
    fast = Config("hysteria2", "fast.example", 443, "secret")
    slow = Config("hysteria2", "slow.example", 443, "secret")
    out = await sb.validate_configs_singbox(
        [fast, slow],
        singbox_path="/x",
        attempts_per_config=2,
        min_attempt_successes=2,
        concurrency=2,
        max_alive=1,
    )
    assert out == [fast]
    assert slow.is_alive is None
    assert slow.xray_was_checked is False


async def test_validate_configs_singbox_trims_alive_overshoot(monkeypatch) -> None:
    """Tasks past the stop check can overshoot the cap; the list is trimmed."""
    _patch_validate_prelude(monkeypatch)

    async def fake_probe(_cfg, **_kw):
        await asyncio.sleep(0)
        return 0.5

    monkeypatch.setattr(sb, "singbox_probe_check", fake_probe)
    cfgs = [Config("hysteria2", "93.184.216.34", 443, f"secret{i}") for i in range(2)]
    out = await sb.validate_configs_singbox(
        cfgs, singbox_path="/x", concurrency=2, max_alive=1
    )
    assert len(out) == 1
    assert out[0] is cfgs[0]


class TestTuicCongestionControl:
    """tuic links carry their own congestion control; the probe must honour it."""

    def test_stored_cc_is_used(self) -> None:
        from src.parsers.tuic import TuicParser

        cfg = TuicParser().parse(
            "tuic://11111111-1111-4111-8111-111111111111:pw@a.com:443?sni=s&congestion_control=cubic#T",
        )
        assert cfg is not None and cfg.congestion_control == "cubic"
        config = sb.build_singbox_config(cfg, 18080)
        assert config["outbounds"][0]["congestion_control"] == "cubic"

    def test_missing_cc_defaults_to_bbr(self) -> None:
        from src.parsers.tuic import TuicParser

        cfg = TuicParser().parse(
            "tuic://11111111-1111-4111-8111-111111111111:pw@a.com:443?sni=s#T"
        )
        assert cfg is not None and cfg.congestion_control is None
        config = sb.build_singbox_config(cfg, 18080)
        assert config["outbounds"][0]["congestion_control"] == "bbr"
