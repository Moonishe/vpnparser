"""L3 validator for QUIC protocols (hysteria2/tuic) via sing-box.

Xray-core cannot speak hysteria2/tuic, so those configs used to die in the
Xray stage as "unsupported" no matter how alive the servers were. sing-box
natively dials both; this module runs one sing-box instance per config with
a local SOCKS inbound — the exact shape :mod:`src.validators.xray_probe`
uses — and performs the same HTTPS probes through it.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, BinaryIO
from urllib.parse import unquote, urlparse

from src.parsers.base import Config
from src.utils.net import redact_proxy_url
from src.validators.address_guard import (
    filter_public_configs,
    is_blocked_literal,
    resolve_pinned_address,
)
from src.validators.xray_probe import (
    _DEFAULT_ACCEPTED_STATUS_CODES,
    _free_local_port,
    _https_probe_response,
    _normalize_probe_urls,
    _NoVerdictError,
    _release_local_port,
    _resolve_configured_path,
    _rotated_proxy_urls_for_config,
    _server_name,
    _sweep_stale_probe_dirs,
    _wait_for_port,
    _which_in_path,
)

logger = logging.getLogger(__name__)

_SUPPORTED_PROTOCOLS = {"hysteria2", "tuic"}

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def find_singbox_executable(explicit_path: str | None = None) -> str | None:
    """Return a usable sing-box path from config/env/PATH, if available."""
    for candidate in (explicit_path, os.environ.get("SINGBOX_EXECUTABLE")):
        if not candidate:
            continue
        resolved = _resolve_configured_path(str(candidate))
        if resolved:
            return resolved
    for name in ("sing-box", "sing-box.exe"):
        # Same rooted-path guard as the Xray lookup (_which_in_path): bare
        # os.path.isabs lets drive-relative paths like "C:sing-box.exe"
        # resolve against the current directory.
        resolved = _which_in_path(name)
        if resolved:
            return resolved
    return None


def _socks_dial_proxy(proxy_url: str) -> dict[str, Any] | None:
    """Build a sing-box socks/http outbound used as the VPN outbound's detour."""
    try:
        parsed = urlparse(proxy_url)
        # Port 0 is compared against None, not truthiness (see xray
        # _proxy_outbound): `or` silently turned an explicit :0 into default.
        port = parsed.port
        if port is None:
            port = 1080 if parsed.scheme.lower() != "http" else 8080
        port = int(port)
    except ValueError:
        logger.warning(
            "Skipping invalid proxy url (bad port): %r",
            redact_proxy_url(proxy_url),
        )
        return None
    scheme = parsed.scheme.lower()
    # ``http`` is accepted for parity with xray_probe._proxy_outbound: the pool
    # mixes both kinds, and rejecting http here silently failed every QUIC probe
    # behind an http proxy while the Xray stage dialled it fine.
    if scheme not in {"socks", "socks5", "http"} or not parsed.hostname:
        return None
    outbound: dict[str, Any] = {
        "tag": "dial-proxy",
        "type": "http" if scheme == "http" else "socks",
        "server": parsed.hostname,
        "server_port": port,
    }
    if scheme != "http":
        outbound["version"] = "5"
    # Credentials must be forwarded, as xray_probe._proxy_outbound does: without
    # them an authenticated pool entry was dialled anonymously, the proxy
    # answered 407/refused, and every hysteria2/tuic config behind it was
    # recorded dead. urlsplit returns them percent-encoded.
    if parsed.username or parsed.password:
        outbound["username"] = unquote(parsed.username) if parsed.username else ""
        outbound["password"] = unquote(parsed.password) if parsed.password else ""
    return outbound


def build_singbox_config(
    cfg: Config,
    socks_port: int,
    *,
    dial_proxy_url: str | None = None,
    pinned_address: str | None = None,
) -> dict[str, Any] | None:
    """Build a minimal sing-box config with one outbound and a SOCKS inbound.

    ``pinned_address`` (a validated public IP literal) replaces the connect
    address while ``tls.server_name`` keeps the hostname — the same DNS
    rebinding guard as the Xray builder.
    """
    connect_address = pinned_address or cfg.address
    protocol = str(cfg.protocol or "").lower()
    if protocol not in _SUPPORTED_PROTOCOLS:
        return None

    # Reuse xray's SNI validation so an attacker-controlled SNI cannot inject
    # unexpected characters into the sing-box tls server_name field.
    server_name = _server_name(cfg)
    tls: dict[str, Any] = {
        "enabled": True,
        # Free-list QUIC servers overwhelmingly use self-signed certificates;
        # the TLS stage of this pipeline is equally non-verifying.
        "insecure": True,
    }
    if server_name:
        tls["server_name"] = server_name
    if cfg.alpn:
        alpn = [
            part.strip()
            for part in str(cfg.alpn).replace(";", ",").split(",")
            if part.strip()
        ]
        if alpn:
            tls["alpn"] = alpn

    outbound: dict[str, Any] = {
        "tag": "vpn",
        "type": protocol,
        "server": connect_address,
        "server_port": int(cfg.port),
        "tls": tls,
    }
    if protocol == "hysteria2":
        outbound["password"] = cfg.uuid_or_password
        # Salamander obfuscation must be forwarded: probing an obfs-required
        # server without it marks a working config dead.
        obfs = getattr(cfg, "obfs", None)
        if obfs:
            outbound["obfs"] = str(obfs)
            obfs_password = getattr(cfg, "obfs_password", None)
            if obfs_password:
                outbound["obfs_password"] = str(obfs_password)
    else:  # tuic v5: "uuid:password"; the token-only v4 format has no colon
        credential = str(cfg.uuid_or_password or "")
        uuid_part, separator, password_part = credential.partition(":")
        if not separator or not uuid_part.strip() or not password_part.strip():
            return None
        outbound["uuid"] = uuid_part.strip()
        outbound["password"] = password_part.strip()
        # Honour the link's congestion control when the parser stored one;
        # Mihomo/sing-box default to bbr, which the probe also used blindly —
        # a server configured for cubic rejected the bbr handshake.
        cc = getattr(cfg, "congestion_control", None)
        outbound["congestion_control"] = str(cc) if cc else "bbr"

    outbounds: list[dict[str, Any]] = [outbound]
    if dial_proxy_url:
        proxy = _socks_dial_proxy(dial_proxy_url)
        if proxy is None:
            return None
        outbound["detour"] = "dial-proxy"
        outbounds.append(proxy)

    return {
        "log": {"level": "warn"},
        "inbounds": [
            {
                "type": "socks",
                "tag": "in",
                "listen": "127.0.0.1",
                "listen_port": socks_port,
            },
        ],
        # No route block: sing-box routes everything through the first
        # outbound, which is the one under test.
        "outbounds": outbounds,
    }


def is_singbox_supported(cfg: Config) -> bool:
    return build_singbox_config(cfg, 1) is not None


def _log_probe_stderr(fh: BinaryIO, *, tool: str) -> None:
    """Log a bounded tail of a probe process's stderr temp file.

    Mirrors xray_probe._log_probe_stderr: DEVNULL made a startup failure
    undiagnosable (the exit code was logged, but not WHY the generated
    config was rejected). A temp file cannot deadlock like an unread PIPE.
    """
    try:
        fh.seek(0)
        data = fh.read(8192)
    except OSError:
        return
    text = data.decode("utf-8", errors="replace").strip()
    if text:
        logger.warning("%s startup output: %s", tool, text[-2000:])


async def singbox_probe_check(
    cfg: Config,
    *,
    singbox_path: str,
    probe_urls: list[str] | tuple[str, ...] | None = None,
    min_probe_successes: int = 1,
    accepted_status_codes: set[int] | None = None,
    dial_proxy_url: str | None = None,
    verify_probe_tls: bool = True,
    timeout: float = 12.0,
    startup_timeout: float = 4.0,
    pin_address: bool = True,
    resolve_timeout: float = 5.0,
    per_config_timeout: float | None = None,
) -> float | None:
    """Public wrapper: applies the optional per-config ceiling (see body)."""
    if per_config_timeout is None or per_config_timeout <= 0:
        return await _singbox_probe_check_body(
            cfg,
            singbox_path=singbox_path,
            probe_urls=probe_urls,
            min_probe_successes=min_probe_successes,
            accepted_status_codes=accepted_status_codes,
            dial_proxy_url=dial_proxy_url,
            verify_probe_tls=verify_probe_tls,
            timeout=timeout,
            startup_timeout=startup_timeout,
            pin_address=pin_address,
            resolve_timeout=resolve_timeout,
        )
    try:
        async with asyncio.timeout(per_config_timeout):
            return await _singbox_probe_check_body(
                cfg,
                singbox_path=singbox_path,
                probe_urls=probe_urls,
                min_probe_successes=min_probe_successes,
                accepted_status_codes=accepted_status_codes,
                dial_proxy_url=dial_proxy_url,
                verify_probe_tls=verify_probe_tls,
                timeout=timeout,
                startup_timeout=startup_timeout,
                pin_address=pin_address,
                resolve_timeout=resolve_timeout,
            )
    except TimeoutError:
        logger.warning(
            "sing-box probe of %s:%s exceeded the %ss per-config ceiling — "
            "treated as not probed.",
            cfg.address,
            cfg.port,
            per_config_timeout,
        )
        raise _NoVerdictError(
            f"per-config ceiling {per_config_timeout}s exceeded"
        ) from None


async def _singbox_probe_check_body(
    cfg: Config,
    *,
    singbox_path: str,
    probe_urls: list[str] | tuple[str, ...] | None = None,
    min_probe_successes: int = 1,
    accepted_status_codes: set[int] | None = None,
    dial_proxy_url: str | None = None,
    verify_probe_tls: bool = True,
    timeout: float = 12.0,
    startup_timeout: float = 4.0,
    pin_address: bool = True,
    resolve_timeout: float = 5.0,
) -> float | None:
    """Run real HTTPS probes through one sing-box outbound.

    ``pin_address`` mirrors :func:`xray_probe.xray_probe_check`: resolve once,
    connect to the validated literal, keep the hostname only in ``tls.server_name``.

    Returns the successful probe's latency in seconds, or ``None`` on
    failure — the same contract as :func:`xray_probe.xray_probe_check`.
    """
    if is_blocked_literal(cfg.address):
        logger.warning(
            "Refusing sing-box probe of non-public address %s:%s.",
            cfg.address,
            cfg.port,
        )
        return None

    pinned_address: str | None = None
    if pin_address:
        pinned_address = await resolve_pinned_address(
            cfg.address,
            timeout=resolve_timeout,
        )
        if pinned_address is None:
            logger.warning(
                "sing-box probe of %s:%s skipped — no validated public "
                "address (DNS pin failed).",
                cfg.address,
                cfg.port,
            )
            raise _NoVerdictError("DNS pin failed")

    try:
        socks_port = _free_local_port()
    except OSError as exc:
        logger.warning("Cannot reserve a local SOCKS port for sing-box: %s", exc)
        raise _NoVerdictError("no free local port") from exc

    try:
        sb_config = build_singbox_config(
            cfg,
            socks_port,
            dial_proxy_url=dial_proxy_url,
            pinned_address=pinned_address,
        )
        if sb_config is None:
            raise _NoVerdictError("cannot build sing-box config")

        urls = _normalize_probe_urls(None, probe_urls)
        required_successes = min(len(urls), max(1, min_probe_successes))
        accepted = accepted_status_codes or _DEFAULT_ACCEPTED_STATUS_CODES

        with tempfile.TemporaryDirectory(
            prefix="vpnparser-singbox-",
            ignore_cleanup_errors=True,
        ) as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            config_path.write_text(json.dumps(sb_config), encoding="utf-8")
            # stderr to a temp file: see _log_probe_stderr. Not a pipe (a
            # chatty process would deadlock an unread PIPE buffer) and not
            # DEVNULL (a bare exit code does not diagnose a bad config).
            err_fh = (Path(tmpdir) / "stderr.log").open("wb")
            try:
                proc = await asyncio.create_subprocess_exec(
                    singbox_path,
                    "run",
                    "-c",
                    str(config_path),
                    stdout=subprocess.DEVNULL,
                    stderr=err_fh,
                )
            except OSError as exc:
                err_fh.close()
                logger.warning("Cannot start sing-box from %s: %s", singbox_path, exc)
                raise _NoVerdictError("cannot start sing-box") from exc
            try:
                if not await _wait_for_port(socks_port, startup_timeout, proc=proc):
                    _log_probe_stderr(err_fh, tool="sing-box")
                    raise _NoVerdictError("sing-box startup timeout")
                successes = 0
                failures_allowed = len(urls) - required_successes
                failures = 0
                success_latency: float | None = None
                consecutive_full_timeouts = 0
                for url in urls:
                    probe_started = time.monotonic()
                    status_code, _body = await _https_probe_response(
                        socks_port=socks_port,
                        probe_url=url,
                        timeout=timeout,
                        verify_tls=verify_probe_tls,
                    )
                    elapsed = time.monotonic() - probe_started
                    if status_code in accepted:
                        consecutive_full_timeouts = 0
                        successes += 1
                        success_latency = time.monotonic() - probe_started
                        if successes >= required_successes:
                            return success_latency
                        continue
                    failures += 1
                    if elapsed >= timeout * 0.9:
                        consecutive_full_timeouts += 1
                        if consecutive_full_timeouts >= 2:
                            return None
                    else:
                        consecutive_full_timeouts = 0
                    if failures > failures_allowed:
                        return None
                return success_latency if successes >= required_successes else None
            finally:
                with contextlib.suppress(Exception):
                    err_fh.close()
                if proc.returncode is None:
                    proc.terminate()
                    try:
                        await asyncio.wait_for(proc.wait(), timeout=2.0)
                    except TimeoutError:
                        proc.kill()
                        with contextlib.suppress(Exception):
                            await proc.wait()
                    except asyncio.CancelledError:
                        # A second cancellation (stage shutdown) arriving
                        # during the grace wait must not skip the kill.
                        proc.kill()
                        with contextlib.suppress(Exception):
                            await proc.wait()
                        raise
                # Same credential-at-rest shrink as the Xray probe: wipe the
                # cleartext config now instead of waiting for the context
                # cleanup (which Windows may delay on open handles).
                with contextlib.suppress(Exception):
                    config_path.unlink()
                with contextlib.suppress(Exception):
                    shutil.rmtree(tmpdir, ignore_errors=True)
    finally:
        _release_local_port(socks_port)


async def validate_configs_singbox(
    configs: list[Config],
    *,
    singbox_path: str,
    probe_urls: list[str] | tuple[str, ...] | None = None,
    min_probe_successes: int = 1,
    attempts_per_config: int = 1,
    min_attempt_successes: int = 1,
    probe_proxy_urls: list[str] | tuple[str, ...] | None = None,
    proxy_latency_ms: dict[str, float] | None = None,
    verify_probe_tls: bool = True,
    check_hostnames: bool = True,
    resolve_timeout: float = 5.0,
    timeout: float = 12.0,
    startup_timeout: float = 4.0,
    concurrency: int = 6,
    max_alive: int = 0,
    deadline: float | None = None,
    per_config_timeout: float | None = None,
) -> list[Config]:
    """Return QUIC configs that pass a real HTTPS probe through sing-box.

    Probes always dial through the SOCKS pool when one is given — QUIC
    endpoints face the same datacenter-egress filtering the Xray stage works
    around — with the direct path as the empty-pool fallback. The Xray
    bookkeeping fields (``xray_was_checked`` & co) are reused so health
    history, run-summary and the Telegram reporter treat this as the same
    L3 verdict.

    ``deadline`` (absolute ``time.monotonic()``) past which no NEW candidate
    starts: without it this stage was unbounded — ``xray_stage_budget_minutes``
    only reached the Xray pass, so the QUIC stage could outlive the whole
    budget on its own.
    """
    if not configs:
        return []

    configs = await filter_public_configs(
        configs,
        stage="sing-box probe",
        check_hostnames=check_hostnames,
        resolve_timeout=resolve_timeout,
    )
    if not configs:
        return []
    # Blocking filesystem scan — off the event loop (see xray_probe).
    await asyncio.to_thread(_sweep_stale_probe_dirs)

    for cfg in configs:
        cfg.xray_was_checked = False
        # None = no verdict yet (see xray_probe: False turned
        # budget-skipped candidates into health-history failures).
        cfg.is_alive = None

    semaphore = asyncio.Semaphore(max(1, concurrency))
    alive: list[Config] = []
    alive_lock = asyncio.Lock()
    done_event = asyncio.Event()
    proxy_urls = [url for url in (probe_proxy_urls or []) if str(url).strip()]
    probe_targets = _normalize_probe_urls(None, probe_urls)
    budget_skipped = 0
    done_count = 0
    no_verdict_count = 0
    total_count = len(configs)

    async def _check_one(cfg: Config) -> None:
        nonlocal budget_skipped, done_count, no_verdict_count
        if done_event.is_set():
            return
        async with semaphore:
            if done_event.is_set():
                return
            # Same budget gate as the Xray stage: candidates arriving after
            # the deadline get no verdict (xray_was_checked stays False), so
            # the health history records nothing against them and the next
            # run probes them first.
            if deadline is not None and time.monotonic() > deadline:
                budget_skipped += 1
                cfg.xray_was_checked = False
                cfg.is_alive = None
                return
            cfg.xray_was_checked = True
            attempts = max(1, attempts_per_config)
            required_attempts = min(attempts, max(1, min_attempt_successes))
            failures_allowed = attempts - required_attempts
            attempt_successes = 0
            attempt_failures = 0
            successful_latencies: list[float] = []
            attempt_proxies = (
                _rotated_proxy_urls_for_config(cfg, proxy_urls) if proxy_urls else []
            )
            for attempt_index in range(attempts):
                if done_event.is_set():
                    cfg.xray_was_checked = False
                    cfg.is_alive = None
                    return
                dial_proxy_url = (
                    attempt_proxies[attempt_index % len(attempt_proxies)]
                    if attempt_proxies
                    else None
                )
                try:
                    probe_latency = await singbox_probe_check(
                        cfg,
                        singbox_path=singbox_path,
                        probe_urls=probe_targets,
                        min_probe_successes=min_probe_successes,
                        dial_proxy_url=dial_proxy_url,
                        verify_probe_tls=verify_probe_tls,
                        timeout=timeout,
                        startup_timeout=startup_timeout,
                        pin_address=check_hostnames,
                        resolve_timeout=resolve_timeout,
                        per_config_timeout=per_config_timeout,
                    )
                except _NoVerdictError:
                    cfg.xray_was_checked = False
                    cfg.is_alive = None
                    no_verdict_count += 1
                    return
                if probe_latency is not None:
                    raw_ms = float(probe_latency) * 1000.0
                    baseline = (
                        float(proxy_latency_ms.get(str(dial_proxy_url), 0.0))
                        if dial_proxy_url and proxy_latency_ms
                        else 0.0
                    )
                    successful_latencies.append(max(raw_ms - baseline, 1.0))
                    attempt_successes += 1
                    if attempt_successes >= required_attempts:
                        break
                    continue

                attempt_failures += 1
                if attempt_failures > failures_allowed:
                    break

            cfg.xray_attempt_successes = attempt_successes
            cfg.xray_attempts_per_config = attempts
            # Same proxy-search bookkeeping the Xray stage writes: the QUIC
            # stage dials the pool inside the attempt loop and has no separate
            # direct-mode proxy check, so the numbers mirror xray_probe's
            # via-proxy mode (successes 0, checks = pool size) instead of
            # staying unset — the report showed 0/0 for every hysteria2/tuic
            # config otherwise.
            cfg.xray_proxy_successes = 0
            cfg.xray_proxy_checks = len(proxy_urls)
            if successful_latencies:
                successful_latencies.sort()
                mid = len(successful_latencies) // 2
                cfg.latency_ms = successful_latencies[mid]
            cfg.is_alive = attempt_successes >= required_attempts
            done_count += 1
            if not cfg.is_alive:
                return
            async with alive_lock:
                alive.append(cfg)
                if max_alive > 0 and len(alive) >= max_alive:
                    done_event.set()

    tasks = [asyncio.create_task(_check_one(cfg)) for cfg in configs]

    # Race gather against the max_alive event (same shape as tcp_check): the
    # old re-registration loop was O(n²) in done-callbacks and orphaned every
    # in-flight probe — subprocess and reserved port included — when outer
    # cancellation landed during the loop.
    gather_task: asyncio.Future[Any] = asyncio.gather(*tasks, return_exceptions=True)
    if max_alive > 0:
        done_task = asyncio.ensure_future(done_event.wait())
        try:
            await asyncio.wait(
                [gather_task, done_task],
                return_when=asyncio.FIRST_COMPLETED,
            )
        except asyncio.CancelledError:
            for task in tasks:
                if not task.done():
                    task.cancel()
            done_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await gather_task
            with contextlib.suppress(asyncio.CancelledError):
                await done_task
            raise
        finally:
            # Outer cancellation during the wait must still reap in-flight
            # probes (subprocess and reserved port included).
            if done_task.done() and not done_event.is_set():
                done_event.set()
            for task in tasks:
                if not task.done():
                    task.cancel()
            done_task.cancel()
    try:
        results = await gather_task
    except asyncio.CancelledError:
        for task in tasks:
            if not task.done():
                task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await gather_task
        raise
    if max_alive > 0:
        # Reap the watcher: cancel() only requests cancellation.
        with contextlib.suppress(asyncio.CancelledError):
            await done_task
    for cfg, result in zip(configs, results, strict=False):
        if isinstance(result, (asyncio.CancelledError, BaseException)):
            cfg.xray_was_checked = False
            cfg.is_alive = None
            if not isinstance(result, asyncio.CancelledError):
                logger.warning(
                    "sing-box probe of %s:%s raised %s: %s",
                    cfg.address,
                    cfg.port,
                    type(result).__name__,
                    result,
                )
    logger.info(
        "sing-box stage finished: %d/%d checked, %d alive%s%s.",
        done_count,
        total_count,
        len(alive),
        f", {no_verdict_count} no-verdict" if no_verdict_count else "",
        (
            ""
            if done_count + budget_skipped + no_verdict_count >= total_count
            else " (remainder skipped by early stop)"
        ),
    )
    if budget_skipped:
        logger.info(
            "sing-box stage budget exceeded: %d candidate(s) not started "
            "(no verdict recorded, they retry first next run).",
            budget_skipped,
        )
    if max_alive > 0 and len(alive) > max_alive:
        del alive[max_alive:]
    return alive
