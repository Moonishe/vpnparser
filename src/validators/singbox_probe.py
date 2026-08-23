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
from typing import Any
from urllib.parse import urlparse

from src.parsers.base import Config
from src.validators.address_guard import filter_public_configs, is_blocked_literal
from src.validators.xray_probe import (
    _DEFAULT_ACCEPTED_STATUS_CODES,
    _free_local_port,
    _https_probe_response,
    _is_ip,
    _normalize_probe_urls,
    _release_local_port,
    _resolve_configured_path,
    _rotated_proxy_urls_for_config,
    _wait_for_port,
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
        resolved = shutil.which(name)
        if resolved and os.path.isabs(resolved):
            return resolved
    return None


def _socks_dial_proxy(proxy_url: str) -> dict[str, Any] | None:
    """Build a sing-box socks outbound used as the VPN outbound's detour."""
    try:
        parsed = urlparse(proxy_url)
        port = int(parsed.port or 1080)
    except ValueError:
        logger.warning("Skipping invalid proxy url (bad port): %r", proxy_url)
        return None
    scheme = parsed.scheme.lower()
    if scheme not in {"socks", "socks5"} or not parsed.hostname:
        return None
    outbound: dict[str, Any] = {
        "tag": "dial-proxy",
        "type": "socks",
        "version": "5",
        "server": parsed.hostname,
        "server_port": port,
    }
    return outbound


def build_singbox_config(
    cfg: Config,
    socks_port: int,
    *,
    dial_proxy_url: str | None = None,
) -> dict[str, Any] | None:
    """Build a minimal sing-box config with one outbound and a SOCKS inbound."""
    protocol = str(cfg.protocol or "").lower()
    if protocol not in _SUPPORTED_PROTOCOLS:
        return None

    server_name = None
    if cfg.sni and not _is_ip(cfg.sni):
        server_name = cfg.sni
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
        "server": cfg.address,
        "server_port": int(cfg.port),
        "tls": tls,
    }
    if protocol == "hysteria2":
        outbound["password"] = cfg.uuid_or_password
    else:  # tuic v5: "uuid:password"; the token-only v4 format has no colon
        credential = str(cfg.uuid_or_password or "")
        uuid_part, separator, password_part = credential.partition(":")
        if not separator or not uuid_part.strip() or not password_part.strip():
            return None
        outbound["uuid"] = uuid_part.strip()
        outbound["password"] = password_part.strip()
        outbound["congestion_control"] = "bbr"

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
) -> float | None:
    """Run real HTTPS probes through one sing-box outbound.

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

    try:
        socks_port = _free_local_port()
    except OSError as exc:
        logger.warning("Cannot reserve a local SOCKS port for sing-box: %s", exc)
        return None

    try:
        sb_config = build_singbox_config(cfg, socks_port, dial_proxy_url=dial_proxy_url)
        if sb_config is None:
            return None

        urls = _normalize_probe_urls(None, probe_urls)
        required_successes = min(len(urls), max(1, min_probe_successes))
        accepted = accepted_status_codes or _DEFAULT_ACCEPTED_STATUS_CODES

        with tempfile.TemporaryDirectory(
            prefix="vpnparser-singbox-",
            ignore_cleanup_errors=True,
        ) as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            config_path.write_text(json.dumps(sb_config), encoding="utf-8")
            try:
                proc = await asyncio.create_subprocess_exec(
                    singbox_path,
                    "run",
                    "-c",
                    str(config_path),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except OSError as exc:
                logger.warning("Cannot start sing-box from %s: %s", singbox_path, exc)
                return None
            try:
                if not await _wait_for_port(socks_port, startup_timeout, proc=proc):
                    return None
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
) -> list[Config]:
    """Return QUIC configs that pass a real HTTPS probe through sing-box.

    Probes always dial through the SOCKS pool when one is given — QUIC
    endpoints face the same datacenter-egress filtering the Xray stage works
    around — with the direct path as the empty-pool fallback. The Xray
    bookkeeping fields (``xray_was_checked`` & co) are reused so health
    history, run-summary and the Telegram reporter treat this as the same
    L3 verdict.
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

    for cfg in configs:
        cfg.xray_was_checked = False
        cfg.is_alive = False

    semaphore = asyncio.Semaphore(max(1, concurrency))
    alive: list[Config] = []
    alive_lock = asyncio.Lock()
    done_event = asyncio.Event()
    proxy_urls = [url for url in (probe_proxy_urls or []) if str(url).strip()]
    probe_targets = _normalize_probe_urls(None, probe_urls)

    async def _check_one(cfg: Config) -> None:
        if done_event.is_set():
            return
        async with semaphore:
            if done_event.is_set():
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
                    return
                dial_proxy_url = (
                    attempt_proxies[attempt_index % len(attempt_proxies)]
                    if attempt_proxies
                    else None
                )
                probe_latency = await singbox_probe_check(
                    cfg,
                    singbox_path=singbox_path,
                    probe_urls=probe_targets,
                    min_probe_successes=min_probe_successes,
                    dial_proxy_url=dial_proxy_url,
                    timeout=timeout,
                    startup_timeout=startup_timeout,
                )
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
            if successful_latencies:
                successful_latencies.sort()
                mid = len(successful_latencies) // 2
                cfg.latency_ms = successful_latencies[mid]
            cfg.is_alive = attempt_successes >= required_attempts
            if not cfg.is_alive:
                return
            async with alive_lock:
                alive.append(cfg)
                if max_alive > 0 and len(alive) >= max_alive:
                    done_event.set()

    tasks = [asyncio.create_task(_check_one(cfg)) for cfg in configs]

    if max_alive > 0:
        pending_tasks = set(tasks)
        done_task = asyncio.create_task(done_event.wait())
        while pending_tasks and not done_event.is_set():
            done, _pending = await asyncio.wait(
                [*pending_tasks, done_task],
                return_when=asyncio.FIRST_COMPLETED,
            )
            pending_tasks -= done
        if done_event.is_set():
            for task in pending_tasks:
                task.cancel()
        if not done_task.done():
            done_task.cancel()
            await asyncio.gather(done_task, return_exceptions=True)

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for cfg, result in zip(configs, results, strict=False):
        if isinstance(result, (asyncio.CancelledError, BaseException)):
            cfg.xray_was_checked = False
            if not isinstance(result, asyncio.CancelledError):
                logger.warning(
                    "sing-box probe of %s:%s raised %s: %s",
                    cfg.address,
                    cfg.port,
                    type(result).__name__,
                    result,
                )
    if max_alive > 0 and len(alive) > max_alive:
        del alive[max_alive:]
    return alive
