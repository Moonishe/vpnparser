"""L3 validator: real outbound probe through Xray-core.

TCP and TLS checks only prove that a server is reachable and speaks something
TLS-like. This validator starts Xray with a single outbound config and a local
SOCKS inbound, then performs a small HTTPS request through that SOCKS listener.
If the request succeeds, the VPN config is much closer to what an actual client
can use.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import logging
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from src.parsers.base import Config

logger = logging.getLogger(__name__)

_SUPPORTED_PROTOCOLS = {"vless", "trojan", "vmess", "ss"}
_SUPPORTED_NETWORKS = {"tcp", "ws", "grpc"}
_DEFAULT_PROBE_URLS = ["https://www.gstatic.com/generate_204"]
_DEFAULT_ACCEPTED_STATUS_CODES = set(range(200, 400))


def find_xray_executable(explicit_path: str | None = None) -> str | None:
    """Return an executable Xray path from config/env/PATH, if available."""
    candidates = [
        explicit_path,
        os.environ.get("XRAY_EXECUTABLE"),
        shutil.which("xray"),
        shutil.which("xray.exe"),
    ]
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(str(candidate))
        if path.exists():
            return str(path)
        if os.path.isabs(str(candidate)):
            continue
        resolved = shutil.which(str(candidate))
        if resolved:
            return resolved
    return None


def _first_csv(value: str | None) -> str | None:
    if not value:
        return None
    for part in str(value).replace(";", ",").split(","):
        cleaned = part.strip().strip("\"'")
        if cleaned:
            return cleaned
    return None


def _is_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return False
    return True


def _server_name(cfg: Config) -> str | None:
    for candidate in (_first_csv(cfg.sni), _first_csv(cfg.host), cfg.address):
        if candidate and not _is_ip(candidate):
            return candidate
    return None


def _alpn(value: str | None) -> list[str] | None:
    if not value:
        return None
    protocols = [part.strip() for part in value.replace(";", ",").split(",")]
    protocols = [part for part in protocols if part]
    return protocols or None


def _stream_settings(cfg: Config) -> dict[str, Any] | None:
    network = str(cfg.network or "tcp").lower()
    security = str(cfg.security or "none").lower()
    if network not in _SUPPORTED_NETWORKS:
        return None

    stream: dict[str, Any] = {"network": network}

    if network == "ws":
        ws: dict[str, Any] = {}
        if cfg.path:
            ws["path"] = cfg.path
        if cfg.host:
            ws["headers"] = {"Host": _first_csv(cfg.host) or cfg.host}
        stream["wsSettings"] = ws
    elif network == "grpc":
        grpc: dict[str, Any] = {}
        if cfg.path:
            grpc["serviceName"] = cfg.path.lstrip("/")
        if cfg.host:
            grpc["authority"] = _first_csv(cfg.host) or cfg.host
        stream["grpcSettings"] = grpc

    if security == "reality":
        if not cfg.pbk:
            return None
        reality: dict[str, Any] = {
            "fingerprint": cfg.fp or "chrome",
            "serverName": _server_name(cfg) or "",
            "publicKey": cfg.pbk,
            "shortId": cfg.sid or "",
            "spiderX": "/",
        }
        stream["security"] = "reality"
        stream["realitySettings"] = reality
    elif security == "tls":
        tls: dict[str, Any] = {}
        server_name = _server_name(cfg)
        if server_name:
            tls["serverName"] = server_name
        if cfg.fp:
            tls["fingerprint"] = cfg.fp
        alpn = _alpn(cfg.alpn)
        if alpn:
            tls["alpn"] = alpn
        stream["security"] = "tls"
        stream["tlsSettings"] = tls
    elif security != "none":
        return None

    return stream


def build_xray_config(cfg: Config, socks_port: int) -> dict[str, Any] | None:
    """Build a minimal Xray config for one outbound."""
    protocol = str(cfg.protocol or "").lower()
    if protocol not in _SUPPORTED_PROTOCOLS:
        return None

    stream = _stream_settings(cfg)
    if stream is None:
        return None

    outbound: dict[str, Any] = {"protocol": protocol, "streamSettings": stream}
    if protocol == "vless":
        user: dict[str, Any] = {
            "id": cfg.uuid_or_password,
            "encryption": "none",
        }
        if cfg.flow:
            user["flow"] = cfg.flow
        outbound["settings"] = {
            "vnext": [
                {
                    "address": cfg.address,
                    "port": int(cfg.port),
                    "users": [user],
                }
            ]
        }
    elif protocol == "trojan":
        outbound["settings"] = {
            "servers": [
                {
                    "address": cfg.address,
                    "port": int(cfg.port),
                    "password": cfg.uuid_or_password,
                }
            ]
        }
    elif protocol == "vmess":
        outbound["settings"] = {
            "vnext": [
                {
                    "address": cfg.address,
                    "port": int(cfg.port),
                    "users": [
                        {
                            "id": cfg.uuid_or_password,
                            "alterId": 0,
                            "security": "auto",
                        }
                    ],
                }
            ]
        }
    elif protocol == "ss":
        if not cfg.ss_method:
            return None
        outbound["settings"] = {
            "servers": [
                {
                    "address": cfg.address,
                    "port": int(cfg.port),
                    "method": cfg.ss_method,
                    "password": cfg.uuid_or_password,
                }
            ]
        }

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False},
            }
        ],
        "outbounds": [outbound],
    }


def is_xray_supported(cfg: Config) -> bool:
    return build_xray_config(cfg, 1) is not None


def _free_local_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


async def _wait_for_port(port: int, timeout: float) -> bool:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
        except OSError:
            await asyncio.sleep(0.05)
            continue
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        return True
    return False


def _http_status_code(chunk: bytes) -> int | None:
    if not chunk.startswith(b"HTTP/"):
        return None
    parts = chunk.split(maxsplit=2)
    if len(parts) < 2:
        return None
    try:
        return int(parts[1])
    except ValueError:
        return None


def _normalize_probe_urls(
    probe_url: str | None = None,
    probe_urls: list[str] | tuple[str, ...] | None = None,
) -> list[str]:
    candidates: list[str] = []
    if probe_urls:
        candidates.extend(str(url) for url in probe_urls)
    if probe_url:
        candidates.append(str(probe_url))
    if not candidates:
        candidates.extend(_DEFAULT_PROBE_URLS)

    normalized: list[str] = []
    seen: set[str] = set()
    for url in candidates:
        cleaned = url.strip()
        if not cleaned or cleaned in seen:
            continue
        normalized.append(cleaned)
        seen.add(cleaned)
    return normalized or list(_DEFAULT_PROBE_URLS)


async def _https_probe_via_socks(
    socks_port: int,
    *,
    probe_url: str,
    timeout: float,
) -> int | None:
    parsed = urlparse(probe_url)
    host = parsed.hostname
    if parsed.scheme != "https" or not host:
        raise ValueError(f"probe_url must be HTTPS: {probe_url!r}")
    port = parsed.port or 443
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    try:
        from python_socks.async_.asyncio import Proxy

        proxy = Proxy.from_url(f"socks5://127.0.0.1:{socks_port}")
        sock = await proxy.connect(dest_host=host, dest_port=port, timeout=timeout)
        context = ssl.create_default_context()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(sock=sock, ssl=context, server_hostname=host),
            timeout=timeout,
        )
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "User-Agent: vpn-config-parser/1.0\r\n"
            "Connection: close\r\n\r\n"
        )
        writer.write(request.encode("ascii"))
        await writer.drain()
        chunk = await asyncio.wait_for(reader.read(64), timeout=timeout)
    except Exception:
        return None
    finally:
        with contextlib.suppress(Exception):
            writer.close()  # type: ignore[name-defined]
            await writer.wait_closed()  # type: ignore[name-defined]

    return _http_status_code(chunk)


async def xray_probe_check(
    cfg: Config,
    *,
    xray_path: str,
    probe_url: str = "https://www.gstatic.com/generate_204",
    probe_urls: list[str] | tuple[str, ...] | None = None,
    min_probe_successes: int = 1,
    accepted_status_codes: set[int] | None = None,
    timeout: float = 12.0,
    startup_timeout: float = 4.0,
) -> bool:
    """Run real HTTPS probes through one Xray outbound."""
    socks_port = _free_local_port()
    xray_config = build_xray_config(cfg, socks_port)
    if xray_config is None:
        return False

    urls = _normalize_probe_urls(probe_url, probe_urls)
    required_successes = min(len(urls), max(1, min_probe_successes))
    accepted = accepted_status_codes or _DEFAULT_ACCEPTED_STATUS_CODES

    with tempfile.TemporaryDirectory(prefix="vpnparser-xray-") as tmpdir:
        config_path = Path(tmpdir) / "config.json"
        config_path.write_text(json.dumps(xray_config), encoding="utf-8")
        proc = await asyncio.create_subprocess_exec(
            xray_path,
            "run",
            "-config",
            str(config_path),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            if not await _wait_for_port(socks_port, startup_timeout):
                return False
            successes = 0
            failures_allowed = len(urls) - required_successes
            failures = 0
            for url in urls:
                status_code = await _https_probe_via_socks(
                    socks_port,
                    probe_url=url,
                    timeout=timeout,
                )
                if status_code in accepted:
                    successes += 1
                    if successes >= required_successes:
                        return True
                    continue

                failures += 1
                if failures > failures_allowed:
                    return False
            return successes >= required_successes
        finally:
            if proc.returncode is None:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=2.0)
                except asyncio.TimeoutError:
                    proc.kill()
                    with contextlib.suppress(Exception):
                        await proc.wait()


async def validate_configs_xray(
    configs: list[Config],
    *,
    xray_path: str,
    probe_url: str = "https://www.gstatic.com/generate_204",
    probe_urls: list[str] | tuple[str, ...] | None = None,
    min_probe_successes: int = 1,
    timeout: float = 12.0,
    startup_timeout: float = 4.0,
    concurrency: int = 6,
    max_alive: int = 0,
) -> list[Config]:
    """Return configs that can pass a real HTTPS probe through Xray."""
    if not configs:
        return []

    semaphore = asyncio.Semaphore(max(1, concurrency))
    alive: list[Config] = []
    alive_lock = asyncio.Lock()
    done_event = asyncio.Event()

    async def _check_one(cfg: Config) -> None:
        if done_event.is_set():
            return
        async with semaphore:
            if done_event.is_set():
                return
            ok = await xray_probe_check(
                cfg,
                xray_path=xray_path,
                probe_url=probe_url,
                probe_urls=probe_urls,
                min_probe_successes=min_probe_successes,
                timeout=timeout,
                startup_timeout=startup_timeout,
            )
            cfg.is_alive = ok
            if not ok:
                return
            async with alive_lock:
                alive.append(cfg)
                if max_alive > 0 and len(alive) >= max_alive:
                    done_event.set()

    tasks = [asyncio.create_task(_check_one(cfg)) for cfg in configs]
    await asyncio.gather(*tasks, return_exceptions=True)
    return alive
