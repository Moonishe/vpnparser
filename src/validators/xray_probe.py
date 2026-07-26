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
import hashlib
import ipaddress
import json
import logging
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from src.parsers.base import Config
from src.validators.address_guard import filter_public_configs, is_blocked_literal

logger = logging.getLogger(__name__)

_SUPPORTED_PROTOCOLS = {"vless", "trojan", "vmess", "ss"}
_SUPPORTED_NETWORKS = {"tcp", "ws", "grpc"}
_DEFAULT_PROBE_URLS = ["https://www.gstatic.com/generate_204"]
_DEFAULT_IDENTITY_PROBE_URLS = [
    "https://api.ipify.org",
    "https://www.cloudflare.com/cdn-cgi/trace",
]
_DEFAULT_ACCEPTED_STATUS_CODES = set(range(200, 400))
#: Cap on how much of a probe response is buffered before giving up on EOF.
_MAX_PROBE_RESPONSE_BYTES = 64 * 1024
#: Statuses defined to carry no body, so the response ends with its headers.
_BODILESS_STATUS_CODES = frozenset({204, 304})


def _is_rooted_path(candidate: str) -> bool:
    """Return ``True`` when *candidate* never resolves against the current dir.

    ``os.path.isabs`` is not enough on Windows, where a leading separator is
    drive-relative rather than absolute — still rooted, just not at a drive.
    """
    return os.path.isabs(candidate) or candidate.startswith(("/", "\\"))


def _which_in_path(name: str) -> str | None:
    """Resolve *name* through PATH, ignoring hits in the current directory.

    On Windows :func:`shutil.which` searches ``.`` first, so a stray
    ``xray.exe`` next to the working directory would shadow the real
    installation. Such a hit comes back as a path relative to the current
    directory and is rejected here; PATH entries stay.
    """
    resolved = shutil.which(name)
    if resolved and _is_rooted_path(resolved):
        return resolved
    return None


#: Repository root, derived from this file rather than the working directory:
#: ``src/validators/xray_probe.py`` -> ``<root>``.
_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _resolve_configured_path(candidate: str) -> str | None:
    """Resolve an operator-supplied Xray path without consulting the CWD.

    Rooted paths are taken as given. A relative path is anchored at the project
    root — ``XRAY_EXECUTABLE=bin/xray/xray.exe`` is the layout this repository
    ships — so the binary that gets executed does not depend on the directory
    the runner was started from, and a stray ``xray.exe`` sitting in that
    directory can never win. PATH is the last resort.

    Args:
        candidate: Path or program name from settings or the environment.

    Returns:
        A usable path, or ``None`` when the candidate resolves to nothing
        outside the current directory.
    """
    if _is_rooted_path(candidate):
        return candidate if Path(candidate).exists() else None
    anchored = _PROJECT_ROOT / candidate
    if anchored.is_file():
        return str(anchored)
    return _which_in_path(candidate)


def find_xray_executable(explicit_path: str | None = None) -> str | None:
    """Return an executable Xray path from config/env/PATH, if available.

    Configured paths (``explicit_path``, then ``XRAY_EXECUTABLE``) are trusted
    at the same level as the settings file they come from, but are never
    resolved against the current working directory — see
    :func:`_resolve_configured_path`. Bare names fall back to PATH only.
    """
    for candidate in (explicit_path, os.environ.get("XRAY_EXECUTABLE")):
        if not candidate:
            continue
        resolved = _resolve_configured_path(str(candidate))
        if resolved:
            return resolved
    for name in ("xray", "xray.exe"):
        resolved = _which_in_path(name)
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


def _proxy_outbound(proxy_url: str) -> dict[str, Any] | None:
    parsed = urlparse(proxy_url)
    scheme = parsed.scheme.lower()
    if scheme not in {"socks", "socks5", "http"} or not parsed.hostname:
        return None

    server: dict[str, Any] = {
        "address": parsed.hostname,
        "port": int(parsed.port or (1080 if scheme in {"socks", "socks5"} else 8080)),
    }
    if parsed.username or parsed.password:
        server["users"] = [
            {
                "user": unquote(parsed.username) if parsed.username else "",
                "pass": unquote(parsed.password) if parsed.password else "",
            },
        ]
    return {
        "tag": "dial-proxy",
        "protocol": "socks" if scheme in {"socks", "socks5"} else "http",
        "settings": {"servers": [server]},
    }


def build_xray_config(
    cfg: Config,
    socks_port: int,
    *,
    dial_proxy_url: str | None = None,
) -> dict[str, Any] | None:
    """Build a minimal Xray config for one outbound."""
    protocol = str(cfg.protocol or "").lower()
    if protocol not in _SUPPORTED_PROTOCOLS:
        return None

    stream = _stream_settings(cfg)
    if stream is None:
        return None

    outbound: dict[str, Any] = {
        "tag": "vpn",
        "protocol": protocol,
        "streamSettings": stream,
    }
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
                },
            ],
        }
    elif protocol == "trojan":
        outbound["settings"] = {
            "servers": [
                {
                    "address": cfg.address,
                    "port": int(cfg.port),
                    "password": cfg.uuid_or_password,
                },
            ],
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
                        },
                    ],
                },
            ],
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
                },
            ],
        }

    outbounds = [outbound]
    if dial_proxy_url:
        proxy = _proxy_outbound(dial_proxy_url)
        if proxy is None:
            return None
        outbound["proxySettings"] = {"tag": "dial-proxy"}
        outbounds.append(proxy)

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False},
            },
        ],
        "outbounds": outbounds,
    }


def is_xray_supported(cfg: Config) -> bool:
    return build_xray_config(cfg, 1) is not None


#: Port numbers already handed out by _free_local_port() and not released yet.
_reserved_ports: set[int] = set()


def _free_local_port(*, attempts: int = 20) -> int:
    """Reserve a free loopback port number for an Xray instance.

    The probing socket is closed before Xray binds the number, so the OS may
    hand the same port to a second concurrent probe. Numbers handed out in this
    process are tracked until :func:`_release_local_port`, which removes the
    in-process half of that race.
    """
    port = 0
    for _ in range(max(1, attempts)):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(("127.0.0.1", 0))
            port = int(sock.getsockname()[1])
        finally:
            sock.close()
        if port not in _reserved_ports:
            _reserved_ports.add(port)
            return port
    return port


def _release_local_port(port: int) -> None:
    """Give a reserved port number back to the pool."""
    _reserved_ports.discard(port)


async def _wait_for_port(
    port: int,
    timeout: float,
    *,
    proc: asyncio.subprocess.Process | None = None,
) -> bool:
    """Wait until *port* accepts connections on loopback.

    ``proc`` is polled while waiting: if Xray died during startup (typically
    "address already in use"), the probe must fail right away. Otherwise the
    connect could succeed against another probe's listener on the same port
    number and report that config's liveness instead of this one's.
    """
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        if proc is not None and proc.returncode is not None:
            logger.warning(
                "Xray exited with code %s before its SOCKS port %d was ready.",
                proc.returncode,
                port,
            )
            return False
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


def _content_length(header: bytes) -> int | None:
    """Return the ``Content-Length`` a response header block states, if any."""
    for line in header.split(b"\r\n")[1:]:
        name, separator, value = line.partition(b":")
        if separator and name.strip().lower() == b"content-length":
            try:
                length = int(value.strip())
            except ValueError:
                return None
            return length if length >= 0 else None
    return None


def _probe_response_is_complete(chunk: bytes) -> bool:
    """Return ``True`` when *chunk* already holds the whole probe response.

    The request asks for ``Connection: close``, but a keep-alive server or a
    transparent proxy on the path through the VPN may ignore it. Reading to EOF
    then burns the full timeout on every single probe, even though the status
    and body arrived in the first read.
    """
    header, separator, body = chunk.partition(b"\r\n\r\n")
    if not separator:
        return False
    if _http_status_code(header) in _BODILESS_STATUS_CODES:
        return True
    length = _content_length(header)
    return length is not None and len(body) >= length


def _extract_probe_ip(body: str) -> str | None:
    text = body.strip()
    if not text:
        return None

    candidates: list[str] = [text]
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip().lower() in {"ip", "ip_addr", "query"}:
            candidates.append(value.strip())
        else:
            candidates.append(line.strip())

    for candidate in candidates:
        cleaned = candidate.strip().strip("[]")
        try:
            return str(ipaddress.ip_address(cleaned))
        except ValueError:
            continue
    return None


def _probe_ssl_context(verify_tls: bool) -> ssl.SSLContext:
    """Build the TLS context used for probe requests.

    Probe traffic goes *through* the untrusted server under test, so a hostile
    endpoint can terminate TLS itself. With verification on, its self-signed
    certificate fails and it can neither fake a 204 nor fake the outbound IP
    seen by the identity probe. Verification is only skipped when the caller
    opts out via ``verify_probe_tls=False``, which is not the default.
    """
    if verify_tls:
        return ssl.create_default_context()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _is_https_probe_url(url: str) -> bool:
    """Return ``True`` when *url* is something :func:`_https_probe_response` can use."""
    try:
        parsed = urlparse(url)
        return parsed.scheme == "https" and bool(parsed.hostname)
    except ValueError:
        return False


def _normalize_probe_urls(
    probe_url: str | None = None,
    probe_urls: list[str] | tuple[str, ...] | None = None,
) -> list[str]:
    """Return the probe targets to use, in order.

    ``probe_urls`` is authoritative when it holds anything usable: appending
    ``probe_url`` to an operator-supplied list would let a config that fails
    every configured probe pass on the built-in one instead. Non-HTTPS and
    host-less entries are dropped with a warning rather than raising, so one
    typo in the settings cannot abort the liveness stage.

    Args:
        probe_url: Single fallback target, used only when ``probe_urls`` is
            empty.
        probe_urls: Configured targets.
    """
    candidates = [str(url) for url in (probe_urls or [])]
    if not any(url.strip() for url in candidates):
        candidates = [str(probe_url)] if probe_url else list(_DEFAULT_PROBE_URLS)

    normalized: list[str] = []
    seen: set[str] = set()
    for url in candidates:
        cleaned = url.strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        if not _is_https_probe_url(cleaned):
            logger.warning("Ignoring probe URL %r: not an HTTPS URL.", cleaned)
            continue
        normalized.append(cleaned)
    return normalized or list(_DEFAULT_PROBE_URLS)


async def _https_probe_response(
    *,
    probe_url: str,
    timeout: float,
    socks_port: int | None = None,
    proxy_url: str | None = None,
    verify_tls: bool = True,
) -> tuple[int | None, str]:
    parsed = urlparse(probe_url)
    host = parsed.hostname
    if parsed.scheme != "https" or not host:
        raise ValueError(f"probe_url must be HTTPS: {probe_url!r}")
    port = parsed.port or 443
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    writer = None
    try:
        sock = None
        if socks_port is not None or proxy_url:
            from python_socks.async_.asyncio import Proxy

            proxy = Proxy.from_url(proxy_url or f"socks5://127.0.0.1:{socks_port}")
            sock = await proxy.connect(dest_host=host, dest_port=port, timeout=timeout)
        # The probe target is a public host with a valid certificate, unlike the
        # VPN endpoint itself — verify it, see _probe_ssl_context().
        context = _probe_ssl_context(verify_tls)
        if sock is not None:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(sock=sock, ssl=context, server_hostname=host),
                timeout=timeout,
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=context, server_hostname=host),
                timeout=timeout,
            )
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "User-Agent: vpn-config-parser/1.0\r\n"
            "Connection: close\r\n\r\n"
        )
        if writer is None:
            return (None, "")
        writer.write(request.encode("ascii"))
        await writer.drain()
        # Headers and body usually arrive in separate TLS records, so a single
        # read() often yields the headers only and loses the identity body.
        # Stop as soon as the response is provably complete; EOF, the deadline
        # and the size cap are only the fallbacks for servers that do not say
        # how long the body is.
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        buffer = bytearray()
        while len(buffer) < _MAX_PROBE_RESPONSE_BYTES:
            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            try:
                piece = await asyncio.wait_for(reader.read(4096), timeout=remaining)
            except TimeoutError:
                break
            if not piece:
                break
            buffer += piece
            if _probe_response_is_complete(bytes(buffer)):
                break
        chunk = bytes(buffer)
    except Exception:
        return (None, "")
    finally:
        with contextlib.suppress(Exception):
            if writer is not None:
                writer.close()
                await writer.wait_closed()

    header, _, body = chunk.partition(b"\r\n\r\n")
    return (_http_status_code(header), body.decode("utf-8", errors="ignore"))


async def _https_probe_via_socks(
    socks_port: int,
    *,
    probe_url: str,
    timeout: float,
    verify_tls: bool = True,
) -> int | None:
    status_code, _body = await _https_probe_response(
        probe_url=probe_url,
        timeout=timeout,
        socks_port=socks_port,
        verify_tls=verify_tls,
    )
    return status_code


async def discover_public_ip(
    *,
    probe_urls: list[str] | tuple[str, ...] | None = None,
    proxy_url: str | None = None,
    timeout: float = 12.0,
    verify_tls: bool = True,
) -> str | None:
    """Return the public IP seen by an identity endpoint."""
    urls = _normalize_probe_urls(None, probe_urls or _DEFAULT_IDENTITY_PROBE_URLS)
    for url in urls:
        status_code, body = await _https_probe_response(
            probe_url=url,
            timeout=timeout,
            proxy_url=proxy_url,
            verify_tls=verify_tls,
        )
        if status_code not in _DEFAULT_ACCEPTED_STATUS_CODES:
            continue
        found = _extract_probe_ip(body)
        if found:
            return found
    return None


def _rotated_proxy_urls_for_config(
    cfg: Config,
    proxy_urls: list[str] | tuple[str, ...],
) -> list[str]:
    """Rotate proxy order per config so one bad proxy prefix cannot poison a run."""
    urls = [str(url).strip() for url in proxy_urls if str(url).strip()]
    if len(urls) <= 1:
        return urls
    key = f"{cfg.address}:{cfg.port}:{cfg.uuid_or_password}".encode()
    offset = int.from_bytes(hashlib.sha256(key).digest()[:4], "big") % len(urls)
    return [*urls[offset:], *urls[:offset]]


async def xray_probe_check(
    cfg: Config,
    *,
    xray_path: str,
    probe_url: str | None = "https://www.gstatic.com/generate_204",
    probe_urls: list[str] | tuple[str, ...] | None = None,
    min_probe_successes: int = 1,
    accepted_status_codes: set[int] | None = None,
    dial_proxy_url: str | None = None,
    require_distinct_outbound_ip: bool = False,
    reject_outbound_ips: set[str] | None = None,
    verify_probe_tls: bool = True,
    timeout: float = 12.0,
    startup_timeout: float = 4.0,
) -> bool:
    """Run real HTTPS probes through one Xray outbound."""
    if is_blocked_literal(cfg.address):
        logger.warning(
            "Refusing Xray probe of non-public address %s:%s.",
            cfg.address,
            cfg.port,
        )
        return False

    socks_port = _free_local_port()
    # Everything below runs under one finally: a reserved port number that is
    # never released is burnt for the lifetime of the process, and preparing the
    # config can fail for reasons of its own (full disk, locked temp file).
    try:
        xray_config = build_xray_config(cfg, socks_port, dial_proxy_url=dial_proxy_url)
        if xray_config is None:
            return False

        urls = _normalize_probe_urls(probe_url, probe_urls)
        required_successes = min(len(urls), max(1, min_probe_successes))
        accepted = accepted_status_codes or _DEFAULT_ACCEPTED_STATUS_CODES
        rejected_ips = {
            str(ip).strip() for ip in (reject_outbound_ips or set()) if str(ip).strip()
        }

        with tempfile.TemporaryDirectory(prefix="vpnparser-xray-") as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            config_path.write_text(json.dumps(xray_config), encoding="utf-8")
            try:
                proc = await asyncio.create_subprocess_exec(
                    xray_path,
                    "run",
                    "-config",
                    str(config_path),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except OSError as exc:
                # Deleted binary, missing permissions, antivirus lock: without
                # this every config would silently fail with is_alive=False.
                logger.warning("Cannot start Xray from %s: %s", xray_path, exc)
                return False
            try:
                if not await _wait_for_port(socks_port, startup_timeout, proc=proc):
                    return False
                successes = 0
                failures_allowed = len(urls) - required_successes
                failures = 0
                identity_ok = False
                for url in urls:
                    status_code, body = await _https_probe_response(
                        socks_port=socks_port,
                        probe_url=url,
                        timeout=timeout,
                        verify_tls=verify_probe_tls,
                    )
                    if status_code in accepted:
                        successes += 1
                        outbound_ip = _extract_probe_ip(body)
                        if outbound_ip and outbound_ip not in rejected_ips:
                            identity_ok = True
                        if successes >= required_successes and (
                            not require_distinct_outbound_ip or identity_ok
                        ):
                            return True
                        continue

                    failures += 1
                    if failures > failures_allowed:
                        return False
                return successes >= required_successes and (
                    not require_distinct_outbound_ip or identity_ok
                )
            finally:
                if proc.returncode is None:
                    proc.terminate()
                    try:
                        await asyncio.wait_for(proc.wait(), timeout=2.0)
                    except TimeoutError:
                        proc.kill()
                        with contextlib.suppress(Exception):
                            await proc.wait()
    finally:
        _release_local_port(socks_port)


async def validate_configs_xray(
    configs: list[Config],
    *,
    xray_path: str,
    probe_url: str = "https://www.gstatic.com/generate_204",
    probe_urls: list[str] | tuple[str, ...] | None = None,
    min_probe_successes: int = 1,
    attempts_per_config: int = 1,
    min_attempt_successes: int = 1,
    probe_proxy_urls: list[str] | tuple[str, ...] | None = None,
    min_proxy_successes: int = 0,
    require_distinct_outbound_ip: bool = False,
    verify_probe_tls: bool = True,
    check_hostnames: bool = True,
    timeout: float = 12.0,
    startup_timeout: float = 4.0,
    concurrency: int = 6,
    max_alive: int = 0,
) -> list[Config]:
    """Return configs that can pass a real HTTPS probe through Xray.

    ``probe_urls`` is the authoritative list of probe targets; ``probe_url`` is
    a fallback used only when that list is empty — see
    :func:`_normalize_probe_urls`.
    """
    if not configs:
        return []

    configs = await filter_public_configs(
        configs,
        stage="Xray probe",
        check_hostnames=check_hostnames,
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
    reject_ips: set[str] = set()
    proxy_reject_ips: dict[str, set[str]] = {}
    probe_targets = _normalize_probe_urls(probe_url, probe_urls)
    if require_distinct_outbound_ip:
        identity_urls = [
            url
            for url in probe_targets
            if url in _DEFAULT_IDENTITY_PROBE_URLS
            or "ipify" in url
            or "cdn-cgi/trace" in url
        ]
        identity_urls = identity_urls or list(_DEFAULT_IDENTITY_PROBE_URLS)
        # The distinct-IP verdict reads the outbound IP out of a probe body, so
        # the probes themselves must hit an identity endpoint. A status-only
        # target (generate_204) has an empty body and would fail every config.
        probe_targets = [
            *probe_targets,
            *[url for url in identity_urls if url not in probe_targets],
        ]
        direct_ip = await discover_public_ip(
            probe_urls=identity_urls,
            timeout=timeout,
            verify_tls=verify_probe_tls,
        )
        if direct_ip is None and require_distinct_outbound_ip:
            logger.warning(
                "require_distinct_outbound_ip is True but cannot determine "
                "direct public IP — failing closed (no configs pass).",
            )
            return []
        if direct_ip:
            reject_ips.add(direct_ip)
        if proxy_urls:
            proxy_results = await asyncio.gather(
                *[
                    discover_public_ip(
                        probe_urls=identity_urls,
                        proxy_url=str(proxy_url).strip(),
                        timeout=timeout,
                        verify_tls=verify_probe_tls,
                    )
                    for proxy_url in proxy_urls
                ],
                return_exceptions=True,
            )
            for proxy_url, found in zip(proxy_urls, proxy_results, strict=False):
                proxy_reject_ips[str(proxy_url).strip()] = set(reject_ips)
                if isinstance(found, str) and found.strip():
                    proxy_reject_ips[str(proxy_url).strip()].add(found.strip())

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
            for _attempt in range(attempts):
                started = time.monotonic()
                ok = await xray_probe_check(
                    cfg,
                    xray_path=xray_path,
                    probe_url=None,
                    probe_urls=probe_targets,
                    min_probe_successes=min_probe_successes,
                    require_distinct_outbound_ip=require_distinct_outbound_ip,
                    reject_outbound_ips=reject_ips,
                    verify_probe_tls=verify_probe_tls,
                    timeout=timeout,
                    startup_timeout=startup_timeout,
                )
                if ok:
                    successful_latencies.append((time.monotonic() - started) * 1000)
                    attempt_successes += 1
                    if attempt_successes >= required_attempts:
                        break
                    continue

                attempt_failures += 1
                if attempt_failures > failures_allowed:
                    break

            ok = attempt_successes >= required_attempts
            proxy_successes = 0
            required_proxy_successes = max(0, min_proxy_successes)
            # With required_proxy_successes == 0 the requirement is already met,
            # so the loop would only burn one Xray startup per dead proxy.
            if ok and proxy_urls and required_proxy_successes > 0:
                for proxy_url in _rotated_proxy_urls_for_config(cfg, proxy_urls):
                    proxy_url = str(proxy_url).strip()
                    proxy_ok = await xray_probe_check(
                        cfg,
                        xray_path=xray_path,
                        probe_url=None,
                        probe_urls=probe_targets,
                        min_probe_successes=min_probe_successes,
                        dial_proxy_url=proxy_url,
                        require_distinct_outbound_ip=require_distinct_outbound_ip,
                        reject_outbound_ips=proxy_reject_ips.get(proxy_url, reject_ips),
                        verify_probe_tls=verify_probe_tls,
                        timeout=timeout,
                        startup_timeout=startup_timeout,
                    )
                    if proxy_ok:
                        proxy_successes += 1
                        if proxy_successes >= required_proxy_successes:
                            break
                ok = proxy_successes >= required_proxy_successes

            cfg.xray_attempt_successes = attempt_successes
            cfg.xray_attempts_per_config = attempts
            cfg.xray_proxy_successes = proxy_successes
            cfg.xray_proxy_checks = len(proxy_urls)
            if successful_latencies:
                successful_latencies.sort()
                mid = len(successful_latencies) // 2
                cfg.latency_ms = successful_latencies[mid]
            cfg.is_alive = ok
            if not ok:
                return
            async with alive_lock:
                alive.append(cfg)
                if max_alive > 0 and len(alive) >= max_alive:
                    done_event.set()

    tasks = [asyncio.create_task(_check_one(cfg)) for cfg in configs]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for cfg, result in zip(configs, results, strict=False):
        if isinstance(result, asyncio.CancelledError):
            continue
        if isinstance(result, BaseException):
            # Without this the real reason (missing binary, permission error)
            # is swallowed and the whole stage just returns no configs.
            logger.warning(
                "Xray probe of %s:%s raised %s: %s",
                cfg.address,
                cfg.port,
                type(result).__name__,
                result,
            )
    return alive
