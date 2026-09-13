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
import functools
import hashlib
import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import ssl
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

logger = logging.getLogger(__name__)

_SUPPORTED_PROTOCOLS = {"vless", "trojan", "vmess", "ss"}
_SUPPORTED_NETWORKS = {"tcp", "ws", "grpc", "httpupgrade", "xhttp"}
#: REALITY is implemented over RAW (tcp), gRPC and XHTTP only; any other
#: combination makes Xray refuse the whole config at load time
#: ("REALITY only supports RAW, XHTTP and gRPC for now").
_REALITY_NETWORKS = {"tcp", "grpc", "xhttp"}
_DEFAULT_PROBE_URLS = ["https://www.gstatic.com/generate_204"]
_DEFAULT_IDENTITY_PROBE_URLS = [
    "https://api.ipify.org",
    "https://www.cloudflare.com/cdn-cgi/trace",
]
_DEFAULT_ACCEPTED_STATUS_CODES = set(range(200, 300))
#: Cap on how much of a probe response is buffered before giving up on EOF.
_MAX_PROBE_RESPONSE_BYTES = 64 * 1024
#: Statuses defined to carry no body, so the response ends with its headers.
_BODILESS_STATUS_CODES = frozenset({204, 304})
#: Terminator of a chunked body.
_LAST_CHUNK = b"0\r\n\r\n"
#: How long a body no header framed may still keep the probe waiting.
_UNFRAMED_BODY_IDLE_SECONDS = 2.0
#: Interval of the stage heartbeat ("X checked, Y alive") in long probe runs.
_PROBE_HEARTBEAT_SECONDS = 60


class _NoVerdictError(Exception):
    """Probe reached no verdict (infra/timeout), not a dead server.

    Raised for per-config ceiling timeouts, DNS-pin failures, port
    exhaustion, spawn failures and startup timeouts. Callers convert
    it to ``xray_was_checked=False, is_alive=None`` so health history
    records nothing instead of a false failure.
    """


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
    root — the CI layout is ``bin/xray/xray`` (see update.yml), the local
    Windows checkout ships the flat ``bin/xray.exe`` — so the binary that gets
    executed does not depend on the directory the runner was started from, and
    a stray ``xray.exe`` sitting in that directory can never win. PATH is the
    last resort; there is NO implicit ``bin/`` scan.

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


#: Allowed characters in a server name passed to Xray. SNI/serverName comes
#: from an untrusted subscription link, so anything outside DNS characters is
#: rejected instead of being handed to the probe verbatim; a weird value would
#: otherwise just fail the probe with an opaque Xray error.
_SERVER_NAME_RE = re.compile(r"^[A-Za-z0-9._*-]+$")
_MAX_SERVER_NAME_LENGTH = 253


def _valid_server_name(value: str | None) -> bool:
    """Return ``True`` when *value* is a sane DNS-style server name."""
    if not value or len(value) > _MAX_SERVER_NAME_LENGTH:
        return False
    return _SERVER_NAME_RE.match(value) is not None


def _server_name(cfg: Config) -> str | None:
    for candidate in (_first_csv(cfg.sni), _first_csv(cfg.host), cfg.address):
        if candidate and not _is_ip(candidate) and _valid_server_name(candidate):
            return candidate
    return None


def _alpn(value: str | None) -> list[str] | None:
    if not value:
        return None
    protocols = [part.strip() for part in value.replace(";", ",").split(",")]
    protocols = [part for part in protocols if part]
    return protocols or None


def _clean_transport_field(value: str | None) -> bool:
    """Return ``True`` when *value* holds no control characters (CR/LF incl.).

    ``path``/``host`` come from untrusted subscription links and are placed
    verbatim into Xray settings (ws Host header, grpc serviceName,
    httpupgrade host, xhttp path); SNI is regex-validated separately, these
    fields only get the cheapest safe check. Anything with a control
    character makes the probe fail — the value is never transformed.
    """
    if not value:
        return True
    return not any(ord(char) < 0x20 or char == "\x7f" for char in value)


def _stream_settings(cfg: Config) -> dict[str, Any] | None:
    network = str(cfg.network or "tcp").lower()
    security = str(cfg.security or "none").lower()
    # The old H2 transport ("h2", and v2rayN's ``type=http`` alias) was
    # removed from Xray-core in v24.12.18 — such configs cannot be probed on
    # the pinned core at all, so they stay "unsupported" instead of dying on
    # an Xray startup error. ``splithttp`` is the old name of xhttp; both
    # spellings still load.
    if network == "splithttp":
        network = "xhttp"
    if network not in _SUPPORTED_NETWORKS:
        return None
    if not _clean_transport_field(cfg.path) or not _clean_transport_field(cfg.host):
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
    elif network == "httpupgrade":
        upgrade: dict[str, Any] = {}
        if cfg.path:
            upgrade["path"] = cfg.path
        if cfg.host:
            upgrade["host"] = _first_csv(cfg.host) or cfg.host
        stream["httpupgradeSettings"] = upgrade
    elif network == "xhttp":
        xhttp: dict[str, Any] = {}
        if cfg.path:
            xhttp["path"] = cfg.path
        if cfg.host:
            xhttp["host"] = _first_csv(cfg.host) or cfg.host
        stream["xhttpSettings"] = xhttp

    if security == "reality":
        if network not in _REALITY_NETWORKS:
            return None
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
        # NOTE, verified against bin/xray.exe (Xray 26.3.27) on 2026-09-12:
        # this tunnel endpoint IS certificate-verified. The previous comment
        # here claimed a "non-verifying tunnel endpoint, as before"; that was
        # wrong on both counts. Xray >= 24 removed `allowInsecure` (26.x
        # rejects it with exit 23), and `pinnedPeerCertSha256: []` is a schema
        # error rather than a no-op: the field is a hex STRING, and a JSON
        # array fails to unmarshal. Neither key is emitted below, so both the
        # chain and the hostname of the endpoint are checked.
        #
        # Measured cost of that, on the live corpus: 147 reachable TLS
        # endpoints were sampled and NONE was self-signed, so this does not
        # currently drop configs. A handshake against a genuinely self-signed
        # endpoint does fail with "x509: certificate signed by unknown
        # authority"; to probe one, obtain the leaf SHA-256 out of band (TOFU)
        # and set `pinnedPeerCertSha256` to that hex string.
        #
        # Probe integrity is provided separately by verifying the PROBE
        # TARGET's certificate (_probe_ssl_context).
        stream["security"] = "tls"
        stream["tlsSettings"] = tls
    elif security != "none":
        return None

    return stream


def _proxy_outbound(proxy_url: str) -> dict[str, Any] | None:
    try:
        parsed = urlparse(proxy_url)
        # Reading .port validates it and raises ValueError on garbage like
        # "socks5://h:notaport" — one bad operator URL must not crash the
        # probe phase for every config. Port 0 is compared against None, not
        # truthiness: a literal 0 is invalid for a listener but is a valid
        # parse result, and `or` silently turned it into the default.
        port = parsed.port
        if port is None:
            port = 1080 if parsed.scheme.lower() in {"socks", "socks5"} else 8080
        port = int(port)
    except ValueError:
        logger.warning(
            "Skipping invalid proxy url (bad port): %r",
            redact_proxy_url(proxy_url),
        )
        return None
    scheme = parsed.scheme.lower()
    if scheme not in {"socks", "socks5", "http"} or not parsed.hostname:
        return None

    server: dict[str, Any] = {
        "address": parsed.hostname,
        "port": port,
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
    pinned_address: str | None = None,
) -> dict[str, Any] | None:
    """Build a minimal Xray config for one outbound.

    ``pinned_address`` (a validated public IP literal) replaces the address
    in the *connect* fields while SNI/Host keep the hostname: handing the
    raw hostname to Xray lets the core resolve it itself, reopening the
    resolve-then-connect window the TCP/TLS stages close via
    :func:`resolve_pinned_address`.
    """
    connect_address = pinned_address or cfg.address
    protocol = str(cfg.protocol or "").lower()
    if protocol not in _SUPPORTED_PROTOCOLS:
        return None

    stream = _stream_settings(cfg)
    if stream is None:
        return None

    outbound: dict[str, Any] = {
        "tag": "vpn",
        # Xray's outbound registry only knows "shadowsocks"; the link scheme
        # and the internal protocol id stay "ss".
        "protocol": "shadowsocks" if protocol == "ss" else protocol,
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
                    "address": connect_address,
                    "port": int(cfg.port),
                    "users": [user],
                },
            ],
        }
    elif protocol == "trojan":
        outbound["settings"] = {
            "servers": [
                {
                    "address": connect_address,
                    "port": int(cfg.port),
                    "password": cfg.uuid_or_password,
                },
            ],
        }
    elif protocol == "vmess":
        user = {
            "id": cfg.uuid_or_password,
            # Ignored by Xray >= 1.8.5 (legacy MD5 auth removed, client is
            # AEAD-only); older cores still need the panel's real value.
            "alterId": int(cfg.alter_id or 0),
            "security": "auto",
        }
        outbound["settings"] = {
            "vnext": [
                {
                    "address": connect_address,
                    "port": int(cfg.port),
                    "users": [user],
                },
            ],
        }
    elif protocol == "ss":
        if not cfg.ss_method:
            return None
        outbound["settings"] = {
            "servers": [
                {
                    "address": connect_address,
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

    Raises:
        OSError: When no *unreserved* port could be bound, or when binding
            itself failed. Returning an unreserved number instead would hand
            out a port another probe is still using — and the caller's
            ``_release_local_port`` would then drop that probe's reservation,
            leaving a third probe free to collide with it.
    """
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
    msg = f"no unreserved loopback port after {max(1, attempts)} attempt(s)"
    raise OSError(msg)


def _release_local_port(port: int) -> None:
    """Give a reserved port number back to the pool."""
    _reserved_ports.discard(port)


_PROBE_DIR_PREFIXES = ("vpnparser-xray-", "vpnparser-singbox-")

#: A directory younger than this belongs to a live probe of another pipeline
#: process (manual run next to --continuous): rmtree-ing it would unlink that
#: probe's config.json mid-run. Older than this, the owner is gone.
_SWEEP_MIN_AGE_SECONDS = 600.0


def _sweep_stale_probe_dirs(
    prefixes: tuple[str, ...] = _PROBE_DIR_PREFIXES,
    *,
    min_age_seconds: float = _SWEEP_MIN_AGE_SECONDS,
) -> int:
    """Best-effort delete leftover probe temp directories from earlier runs.

    ``ignore_cleanup_errors=True`` keeps a cleanup failure from corrupting a
    verdict, but on Windows the failed rmtree left the directory behind —
    each one carrying ``config.json`` with the probe's credentials. A short
    sweep at stage start reclaims them once the owning processes are gone.
    Fresh directories are skipped: two pipeline processes on one host would
    otherwise delete each other's live probe configs.
    """
    removed = 0
    now = time.time()
    with contextlib.suppress(OSError):
        for entry in Path(tempfile.gettempdir()).iterdir():
            if not entry.is_dir() or not entry.name.startswith(prefixes):
                continue
            try:
                if now - entry.stat().st_mtime < min_age_seconds:
                    continue
            except OSError:
                continue
            try:
                shutil.rmtree(entry, ignore_errors=False)
            except OSError:
                continue
            removed += 1
    if removed:
        logger.info("Reclaimed %d leftover probe temp director(y/ies).", removed)
    return removed


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


def _is_chunked_transfer(header: bytes) -> bool:
    """Return ``True`` when the response header block announces chunking."""
    for line in header.split(b"\r\n")[1:]:
        name, separator, value = line.partition(b":")
        if separator and name.strip().lower() == b"transfer-encoding":
            return b"chunked" in value.lower()
    return False


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
    if _is_chunked_transfer(header):
        return body.endswith(_LAST_CHUNK)
    length = _content_length(header)
    return length is not None and len(body) >= length


def _probe_response_is_unframed(chunk: bytes) -> bool:
    """Return ``True`` when the headers are in but nothing bounds the body.

    Neither ``Content-Length`` nor chunking means the body ends at EOF — which
    a server ignoring ``Connection: close`` never sends. Such a response is
    otherwise complete on arrival, so it must not cost the whole probe timeout.
    """
    header, separator, _body = chunk.partition(b"\r\n\r\n")
    if not separator:
        return False
    if _http_status_code(header) in _BODILESS_STATUS_CODES:
        return False
    return not _is_chunked_transfer(header) and _content_length(header) is None


#: Explicitly local answer ranges for the identity-probe verdict. Deliberately
#: NOT ``ipaddress``'s ``is_private``: that flag also covers documentation
#: ranges (TEST-NET-1/2/3), which the pipeline's fixtures and logs treat as
#: public addresses. What must be rejected is space no routable server lives
#: in: RFC1918, loopback, link-local (incl. the cloud metadata endpoint),
#: CGNAT, this-host and broadcast.
_LOCAL_OUTBOUND_V4_NETWORKS = (
    ipaddress.IPv4Network("0.0.0.0/8"),
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("100.64.0.0/10"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("255.255.255.255/32"),
)
_LOCAL_OUTBOUND_V6_NETWORKS = (
    ipaddress.IPv6Network("::1/128"),
    ipaddress.IPv6Network("fe80::/10"),
    ipaddress.IPv6Network("fc00::/7"),
)


def _is_local_outbound_ip(ip_text: str) -> bool:
    """Return ``True`` for RFC1918/loopback/link-local/CGNAT/metadata answers.

    The identity-probe body arrives *through the server under test*, so the
    reported IP is attacker-controlled: a hostile endpoint answering
    ``10.0.0.1`` would otherwise satisfy ``require_distinct_outbound_ip``
    (which only compares the value against the known-rejected set) without
    ever proxying anything.
    """
    try:
        addr = ipaddress.ip_address(ip_text.strip())
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    if isinstance(addr, ipaddress.IPv6Address):
        return any(addr in net for net in _LOCAL_OUTBOUND_V6_NETWORKS)
    return any(addr in net for net in _LOCAL_OUTBOUND_V4_NETWORKS)


def _extract_probe_ip(body: str) -> str | None:
    """Return the first parseable IP an identity endpoint reported."""
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


@functools.cache
def _probe_ssl_context(verify_tls: bool) -> ssl.SSLContext:
    """Build the TLS context used for probe requests.

    Probe traffic goes *through* the untrusted server under test, so a hostile
    endpoint can terminate TLS itself. With verification on, its self-signed
    certificate fails and it can neither fake a 204 nor fake the outbound IP
    seen by the identity probe. Verification is only skipped when the caller
    opts out via ``verify_probe_tls=False``, which is not the default.

    Cached because ``ssl.create_default_context()`` re-reads the system trust
    store — ~15ms of *blocking* work on Windows — and this runs once per probe
    URL per attempt, inside the event loop shared by every concurrent probe.
    An ``SSLContext`` is reusable and thread-safe as long as nobody mutates it,
    which nothing here does.
    """
    if verify_tls:
        return ssl.create_default_context()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


# Probe hosts are operator-configured; cache the SSRF verdict per run so a
# large batch does not re-check the same host on every config/attempt.
# lru_cache with a cap instead of a bare dict: the dict grew for the life of
# a --continuous process, and while the cardinality is config-bounded today,
# the cap makes that a property rather than an assumption.
@functools.lru_cache(maxsize=256)
def _probe_host_blocked(host: str) -> bool:
    """Return ``True`` when *host* is a non-public IP literal (SSRF guard)."""
    return is_blocked_literal(host)


async def _safe_probe_host(host: str) -> bool:
    """Return ``True`` unless *host* is a non-public IP literal (SSRF guard).

    Only IP literals are rejected: hostnames resolve through the operator's DNS
    and are trusted (mirrors the LLM api_base guard). Checking a literal needs
    no network, so a probe never depends on live name resolution.

    Judged through :func:`is_blocked_literal`, not bare ``ip_address()``: the
    latter rejects non-canonical spellings (``2130706433``, ``0x7f000001``,
    ``127.1``), which then fell into the "not an IP, therefore a hostname,
    therefore trusted" branch — a fail-open hole for exactly the loopback and
    metadata addresses this guard exists to block.
    """
    return not _probe_host_blocked(host)


def _is_https_probe_url(url: str) -> bool:
    """Return ``True`` when *url* is something :func:`_https_probe_response` can use."""
    try:
        parsed = urlparse(url)
        # ``.port`` is read here, not just in the caller: it raises ValueError
        # on ``:99999``/``:abc``, and in _https_probe_response that raise sits
        # outside the try block — one typo in probe_urls aborted the whole
        # liveness stage instead of dropping the entry.
        return parsed.scheme == "https" and bool(parsed.hostname) and parsed.port != 0
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
    # ``.port`` raises on ``:99999``/``:abc``. Callers reach this through
    # _normalize_probe_urls (which now rejects those), but a direct caller must
    # not be able to abort the liveness stage with one malformed URL either.
    try:
        port = parsed.port or 443
    except ValueError:
        logger.warning("Ignoring probe URL %r: invalid port.", probe_url)
        return (None, "")
    # Config-driven SSRF guard: never connect the probe (which can carry a proxy
    # credential in dial_proxy_url) to a host that resolves into a private/loopback
    # range (e.g. 169.254.169.254). Fail closed. (Normal callers pass through
    # _normalize_probe_urls which rejects bad ports upfront, so a bad probe URL
    # cannot mass-ban the run via per-config failures.)
    if not await _safe_probe_host(host):
        logger.warning(
            "Refusing probe to non-public host %s (SSRF guard).",
            redact_proxy_url(host),
        )
        return (None, "")
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    writer = None
    sock = None
    try:
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
            if _probe_response_is_unframed(bytes(buffer)):
                # Wait for the missing EOF only briefly: an unframed response is
                # already usable, and a server that keeps the socket open would
                # otherwise cost the full timeout on every probe of every config.
                remaining = min(remaining, _UNFRAMED_BODY_IDLE_SECONDS)
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
    except Exception as exc:
        # A probe is best-effort: report the failure instead of swallowing it
        # silently, so a misconfigured endpoint or proxy surfaces in logs
        # rather than degrading to an "unreachable" verdict. Still return the
        # fail-closed (None, "") tuple — never raise out of a probe.
        logger.warning(
            "xray probe read failed for %s: %s",
            redact_proxy_url(proxy_url or probe_url),
            exc,
        )
        return (None, "")
    finally:
        if writer is None and sock is not None:
            # open_connection never took ownership of the raw SOCKS socket
            # (it raised or was cancelled before a transport existed) — close
            # it here or every failed proxied probe leaks one file descriptor.
            # A double close of an already-dead socket is a harmless no-op.
            with contextlib.suppress(Exception):
                sock.close()
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


def _log_probe_stderr(fh: BinaryIO, *, tool: str) -> None:
    """Log a bounded tail of a probe process's stderr temp file.

    DEVNULL made a startup failure undiagnosable: the exit code was logged,
    but WHY the generated config was rejected (bad inbound, port clash,
    unsupported option) lived only in stderr. The file handle stays open for
    the whole probe — reading via the same handle avoids Windows sharing
    issues — and no pipe is involved, so a chatty process cannot deadlock.
    """
    try:
        fh.seek(0)
        data = fh.read(8192)
    except OSError:
        return
    text = data.decode("utf-8", errors="replace").strip()
    if text:
        logger.warning("%s startup output: %s", tool, text[-2000:])


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
    pin_address: bool = True,
    resolve_timeout: float = 5.0,
    per_config_timeout: float | None = None,
) -> float | None:
    """Run real HTTPS probes through one Xray outbound.

    Args:
        pin_address: Resolve ``cfg.address`` once and connect to the
            validated literal (DNS rebinding guard, same as the TCP/TLS
            stages). ``False`` keeps the legacy hostname connect — the
            operator's explicit ``check_hostnames: false`` opt-out.
        per_config_timeout: Hard wall-clock ceiling for the whole probe of
            THIS config, covering every URL attempt and the subprocess.
            Without it a slow chain holds one of the stage's concurrency
            slots for up to ``attempts x (startup + urls x timeout)``
            seconds, starving every other candidate. A timeout leaves no
            verdict (the caller's ``xray_was_checked`` bookkeeping treats
            the config as not-yet-probed, so it retries first next run).

    Returns:
        Latency in seconds of the successful probe request, or ``None``
        when the config did not pass. Only the successful request is
        timed: time burned on failed probe URLs before it (or on Xray
        startup) says nothing about how fast the config serves traffic,
        and the quality stage drops "slow" configs on exactly this
        number.
    """
    if per_config_timeout is None or per_config_timeout <= 0:
        return await _xray_probe_check_body(
            cfg,
            xray_path=xray_path,
            probe_url=probe_url,
            probe_urls=probe_urls,
            min_probe_successes=min_probe_successes,
            accepted_status_codes=accepted_status_codes,
            dial_proxy_url=dial_proxy_url,
            require_distinct_outbound_ip=require_distinct_outbound_ip,
            reject_outbound_ips=reject_outbound_ips,
            verify_probe_tls=verify_probe_tls,
            timeout=timeout,
            startup_timeout=startup_timeout,
            pin_address=pin_address,
            resolve_timeout=resolve_timeout,
        )
    try:
        async with asyncio.timeout(per_config_timeout):
            return await _xray_probe_check_body(
                cfg,
                xray_path=xray_path,
                probe_url=probe_url,
                probe_urls=probe_urls,
                min_probe_successes=min_probe_successes,
                accepted_status_codes=accepted_status_codes,
                dial_proxy_url=dial_proxy_url,
                require_distinct_outbound_ip=require_distinct_outbound_ip,
                reject_outbound_ips=reject_outbound_ips,
                verify_probe_tls=verify_probe_tls,
                timeout=timeout,
                startup_timeout=startup_timeout,
                pin_address=pin_address,
                resolve_timeout=resolve_timeout,
            )
    except TimeoutError:
        logger.warning(
            "Xray probe of %s:%s exceeded the %ss per-config ceiling — "
            "treated as not probed.",
            cfg.address,
            cfg.port,
            per_config_timeout,
        )
        raise _NoVerdictError(
            f"per-config ceiling {per_config_timeout}s exceeded"
        ) from None


async def _xray_probe_check_body(
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
    pin_address: bool = True,
    resolve_timeout: float = 5.0,
) -> float | None:
    """Single-config probe body: spawn Xray, run the probe URLs, clean up."""
    if is_blocked_literal(cfg.address):
        logger.warning(
            "Refusing Xray probe of non-public address %s:%s.",
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
                "Xray probe of %s:%s skipped — no validated public address "
                "(DNS pin failed).",
                cfg.address,
                cfg.port,
            )
            raise _NoVerdictError("DNS pin failed")

    try:
        socks_port = _free_local_port()
    except OSError as exc:
        logger.warning("Cannot reserve a local SOCKS port for the Xray probe: %s", exc)
        raise _NoVerdictError("no free local port") from exc

    # Everything below runs under one finally: a reserved port number that is
    # never released is burnt for the lifetime of the process, and preparing the
    # config can fail for reasons of its own (full disk, locked temp file).
    try:
        xray_config = build_xray_config(
            cfg,
            socks_port,
            dial_proxy_url=dial_proxy_url,
            pinned_address=pinned_address,
        )
        if xray_config is None:
            # Unbuildable (bad dial proxy URL, unsupported combo): operator
            # or infra problem, not a dead server — no verdict, not a ban.
            raise _NoVerdictError("cannot build xray config")

        urls = _normalize_probe_urls(probe_url, probe_urls)
        required_successes = min(len(urls), max(1, min_probe_successes))
        accepted = accepted_status_codes or _DEFAULT_ACCEPTED_STATUS_CODES
        rejected_ips = {
            str(ip).strip() for ip in (reject_outbound_ips or set()) if str(ip).strip()
        }

        # ignore_cleanup_errors: Xray (Go) keeps config.json open with
        # FILE_SHARE_DELETE, so on Windows the file is unlinked but the
        # directory still holds a handle for a moment after the process is
        # killed. The resulting OSError escaped xray_probe_check, aborted the
        # attempt loop before ``cfg.is_alive`` was set, and recorded a working
        # config as a probe failure in the health history.
        with tempfile.TemporaryDirectory(
            prefix="vpnparser-xray-",
            ignore_cleanup_errors=True,
        ) as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            config_path.write_text(json.dumps(xray_config), encoding="utf-8")
            # stderr to a temp file: see _log_probe_stderr. Not a pipe (a
            # chatty process would deadlock an unread PIPE buffer) and not
            # DEVNULL (a bare exit code does not diagnose a bad config).
            err_fh = (Path(tmpdir) / "stderr.log").open("wb")
            try:
                proc = await asyncio.create_subprocess_exec(
                    xray_path,
                    "run",
                    "-config",
                    str(config_path),
                    stdout=subprocess.DEVNULL,
                    stderr=err_fh,
                )
            except OSError as exc:
                err_fh.close()
                # Deleted binary, missing permissions, antivirus lock: without
                # this every config would silently fail with is_alive=False.
                logger.warning("Cannot start Xray from %s: %s", xray_path, exc)
                raise _NoVerdictError("cannot start xray") from exc
            try:
                if not await _wait_for_port(socks_port, startup_timeout, proc=proc):
                    _log_probe_stderr(err_fh, tool="Xray")
                    raise _NoVerdictError("xray startup timeout")
                successes = 0
                failures_allowed = len(urls) - required_successes
                failures = 0
                identity_ok = False
                success_latency: float | None = None
                consecutive_full_timeouts = 0
                for url in urls:
                    probe_started = time.monotonic()
                    status_code, body = await _https_probe_response(
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
                        outbound_ip = _extract_probe_ip(body)
                        if (
                            outbound_ip
                            and outbound_ip not in rejected_ips
                            # The body arrives through the server under test,
                            # so the answer is attacker-controlled: a hostile
                            # endpoint could report a private address and
                            # satisfy the distinct-IP check without proxying
                            # anything. Documentation ranges (TEST-NET) stay
                            # acceptable — fixtures and logs use them.
                            and not _is_local_outbound_ip(outbound_ip)
                        ):
                            identity_ok = True
                        if successes >= required_successes and (
                            not require_distinct_outbound_ip or identity_ok
                        ):
                            return success_latency
                        continue

                    failures += 1
                    if elapsed >= timeout * 0.9:
                        # A probe that burned its whole timeout without any
                        # answer means the tunnel itself is dead; the
                        # remaining URLs share that tunnel and cannot pass.
                        consecutive_full_timeouts += 1
                        if consecutive_full_timeouts >= 2:
                            return None
                    else:
                        consecutive_full_timeouts = 0
                    if failures > failures_allowed:
                        return None
                return (
                    success_latency
                    if successes >= required_successes
                    and (not require_distinct_outbound_ip or identity_ok)
                    else None
                )
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
                        # during the grace wait must not skip the kill:
                        # Xray ignoring SIGTERM would outlive the pipeline.
                        proc.kill()
                        with contextlib.suppress(Exception):
                            await proc.wait()
                        raise
                # Shrink the credential-at-rest window: config.json holds the
                # VPN credentials in cleartext. The TemporaryDirectory
                # cleanup runs at context exit, but on Windows an open Xray
                # handle can delay it (ignore_cleanup_errors) — wipe the file
                # now and drop the dir immediately.
                with contextlib.suppress(Exception):
                    config_path.unlink()
                with contextlib.suppress(Exception):
                    shutil.rmtree(tmpdir, ignore_errors=True)
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
    probe_via_proxies: bool = False,
    proxy_latency_ms: dict[str, float] | None = None,
    require_distinct_outbound_ip: bool = False,
    verify_probe_tls: bool = True,
    check_hostnames: bool = True,
    resolve_timeout: float = 5.0,
    timeout: float = 12.0,
    startup_timeout: float = 4.0,
    concurrency: int = 6,
    max_alive: int = 0,
    progress_label: str = "",
    time_budget_seconds: float = 0.0,
    deadline: float | None = None,
    per_config_timeout: float | None = None,
) -> list[Config]:
    """Return configs that can pass a real HTTPS probe through Xray.

    ``probe_urls`` is the authoritative list of probe targets; ``probe_url`` is
    a fallback used only when that list is empty — see
    :func:`_normalize_probe_urls`.

    With ``probe_via_proxies`` the *primary* attempts dial the VPN server
    through the SOCKS pool (rotated per attempt): runners in GitHub Actions
    data centers are exactly the traffic RU servers block or drop, so a
    direct probe from there marks living configs dead. The direct path stays
    in use whenever the pool is empty.

    Args:
        time_budget_seconds: Wall-clock budget measured from THIS call
            (0 = off). Kept for standalone callers.
        deadline: Absolute ``time.monotonic()`` deadline shared across the
            fresh/retry/stale passes of one list. When given it wins over
            ``time_budget_seconds`` — without it, three passes each starting
            their own clock meant up to 3x the configured stage budget.
    """
    if not configs:
        return []

    configs = await filter_public_configs(
        configs,
        stage="Xray probe",
        check_hostnames=check_hostnames,
        resolve_timeout=resolve_timeout,
    )
    if not configs:
        return []
    # Blocking filesystem scan — off the event loop.
    await asyncio.to_thread(_sweep_stale_probe_dirs)

    for cfg in configs:
        cfg.xray_was_checked = False
        # None = no verdict yet. False here used to turn every
        # budget-skipped/cancelled candidate into a health-history
        # failure via the shared probe_log (which holds references).
        cfg.is_alive = None

    semaphore = asyncio.Semaphore(max(1, concurrency))
    alive: list[Config] = []
    alive_lock = asyncio.Lock()
    done_event = asyncio.Event()
    # Heartbeat counters: the stage used to be "silent by design", which left
    # operators unable to tell a healthy grind from a dead-proxy spiral during
    # a 1-3h run. done_count increments are plain int ops — asyncio keeps
    # them race-free within one loop. no_verdict_count tracks infra/timeout
    # skips separately so the finished line does not misread them as
    # early-stop remainder.
    done_count = 0
    no_verdict_count = 0
    total_count = len(configs)
    # Time budget (0 = off): a deadline past which no NEW candidate starts —
    # a runaway stage stops gracefully instead of grinding for hours. An
    # explicit absolute ``deadline`` (shared across the list's passes) wins
    # over the per-call duration so N passes cannot multiply the budget.
    budget_deadline: float | None
    if deadline is not None:
        budget_deadline = deadline
    else:
        budget_deadline = (
            time.monotonic() + time_budget_seconds if time_budget_seconds > 0 else None
        )
    budget_skipped = 0
    proxy_urls = [url for url in (probe_proxy_urls or []) if str(url).strip()]
    if probe_via_proxies and not proxy_urls:
        logger.info(
            "probe_via_proxies requested but the proxy pool is empty; "
            "probing directly.",
        )
    elif probe_via_proxies and min_proxy_successes > 0:
        logger.warning(
            "probe_via_proxies routes every attempt through the pool; "
            "min_proxy_successes=%d is not enforced separately in this mode.",
            min_proxy_successes,
        )
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
            if probe_via_proxies and proxy_urls:
                # In via-proxy mode broken direct egress is the expected
                # situation and the probes never use it, so the stage must
                # not fail closed over an unreachable identity endpoint.
                logger.warning(
                    "require_distinct_outbound_ip is True but the direct "
                    "public IP is unknown; probes run through the proxy "
                    "pool — continuing without the direct-IP reject set.",
                )
            else:
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
        nonlocal done_count, budget_skipped, no_verdict_count
        if done_event.is_set():
            return
        async with semaphore:
            if done_event.is_set():
                return
            # Time budget: candidates arriving after the deadline get no
            # verdict (xray_was_checked stays False), so the health history
            # counts nothing against them and the next run probes them
            # first — a safety net against a runaway stage, not a verdict.
            if budget_deadline is not None and time.monotonic() > budget_deadline:
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
            # In via-proxy mode each retry moves to the next rotated proxy:
            # retrying through the same dead proxy would prove nothing.
            attempt_proxies = (
                _rotated_proxy_urls_for_config(cfg, proxy_urls)
                if probe_via_proxies and proxy_urls
                else []
            )
            for attempt_index in range(attempts):
                if done_event.is_set():
                    # Enough configs are alive already. Stopping between two
                    # attempts saves a full Xray startup per remaining attempt;
                    # the config goes back to "not checked" so the health
                    # history records no verdict it never earned.
                    cfg.xray_was_checked = False
                    cfg.is_alive = None
                    return
                dial_proxy_url = (
                    attempt_proxies[attempt_index % len(attempt_proxies)]
                    if attempt_proxies
                    else None
                )
                try:
                    probe_latency = await xray_probe_check(
                        cfg,
                        xray_path=xray_path,
                        probe_url=None,
                        probe_urls=probe_targets,
                        min_probe_successes=min_probe_successes,
                        dial_proxy_url=dial_proxy_url,
                        require_distinct_outbound_ip=require_distinct_outbound_ip,
                        # A proxied attempt must also reject the proxy's own
                        # exit IP: a "VPN" whose outbound equals the SOCKS
                        # proxy's exit is just the proxy itself.
                        reject_outbound_ips=(
                            proxy_reject_ips.get(dial_proxy_url, reject_ips)
                            if dial_proxy_url
                            else reject_ips
                        ),
                        verify_probe_tls=verify_probe_tls,
                        timeout=timeout,
                        startup_timeout=startup_timeout,
                        pin_address=check_hostnames,
                        resolve_timeout=resolve_timeout,
                        # A per-config ceiling keeps one slow URL chain from
                        # holding a stage semaphore slot for minutes; the
                        # docstring of xray_probe_check carries the arithmetic.
                        per_config_timeout=per_config_timeout,
                    )
                except _NoVerdictError:
                    # Infra/timeout/DNS-pin: no verdict, not a dead server.
                    cfg.xray_was_checked = False
                    cfg.is_alive = None
                    no_verdict_count += 1
                    return
                if probe_latency is not None:
                    raw_ms = float(probe_latency) * 1000.0
                    # A via-proxy latency includes the proxy's own dial hop;
                    # subtracting its health baseline keeps the quality stage
                    # from slow-dropping configs that are only as slow as the
                    # free proxy they were probed through.
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

            ok = attempt_successes >= required_attempts
            proxy_successes = 0
            required_proxy_successes = max(0, min_proxy_successes)
            # With required_proxy_successes == 0 the requirement is already met,
            # so the loop would only burn one Xray startup per dead proxy.
            # In via-proxy mode the attempts above already ran through the
            # pool, so extra direct-mode proxy checks are redundant.
            if (
                ok
                and not probe_via_proxies
                and proxy_urls
                and required_proxy_successes > 0
            ):
                for proxy_url in _rotated_proxy_urls_for_config(cfg, proxy_urls):
                    proxy_url = str(proxy_url).strip()
                    try:
                        proxy_ok = (
                            await xray_probe_check(
                                cfg,
                                xray_path=xray_path,
                                probe_url=None,
                                probe_urls=probe_targets,
                                min_probe_successes=min_probe_successes,
                                dial_proxy_url=proxy_url,
                                require_distinct_outbound_ip=require_distinct_outbound_ip,
                                reject_outbound_ips=proxy_reject_ips.get(
                                    proxy_url,
                                    reject_ips,
                                ),
                                verify_probe_tls=verify_probe_tls,
                                timeout=timeout,
                                startup_timeout=startup_timeout,
                                # Same verdict path as the primary attempt: with
                                # check_hostnames=false this check used to re-pin
                                # via DNS while the main probe skipped it.
                                pin_address=check_hostnames,
                                resolve_timeout=resolve_timeout,
                                per_config_timeout=per_config_timeout,
                            )
                            is not None
                        )
                    except _NoVerdictError:
                        cfg.xray_was_checked = False
                        cfg.is_alive = None
                        no_verdict_count += 1
                        return
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
            done_count += 1
            if not ok:
                return
            async with alive_lock:
                alive.append(cfg)
                if max_alive > 0 and len(alive) >= max_alive:
                    done_event.set()

    async def _report_progress() -> None:
        # Heartbeat: one line per interval instead of 96 minutes of silence.
        # Small candidate sets skip it — tests and tiny lists gain nothing.
        if not progress_label or total_count < 50:
            return
        while True:
            await asyncio.sleep(_PROBE_HEARTBEAT_SECONDS)
            logger.info(
                "%s progress: %d/%d checked, %d alive.",
                progress_label,
                done_count,
                total_count,
                len(alive),
            )

    progress_task = asyncio.create_task(_report_progress())
    tasks = [asyncio.create_task(_check_one(cfg)) for cfg in configs]

    try:
        if max_alive > 0:
            # Same early stop as the TCP stage: without cancelling the
            # in-flight probes the stage still waits for the slowest one — up
            # to attempts * (startup + probes) seconds — after its goal is
            # reached. Raced via gather() so the whole pending set does not
            # get re-registered into asyncio.wait on every completion, and so
            # an outer cancellation cannot orphan in-flight probes.
            gather_task: asyncio.Future[Any] = asyncio.gather(
                *tasks, return_exceptions=True
            )
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
            # Reap the watcher: cancel() only requests cancellation, and
            # returning with a not-yet-finished task leaks it past the stage.
            with contextlib.suppress(asyncio.CancelledError):
                await done_task
        else:
            try:
                results = await asyncio.gather(*tasks, return_exceptions=True)
            except asyncio.CancelledError:
                for task in tasks:
                    if not task.done():
                        task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await asyncio.gather(*tasks, return_exceptions=True)
                raise
    finally:
        # An external cancellation (runner shutdown) must not strand the
        # heartbeat task: it would keep sleeping until the loop closes.
        progress_task.cancel()
        await asyncio.gather(progress_task, return_exceptions=True)
    logger.info(
        "%s finished: %d/%d checked, %d alive%s%s.",
        progress_label or "Xray stage",
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
        logger.warning(
            "%s time budget (%.0fs) hit: %d candidate(s) left unprobed "
            "(no verdict recorded, they retry first next run).",
            progress_label or "Xray stage",
            time_budget_seconds,
            budget_skipped,
        )
    for cfg, result in zip(configs, results, strict=False):
        if isinstance(result, asyncio.CancelledError):
            # A cancelled probe reached no verdict, so it must not leave the
            # config marked as attempted: the health history would count the
            # early stop as a failed probe and move the config towards a ban.
            cfg.xray_was_checked = False
            cfg.is_alive = None
            continue
        if isinstance(result, BaseException):
            # Without this the real reason (missing binary, permission error)
            # is swallowed and the whole stage just returns no configs.
            #
            # A probe that raised reached no verdict, so it must not leave the
            # config marked as attempted: the health history would count it as
            # a failed probe and move the config towards a ban (the same rule
            # as the CancelledError branch above).
            cfg.xray_was_checked = False
            cfg.is_alive = None
            logger.warning(
                "Xray probe of %s:%s raised %s: %s",
                cfg.address,
                cfg.port,
                type(result).__name__,
                result,
            )
    if max_alive > 0 and len(alive) > max_alive:
        # Probes already under way when the limit was reached still append
        # their result, so the stage could return more configs than it was
        # asked for and report xray_alive > xray_max_alive in run-summary.json.
        # ``is_alive`` stays truthful — the health history reads it, and these
        # configs did pass their probe, they are simply surplus.
        del alive[max_alive:]
    return alive
