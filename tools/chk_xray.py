"""Functional proof for xray_probe: builds a vless config and probes fail-closed.

Server/connection is mocked (no real network, no TLS cert needed) so the
behaviour of build_xray_config and _https_probe_response is exercised directly.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from src.parsers.base import Config
from src.validators import xray_probe

EXPECTED_SNI = "validated.example.com"


class _FakeReader:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload
        self._pos = 0

    async def read(self, n: int = -1) -> bytes:
        if self._pos >= len(self._payload):
            return b""
        chunk = self._payload[self._pos : self._pos + n]
        self._pos += len(chunk)
        return chunk


class _FakeWriter:
    def __init__(self) -> None:
        self.written = bytearray()

    def write(self, data: bytes) -> None:
        self.written += data

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        return None

    async def wait_closed(self) -> None:
        return None


async def _success_open(*args, **kwargs):
    writer = _FakeWriter()
    body = (
        b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nhello world"
    )
    return _FakeReader(body), writer


async def _fail_open(*args, **kwargs):
    raise ConnectionRefusedError("connection refused to loopback host")


async def build_summary() -> dict:
    # 1) vless config with a validated SNI
    cfg = Config(
        protocol="vless",
        address="203.0.113.10",
        port=443,
        uuid_or_password="11111111-2222-3333-4444-555555555555",
        network="ws",
        security="tls",
        path="/vless",
        host="cdn.example.com",
        sni=EXPECTED_SNI,
        fp="chrome",
    )

    # 2) build xray config and assert tls.serverName is the validated SNI
    xray_cfg = xray_probe.build_xray_config(cfg, socks_port=10999)
    assert xray_cfg is not None, "build_xray_config returned None for valid vless"
    outbound = None
    for ob in xray_cfg["outbounds"]:
        if ob.get("tag") == "vpn":
            outbound = ob
            break
    assert outbound is not None, "no vpn outbound built"
    tls_settings = outbound["streamSettings"].get("tlsSettings", {})
    server_name = tls_settings.get("serverName")
    assert server_name == EXPECTED_SNI, (
        f"tls.serverName {server_name!r} != validated SNI {EXPECTED_SNI!r}"
    )

    summary = {
        "serverName": server_name,
        "probe_status": None,
        "probe_body": None,
        "fail_closed": None,
    }

    # 3) probe against mocked HTTPS server -> (status, body) tuple
    real_open = asyncio.open_connection
    asyncio.open_connection = _success_open  # type: ignore[assignment]
    try:
        status, body = await xray_probe._https_probe_response(
            probe_url="https://validated.example.com/generate_204",
            timeout=5.0,
            verify_tls=False,
        )
    finally:
        asyncio.open_connection = real_open  # type: ignore[assignment]

    assert isinstance(status, int), f"status not int: {status!r}"
    assert isinstance(body, str), f"body not str: {body!r}"
    assert status == 200, f"expected 200, got {status}"
    assert body == "hello world", f"unexpected body: {body!r}"
    summary["probe_status"] = status
    summary["probe_body"] = body

    # 4) probe to private/loopback host -> fail-closed (None, "")
    asyncio.open_connection = _fail_open  # type: ignore[assignment]
    try:
        status2, body2 = await xray_probe._https_probe_response(
            probe_url="https://127.0.0.1:1/",
            timeout=5.0,
            verify_tls=False,
        )
    finally:
        asyncio.open_connection = real_open  # type: ignore[assignment]

    assert (status2, body2) == (None, ""), (
        f"private host did not fail-closed: got {(status2, body2)!r}"
    )
    summary["fail_closed"] = (status2, body2)
    return summary


def main() -> int:
    try:
        summary = asyncio.run(build_summary())
    except AssertionError as exc:
        print("FAILURE:", exc)
        return 1
    print("=== xray_probe functional proof ===")
    print(f"serverName (validated SNI): {summary['serverName']}")
    print(
        "probe result             : "
        f"({summary['probe_status']!r}, {summary['probe_body']!r})"
    )
    print(f"fail-closed on loopback  : {summary['fail_closed']}")
    print("VERDICT                  : PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
