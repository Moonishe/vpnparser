"""Tests for src/validators/address_guard.py — the validator SSRF guard.

DNS is always mocked: ``resolve_host_addresses`` is patched on the module, so no
test performs a real lookup. The few tests that exercise
:mod:`src.utils.net` directly rely on inputs the resolver rejects locally
(malformed DNS labels) or on IP literals, which never reach the network either.
"""

from __future__ import annotations

import asyncio
import socket
import threading

import pytest

from src.parsers.base import Config
from src.utils import net
from src.validators import address_guard
from src.validators.address_guard import (
    classify_host,
    filter_public_configs,
    is_blocked_literal,
)


def _patch_resolver(
    monkeypatch: pytest.MonkeyPatch,
    *,
    answers: dict[str, list[str]] | None = None,
) -> None:
    """Route hostname resolution through an in-memory table.

    A host missing from *answers* stands for a failed lookup (``None``), a
    listed one for whatever ``getaddrinfo`` returned, public or not.
    """
    table = answers or {}

    async def _resolve(host: str, *, timeout: float = 5.0) -> list[str] | None:
        found = table.get(host)
        return list(found) if found is not None else None

    monkeypatch.setattr(address_guard, "resolve_host_addresses", _resolve)


# --- is_blocked_literal ----------------------------------------------------


@pytest.mark.parametrize(
    "host",
    [
        "10.0.0.5",
        "172.16.0.1",
        "192.168.1.1",
        "127.0.0.1",
        "169.254.169.254",
        "0.0.0.0",
        "224.0.0.1",
        "240.0.0.1",
        "::1",
        "[::1]",
        "fe80::1",
        "  10.0.0.5  ",
    ],
)
def test_is_blocked_literal_rejects_non_public_literals(host: str) -> None:
    assert is_blocked_literal(host) is True


@pytest.mark.parametrize(
    "host",
    [
        "8.8.8.8",
        "93.184.216.34",
        "2606:4700:4700::1111",
        "[2606:4700:4700::1111]",
    ],
)
def test_is_blocked_literal_accepts_public_literals(host: str) -> None:
    assert is_blocked_literal(host) is False


@pytest.mark.parametrize("host", ["example.com", "vpn-01.example.net", "", None])
def test_is_blocked_literal_ignores_non_literals(host: str | None) -> None:
    # Hostnames need DNS and are judged by filter_public_configs instead.
    assert is_blocked_literal(host) is False


# --- classify_host ---------------------------------------------------------


async def test_classify_host_literals_need_no_dns(monkeypatch) -> None:
    async def _boom(*_args: object, **_kwargs: object) -> list[str]:
        raise AssertionError("literals must not hit the resolver")

    monkeypatch.setattr(address_guard, "resolve_host_addresses", _boom)

    assert await classify_host("93.184.216.34") == "public"
    assert await classify_host("10.0.0.5") == "blocked"
    assert await classify_host("") == "blocked"


async def test_classify_host_public_hostname(monkeypatch) -> None:
    _patch_resolver(monkeypatch, answers={"good.example": ["93.184.216.34"]})
    assert await classify_host("good.example") == "public"


async def test_classify_host_hostname_resolving_to_private(monkeypatch) -> None:
    _patch_resolver(monkeypatch, answers={"internal.example": ["10.0.0.5"]})
    assert await classify_host("internal.example") == "blocked"


async def test_classify_host_one_private_answer_blocks_the_name(monkeypatch) -> None:
    """A mixed answer set stays an SSRF attempt, not a partially healthy host."""
    _patch_resolver(
        monkeypatch,
        answers={"mixed.example": ["93.184.216.34", "127.0.0.1"]},
    )
    assert await classify_host("mixed.example") == "blocked"


async def test_classify_host_unresolvable_hostname(monkeypatch) -> None:
    _patch_resolver(monkeypatch)
    assert await classify_host("nowhere.example") == "unresolved"


async def test_classify_host_resolves_each_name_once(monkeypatch) -> None:
    """Both halves of the verdict come out of a single lookup."""
    calls: list[str] = []

    async def _resolve(host: str, *, timeout: float = 5.0) -> list[str] | None:
        calls.append(host)
        return ["10.0.0.1"]

    monkeypatch.setattr(address_guard, "resolve_host_addresses", _resolve)
    assert await classify_host("internal.example") == "blocked"
    assert calls == ["internal.example"]


async def test_classify_host_accepts_nat64_answer(monkeypatch) -> None:
    """A DNS64 network answers with 64:ff9b::<ipv4> for every public host."""
    _patch_resolver(monkeypatch, answers={"dns64.example": ["64:ff9b::808:808"]})
    assert await classify_host("dns64.example") == "public"


async def test_classify_host_blocks_nat64_wrapped_loopback(monkeypatch) -> None:
    _patch_resolver(monkeypatch, answers={"evil.example": ["64:ff9b::7f00:1"]})
    assert await classify_host("evil.example") == "blocked"


# --- filter_public_configs -------------------------------------------------


def _cfg(address: str, port: int = 443) -> Config:
    return Config("vless", address, port, "uuid")


async def test_filter_empty_input() -> None:
    assert await filter_public_configs([], stage="test") == []


async def test_filter_keeps_order_and_drops_blocked(monkeypatch, caplog) -> None:
    caplog.set_level("WARNING")
    _patch_resolver(
        monkeypatch,
        answers={
            "good.example": ["93.184.216.34"],
            "internal.example": ["192.168.1.1"],
        },
    )
    configs = [
        _cfg("10.0.0.5", 22),
        _cfg("good.example"),
        _cfg("93.184.216.34"),
        _cfg("internal.example"),
        _cfg("nowhere.example"),
    ]
    kept = await filter_public_configs(configs, stage="TCP check")
    assert [c.address for c in kept] == [
        "good.example",
        "93.184.216.34",
        "nowhere.example",
    ]
    assert "TCP check: dropped 2/5" in caplog.text


async def test_filter_deduplicates_lookups(monkeypatch) -> None:
    calls: list[str] = []

    async def _resolve(host: str, *, timeout: float = 5.0) -> list[str]:
        calls.append(host)
        return ["93.184.216.34"]

    monkeypatch.setattr(address_guard, "resolve_host_addresses", _resolve)
    configs = [_cfg("same.example", port) for port in (443, 8443, 2053)]
    kept = await filter_public_configs(configs, stage="test")
    assert len(kept) == 3
    assert calls == ["same.example"]


async def test_filter_survives_a_failing_classification(monkeypatch, caplog) -> None:
    """One unusable address must cost one config, not the whole stage."""
    caplog.set_level("WARNING")

    async def _resolve(host: str, *, timeout: float = 5.0) -> list[str] | None:
        if host.startswith("a"):
            raise UnicodeEncodeError("idna", host, 0, 1, "label too long")
        return ["93.184.216.34"]

    monkeypatch.setattr(address_guard, "resolve_host_addresses", _resolve)
    bad = _cfg("a" * 70 + ".example.com")
    good = _cfg("good.example")
    kept = await filter_public_configs([good, bad], stage="TCP check")
    # Verdict "unresolved" for the broken host: kept here, dropped later by the
    # connect itself, exactly like any other dead address.
    assert kept == [good, bad]
    assert "treating it as unresolved" in caplog.text


async def _drain_lookup_threads(timeout: float = 5.0) -> None:
    """Wait until the lookup threads a test unblocked have really finished."""
    for _ in range(int(timeout / 0.01)):
        if not net.active_lookup_count():
            return
        await asyncio.sleep(0.01)


async def test_stuck_lookups_never_hide_a_private_host(monkeypatch) -> None:
    """A lookup must always reach DNS, however many earlier ones hang.

    ``getaddrinfo`` cannot be cancelled, so a timed-out lookup keeps its thread.
    With a fixed-width pool the lookups behind it timed out *in the queue*,
    which the guard reads as "unresolved" and lets through — the SSRF guard
    silently stopped guarding under exactly the batch sizes it exists for.
    """
    release = threading.Event()

    def _fake_getaddrinfo(host: str, *_args: object, **_kwargs: object) -> list[object]:
        if host.startswith("stuck"):
            release.wait(30.0)
            raise socket.gaierror("blackholed")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)
    configs = [
        *[_cfg(f"stuck{i}.example") for i in range(address_guard._RESOLVE_CONCURRENCY)],
        _cfg("internal.example", 22),
    ]
    try:
        kept = await filter_public_configs(
            configs,
            stage="TCP check",
            resolve_timeout=0.05,
        )
        assert [c.address for c in kept] == [
            cfg.address for cfg in configs if cfg.address != "internal.example"
        ]
    finally:
        release.set()
        await _drain_lookup_threads()


async def test_lookup_waits_for_a_thread_instead_of_inventing_a_verdict(
    monkeypatch,
) -> None:
    """With every thread stuck, a lookup waits — it never reports a failure.

    "Did not resolve" lets the address through, so a lookup that never ran must
    not be reported as one that ran and failed.
    """
    monkeypatch.setattr(net, "_lookup_slots", net._LookupSlots(1))
    release = threading.Event()

    def _fake_getaddrinfo(host: str, *_args: object, **_kwargs: object) -> list[object]:
        if host == "stuck.example":
            release.wait(30.0)
            raise socket.gaierror("blackholed")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)
    try:
        assert await net.resolve_host_addresses("stuck.example", timeout=0.05) is None
        assert net.active_lookup_count() == 1
        pending = asyncio.ensure_future(
            net.resolve_host_addresses("good.example", timeout=5.0),
        )
        await asyncio.sleep(0.2)
        assert not pending.done()
        release.set()
        assert await pending == ["93.184.216.34"]
    finally:
        release.set()
        await _drain_lookup_threads()


def test_a_cancelled_lookup_never_reaches_the_resolver(monkeypatch) -> None:
    """A lookup cancelled before its thread ran must free its slot anyway."""

    def _boom(*_args: object, **_kwargs: object) -> list[object]:
        raise AssertionError("a cancelled lookup must not query DNS")

    threads: list[object] = []

    class _LazyThread:
        def __init__(self, *, target: object, **_kwargs: object) -> None:
            self._target = target
            threads.append(self)

        def start(self) -> None:
            return None

        def run_now(self) -> None:
            self._target()

    monkeypatch.setattr(socket, "getaddrinfo", _boom)
    monkeypatch.setattr(threading, "Thread", _LazyThread)
    slots = net._LookupSlots(1)
    monkeypatch.setattr(net, "_lookup_slots", slots)

    assert slots.acquire() is True
    future = net._start_lookup("nobody.example")
    assert future.cancel() is True
    threads[0].run_now()  # type: ignore[attr-defined]
    assert net.active_lookup_count() == 0


def test_a_lookup_that_cannot_start_a_thread_frees_its_slot(monkeypatch) -> None:
    """Thread exhaustion must not leak the slot and wedge every later lookup."""

    class _RefusingThread:
        def __init__(self, **_kwargs: object) -> None:
            return None

        def start(self) -> None:
            msg = "can't start new thread"
            raise RuntimeError(msg)

    monkeypatch.setattr(threading, "Thread", _RefusingThread)
    slots = net._LookupSlots(1)
    monkeypatch.setattr(net, "_lookup_slots", slots)

    assert slots.acquire() is True
    with pytest.raises(RuntimeError, match="can't start new thread"):
        net._start_lookup("nobody.example")
    assert net.active_lookup_count() == 0


def test_lookup_slots_refuse_more_than_their_capacity() -> None:
    slots = net._LookupSlots(1)
    assert slots.acquire() is True
    assert slots.acquire() is False
    slots.release()
    slots.release()  # never goes negative
    assert slots.active == 0


async def test_lookup_threads_are_daemons(monkeypatch) -> None:
    """A hung lookup must not keep the interpreter alive at exit.

    The pool this replaced was joined by ``concurrent.futures`` at exit, so a
    single black-holed lookup delayed process shutdown by its full OS timeout —
    and in ``--continuous`` mode the leaked threads piled up run after run.
    """
    running = threading.Event()
    release = threading.Event()

    def _fake_getaddrinfo(*_args: object, **_kwargs: object) -> list[object]:
        running.set()
        release.wait(30.0)
        raise socket.gaierror("blackholed")

    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)
    try:
        assert await net.resolve_host_addresses("stuck.example", timeout=0.05) is None
        assert running.wait(5.0)
        lookup_threads = [t for t in threading.enumerate() if t.name == "net-resolve"]
        assert lookup_threads
        assert all(thread.daemon for thread in lookup_threads)
    finally:
        release.set()
        await _drain_lookup_threads()


async def test_filter_without_hostname_check_makes_no_dns_query(
    monkeypatch,
) -> None:
    async def _boom(*_args: object, **_kwargs: object) -> list[str]:
        raise AssertionError("check_hostnames=False must not resolve")

    monkeypatch.setattr(address_guard, "resolve_host_addresses", _boom)

    configs = [_cfg("whatever.example"), _cfg("10.0.0.5"), _cfg("8.8.8.8")]
    kept = await filter_public_configs(
        configs,
        stage="test",
        check_hostnames=False,
    )
    assert [c.address for c in kept] == ["whatever.example", "8.8.8.8"]


async def test_filter_drops_empty_address(monkeypatch) -> None:
    _patch_resolver(monkeypatch)
    kept = await filter_public_configs([_cfg("")], stage="test")
    assert kept == []


# --- src.utils.net predicates ----------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "100.64.0.1",  # RFC 6598 carrier-grade NAT
        "100.127.255.254",
        "fec0::1",  # deprecated IPv6 site-local (RFC 3879)
        "64:ff9b::7f00:1",  # NAT64-wrapped 127.0.0.1
        "64:ff9b::a00:1",  # NAT64-wrapped 10.0.0.1
    ],
)
def test_is_private_address_covers_ranges_python_calls_global(value: str) -> None:
    assert net.is_private_address(value) is True


@pytest.mark.parametrize(
    "value",
    [
        "8.8.8.8",
        "93.184.216.34",
        "2606:4700:4700::1111",
        "64:ff9b::808:808",  # NAT64-wrapped 8.8.8.8 — reachable, so public
    ],
)
def test_is_private_address_keeps_public_addresses_public(value: str) -> None:
    assert net.is_private_address(value) is False


@pytest.mark.parametrize(
    "host",
    ["a" * 70 + ".example.com", ".example.com", "a..b"],
)
async def test_resolve_survives_malformed_dns_labels(host: str) -> None:
    """getaddrinfo raises UnicodeError (a ValueError) before it queries DNS.

    Subscriptions carry such hosts constantly (a base64 blob parsed as an
    address), and an escaping exception used to abort the whole stage.
    """
    assert await net.resolve_host_addresses(host, timeout=1.0) is None
    assert await net.resolve_global_ips(host, timeout=1.0) == []
    assert await classify_host(host, timeout=1.0) == "unresolved"


async def test_resolve_global_ips_handles_literals_and_blanks() -> None:
    assert await net.resolve_global_ips("") == []
    assert await net.resolve_global_ips("  [::1]  ") == []
    assert await net.resolve_global_ips("[2606:4700:4700::1111]") == [
        "2606:4700:4700::1111",
    ]


async def test_resolve_host_addresses_skips_non_string_sockaddr(monkeypatch) -> None:
    """AF_PACKET-style answers carry an int where an address is expected."""

    def _fake_getaddrinfo(*_args: object, **_kwargs: object) -> list[object]:
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ()),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (7, b"raw")),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)
    assert await net.resolve_host_addresses("some.example") == ["93.184.216.34"]


async def test_is_public_host_accepts_a_public_literal() -> None:
    assert await net.is_public_host("8.8.8.8") is True
    assert await net.is_public_host("10.0.0.1") is False


async def test_is_public_host_retries_a_failed_lookup(monkeypatch) -> None:
    """One slow answer must not cost an upstream index for the whole run.

    The source manager turns a ``False`` here into a ``ValueError`` it never
    retries, so a transient resolver hiccup used to drop a perfectly public
    URL (jsdelivr, raw.githubusercontent.com) until the next run.
    """
    calls: list[str] = []

    async def _resolve(host: str, *, timeout: float = 5.0) -> list[str] | None:
        calls.append(host)
        return None if len(calls) == 1 else ["93.184.216.34"]

    monkeypatch.setattr(net, "resolve_host_addresses", _resolve)
    assert await net.is_public_host("cdn.example", retry_delay=0.0) is True
    assert calls == ["cdn.example", "cdn.example"]


async def test_is_public_host_gives_up_after_its_attempts(monkeypatch) -> None:
    """Retrying is a hedge against a hiccup, not a way around a dead name."""
    calls: list[str] = []

    async def _resolve(host: str, *, timeout: float = 5.0) -> list[str] | None:
        calls.append(host)
        return None

    monkeypatch.setattr(net, "resolve_host_addresses", _resolve)
    assert await net.is_public_host("nowhere.example", retry_delay=0.0) is False
    assert calls == ["nowhere.example", "nowhere.example"]
    assert await net.is_public_host("   ") is False


async def test_is_public_host_does_not_retry_a_resolved_private_host(
    monkeypatch,
) -> None:
    """A name answering with an internal address is rejected on the spot."""
    calls: list[str] = []

    async def _resolve(host: str, *, timeout: float = 5.0) -> list[str] | None:
        calls.append(host)
        return ["10.0.0.5"]

    monkeypatch.setattr(net, "resolve_host_addresses", _resolve)
    assert await net.is_public_host("internal.example", retry_delay=0.0) is False
    assert calls == ["internal.example"]


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://8.8.8.8/list.txt", True),
        ("http://10.0.0.1/list.txt", False),
        ("ftp://8.8.8.8/list.txt", False),
        ("https://", False),
        ("http://[oops", False),
    ],
)
async def test_is_safe_public_url(url: str, expected: bool) -> None:
    assert await net.is_safe_public_url(url) is expected


# --- verdict cache ---------------------------------------------------------


async def test_filter_reuses_a_decided_verdict_across_stages(monkeypatch) -> None:
    """One run guards the same hosts three times; DNS must be asked once.

    Resolver starvation is what turned this guard fail-open twice, so paying
    for three full resolutions of the same list is a risk, not just a cost.
    """
    lookups: list[str] = []

    async def _resolve(host: str, *, timeout: float = 5.0) -> list[str] | None:
        lookups.append(host)
        return ["93.184.216.34"] if host == "good.example" else ["10.0.0.5"]

    monkeypatch.setattr(address_guard, "resolve_host_addresses", _resolve)
    configs = [_cfg("good.example"), _cfg("internal.example")]

    for stage in ("tcp", "tls", "xray"):
        kept = await filter_public_configs(list(configs), stage=stage)
        assert [c.address for c in kept] == ["good.example"]

    assert lookups == ["good.example", "internal.example"]


async def test_unresolved_verdict_is_not_cached(monkeypatch) -> None:
    """``unresolved`` is the permissive answer, so it must be retried."""
    lookups: list[str] = []

    async def _resolve(host: str, *, timeout: float = 5.0) -> list[str] | None:
        lookups.append(host)
        return None

    monkeypatch.setattr(address_guard, "resolve_host_addresses", _resolve)

    for _ in range(3):
        await filter_public_configs([_cfg("nowhere.example")], stage="tcp")

    assert lookups == ["nowhere.example"] * 3


async def test_expired_verdict_is_resolved_again(monkeypatch) -> None:
    """A stale verdict must not keep a rebinding host allowed forever."""
    lookups: list[str] = []

    async def _resolve(host: str, *, timeout: float = 5.0) -> list[str] | None:
        lookups.append(host)
        return ["93.184.216.34"]

    monkeypatch.setattr(address_guard, "resolve_host_addresses", _resolve)

    await filter_public_configs([_cfg("good.example")], stage="tcp")
    # Age the stored verdict instead of moving the clock: time.monotonic is
    # shared with the event loop, so patching it breaks the awaits below.
    address_guard._verdict_cache["good.example"] = (
        address_guard.time.monotonic() - 1.0,
        "public",
    )
    await filter_public_configs([_cfg("good.example")], stage="tls")

    assert lookups == ["good.example", "good.example"]
