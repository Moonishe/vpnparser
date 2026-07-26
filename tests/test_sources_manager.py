"""Tests for src.sources.manager — 100% coverage target."""

from __future__ import annotations

import asyncio
import json
from unittest import mock

import httpx
import pytest

import src.sources.manager as manager_module
from src.sources.list_types import DEFAULT_LIST_TYPE
from src.sources.manager import SourceManager, SourceResult

# ===================================================================
# _FakeResponse helper
# ===================================================================


class _FakeResponse:
    """Simulates an httpx.Response, including the streaming interface."""

    def __init__(
        self,
        status_code: int = 200,
        *,
        text: str = "",
        headers: dict[str, str] | None = None,
        chunks: list[bytes] | None = None,
    ):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.encoding = "utf-8"
        self._chunks = chunks

    async def aiter_bytes(self):
        for chunk in (
            self._chunks if self._chunks is not None else [self.text.encode("utf-8")]
        ):
            yield chunk

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                f"{self.status_code} error",
                request=mock.MagicMock(),
                response=self,
            )

    def json(self):
        return {}


class _NeverEndingResponse(_FakeResponse):
    """A 200 whose body never completes — the slow-drip / slowloris source.

    Every individual read succeeds, so a per-operation timeout never fires;
    only a wall-clock budget around the whole transfer can stop it.
    """

    def __init__(self) -> None:
        super().__init__(200, text="")

    async def aiter_bytes(self):
        yield b"x"
        await asyncio.Event().wait()  # never set: the drip never ends


class _FakeStream:
    """Async context manager returned by a fake ``client.stream(...)``."""

    def __init__(self, handler, url: str):
        self._handler = handler
        self._url = url

    async def __aenter__(self) -> _FakeResponse:
        # The handler may raise to simulate a transport error, exactly like
        # httpx does when the request is sent inside the context manager.
        return self._handler(self._url)

    async def __aexit__(self, *args) -> None:
        return None


def _streaming_client(
    handler,
    requested: list[str] | None = None,
    calls: list[dict] | None = None,
):
    """Build an httpx.AsyncClient stand-in whose stream() calls *handler*.

    Args:
        handler: Called with the requested URL; returns a fake response.
        requested: Collects every requested URL, in order.
        calls: Collects ``{"url": ..., **stream kwargs}`` for assertions on the
            headers and extensions the manager attaches.
    """

    class _Client:
        def __init__(self, *args, **kwargs):
            self.kwargs = kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        def stream(self, method, url, **kwargs):
            if requested is not None:
                requested.append(url)
            if calls is not None:
                calls.append({"url": url, **kwargs})
            return _FakeStream(handler, url)

    return _Client


#: Address the fake resolver hands back for every host it approves. The manager
#: connects to the address it validated, so requests carry this literal.
PUBLIC_IP = "93.184.216.34"


def _patch_url_guard(
    monkeypatch,
    blocked: set[str] | None = None,
    addresses: list[str] | None = None,
) -> None:
    """Replace the SSRF resolver with a host blocklist so no DNS is needed.

    Blocked hosts resolve to nothing, which is how ``resolve_global_ips``
    reports both "does not resolve" and "resolves into private space".
    """
    blocked_hosts = blocked or set()
    answers = addresses if addresses is not None else [PUBLIC_IP]

    async def fake_resolve_global_ips(host: str, **kwargs) -> list[str]:
        return [] if host in blocked_hosts else list(answers)

    monkeypatch.setattr(
        "src.sources.manager.resolve_global_ips",
        fake_resolve_global_ips,
    )


# ===================================================================
# Config loading tests
# ===================================================================


class TestConfigLoading:
    def test_init_with_missing_files(self, tmp_path) -> None:
        """Missing sources/settings files produce empty config."""
        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )
        assert sm.sources == []
        assert sm.settings == {}

    def test_init_with_valid_files(self, tmp_path) -> None:
        sources_file = tmp_path / "sources.json"
        sources_file.write_text(
            json.dumps(
                {
                    "sources": [
                        {"name": "src1", "type": "raw", "enabled": True},
                    ]
                }
            ),
            encoding="utf-8",
        )
        settings_file = tmp_path / "settings.yaml"
        settings_file.write_text(
            "sources:\n  max_concurrent_fetches: 5\n", encoding="utf-8"
        )

        sm = SourceManager(
            sources_file=str(sources_file),
            settings_file=str(settings_file),
        )
        assert len(sm.sources) == 1
        assert sm.sources[0]["name"] == "src1"
        assert sm.settings["sources"]["max_concurrent_fetches"] == 5
        assert sm._semaphore._value == 5

    def test_init_bad_max_concurrent_falls_back(self, tmp_path) -> None:
        settings_file = tmp_path / "settings.yaml"
        settings_file.write_text(
            "sources:\n  max_concurrent_fetches: invalid\n", encoding="utf-8"
        )

        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(settings_file),
        )
        # Falls back to default 10
        assert sm._semaphore._value == 10

    def test_load_settings_yaml_error(self, tmp_path) -> None:
        settings_file = tmp_path / "settings.yaml"
        settings_file.write_text("{invalid: yaml: [\n", encoding="utf-8")

        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(settings_file),
        )
        assert sm.settings == {}

    def test_load_settings_os_error(self, tmp_path, monkeypatch) -> None:
        settings_file = tmp_path / "settings.yaml"
        settings_file.write_text("key: val\n", encoding="utf-8")

        import yaml as yaml_mod

        def broken_yaml_load(stream):
            raise OSError("disk read error")

        monkeypatch.setattr(yaml_mod, "safe_load", broken_yaml_load)

        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(settings_file),
        )
        # yaml.safe_load raises OSError, caught by except (YAMLError, OSError)
        assert sm.settings == {}

    def test_load_sources_json_decode_error(self, tmp_path) -> None:
        sources_file = tmp_path / "sources.json"
        sources_file.write_text("not json\n", encoding="utf-8")

        sm = SourceManager(
            sources_file=str(sources_file),
            settings_file=str(tmp_path / "missing.yaml"),
        )
        assert sm.sources == []

    def test_load_sources_os_error(self, tmp_path, monkeypatch) -> None:
        sources_file = tmp_path / "sources.json"
        sources_file.write_text("[]\n", encoding="utf-8")

        import json as json_mod

        def broken_json_load(fh):
            raise OSError("disk read error")

        monkeypatch.setattr(json_mod, "load", broken_json_load)

        sm = SourceManager(
            sources_file=str(sources_file),
            settings_file=str(tmp_path / "missing.yaml"),
        )
        assert sm.sources == []

    def test_sources_filter_to_dicts_only(self, tmp_path) -> None:
        sources_file = tmp_path / "sources.json"
        sources_file.write_text(
            json.dumps(
                {
                    "sources": [
                        {"name": "valid", "enabled": True},
                        "not a dict",
                        None,
                        42,
                    ]
                }
            ),
            encoding="utf-8",
        )

        sm = SourceManager(
            sources_file=str(sources_file),
            settings_file=str(tmp_path / "missing.yaml"),
        )
        assert len(sm.sources) == 1
        assert sm.sources[0]["name"] == "valid"

    def test_sources_not_a_dict(self, tmp_path) -> None:
        sources_file = tmp_path / "sources.json"
        sources_file.write_text('"just a string"', encoding="utf-8")

        sm = SourceManager(
            sources_file=str(sources_file),
            settings_file=str(tmp_path / "missing.yaml"),
        )
        assert sm.sources == []

    def test_settings_not_a_dict(self, tmp_path) -> None:
        settings_file = tmp_path / "settings.yaml"
        settings_file.write_text("just a string\n", encoding="utf-8")

        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(settings_file),
        )
        assert sm.settings == {}

    def test_enabled_sources_filters(self, tmp_path) -> None:
        sources_file = tmp_path / "sources.json"
        sources_file.write_text(
            json.dumps(
                {
                    "sources": [
                        {"name": "enabled1", "enabled": True},
                        {"name": "disabled", "enabled": False},
                        {"name": "enabled2", "enabled": "true"},
                        {"name": "no_enabled_field"},
                    ]
                }
            ),
            encoding="utf-8",
        )

        sm = SourceManager(
            sources_file=str(sources_file),
            settings_file=str(tmp_path / "missing.yaml"),
        )
        enabled = sm.enabled_sources()
        assert len(enabled) == 2
        assert enabled[0]["name"] == "enabled1"
        assert enabled[1]["name"] == "enabled2"

    def test_enabled_sources_parses_negative_strings(self, tmp_path) -> None:
        """Hand-written "false"/"no"/"0"/"off" disable a source.

        Plain bool() would enable all of them — every non-empty string is
        truthy.
        """
        sources_file = tmp_path / "sources.json"
        sources_file.write_text(
            json.dumps(
                {
                    "sources": [
                        {"name": "off_false", "enabled": "false"},
                        {"name": "off_no", "enabled": "No"},
                        {"name": "off_zero", "enabled": "0"},
                        {"name": "off_off", "enabled": "off"},
                        {"name": "on_yes", "enabled": "yes"},
                        {"name": "on_one", "enabled": 1},
                    ]
                }
            ),
            encoding="utf-8",
        )

        sm = SourceManager(
            sources_file=str(sources_file),
            settings_file=str(tmp_path / "missing.yaml"),
        )
        assert [s["name"] for s in sm.enabled_sources()] == ["on_yes", "on_one"]

    def test_empty_github_api_base_falls_back(self, tmp_path) -> None:
        """A present-but-null github_api_base must not reach GitHubClient.

        YAML parses a bare ``github_api_base:`` as None, and
        ``None.rstrip("/")`` inside GitHubClient would kill the pipeline at
        startup.
        """
        settings_file = tmp_path / "settings.yaml"
        settings_file.write_text("sources:\n  github_api_base:\n", encoding="utf-8")

        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(settings_file),
        )
        assert sm._github.api_base == "https://api.github.com"


# ===================================================================
# fetch_all
# ===================================================================


class TestFetchAll:
    def test_fetch_all_empty_enabled_returns_empty(self, tmp_path, monkeypatch) -> None:
        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )
        # No sources configured at all
        monkeypatch.setattr(sm, "sources", [])
        result = asyncio.run(sm.fetch_all())
        assert result == []

    def test_fetch_all_all_succeed(self, tmp_path, monkeypatch) -> None:
        sources_file = tmp_path / "sources.json"
        sources_file.write_text(
            json.dumps(
                {
                    "sources": [
                        {
                            "name": "a",
                            "type": "raw",
                            "enabled": True,
                            "owner": "o",
                            "repo": "r",
                            "path": "dir",
                        },
                        {
                            "name": "b",
                            "type": "raw",
                            "enabled": True,
                            "owner": "o",
                            "repo": "r",
                            "path": "dir2",
                        },
                    ]
                }
            ),
            encoding="utf-8",
        )

        sm = SourceManager(
            sources_file=str(sources_file),
            settings_file=str(tmp_path / "missing.yaml"),
        )

        async def fake_fetch_source(src):
            return SourceResult(
                source_name=src.get("name", "?"),
                files=[("f.txt", "content")],
            )

        monkeypatch.setattr(sm, "fetch_source", fake_fetch_source)

        results = asyncio.run(sm.fetch_all())
        assert len(results) == 2
        assert results[0].source_name == "a"
        assert results[0].ok is True
        assert results[1].source_name == "b"

    def test_fetch_all_partial_failures(self, tmp_path, monkeypatch) -> None:
        sources_file = tmp_path / "sources.json"
        sources_file.write_text(
            json.dumps(
                {
                    "sources": [
                        {
                            "name": "good",
                            "type": "raw",
                            "enabled": True,
                            "owner": "o",
                            "repo": "r",
                        },
                        {
                            "name": "bad",
                            "type": "sub",
                            "enabled": True,
                            "owner": "o",
                            "repo": "r",
                        },
                    ]
                }
            ),
            encoding="utf-8",
        )

        sm = SourceManager(
            sources_file=str(sources_file),
            settings_file=str(tmp_path / "missing.yaml"),
        )

        async def fake_fetch_source(src):
            name = src.get("name", "?")
            if name == "bad":
                return SourceResult(source_name=name, error="something failed")
            return SourceResult(source_name=name, files=[("f.txt", "c")])

        monkeypatch.setattr(sm, "fetch_source", fake_fetch_source)

        results = asyncio.run(sm.fetch_all())
        assert len(results) == 2
        assert results[0].source_name == "good"
        assert results[0].ok is True
        assert results[1].source_name == "bad"
        assert results[1].ok is False
        assert results[1].error == "something failed"

    def test_fetch_all_task_exception(self, tmp_path, monkeypatch) -> None:
        """A task that raises a raw Exception is captured as error."""
        sources_file = tmp_path / "sources.json"
        sources_file.write_text(
            json.dumps(
                {
                    "sources": [
                        {
                            "name": "raising",
                            "type": "raw",
                            "enabled": True,
                            "owner": "o",
                            "repo": "r",
                        },
                    ]
                }
            ),
            encoding="utf-8",
        )

        sm = SourceManager(
            sources_file=str(sources_file),
            settings_file=str(tmp_path / "missing.yaml"),
        )

        async def fake_fetch_source(src):
            raise ValueError("unexpected crash")

        monkeypatch.setattr(sm, "fetch_source", fake_fetch_source)

        results = asyncio.run(sm.fetch_all())
        assert len(results) == 1
        assert results[0].ok is False
        assert "unexpected crash" in results[0].error

    def test_fetch_all_base_exception_propagates(self, tmp_path, monkeypatch) -> None:
        """Cancellation / SystemExit must propagate, not be swallowed."""
        sources_file = tmp_path / "sources.json"
        sources_file.write_text(
            json.dumps(
                {
                    "sources": [
                        {
                            "name": "cancel",
                            "type": "raw",
                            "enabled": True,
                            "owner": "o",
                            "repo": "r",
                        },
                    ]
                }
            ),
            encoding="utf-8",
        )

        sm = SourceManager(
            sources_file=str(sources_file),
            settings_file=str(tmp_path / "missing.yaml"),
        )

        async def fake_fetch_source(src):
            raise asyncio.CancelledError()

        monkeypatch.setattr(sm, "fetch_source", fake_fetch_source)

        with pytest.raises(asyncio.CancelledError):
            asyncio.run(sm.fetch_all())


# ===================================================================
# _fetch_with_semaphore
# ===================================================================


class TestFetchWithSemaphore:
    def test_semaphore_bounds_concurrency(self, tmp_path, monkeypatch) -> None:
        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )
        call_order = []

        async def slow_fetch(src):
            call_order.append(src.get("name"))
            await asyncio.sleep(0.01)
            return SourceResult(source_name=src.get("name", "?"))

        monkeypatch.setattr(sm, "fetch_source", slow_fetch)

        sources = [
            {"name": "a", "type": "raw", "enabled": True},
            {"name": "b", "type": "raw", "enabled": True},
        ]
        monkeypatch.setattr(sm, "sources", sources)

        results = asyncio.run(sm.fetch_all())
        assert len(results) == 2


# ===================================================================
# fetch_source — routing
# ===================================================================


class TestFetchSourceRouting:
    def test_unknown_source_type(self, tmp_path) -> None:
        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )
        result = asyncio.run(
            sm.fetch_source(
                {
                    "name": "weird",
                    "type": "unknown-type",
                    "owner": "o",
                    "repo": "r",
                }
            )
        )
        assert result.ok is False
        assert "unknown source type" in result.error

    def test_source_exception_caught(self, tmp_path) -> None:
        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )

        class ExplodingSource(dict):
            pass

        src = ExplodingSource({"name": "boom", "type": "raw"})
        # Monkeypatch get to raise
        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setitem(src, "type", "raw")

        # Force an exception in the try block by making owner access fail
        async def fail_fetch():
            # This won't be reached; the exception should happen during source.get
            pass

        # The simplest way: pass a source that raises on .get
        class BadDict(dict):
            def get(self, key, default=None):
                if key == "owner":
                    raise RuntimeError("oops")
                return super().get(key, default)

        result = asyncio.run(sm.fetch_source(BadDict({"name": "bad", "type": "raw"})))
        assert result.ok is False
        assert result.error is not None

    def test_exception_in_fetch_source_caught(self, tmp_path, monkeypatch) -> None:
        """Any exception in fetch_source is caught and returned as error."""
        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )

        async def failing_fetch(*args, **kwargs):
            raise httpx.ConnectError("network error")

        monkeypatch.setattr(sm._github, "fetch_file", failing_fetch)

        result = asyncio.run(
            sm.fetch_source(
                {
                    "name": "net fail",
                    "type": "subscription",
                    "owner": "o",
                    "repo": "r",
                    "path": "f.txt",
                }
            )
        )
        assert result.ok is False
        assert "network error" in result.error


# ===================================================================
# fetch_source — URL / subscription type
# ===================================================================


class TestFetchSourceUrl:
    def test_url_type_fetches(self, tmp_path) -> None:
        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )

        async def fake_direct(url, **kw):
            return "content-from-url"

        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setattr(sm, "_fetch_direct_url", fake_direct)

        result = asyncio.run(
            sm.fetch_source(
                {
                    "name": "direct",
                    "type": "url",
                    "url": "https://example.com/sub.txt",
                    "list_type": "blacklist",
                }
            )
        )
        assert result.ok is True
        assert result.files == [("sub.txt", "content-from-url")]
        assert result.list_type == "blacklist"

    def test_url_type_empty_content(self, tmp_path) -> None:
        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )

        async def fake_direct(url, **kw):
            return ""

        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setattr(sm, "_fetch_direct_url", fake_direct)

        result = asyncio.run(
            sm.fetch_source(
                {
                    "name": "empty-url",
                    "type": "url",
                    "url": "https://example.com/empty.txt",
                }
            )
        )
        assert result.ok is False
        assert "empty or not found" in result.error

    def test_subscription_with_url_type(self, tmp_path) -> None:
        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )

        async def fake_direct(url, **kw):
            return "subscription-data"

        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setattr(sm, "_fetch_direct_url", fake_direct)

        result = asyncio.run(
            sm.fetch_source(
                {
                    "name": "sub-url",
                    "type": "subscription",
                    "url": "https://example.com/sub",
                }
            )
        )
        assert result.ok is True
        assert result.files == [("sub", "subscription-data")]

    def test_subscription_with_url_but_empty(self, tmp_path) -> None:
        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )

        async def fake_direct(url, **kw):
            return ""

        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setattr(sm, "_fetch_direct_url", fake_direct)

        result = asyncio.run(
            sm.fetch_source(
                {
                    "name": "sub-empty",
                    "type": "subscription",
                    "url": "https://example.com/sub",
                }
            )
        )
        assert result.ok is False

    def test_url_type_with_filename(self, tmp_path) -> None:
        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )

        async def fake_direct(url, **kw):
            return "data"

        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setattr(sm, "_fetch_direct_url", fake_direct)

        result = asyncio.run(
            sm.fetch_source(
                {
                    "name": "custom-name",
                    "type": "url",
                    "url": "https://example.com/data.txt",
                    "filename": "myfile.txt",
                }
            )
        )
        assert result.ok is True
        assert result.files == [("myfile.txt", "data")]

    def test_url_type_custom_list_type_and_country(self, tmp_path) -> None:
        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )

        async def fake_direct(url, **kw):
            return "data"

        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setattr(sm, "_fetch_direct_url", fake_direct)

        result = asyncio.run(
            sm.fetch_source(
                {
                    "name": "custom",
                    "type": "url",
                    "url": "https://example.com/d.txt",
                    "list_type": "whitelist",
                    "default_country": "DE",
                }
            )
        )
        assert result.ok is True
        assert result.list_type == "whitelist"
        assert result.default_country == "DE"


# ===================================================================
# fetch_source — GitHub subscription type
# ===================================================================


class TestFetchSourceSubscription:
    def test_missing_owner_repo(self, tmp_path) -> None:
        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )
        result = asyncio.run(
            sm.fetch_source(
                {
                    "name": "no-owner",
                    "type": "subscription",
                }
            )
        )
        assert result.ok is False
        assert "missing owner/repo" in result.error

    def test_missing_path(self, tmp_path) -> None:
        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )
        result = asyncio.run(
            sm.fetch_source(
                {
                    "name": "no-path",
                    "type": "subscription",
                    "owner": "o",
                    "repo": "r",
                }
            )
        )
        assert result.ok is False
        assert "requires a file path" in result.error

    def test_successful_fetch(self, tmp_path, monkeypatch) -> None:
        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )

        async def fake_fetch_file(owner, repo, path, branch="main"):
            return "file-content"

        monkeypatch.setattr(sm._github, "fetch_file", fake_fetch_file)

        result = asyncio.run(
            sm.fetch_source(
                {
                    "name": "sub1",
                    "type": "subscription",
                    "owner": "o",
                    "repo": "r",
                    "path": "dir/sub.txt",
                    "list_type": "mixed",
                }
            )
        )
        assert result.ok is True
        assert result.files == [("sub.txt", "file-content")]

    def test_empty_file(self, tmp_path, monkeypatch) -> None:
        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )

        async def fake_fetch_file(owner, repo, path, branch="main"):
            return ""

        monkeypatch.setattr(sm._github, "fetch_file", fake_fetch_file)

        result = asyncio.run(
            sm.fetch_source(
                {
                    "name": "empty-sub",
                    "type": "subscription",
                    "owner": "o",
                    "repo": "r",
                    "path": "empty.txt",
                }
            )
        )
        assert result.ok is False
        assert "empty or not found" in result.error

    def test_subscription_with_country_info(self, tmp_path, monkeypatch) -> None:
        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )

        async def fake_fetch_file(owner, repo, path, branch="main"):
            return "data"

        monkeypatch.setattr(sm._github, "fetch_file", fake_fetch_file)

        result = asyncio.run(
            sm.fetch_source(
                {
                    "name": "sub-country",
                    "type": "subscription",
                    "owner": "o",
                    "repo": "r",
                    "path": "f.txt",
                    "default_country": "RU",
                    "list_type": "blacklist",
                }
            )
        )
        assert result.ok is True
        assert result.default_country == "RU"
        assert result.list_type == "blacklist"


# ===================================================================
# fetch_source — raw type with filters
# ===================================================================


class TestFetchSourceRaw:
    def test_empty_directory(self, tmp_path, monkeypatch) -> None:
        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )

        async def fake_fetch_directory(*args, **kwargs):
            return []

        monkeypatch.setattr(sm._github, "fetch_directory", fake_fetch_directory)

        result = asyncio.run(
            sm.fetch_source(
                {
                    "name": "raw-empty",
                    "type": "raw",
                    "owner": "o",
                    "repo": "r",
                    "path": "empty_dir",
                }
            )
        )
        assert result.ok is False
        assert "empty or not found" in result.error

    def test_successful_raw_with_filters(self, tmp_path, monkeypatch) -> None:
        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )

        async def fake_fetch_directory(*args, **kwargs):
            return [
                ("keep.txt", "content1"),
                ("skip.txt", "content2"),
            ]

        monkeypatch.setattr(sm._github, "fetch_directory", fake_fetch_directory)

        result = asyncio.run(
            sm.fetch_source(
                {
                    "name": "raw-filtered",
                    "type": "raw",
                    "owner": "o",
                    "repo": "r",
                    "path": "dir",
                    "include_files": ["keep.txt"],
                    "list_type": "whitelist",
                }
            )
        )
        assert result.ok is True
        assert result.files == [("keep.txt", "content1")]
        assert result.list_type == "whitelist"

    def test_raw_with_custom_depth_and_max_files(self, tmp_path, monkeypatch) -> None:
        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )

        captured = {}

        async def fake_fetch_directory(*args, **kwargs):
            captured["args"] = (args, kwargs)
            return [("f.txt", "c")]

        monkeypatch.setattr(sm._github, "fetch_directory", fake_fetch_directory)

        result = asyncio.run(
            sm.fetch_source(
                {
                    "name": "custom-params",
                    "type": "raw",
                    "owner": "o",
                    "repo": "r",
                    "path": "dir",
                    "max_depth": 5,
                    "max_files": 100,
                }
            )
        )
        assert result.ok is True
        # Verify parameters passed through
        kws = captured["args"][1]
        assert kws.get("max_depth") == 5
        assert kws.get("max_files") == 100


# ===================================================================
# _fetch_direct_url
# ===================================================================


class TestFetchDirectUrl:
    def test_fetch_direct_url_success(self, tmp_path, monkeypatch) -> None:
        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )
        _patch_url_guard(monkeypatch)
        monkeypatch.setattr(
            "src.sources.manager.httpx.AsyncClient",
            _streaming_client(lambda url: _FakeResponse(text="hello world")),
        )

        result = asyncio.run(sm._fetch_direct_url("https://example.com/f.txt"))
        assert result == "hello world"

    def test_fetch_direct_url_404(self, tmp_path, monkeypatch) -> None:
        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )
        _patch_url_guard(monkeypatch)
        monkeypatch.setattr(
            "src.sources.manager.httpx.AsyncClient",
            _streaming_client(lambda url: _FakeResponse(status_code=404)),
        )

        result = asyncio.run(sm._fetch_direct_url("https://example.com/missing.txt"))
        assert result == ""

    def test_fetch_direct_url_raises_on_invalid_scheme(self) -> None:
        sm = SourceManager(
            sources_file="missing.json",
            settings_file="missing.yaml",
        )
        with pytest.raises(ValueError, match="absolute HTTP/HTTPS"):
            asyncio.run(sm._fetch_direct_url("ftp://example.com/f.txt"))

    def test_fetch_direct_url_retry_then_success(self, tmp_path, monkeypatch) -> None:
        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )
        attempt = {"count": 0}

        def flaky(url):
            attempt["count"] += 1
            if attempt["count"] == 1:
                raise httpx.ConnectError("transient")
            return _FakeResponse(text="final")

        _patch_url_guard(monkeypatch)
        monkeypatch.setattr(
            "src.sources.manager.httpx.AsyncClient",
            _streaming_client(flaky),
        )

        async def fake_sleep(_secs):
            pass

        monkeypatch.setattr("src.sources.manager.asyncio.sleep", fake_sleep)

        result = asyncio.run(sm._fetch_direct_url("https://example.com/f.txt"))
        assert result == "final"
        assert attempt["count"] == 2

    def test_fetch_direct_url_all_attempts_fail(self, tmp_path, monkeypatch) -> None:
        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )

        def always_fail(url):
            raise httpx.ConnectError("always fails")

        _patch_url_guard(monkeypatch)
        monkeypatch.setattr(
            "src.sources.manager.httpx.AsyncClient",
            _streaming_client(always_fail),
        )

        async def fake_sleep(_secs):
            pass

        monkeypatch.setattr("src.sources.manager.asyncio.sleep", fake_sleep)

        with pytest.raises(httpx.ConnectError):
            asyncio.run(sm._fetch_direct_url("https://example.com/f.txt"))

    def test_fetch_direct_url_http_error_retries(self, tmp_path, monkeypatch) -> None:
        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )
        attempt = {"count": 0}

        def flaky(url):
            attempt["count"] += 1
            if attempt["count"] < 3:
                return _FakeResponse(status_code=500)
            return _FakeResponse(text="ok")

        _patch_url_guard(monkeypatch)
        monkeypatch.setattr(
            "src.sources.manager.httpx.AsyncClient",
            _streaming_client(flaky),
        )

        async def fake_sleep(_secs):
            pass

        monkeypatch.setattr("src.sources.manager.asyncio.sleep", fake_sleep)

        result = asyncio.run(sm._fetch_direct_url("https://example.com/f.txt"))
        assert result == "ok"
        assert attempt["count"] == 3

    # --- SSRF guard (regression) ----------------------------------------

    def test_fetch_direct_url_rejects_private_host(
        self, tmp_path, monkeypatch, caplog
    ) -> None:
        """A URL resolving to a private address is never requested."""
        caplog.set_level("WARNING")
        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )
        requested: list[str] = []
        _patch_url_guard(monkeypatch, blocked={"127.0.0.1"})
        monkeypatch.setattr(
            "src.sources.manager.httpx.AsyncClient",
            _streaming_client(lambda url: _FakeResponse(text="secret"), requested),
        )

        with pytest.raises(ValueError, match="non-public url"):
            asyncio.run(sm._fetch_direct_url("http://127.0.0.1:9200/_cat/indices"))
        assert requested == []
        assert "Dropped non-public source url" in caplog.text

    def test_fetch_direct_url_redirect_to_loopback_not_followed(
        self, tmp_path, monkeypatch
    ) -> None:
        """A public URL redirecting to 127.0.0.1 must not reach the loopback."""
        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )
        requested: list[str] = []

        def redirector(url):
            if "127.0.0.1" in url:  # pragma: no cover - must never happen
                return _FakeResponse(text="internal data")
            return _FakeResponse(
                status_code=302,
                headers={"location": "http://127.0.0.1:9200/_cat/indices"},
            )

        _patch_url_guard(monkeypatch, blocked={"127.0.0.1"})
        monkeypatch.setattr(
            "src.sources.manager.httpx.AsyncClient",
            _streaming_client(redirector, requested),
        )

        with pytest.raises(ValueError, match="non-public url"):
            asyncio.run(sm._fetch_direct_url("https://example.com/redirect"))
        # Only the first hop is requested, and it goes to the validated address.
        assert requested == [f"https://{PUBLIC_IP}/redirect"]

    def test_fetch_direct_url_follows_public_redirect(
        self, tmp_path, monkeypatch
    ) -> None:
        """A redirect to another public host is followed and validated."""
        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )
        requested: list[str] = []

        def redirector(url):
            if url.endswith("/final.txt"):
                return _FakeResponse(text="payload")
            return _FakeResponse(status_code=301, headers={"location": "/final.txt"})

        _patch_url_guard(monkeypatch)
        monkeypatch.setattr(
            "src.sources.manager.httpx.AsyncClient",
            _streaming_client(redirector, requested),
        )

        result = asyncio.run(sm._fetch_direct_url("https://example.com/start"))
        assert result == "payload"
        # The relative Location is resolved against the logical URL, and each
        # hop is then requested on the address that hop was validated on.
        assert requested == [
            f"https://{PUBLIC_IP}/start",
            f"https://{PUBLIC_IP}/final.txt",
        ]

    def test_fetch_direct_url_redirect_loop_is_bounded(
        self, tmp_path, monkeypatch
    ) -> None:
        """An endless redirect chain raises instead of looping forever."""
        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )
        requested: list[str] = []
        counter = {"n": 0}

        def redirector(url):
            counter["n"] += 1
            return _FakeResponse(
                status_code=302,
                headers={"location": f"/hop{counter['n']}"},
            )

        _patch_url_guard(monkeypatch)
        monkeypatch.setattr(
            "src.sources.manager.httpx.AsyncClient",
            _streaming_client(redirector, requested),
        )

        with pytest.raises(ValueError, match="too many redirects"):
            asyncio.run(sm._fetch_direct_url("https://example.com/start"))
        assert len(requested) == 6

    # --- response size cap (regression) ---------------------------------

    def test_fetch_direct_url_oversized_body_discarded(
        self, tmp_path, monkeypatch, caplog
    ) -> None:
        """A body past MAX_DOWNLOAD_BYTES is dropped instead of buffered."""
        caplog.set_level("WARNING")
        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )
        monkeypatch.setattr("src.sources.manager.MAX_DOWNLOAD_BYTES", 8)
        _patch_url_guard(monkeypatch)
        monkeypatch.setattr(
            "src.sources.manager.httpx.AsyncClient",
            _streaming_client(
                lambda url: _FakeResponse(chunks=[b"12345", b"67890", b"more"]),
            ),
        )

        result = asyncio.run(sm._fetch_direct_url("https://example.com/huge.txt"))
        assert result == ""
        assert "oversized response" in caplog.text

    # --- total download time cap (regression) ---------------------------

    def test_fetch_direct_url_bounds_total_transfer_time(
        self, tmp_path, monkeypatch
    ) -> None:
        """A slow-drip source cannot hold the fetch open indefinitely.

        ``timeout`` is a *per-operation* limit — httpx restarts the read timer
        on every chunk — so a host trickling bytes stayed under both the
        timeout and MAX_DOWNLOAD_BYTES while parking the fetch stage forever.
        """
        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )
        _patch_url_guard(monkeypatch)
        monkeypatch.setattr(
            "src.sources.manager.httpx.AsyncClient",
            _streaming_client(lambda url: _NeverEndingResponse()),
        )

        async def scenario() -> str:
            # The outer bound only keeps a regression from hanging the suite;
            # it is 25x the inner budget (0.05s * DOWNLOAD_TIMEOUT_FACTOR).
            return await asyncio.wait_for(
                sm._fetch_direct_url(
                    "https://example.com/drip.txt",
                    timeout=0.05,
                    attempts=1,
                ),
                timeout=5.0,
            )

        with pytest.raises(TimeoutError, match="exceeded its 0.2s budget"):
            asyncio.run(scenario())

    def test_fetch_direct_url_retries_after_wall_clock_timeout(
        self, tmp_path, monkeypatch
    ) -> None:
        """A timed-out attempt is retried like any other transport failure."""
        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )
        attempt = {"count": 0}

        def flaky(url):
            attempt["count"] += 1
            if attempt["count"] == 1:
                return _NeverEndingResponse()
            return _FakeResponse(text="final")

        _patch_url_guard(monkeypatch)
        monkeypatch.setattr(
            "src.sources.manager.httpx.AsyncClient",
            _streaming_client(flaky),
        )

        async def fake_sleep(_secs):
            pass

        monkeypatch.setattr("src.sources.manager.asyncio.sleep", fake_sleep)

        result = asyncio.run(
            sm._fetch_direct_url(
                "https://example.com/drip.txt",
                timeout=0.05,
                attempts=2,
            ),
        )
        assert result == "final"
        assert attempt["count"] == 2

    def test_filename_from_url(self) -> None:
        sm = SourceManager(
            sources_file="missing.json",
            settings_file="missing.yaml",
        )
        assert sm._filename_from_url("https://example.com/dir/file.txt") == "file.txt"
        assert sm._filename_from_url("https://example.com/") == ""
        assert sm._filename_from_url("") == ""
        # For a string without path separators, PurePosixPath.name returns the whole string
        assert sm._filename_from_url("not-a-url") == "not-a-url"


# ===================================================================
# _fetch_url_list
# ===================================================================


class TestFetchUrlList:
    def test_missing_url(self, tmp_path) -> None:
        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )

        result = asyncio.run(
            sm._fetch_url_list(
                {"name": "no-url"},
                "no-url",
                DEFAULT_LIST_TYPE,
                None,
            )
        )
        assert result.ok is False
        assert "missing url" in result.error

    def test_empty_index(self, tmp_path, monkeypatch) -> None:
        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )

        async def fake_direct(url, **kw):
            return ""

        monkeypatch.setattr(sm, "_fetch_direct_url", fake_direct)

        result = asyncio.run(
            sm._fetch_url_list(
                {"name": "empty-index", "url": "https://example.com/index.txt"},
                "empty-index",
                DEFAULT_LIST_TYPE,
                None,
            )
        )
        assert result.ok is False
        assert "empty or not found" in result.error

    def test_no_valid_urls(self, tmp_path, monkeypatch) -> None:
        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )

        async def fake_direct(url, **kw):
            return "# just a comment\n// another comment\nnot-a-url"

        monkeypatch.setattr(sm, "_fetch_direct_url", fake_direct)

        result = asyncio.run(
            sm._fetch_url_list(
                {"name": "no-urls", "url": "https://example.com/index.txt"},
                "no-urls",
                DEFAULT_LIST_TYPE,
                None,
            )
        )
        assert result.ok is False
        assert "contains no valid URLs" in result.error

    def test_successful_fetch(self, tmp_path, monkeypatch) -> None:
        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )

        index_text = "\n".join(
            [
                "# comment",
                "https://example.com/a.txt",
                "https://example.com/b.txt",
                "not-a-url",
            ]
        )
        fetched = {
            "https://example.com/a.txt": "content-a",
            "https://example.com/b.txt": "content-b",
        }

        async def fake_direct(url, **kw):
            if url == "https://example.com/index.txt":
                return index_text
            return fetched.get(url, "")

        monkeypatch.setattr(sm, "_fetch_direct_url", fake_direct)

        result = asyncio.run(
            sm._fetch_url_list(
                {
                    "name": "test-list",
                    "url": "https://example.com/index.txt",
                    "list_type": "blacklist",
                },
                "test-list",
                "blacklist",
                None,
            )
        )
        assert result.ok is True
        assert len(result.files) == 2
        assert result.list_type == "blacklist"

    def test_all_fetches_fail(self, tmp_path, monkeypatch) -> None:
        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )

        async def fake_direct(url, **kw):
            if "index" in url:
                return "\nhttps://example.com/a.txt\nhttps://example.com/b.txt"
            return ""

        monkeypatch.setattr(sm, "_fetch_direct_url", fake_direct)

        result = asyncio.run(
            sm._fetch_url_list(
                {"name": "all-fail", "url": "https://example.com/index.txt"},
                "all-fail",
                DEFAULT_LIST_TYPE,
                None,
            )
        )
        assert result.ok is False
        assert "none returned content" in result.error

    def test_date_token_replacement(self, tmp_path, monkeypatch) -> None:
        """Date tokens use a frozen clock — comparing against a second
        datetime.now() flakes across a month/year boundary."""
        import datetime as datetime_module

        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )

        class _FrozenDatetime(datetime_module.datetime):
            @classmethod
            def now(cls, tz=None):
                return cls(2024, 3, 7, 12, 0, 0, tzinfo=tz)

        # _fetch_url_list does `from datetime import datetime` at call time, so
        # patching the attribute on the module is what it picks up.
        monkeypatch.setattr(datetime_module, "datetime", _FrozenDatetime)

        expected_url = "https://example.com/2024/03/data.txt"

        captured = []

        async def fake_direct(url, **kw):
            captured.append(url)
            if "index" in url:
                return "https://example.com/{YYYY}/{MM}/data.txt"
            return "content"

        monkeypatch.setattr(sm, "_fetch_direct_url", fake_direct)

        result = asyncio.run(
            sm._fetch_url_list(
                {"name": "date-test", "url": "https://example.com/index.txt"},
                "date-test",
                DEFAULT_LIST_TYPE,
                None,
            )
        )
        assert result.ok is True
        # Second call should have resolved the date tokens
        assert any(expected_url in c for c in captured)

    def test_url_list_with_exception_in_fetch(self, tmp_path, monkeypatch) -> None:
        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )

        async def fake_direct(url, **kw):
            if "index" in url:
                return "\nhttps://example.com/a.txt\nhttps://example.com/b.txt"
            raise httpx.ConnectError("fail")

        monkeypatch.setattr(sm, "_fetch_direct_url", fake_direct)

        async def fake_sleep(_secs):
            pass

        monkeypatch.setattr("src.sources.manager.asyncio.sleep", fake_sleep)

        result = asyncio.run(
            sm._fetch_url_list(
                {"name": "partial-fail", "url": "https://example.com/index.txt"},
                "partial-fail",
                DEFAULT_LIST_TYPE,
                None,
            )
        )
        assert result.ok is False
        assert "none returned content" in result.error

    def test_deduplication(self, tmp_path, monkeypatch) -> None:
        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )

        async def fake_direct(url, **kw):
            if "index" in url:
                return "\n".join(
                    [
                        "https://example.com/a.txt",
                        "https://example.com/a.txt",  # duplicate
                    ]
                )
            return "content"

        monkeypatch.setattr(sm, "_fetch_direct_url", fake_direct)

        result = asyncio.run(
            sm._fetch_url_list(
                {
                    "name": "dedup",
                    "url": "https://example.com/index.txt",
                    "max_files": 200,
                },
                "dedup",
                DEFAULT_LIST_TYPE,
                None,
            )
        )
        # Should have deduplicated to 1 file
        assert len(result.files) == 1

    def test_url_list_drops_private_urls(self, tmp_path, monkeypatch, caplog) -> None:
        """A loopback URL listed in an untrusted index is never requested."""
        caplog.set_level("WARNING")
        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )
        index = "\n".join(
            [
                "http://127.0.0.1:9200/_cat/indices",
                "http://169.254.169.254/latest/meta-data/",
                "https://example.com/good.txt",
            ]
        )
        requested: list[str] = []

        def handler(url):
            if url.endswith("index.txt"):
                return _FakeResponse(text=index)
            return _FakeResponse(text="vless://ok")

        _patch_url_guard(monkeypatch, blocked={"127.0.0.1", "169.254.169.254"})
        monkeypatch.setattr(
            "src.sources.manager.httpx.AsyncClient",
            _streaming_client(handler, requested),
        )

        result = asyncio.run(
            sm._fetch_url_list(
                {"name": "index", "url": "https://example.com/index.txt"},
                "index",
                DEFAULT_LIST_TYPE,
                None,
            )
        )
        assert result.ok is True
        assert result.files == [("good.txt", "vless://ok")]
        assert requested == [
            f"https://{PUBLIC_IP}/index.txt",
            f"https://{PUBLIC_IP}/good.txt",
        ]
        assert "Dropped non-public source url" in caplog.text


# ===================================================================
# SourceResult properties
# ===================================================================


class TestSourceResult:
    def test_ok_property(self) -> None:
        assert SourceResult(source_name="a", error=None).ok is True
        assert SourceResult(source_name="a", error="fail").ok is False
        assert SourceResult(source_name="a", files=[], error=None).ok is True

    def test_default_values(self) -> None:
        r = SourceResult(source_name="test")
        assert r.files == []
        assert r.error is None
        assert r.list_type == DEFAULT_LIST_TYPE
        assert r.default_country is None


# ===================================================================
# _source_default_country
# ===================================================================


class TestSourceDefaultCountry:
    def test_valid_two_letter_code(self) -> None:
        assert SourceManager._source_default_country({"default_country": "DE"}) == "DE"
        assert SourceManager._source_default_country({"default_country": "ru"}) == "RU"

    def test_none_returns_none(self) -> None:
        assert SourceManager._source_default_country({}) is None
        assert SourceManager._source_default_country({"default_country": None}) is None

    def test_invalid_code_returns_none(self) -> None:
        assert SourceManager._source_default_country({"default_country": "USA"}) is None
        assert SourceManager._source_default_country({"default_country": ""}) is None
        assert SourceManager._source_default_country({"default_country": "12"}) is None


# ===================================================================
# _int_source_value / _float_source_value
# ===================================================================


class TestSourceValueHelpers:
    def test_int_source_value_valid(self) -> None:
        assert SourceManager._int_source_value({"max_files": 42}, "max_files", 10) == 42
        assert (
            SourceManager._int_source_value({"max_files": "42"}, "max_files", 10) == 42
        )

    def test_int_source_value_default(self) -> None:
        assert SourceManager._int_source_value({}, "missing", 10) == 10

    def test_int_source_value_bool_rejected(self) -> None:
        # bool is subclass of int, but should be rejected
        assert (
            SourceManager._int_source_value({"max_files": False}, "max_files", 10) == 10
        )
        assert (
            SourceManager._int_source_value({"max_files": True}, "max_files", 10) == 10
        )

    def test_int_source_value_invalid_type(self) -> None:
        assert (
            SourceManager._int_source_value(
                {"max_files": "not-a-number"}, "max_files", 5
            )
            == 5
        )
        assert SourceManager._int_source_value({"max_files": None}, "max_files", 5) == 5

    def test_int_source_value_minimum(self) -> None:
        assert SourceManager._int_source_value({"x": 0}, "x", 1, minimum=1) == 1

    def test_float_source_value_valid(self) -> None:
        assert (
            SourceManager._float_source_value({"timeout": 30.5}, "timeout", 10.0)
            == 30.5
        )
        assert (
            SourceManager._float_source_value({"timeout": "30.5"}, "timeout", 10.0)
            == 30.5
        )

    def test_float_source_value_default(self) -> None:
        assert SourceManager._float_source_value({}, "missing", 15.0) == 15.0

    def test_float_source_value_bool_rejected(self) -> None:
        assert (
            SourceManager._float_source_value({"timeout": False}, "timeout", 10.0)
            == 10.0
        )

    def test_float_source_value_invalid(self) -> None:
        assert (
            SourceManager._float_source_value({"timeout": "bad"}, "timeout", 5.0) == 5.0
        )
        assert (
            SourceManager._float_source_value({"timeout": None}, "timeout", 5.0) == 5.0
        )


# ===================================================================
# _filter_files — additional edge cases
# ===================================================================


class TestFilterFiles:
    def test_exclude_files_by_basename(self) -> None:
        files = [
            ("dir/a.txt", "x"),
            ("dir/b.txt", "y"),
        ]
        result = SourceManager._filter_files({"exclude_files": ["a.txt"]}, files)
        assert result == [("dir/b.txt", "y")]

    def test_include_full_path(self) -> None:
        files = [
            ("subdir/file.txt", "x"),
            ("other/file.txt", "y"),
        ]
        result = SourceManager._filter_files(
            {"include_files": ["subdir/file.txt"]}, files
        )
        assert result == [("subdir/file.txt", "x")]

    def test_include_basename(self) -> None:
        files = [
            ("a/b/data.txt", "x"),
            ("c/d/data.txt", "y"),
        ]
        result = SourceManager._filter_files({"include_files": ["data.txt"]}, files)
        assert result == files  # both match by basename

    def test_exclude_basename(self) -> None:
        files = [
            ("a/keep.txt", "x"),
            ("b/drop.txt", "y"),
        ]
        result = SourceManager._filter_files({"exclude_files": ["drop.txt"]}, files)
        assert result == [("a/keep.txt", "x")]


# ===================================================================
# aclose / async context manager
# ===================================================================


class TestLifecycle:
    def test_aclose(self, tmp_path) -> None:
        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )
        # Should not crash
        asyncio.run(sm.aclose())

    def test_async_context_manager(self, tmp_path) -> None:
        async def test():
            async with SourceManager(
                sources_file=str(tmp_path / "missing.json"),
                settings_file=str(tmp_path / "missing.yaml"),
            ) as sm:
                assert sm is not None

        asyncio.run(test())


# ===================================================================
# Connection pinning (SSRF / DNS rebinding)
# ===================================================================


def _manager(tmp_path) -> SourceManager:
    return SourceManager(
        sources_file=str(tmp_path / "missing.json"),
        settings_file=str(tmp_path / "missing.yaml"),
    )


class TestConnectionPinning:
    """The request must go to the address the guard approved, not to the name."""

    def test_request_uses_the_validated_address_with_host_and_sni(
        self, tmp_path, monkeypatch
    ) -> None:
        sm = _manager(tmp_path)
        calls: list[dict] = []
        _patch_url_guard(monkeypatch)
        monkeypatch.setattr(
            "src.sources.manager.httpx.AsyncClient",
            _streaming_client(lambda url: _FakeResponse(text="body"), calls=calls),
        )

        assert asyncio.run(sm._fetch_direct_url("https://example.com/f.txt")) == "body"
        assert calls[0]["url"] == f"https://{PUBLIC_IP}/f.txt"
        assert calls[0]["headers"]["Host"] == "example.com"
        # TLS still negotiates and verifies against the hostname.
        assert calls[0]["extensions"] == {"sni_hostname": "example.com"}

    def test_rebinding_after_the_check_cannot_move_the_connection(
        self, tmp_path, monkeypatch
    ) -> None:
        """Regression: the guard judged the name, httpx resolved it again.

        A source URL whose DNS answers public once and ``127.0.0.1`` the next
        time (TTL 0) used to be validated on the first answer and connected on
        the second. Only one lookup happens now and its result is what the
        connection uses, so the later answer has nothing to poison.
        """
        sm = _manager(tmp_path)
        answers = [[PUBLIC_IP], ["127.0.0.1"], ["127.0.0.1"]]
        lookups: list[str] = []

        async def rebinding_resolver(host: str, **kwargs) -> list[str]:
            lookups.append(host)
            return answers.pop(0) if answers else ["127.0.0.1"]

        monkeypatch.setattr(
            "src.sources.manager.resolve_global_ips",
            rebinding_resolver,
        )
        requested: list[str] = []

        def handler(url):
            if "127.0.0.1" in url:  # pragma: no cover - must never happen
                return _FakeResponse(text="internal data")
            return _FakeResponse(text="public data")

        monkeypatch.setattr(
            "src.sources.manager.httpx.AsyncClient",
            _streaming_client(handler, requested),
        )

        result = asyncio.run(sm._fetch_direct_url("https://example.com/f.txt"))
        assert result == "public data"
        assert requested == [f"https://{PUBLIC_IP}/f.txt"]
        assert lookups == ["example.com"]

    def test_port_is_preserved_in_url_and_host_header(
        self, tmp_path, monkeypatch
    ) -> None:
        sm = _manager(tmp_path)
        calls: list[dict] = []
        _patch_url_guard(monkeypatch)
        monkeypatch.setattr(
            "src.sources.manager.httpx.AsyncClient",
            _streaming_client(lambda url: _FakeResponse(text="ok"), calls=calls),
        )

        asyncio.run(sm._fetch_direct_url("http://example.com:8080/a?b=1"))
        assert calls[0]["url"] == f"http://{PUBLIC_IP}:8080/a?b=1"
        assert calls[0]["headers"]["Host"] == "example.com:8080"
        # Plain HTTP negotiates no TLS, so there is no SNI to carry.
        assert calls[0]["extensions"] == {}

    def test_ipv6_answer_is_bracketed(self, tmp_path, monkeypatch) -> None:
        sm = _manager(tmp_path)
        calls: list[dict] = []
        _patch_url_guard(monkeypatch, addresses=["2606:2800:220:1:248:1893:25c8:1946"])
        monkeypatch.setattr(
            "src.sources.manager.httpx.AsyncClient",
            _streaming_client(lambda url: _FakeResponse(text="ok"), calls=calls),
        )

        asyncio.run(sm._fetch_direct_url("https://example.com/f.txt"))
        assert calls[0]["url"] == "https://[2606:2800:220:1:248:1893:25c8:1946]/f.txt"

    def test_ipv6_literal_url_keeps_its_brackets(self, tmp_path, monkeypatch) -> None:
        sm = _manager(tmp_path)
        calls: list[dict] = []
        _patch_url_guard(monkeypatch, addresses=["2001:4860:4860::8888"])
        monkeypatch.setattr(
            "src.sources.manager.httpx.AsyncClient",
            _streaming_client(lambda url: _FakeResponse(text="ok"), calls=calls),
        )

        asyncio.run(sm._fetch_direct_url("https://[2001:4860:4860::8888]:8443/f.txt"))
        assert calls[0]["url"] == "https://[2001:4860:4860::8888]:8443/f.txt"
        assert calls[0]["headers"]["Host"] == "[2001:4860:4860::8888]:8443"

    def test_credentials_in_the_url_survive_pinning(
        self, tmp_path, monkeypatch
    ) -> None:
        """httpx turns URL userinfo into Basic auth — it must not be dropped."""
        sm = _manager(tmp_path)
        calls: list[dict] = []
        _patch_url_guard(monkeypatch)
        monkeypatch.setattr(
            "src.sources.manager.httpx.AsyncClient",
            _streaming_client(lambda url: _FakeResponse(text="ok"), calls=calls),
        )

        asyncio.run(sm._fetch_direct_url("https://user:pw@example.com/f.txt"))
        assert calls[0]["url"] == f"https://user:pw@{PUBLIC_IP}/f.txt"
        assert calls[0]["headers"]["Host"] == "example.com"

    def test_next_address_is_tried_when_the_first_is_unreachable(
        self, tmp_path, monkeypatch
    ) -> None:
        """Pinning must not lose the connector's walk over the address list.

        A host answering with an AAAA record first is normal; on an IPv4-only
        runner that address simply refuses and the A record still has to work.
        """
        sm = _manager(tmp_path)
        requested: list[str] = []
        _patch_url_guard(monkeypatch, addresses=["203.0.113.7", PUBLIC_IP])

        def handler(url):
            if "203.0.113.7" in url:
                raise httpx.ConnectError("network unreachable")
            return _FakeResponse(text="second address served it")

        monkeypatch.setattr(
            "src.sources.manager.httpx.AsyncClient",
            _streaming_client(handler, requested),
        )

        result = asyncio.run(sm._fetch_direct_url("https://example.com/f.txt"))
        assert result == "second address served it"
        assert requested == [
            "https://203.0.113.7/f.txt",
            f"https://{PUBLIC_IP}/f.txt",
        ]

    def test_all_addresses_unreachable_raises_the_last_error(
        self, tmp_path, monkeypatch
    ) -> None:
        sm = _manager(tmp_path)
        _patch_url_guard(monkeypatch, addresses=["203.0.113.7", PUBLIC_IP])

        def handler(url):
            raise httpx.ConnectError("network unreachable")

        monkeypatch.setattr(
            "src.sources.manager.httpx.AsyncClient",
            _streaming_client(handler),
        )

        with pytest.raises(httpx.ConnectError):
            asyncio.run(sm._fetch_direct_url("https://example.com/f.txt", attempts=1))

    def test_only_the_first_addresses_are_tried(self, tmp_path, monkeypatch) -> None:
        """A CDN answering with a dozen addresses must not multiply the wait."""
        sm = _manager(tmp_path)
        requested: list[str] = []
        _patch_url_guard(
            monkeypatch,
            addresses=[f"203.0.113.{n}" for n in range(1, 11)],
        )

        def handler(url):
            raise httpx.ConnectError("network unreachable")

        monkeypatch.setattr(
            "src.sources.manager.httpx.AsyncClient",
            _streaming_client(handler, requested),
        )

        with pytest.raises(httpx.ConnectError):
            asyncio.run(sm._fetch_direct_url("https://example.com/f.txt", attempts=1))
        assert len(requested) == manager_module._MAX_PINNED_ADDRESSES

    def test_unparsable_authority_is_refused_before_connecting(
        self, tmp_path, monkeypatch
    ) -> None:
        """An out-of-range port only raises when the port is actually read."""
        sm = _manager(tmp_path)
        requested: list[str] = []
        _patch_url_guard(monkeypatch)
        monkeypatch.setattr(
            "src.sources.manager.httpx.AsyncClient",
            _streaming_client(
                lambda url: _FakeResponse(text="never"),  # pragma: no cover
                requested,
            ),
        )

        with pytest.raises(ValueError, match="non-public url"):
            asyncio.run(sm._fetch_direct_url("https://example.com:99999/f.txt"))
        assert requested == []

    def test_redirect_to_a_non_http_scheme_is_refused(
        self, tmp_path, monkeypatch
    ) -> None:
        sm = _manager(tmp_path)
        _patch_url_guard(monkeypatch)
        monkeypatch.setattr(
            "src.sources.manager.httpx.AsyncClient",
            _streaming_client(
                lambda url: _FakeResponse(
                    status_code=302,
                    headers={"location": "file:///etc/passwd"},
                ),
            ),
        )

        with pytest.raises(ValueError, match="non-public url"):
            asyncio.run(sm._fetch_direct_url("https://example.com/redirect"))


# ===================================================================
# Process-wide download gate
# ===================================================================


class TestDownloadGate:
    def test_inflight_fetches_are_capped(self, tmp_path, monkeypatch) -> None:
        """Regression: 4 url-list sources x 20 URLs = 80 lookups at once.

        The resolver expects at most RESOLVER_CONCURRENCY lookups in flight;
        beyond that a lookup waits longer than its own timeout, comes back as
        unresolved, and the source is dropped as "non-public" although it is
        perfectly public. The same ceiling bounds how many 12 MB bodies can be
        buffered at once.
        """
        sm = _manager(tmp_path)
        wanted = manager_module.MAX_INFLIGHT_DOWNLOADS + 30
        state = {"active": 0, "peak": 0}

        async def counting_resolver(host: str, **kwargs) -> list[str]:
            state["active"] += 1
            state["peak"] = max(state["peak"], state["active"])
            for _ in range(3):
                await asyncio.sleep(0)
            state["active"] -= 1
            return [PUBLIC_IP]

        monkeypatch.setattr(
            "src.sources.manager.resolve_global_ips",
            counting_resolver,
        )
        monkeypatch.setattr(
            "src.sources.manager.httpx.AsyncClient",
            _streaming_client(lambda url: _FakeResponse(text="ok")),
        )

        async def run_all():
            return await asyncio.gather(
                *[
                    sm._fetch_direct_url(f"https://example.com/{n}.txt")
                    for n in range(wanted)
                ]
            )

        results = asyncio.run(run_all())
        assert results == ["ok"] * wanted
        assert state["peak"] <= manager_module.MAX_INFLIGHT_DOWNLOADS
        assert state["peak"] > 1

    def test_each_event_loop_gets_its_own_gate(self, tmp_path, monkeypatch) -> None:
        """A semaphore bound to a finished loop must not leak into the next run."""
        sm = _manager(tmp_path)
        _patch_url_guard(monkeypatch)
        monkeypatch.setattr(
            "src.sources.manager.httpx.AsyncClient",
            _streaming_client(lambda url: _FakeResponse(text="ok")),
        )

        async def run_many():
            return await asyncio.gather(
                *[
                    sm._fetch_direct_url(f"https://example.com/{n}.txt")
                    for n in range(manager_module.MAX_INFLIGHT_DOWNLOADS + 5)
                ]
            )

        assert asyncio.run(run_many())[0] == "ok"
        assert asyncio.run(run_many())[0] == "ok"


# ===================================================================
# Per-source timeout / attempts
# ===================================================================


class TestPerSourceFetchOptions:
    """timeout/attempts are documented per source and must reach every fetch."""

    @staticmethod
    def _record(sm, monkeypatch) -> list[tuple[str, dict]]:
        calls: list[tuple[str, dict]] = []

        async def fake_direct(url, **kwargs):
            calls.append((url, kwargs))
            return "https://example.com/listed.txt" if "index" in url else "vless://ok"

        monkeypatch.setattr(sm, "_fetch_direct_url", fake_direct)
        return calls

    def test_url_list_index_honours_the_configured_timeout(
        self, tmp_path, monkeypatch
    ) -> None:
        """Regression: the index ignored ``timeout`` and used 30s x 3 attempts.

        With DOWNLOAD_TIMEOUT_FACTOR that is minutes per source on a hung
        mirror, for an operator who had capped that source at 10s.
        """
        sm = _manager(tmp_path)
        calls = self._record(sm, monkeypatch)

        result = asyncio.run(
            sm._fetch_url_list(
                {
                    "name": "idx",
                    "url": "https://example.com/index.txt",
                    "timeout": 10,
                    "attempts": 2,
                },
                "idx",
                DEFAULT_LIST_TYPE,
                None,
            )
        )
        assert result.ok is True
        assert calls[0] == (
            "https://example.com/index.txt",
            {"timeout": 10.0, "attempts": 2},
        )
        # The URLs listed inside it keep getting the same settings.
        assert calls[1][1] == {"timeout": 10.0, "attempts": 2}

    def test_url_list_without_overrides_passes_none(
        self, tmp_path, monkeypatch
    ) -> None:
        """Unset knobs leave _fetch_direct_url's own defaults in charge."""
        sm = _manager(tmp_path)
        calls = self._record(sm, monkeypatch)

        asyncio.run(
            sm._fetch_url_list(
                {"name": "idx", "url": "https://example.com/index.txt"},
                "idx",
                DEFAULT_LIST_TYPE,
                None,
            )
        )
        assert calls[0] == ("https://example.com/index.txt", {})
        assert calls[1][1] == {
            "timeout": manager_module.DEFAULT_FETCH_TIMEOUT,
            "attempts": manager_module.DEFAULT_LISTED_URL_ATTEMPTS,
        }

    def test_url_source_honours_the_configured_timeout(
        self, tmp_path, monkeypatch
    ) -> None:
        sm = _manager(tmp_path)
        calls = self._record(sm, monkeypatch)

        result = asyncio.run(
            sm.fetch_source(
                {
                    "name": "direct",
                    "type": "url",
                    "url": "https://example.com/sub.txt",
                    "timeout": 7.5,
                    "attempts": 1,
                }
            )
        )
        assert result.ok is True
        assert calls == [
            ("https://example.com/sub.txt", {"timeout": 7.5, "attempts": 1}),
        ]

    def test_bad_override_values_fall_back_to_the_defaults(
        self, tmp_path, monkeypatch
    ) -> None:
        sm = _manager(tmp_path)
        calls = self._record(sm, monkeypatch)

        asyncio.run(
            sm.fetch_source(
                {
                    "name": "direct",
                    "type": "url",
                    "url": "https://example.com/sub.txt",
                    "timeout": "soon",
                    "attempts": True,
                }
            )
        )
        assert calls == [
            (
                "https://example.com/sub.txt",
                {
                    "timeout": manager_module.DEFAULT_FETCH_TIMEOUT,
                    "attempts": manager_module.DEFAULT_FETCH_ATTEMPTS,
                },
            ),
        ]
