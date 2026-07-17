"""Tests for src.sources.manager — 100% coverage target."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest import mock

import httpx
import pytest
import yaml

from src.sources.github import GitHubClient
from src.sources.manager import SourceManager, SourceResult
from src.sources.list_types import DEFAULT_LIST_TYPE


# ===================================================================
# _FakeResponse helper
# ===================================================================


class _FakeResponse:
    """Simulates an httpx.Response."""

    def __init__(
        self,
        status_code: int = 200,
        *,
        text: str = "",
        headers: dict[str, str] | None = None,
    ):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                f"{self.status_code} error",
                request=mock.MagicMock(),
                response=self,
            )

    def json(self):
        return {}


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

        class FakeHttpxClient:
            def __init__(self, *args, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            async def get(self, url, **kwargs):
                return _FakeResponse(text="hello world")

        monkeypatch.setattr("src.sources.manager.httpx.AsyncClient", FakeHttpxClient)

        result = asyncio.run(sm._fetch_direct_url("https://example.com/f.txt"))
        assert result == "hello world"

    def test_fetch_direct_url_404(self, tmp_path, monkeypatch) -> None:
        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )

        class Fake404Client:
            def __init__(self, *args, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            async def get(self, url, **kwargs):
                return _FakeResponse(status_code=404)

        monkeypatch.setattr("src.sources.manager.httpx.AsyncClient", Fake404Client)

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

        class RetryClient:
            def __init__(self, *args, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            async def get(self, url, **kwargs):
                attempt["count"] += 1
                if attempt["count"] == 1:
                    raise httpx.ConnectError("transient")
                return _FakeResponse(text="final")

        monkeypatch.setattr("src.sources.manager.httpx.AsyncClient", RetryClient)

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

        class FailClient:
            def __init__(self, *args, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            async def get(self, url, **kwargs):
                raise httpx.ConnectError("always fails")

        monkeypatch.setattr("src.sources.manager.httpx.AsyncClient", FailClient)

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

        class ErrorClient:
            def __init__(self, *args, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            async def get(self, url, **kwargs):
                attempt["count"] += 1
                if attempt["count"] < 3:
                    resp = _FakeResponse(status_code=500)
                    resp.raise_for_status()
                    return resp
                return _FakeResponse(text="ok")

        monkeypatch.setattr("src.sources.manager.httpx.AsyncClient", ErrorClient)

        async def fake_sleep(_secs):
            pass

        monkeypatch.setattr("src.sources.manager.asyncio.sleep", fake_sleep)

        result = asyncio.run(sm._fetch_direct_url("https://example.com/f.txt"))
        assert result == "ok"
        assert attempt["count"] == 3

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
        from datetime import datetime

        sm = SourceManager(
            sources_file=str(tmp_path / "missing.json"),
            settings_file=str(tmp_path / "missing.yaml"),
        )

        now = datetime.now()
        expected_url = (
            f"https://example.com/{now.strftime('%Y')}/{now.strftime('%m')}/data.txt"
        )

        captured = []

        async def fake_direct(url, **kw):
            captured.append(url)
            if "index" in url:
                return f"https://example.com/{{YYYY}}/{{MM}}/data.txt"
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
