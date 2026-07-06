from __future__ import annotations

import asyncio
import base64
import builtins
import sys
import types

from src.env import load_dotenv_if_available
from src.parsers.base import Config
from src.scheduler.runner import PipelineRunner
from src.sources.github import GitHubClient, GitHubRateLimitError
from src.sources.list_types import infer_source_list_type, normalize_list_type
from src.sources.manager import SourceManager, SourceResult
from src.validators import tls_check as tls_module


def test_list_type_normalization_and_inference() -> None:
    assert normalize_list_type("BL") == "blacklist"
    assert normalize_list_type("white-list") == "whitelist"
    assert normalize_list_type("unknown") == "mixed"
    assert infer_source_list_type({"name": "val41k-obhod_BL"}) == "blacklist"
    assert infer_source_list_type({"path": "configs/obhod_WL"}) == "whitelist"


def test_source_manager_raw_source_filters_files_and_sets_list_type(tmp_path, monkeypatch) -> None:
    manager = SourceManager(
        sources_file=str(tmp_path / "missing-sources.json"),
        settings_file=str(tmp_path / "missing-settings.yaml"),
    )

    async def fake_fetch_directory(*args, **kwargs):
        return [
            ("keep.txt", "vless://11111111-1111-4111-8111-111111111111@example.com:443"),
            ("drop.txt", "trojan://secret@example.org:443"),
        ]

    monkeypatch.setattr(manager._github, "fetch_directory", fake_fetch_directory)

    source = {
        "name": "custom",
        "list_type": "white-list",
        "type": "raw",
        "owner": "owner",
        "repo": "repo",
        "path": "configs",
        "include_files": ["keep.txt"],
    }

    result = asyncio.run(manager.fetch_source(source))

    assert result.ok is True
    assert result.list_type == "whitelist"
    assert result.files == [
        ("keep.txt", "vless://11111111-1111-4111-8111-111111111111@example.com:443")
    ]


def test_load_dotenv_if_available_calls_installed_dotenv(monkeypatch) -> None:
    calls = []
    fake_dotenv = types.SimpleNamespace(load_dotenv=lambda: calls.append("loaded"))

    monkeypatch.setitem(sys.modules, "dotenv", fake_dotenv)

    assert load_dotenv_if_available() is True
    assert calls == ["loaded"]


def test_load_dotenv_if_available_returns_false_without_dependency(monkeypatch) -> None:
    real_import = builtins.__import__
    monkeypatch.delitem(sys.modules, "dotenv", raising=False)

    def fake_import(name, *args, **kwargs):
        if name == "dotenv":
            raise ImportError("missing dotenv")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    assert load_dotenv_if_available() is False


def test_github_fetch_file_falls_back_to_raw_url_on_rate_limit(monkeypatch) -> None:
    client = GitHubClient()
    raw_urls = []

    async def fake_request(*args, **kwargs):
        raise GitHubRateLimitError("limited")

    async def fake_fetch_raw_file(url: str) -> str:
        raw_urls.append(url)
        return "raw-content"

    monkeypatch.setattr(client, "_request", fake_request)
    monkeypatch.setattr(client, "fetch_raw_file", fake_fetch_raw_file)

    result = asyncio.run(client.fetch_file("owner", "repo", "dir/file.txt", "feature"))

    assert result == "raw-content"
    assert raw_urls == [
        "https://raw.githubusercontent.com/owner/repo/feature/dir/file.txt"
    ]


def test_runner_parses_configs_grouped_by_source_list_type() -> None:
    runner = PipelineRunner()
    black = SourceResult(
        source_name="black",
        list_type="blacklist",
        files=[
            (
                "black.txt",
                "vless://11111111-1111-4111-8111-111111111111@example.com:443#DE-01",
            )
        ],
    )
    white = SourceResult(
        source_name="white",
        list_type="whitelist",
        files=[
            (
                "white.txt",
                "trojan://secret@example.org:443#FI-01",
            )
        ],
    )

    grouped = asyncio.run(runner._parse_all_by_list([black, white]))

    assert [cfg.protocol for cfg in grouped["blacklist"]] == ["vless"]
    assert [cfg.protocol for cfg in grouped["whitelist"]] == ["trojan"]


def test_split_output_files_from_settings(tmp_path) -> None:
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        """
publisher:
  split_output_files:
    blacklist: output/subscription-blacklist.txt
    whitelist: output/subscription-whitelist.txt
""",
        encoding="utf-8",
    )
    runner = PipelineRunner(settings_path=str(settings), sources_path="missing.json")

    assert runner._split_output_files("output/subscription.txt") == {
        "blacklist": "output/subscription-blacklist.txt",
        "whitelist": "output/subscription-whitelist.txt",
    }


def test_process_and_write_configs_writes_split_output(tmp_path) -> None:
    output_file = tmp_path / "subscription-whitelist.txt"
    raw_link = "vless://11111111-1111-4111-8111-111111111111@de.server.net:443#DE-01"
    cfg = Config(
        protocol="vless",
        address="de.server.net",
        port=443,
        uuid_or_password="11111111-1111-4111-8111-111111111111",
        remark="DE-01",
        raw_link=raw_link,
        country="DE",
    )
    runner = PipelineRunner(
        settings_path=str(tmp_path / "missing-settings.yaml"),
        sources_path=str(tmp_path / "missing-sources.json"),
    )

    count = runner._process_and_write_configs([cfg], str(output_file), label="whitelist")
    decoded = base64.b64decode(output_file.read_text(encoding="utf-8")).decode("utf-8")

    assert count == 1
    assert raw_link in decoded


def test_tls_validator_marks_successful_tls_configs_alive(monkeypatch) -> None:
    async def fake_tls_check(*args, **kwargs):
        return True

    monkeypatch.setattr(tls_module, "tls_check", fake_tls_check)
    cfg = Config(
        protocol="vless",
        address="example.com",
        port=443,
        uuid_or_password="11111111-1111-4111-8111-111111111111",
        security="tls",
    )

    result = asyncio.run(tls_module.validate_configs_tls([cfg]))

    assert result == [cfg]
    assert cfg.is_alive is True
