from __future__ import annotations

import asyncio
import base64
import builtins
import json
import sys
import types
from collections import Counter
from pathlib import Path

import httpx
import pytest

from src.aggregator.output import generate_plain
from src.env import load_dotenv_if_available
from src.notify import telegram as telegram_module
from src.parsers.base import Config, is_garbage_config
from src.repo_info import _slug_from_remote_url, github_branch
from src.scheduler.runner import PipelineRunner
from src.publisher.github import _contents_url as publisher_contents_url
from src.sources.github import (
    GitHubClient,
    GitHubRateLimitError,
    _contents_url as source_contents_url,
)
from src.sources.list_types import infer_source_list_type, normalize_list_type
from src.sources.manager import SourceManager, SourceResult
from src.validators import tcp_check as tcp_module
from src.validators import proxy_pool as proxy_pool_module
from src.validators import tls_check as tls_module
from src.validators import xray_probe as xray_module
from src.validators.proxy_pool import parse_proxy_candidates


def test_list_type_normalization_and_inference() -> None:
    assert normalize_list_type("BL") == "blacklist"
    assert normalize_list_type("white-list") == "whitelist"
    assert normalize_list_type("unknown") == "mixed"
    assert infer_source_list_type({"name": "val41k-obhod_BL"}) == "blacklist"
    assert infer_source_list_type({"path": "configs/obhod_WL"}) == "whitelist"


def test_output_watermark_uses_github_env(monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_OWNER", "owner")
    monkeypatch.setenv("GITHUB_REPO", "repo")
    plain = generate_plain([])
    watermark = plain.split("vmess://", 1)[1]
    payload = json.loads(base64.b64decode(watermark).decode("utf-8"))

    assert payload["ps"] == "owner/repo"


def test_telegram_subscription_urls_use_github_env(monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_OWNER", "owner")
    monkeypatch.setenv("GITHUB_REPO", "repo")
    monkeypatch.setenv("GITHUB_BRANCH", "main")

    urls = telegram_module._subscription_urls()

    assert urls == {
        "combined": "https://raw.githubusercontent.com/owner/repo/main/output/subscription.txt",
        "blacklist": "https://raw.githubusercontent.com/owner/repo/main/output/subscription-blacklist.txt",
        "whitelist": "https://raw.githubusercontent.com/owner/repo/main/output/subscription-whitelist.txt",
        "mix": "https://raw.githubusercontent.com/owner/repo/main/output/subscription-mix.txt",
    }


def test_telegram_formats_validation_and_per_subscription_countries() -> None:
    summary = {
        "validation": {
            "tcp_enabled": True,
            "tls_enabled": True,
            "xray_enabled": True,
            "fail_open_on_low_alive": False,
            "drop_unchecked_after_tls": True,
            "proxy_pool_enabled": True,
            "proxy_pool_required": True,
            "proxy_count": 10,
            "lists": {
                "blacklist": {
                    "tcp_checked": 1000,
                    "tcp_alive": 150,
                    "tcp_skipped_protocol": 3,
                    "tls_checked": 140,
                    "tls_alive": 90,
                    "tls_unchecked_passthrough": 11,
                    "tls_drop_unchecked": True,
                    "xray_checked": 90,
                    "xray_alive": 42,
                    "xray_unsupported": 2,
                    "xray_probe_count": 3,
                    "xray_min_probe_successes": 3,
                    "xray_attempts_per_config": 3,
                    "xray_min_attempt_successes": 3,
                },
                "whitelist": {
                    "tcp_checked": 217,
                    "tcp_alive": 216,
                    "tcp_skipped_protocol": 1,
                    "tls_checked": 200,
                    "tls_alive": 184,
                },
            },
        },
        "outputs": {
            "whitelist": {
                "count": 150,
                "countries": {"RU": 120, "DE": 30},
            },
            "mix": {
                "count": 200,
                "countries": {"RU": 60, "CA": 49, "DE": 27, "FI": 14},
            },
            "location_de": {
                "count": 50,
                "countries": {"DE": 50},
            },
            "location_ru": {
                "count": 42,
                "countries": {"RU": 42},
            },
        },
    }

    validation = telegram_module._format_validation_section(summary)
    subscriptions = telegram_module._format_subscriptions_section(
        summary, "output/subscription.txt"
    )

    assert "через 10 SOCKS5 прокси" in validation
    assert "strict" in validation
    assert "без TCP-only" in validation
    assert "<b>Blacklist TCP</b>: проверено 1000, порт открыт 150" in validation
    assert (
        "<b>Blacklist TLS/REALITY</b>: проверено 140, живых 90, "
        "TCP-only отброшено 11"
        in validation
    )
    assert (
        "<b>Blacklist Xray</b>: проверено 90, реально рабочих 42, "
        "неподдержано 2, HTTPS-пробы 3/3, повторы 3/3"
        in validation
    )
    assert "<b>Whitelist TCP</b>: проверено 217, порт открыт 216" in validation
    assert "<b>Whitelist TLS/REALITY</b>: проверено 200, живых 184" in validation
    assert "<b>Whitelist</b>: 150" in subscriptions
    assert "Россия 120" in subscriptions
    assert "<b>Mix 100/100</b>: 200" in subscriptions
    assert "<b>Локации</b>: 2 файлов, до 50 серверов" in subscriptions
    assert "Россия 60" in subscriptions


def test_telegram_message_uses_html_links_and_escapes_dynamic_text(monkeypatch) -> None:
    captured: dict[str, str] = {}

    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:ABCDEFGHIJKLMNOPQRST")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "-100123")
    monkeypatch.setenv("GITHUB_OWNER", "owner")
    monkeypatch.setenv("GITHUB_REPO", "repo")
    monkeypatch.setenv("GITHUB_BRANCH", "main")
    monkeypatch.setattr(
        telegram_module, "_generate_fun_fact", lambda _api_key: "опасный <tag> & факт"
    )

    def fake_send(token: str, chat_id: str, text: str) -> bool:
        captured["token"] = token
        captured["chat_id"] = chat_id
        captured["text"] = text
        return True

    monkeypatch.setattr(telegram_module, "_send_telegram", fake_send)

    assert telegram_module.send_notification(configs_count=1)

    text = captured["text"]
    assert "🤖 <b>Я — vpnparser бот</b>" in text
    assert '<a href="https://github.com/owner/repo">owner/repo</a>' in text
    assert (
        '<a href="https://raw.githubusercontent.com/owner/repo/main/output/'
        'subscription-blacklist.txt">Рабочий blacklist</a>'
    ) in text
    assert "опасный &lt;tag&gt; &amp; факт" in text
    assert "&lt;b&gt;" not in text


def test_send_telegram_uses_html_parse_mode(monkeypatch) -> None:
    captured: dict[str, object] = {}

    class DummyResponse:
        def __enter__(self) -> DummyResponse:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self) -> bytes:
            return b'{"ok": true}'

    def fake_urlopen(req: object, timeout: int) -> DummyResponse:
        captured["timeout"] = timeout
        captured["payload"] = json.loads(req.data.decode("utf-8"))  # type: ignore[attr-defined]
        return DummyResponse()

    monkeypatch.setattr(telegram_module.urllib.request, "urlopen", fake_urlopen)

    assert telegram_module._send_telegram(
        "123456789:ABCDEFGHIJKLMNOPQRST", "-100123", "<b>hello</b>"
    )
    assert captured["payload"] == {
        "chat_id": "-100123",
        "text": "<b>hello</b>",
        "parse_mode": "HTML",
    }
    assert captured["timeout"] == 10


def test_runner_summary_uses_config_country_metadata(tmp_path) -> None:
    status_file = tmp_path / "run-summary.json"
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        f"""
publisher:
  status_output_file: {status_file}
""",
        encoding="utf-8",
    )
    runner = PipelineRunner(settings_path=str(settings), sources_path="missing.json")
    cfg = Config(
        "vless",
        "unknown.example",
        443,
        "11111111-1111-4111-8111-111111111111",
        raw_link="vless://11111111-1111-4111-8111-111111111111@unknown.example:443#node",
        country="RU",
    )

    runner._record_output_stats("whitelist", "output/subscription-whitelist.txt", [cfg])
    runner._write_run_summary("ok")
    data = json.loads(status_file.read_text(encoding="utf-8"))

    assert data["outputs"]["whitelist"]["count"] == 1
    assert data["outputs"]["whitelist"]["countries"] == {"RU": 1}


def test_repo_info_parses_github_remote_and_ref(monkeypatch) -> None:
    assert _slug_from_remote_url("https://github.com/owner/repo.git") == "owner/repo"
    assert _slug_from_remote_url("git@github.com:owner/repo.git") == "owner/repo"

    monkeypatch.delenv("GITHUB_BRANCH", raising=False)
    monkeypatch.delenv("GITHUB_REF_NAME", raising=False)
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")

    assert github_branch() == "main"


def test_source_manager_raw_source_filters_files_and_sets_list_type(
    tmp_path, monkeypatch
) -> None:
    manager = SourceManager(
        sources_file=str(tmp_path / "missing-sources.json"),
        settings_file=str(tmp_path / "missing-settings.yaml"),
    )

    async def fake_fetch_directory(*args, **kwargs):
        return [
            (
                "keep.txt",
                "vless://11111111-1111-4111-8111-111111111111@example.com:443",
            ),
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


def test_source_manager_url_source_fetches_direct_url(tmp_path, monkeypatch) -> None:
    manager = SourceManager(
        sources_file=str(tmp_path / "missing-sources.json"),
        settings_file=str(tmp_path / "missing-settings.yaml"),
    )

    async def fake_fetch_direct_url(url: str) -> str:
        assert url == "https://example.com/sub.txt"
        return "vless://11111111-1111-4111-8111-111111111111@example.com:443"

    monkeypatch.setattr(manager, "_fetch_direct_url", fake_fetch_direct_url)

    result = asyncio.run(
        manager.fetch_source(
            {
                "name": "direct",
                "list_type": "blacklist",
                "type": "url",
                "url": "https://example.com/sub.txt",
                "default_country": "DE",
            }
        )
    )

    assert result.ok is True
    assert result.list_type == "blacklist"
    assert result.default_country == "DE"
    assert result.files == [
        ("sub.txt", "vless://11111111-1111-4111-8111-111111111111@example.com:443")
    ]


def test_filter_files_ignores_non_list_values() -> None:
    """Non-list include_files/exclude_files must not filter or crash."""
    files = [("a.txt", "x"), ("b.txt", "y")]

    # String instead of list — must NOT iterate characters.
    assert SourceManager._filter_files({"include_files": "a.txt"}, files) == files
    # Integer instead of list — must NOT raise TypeError.
    assert SourceManager._filter_files({"include_files": 42}, files) == files
    # None — no filtering.
    assert SourceManager._filter_files({"include_files": None}, files) == files


def test_filter_files_skips_none_items_in_list() -> None:
    """None items inside include_files must not become the string 'none'."""
    files = [("a.txt", "x"), ("b.txt", "y"), ("none", "z")]
    # Before the fix, [None] -> {"none"} -> filtered out everything except "none".
    result = SourceManager._filter_files({"include_files": [None]}, files)
    assert result == files  # None item is skipped, no filtering applied


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


def test_ad_filter_rejects_telegram_and_russian_ad_remarks() -> None:
    assert is_garbage_config(
        Config(
            "vless",
            "vpn-host.test",
            443,
            "11111111-1111-4111-8111-111111111111",
            remark="join t.me/channel",
        )
    )
    assert is_garbage_config(
        Config(
            "trojan",
            "vpn-host-2.test",
            443,
            "secret",
            remark="канал купить vpn",
        )
    )


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


def test_github_request_raises_rate_limit_after_retry(monkeypatch) -> None:
    client = GitHubClient()

    class FakeResponse:
        status_code = 403
        headers = {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "0"}

        def raise_for_status(self):
            raise AssertionError("rate limit should be raised before HTTPStatusError")

    class FakeClient:
        async def request(self, *args, **kwargs):
            return FakeResponse()

    async def fake_get_client():
        return FakeClient()

    async def fake_sleep(_seconds):
        return None

    monkeypatch.setattr(client, "_get_client", fake_get_client)
    monkeypatch.setattr("src.sources.github.asyncio.sleep", fake_sleep)

    with pytest.raises(GitHubRateLimitError):
        asyncio.run(client._request("GET", "/repos/o/r/contents/file.txt"))


def test_github_fetch_raw_file_rejects_untrusted_hosts(monkeypatch) -> None:
    client = GitHubClient(token="secret")

    async def fail_get_client():
        raise AssertionError("untrusted raw URL should not be fetched")

    monkeypatch.setattr(client, "_get_client", fail_get_client)

    result = asyncio.run(client.fetch_raw_file("https://example.com/file.txt"))

    assert result == ""


def test_github_fetch_raw_file_does_not_send_authorization(monkeypatch) -> None:
    client = GitHubClient(token="secret")
    captured_headers = {}

    class FakeResponse:
        status_code = 200
        text = "raw-content"

        def raise_for_status(self):
            return None

    class FakeRawClient:
        def __init__(self, *args, **kwargs):
            captured_headers.update(kwargs.get("headers") or {})

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def get(self, url, headers=None):
            captured_headers.update(headers or {})
            return FakeResponse()

    monkeypatch.setattr("src.sources.github.httpx.AsyncClient", FakeRawClient)

    result = asyncio.run(
        client.fetch_raw_file("https://raw.githubusercontent.com/o/r/main/file.txt")
    )

    assert result == "raw-content"
    assert "Authorization" not in captured_headers


def test_github_fetch_raw_file_returns_empty_on_network_error(monkeypatch) -> None:
    client = GitHubClient()

    class FakeRawClient:
        def __init__(self, *args, **kwargs):
            return None

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def get(self, *args, **kwargs):
            raise httpx.ConnectError("boom")

    monkeypatch.setattr("src.sources.github.httpx.AsyncClient", FakeRawClient)

    async def fake_sleep(_seconds):
        return None

    monkeypatch.setattr("src.sources.github.asyncio.sleep", fake_sleep)

    result = asyncio.run(
        client.fetch_raw_file("https://raw.githubusercontent.com/o/r/main/file.txt")
    )

    assert result == ""


def test_github_fetch_raw_file_retries_transient_network_error(monkeypatch) -> None:
    client = GitHubClient()
    attempts = {"count": 0}

    class FakeResponse:
        status_code = 200
        text = "raw-content"

        def raise_for_status(self):
            return None

    class FakeRawClient:
        def __init__(self, *args, **kwargs):
            return None

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def get(self, *args, **kwargs):
            attempts["count"] += 1
            if attempts["count"] == 1:
                raise httpx.ConnectError("temporary")
            return FakeResponse()

    async def fake_sleep(_seconds):
        return None

    monkeypatch.setattr("src.sources.github.httpx.AsyncClient", FakeRawClient)
    monkeypatch.setattr("src.sources.github.asyncio.sleep", fake_sleep)

    result = asyncio.run(
        client.fetch_raw_file("https://raw.githubusercontent.com/o/r/main/file.txt")
    )

    assert result == "raw-content"
    assert attempts["count"] == 2


def test_github_contents_urls_quote_and_reject_unsafe_paths() -> None:
    assert source_contents_url("owner", "repo", "dir/file+name.txt") == (
        "/repos/owner/repo/contents/dir/file%2Bname.txt"
    )
    assert publisher_contents_url("owner", "repo", "output/subscription.txt") == (
        "/repos/owner/repo/contents/output/subscription.txt"
    )

    with pytest.raises(ValueError):
        source_contents_url("owner", "repo", "../secret.txt")
    with pytest.raises(ValueError):
        publisher_contents_url("owner", "repo", "../secret.txt")


def test_filter_files_matches_full_repo_path_and_basename() -> None:
    files = [
        ("githubmirror/1.txt", "black"),
        ("githubmirror/26.txt", "white"),
        ("other/26.txt", "other"),
    ]

    assert SourceManager._filter_files(
        {"include_files": ["githubmirror/26.txt"]}, files
    ) == [("githubmirror/26.txt", "white")]
    assert SourceManager._filter_files({"exclude_files": ["26.txt"]}, files) == [
        ("githubmirror/1.txt", "black")
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


def test_runner_uses_per_list_country_filters(tmp_path) -> None:
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        """
validator:
  allowed_countries: []
  allowed_countries_by_list:
    blacklist: [DE]
    whitelist: [RU]
""",
        encoding="utf-8",
    )
    runner = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    black_de = Config(
        "vless",
        "de.example",
        443,
        "11111111-1111-4111-8111-111111111111",
        remark="DE-01",
    )
    black_ru = Config(
        "vless",
        "ru.example",
        443,
        "11111111-1111-4111-8111-111111111112",
        remark="RU-01",
    )
    white_de = Config(
        "vless",
        "de-white.example",
        443,
        "11111111-1111-4111-8111-111111111113",
        remark="DE-02",
    )
    white_ru = Config(
        "vless",
        "ru-white.example",
        443,
        "11111111-1111-4111-8111-111111111114",
        remark="RU-02",
    )

    assert runner._filter_countries([black_de, black_ru], list_type="blacklist") == [
        black_de
    ]
    assert runner._filter_countries([white_de, white_ru], list_type="whitelist") == [
        white_ru
    ]


def test_runner_uses_source_default_country_when_detection_fails(tmp_path) -> None:
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        """
validator:
  allowed_countries: []
  allowed_countries_by_list:
    whitelist: [RU]
""",
        encoding="utf-8",
    )
    runner = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    cfg = Config(
        "vless",
        "unknown.example",
        443,
        "11111111-1111-4111-8111-111111111111",
        remark="WHITE",
    )
    setattr(cfg, "source_default_country", "RU")

    result = runner._filter_countries([cfg], list_type="whitelist")

    assert result == [cfg]
    assert cfg.country == "RU"


def test_country_balanced_limit_distributes_evenly(tmp_path) -> None:
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        """
aggregator:
  max_configs_in_output: 9
  sort_by: country
  max_per_country: 150
""",
        encoding="utf-8",
    )
    runner = PipelineRunner(settings_path=str(settings), sources_path="missing.json")
    configs = [
        Config(
            "vless",
            f"{country.lower()}-{i}.example",
            443,
            "11111111-1111-4111-8111-111111111111",
            country=country,
        )
        for country in ("CA", "DE", "FI")
        for i in range(20)
    ]

    result = runner._sort_and_limit(configs)
    counts = Counter(cfg.country for cfg in result)

    assert len(result) == 9
    assert counts == {"CA": 3, "DE": 3, "FI": 3}


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


def test_mix_output_file_from_settings(tmp_path) -> None:
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        """
publisher:
  mix_output_file: output/subscription-mix.txt
  split_output_files:
    blacklist: output/subscription-blacklist.txt
    whitelist: output/subscription-whitelist.txt
""",
        encoding="utf-8",
    )
    runner = PipelineRunner(settings_path=str(settings), sources_path="missing.json")
    splits = runner._split_output_files("output/subscription.txt")

    assert runner._mix_output_file("output/subscription.txt", splits) == (
        "output/subscription-mix.txt"
    )


def test_build_mixed_output_uses_blacklist_and_whitelist_halves(tmp_path) -> None:
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        """
aggregator:
  max_configs_in_output: 200
  sort_by: country
validator:
  whitelist_ru_ratio: 0.8
  whitelist_eu_countries: [DE, FI]
""",
        encoding="utf-8",
    )
    runner = PipelineRunner(settings_path=str(settings), sources_path="missing.json")

    blacklist = [
        Config(
            "vless",
            f"black-{i}.example",
            443,
            "11111111-1111-4111-8111-111111111111",
            remark="blacklist",
            country="DE",
        )
        for i in range(100)
    ]
    whitelist = [
        Config(
            "vless",
            f"white-ru-{i}.example",
            443,
            "11111111-1111-4111-8111-111111111111",
            remark="whitelist",
            country="RU",
        )
        for i in range(100)
    ] + [
        Config(
            "vless",
            f"white-de-{i}.example",
            443,
            "11111111-1111-4111-8111-111111111111",
            remark="whitelist",
            country="DE",
        )
        for i in range(100)
    ]

    result = runner._build_mixed_output(
        {"blacklist": blacklist, "whitelist": whitelist}, 200
    )

    assert len(result) == 200
    assert sum(1 for cfg in result if cfg.remark == "blacklist") == 100
    assert sum(1 for cfg in result if cfg.remark == "whitelist") == 100
    assert sum(1 for cfg in result if cfg.remark == "whitelist" and cfg.country == "RU") == 80
    assert sum(1 for cfg in result if cfg.remark == "whitelist" and cfg.country == "DE") == 20


def test_whitelist_balance_spreads_eu_countries(tmp_path) -> None:
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        """
aggregator:
  max_configs_in_output: 75
  sort_by: country
validator:
  whitelist_ru_ratio: 0.8
  whitelist_eu_countries: [DE, FI]
""",
        encoding="utf-8",
    )
    runner = PipelineRunner(settings_path=str(settings), sources_path="missing.json")
    configs = [
        Config(
            "vless",
            f"ru-{i}.example",
            443,
            "11111111-1111-4111-8111-111111111111",
            country="RU",
        )
        for i in range(100)
    ] + [
        Config(
            "vless",
            f"{country.lower()}-{i}.example",
            443,
            "11111111-1111-4111-8111-111111111111",
            country=country,
        )
        for country in ("DE", "FI")
        for i in range(100)
    ]

    result = runner._whitelist_balance(configs, 75)
    counts = Counter(cfg.country for cfg in result)

    assert counts["RU"] == 60
    assert counts["DE"] == 8
    assert counts["FI"] == 7


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

    count = runner._process_and_write_configs(
        [cfg], str(output_file), label="whitelist"
    )
    decoded = base64.b64decode(output_file.read_text(encoding="utf-8")).decode("utf-8")

    assert count == 1
    assert raw_link in decoded


def test_location_outputs_are_capped_per_country(tmp_path) -> None:
    settings = tmp_path / "settings.yaml"
    location_dir = tmp_path / "locations"
    settings.write_text(
        f"""
publisher:
  location_outputs_enabled: true
  location_output_dir: {location_dir}
  location_output_limit: 50
aggregator:
  sort_by: country
  max_per_country: 200
""",
        encoding="utf-8",
    )
    runner = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing-sources.json"),
    )
    configs = [
        Config(
            "vless",
            f"de-{i}.example",
            443,
            "11111111-1111-4111-8111-111111111111",
            raw_link=(
                "vless://11111111-1111-4111-8111-111111111111"
                f"@de-{i}.example:443#DE-{i}"
            ),
            country="DE",
        )
        for i in range(75)
    ] + [
        Config(
            "vless",
            f"ru-{i}.example",
            443,
            "11111111-1111-4111-8111-111111111111",
            raw_link=(
                "vless://11111111-1111-4111-8111-111111111111"
                f"@ru-{i}.example:443#RU-{i}"
            ),
            country="RU",
        )
        for i in range(12)
    ]

    files = runner._write_location_outputs(configs)

    assert sorted(Path(path).name for path in files) == [
        "subscription-DE.txt",
        "subscription-RU.txt",
    ]
    de_text = (location_dir / "subscription-DE.txt").read_text(encoding="utf-8")
    ru_text = (location_dir / "subscription-RU.txt").read_text(encoding="utf-8")
    assert len(base64.b64decode(de_text).decode("utf-8").splitlines()) == 51
    assert len(base64.b64decode(ru_text).decode("utf-8").splitlines()) == 13
    assert runner._output_stats["location_de"]["count"] == 50
    assert runner._output_stats["location_ru"]["count"] == 12


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


def test_tls_validator_tries_host_when_sni_is_missing(monkeypatch) -> None:
    calls = []

    async def fake_tls_check(host, port, sni=None, **kwargs):
        calls.append((host, port, sni, kwargs.get("alpn")))
        return sni == "cdn.example.com"

    monkeypatch.setattr(tls_module, "tls_check", fake_tls_check)
    cfg = Config(
        protocol="vless",
        address="203.0.113.10",
        port=443,
        uuid_or_password="11111111-1111-4111-8111-111111111111",
        security="tls",
        network="ws",
        host="cdn.example.com",
        alpn="h2,http/1.1",
    )

    result = asyncio.run(tls_module.validate_configs_tls([cfg]))

    assert result == [cfg]
    assert cfg.is_alive is True
    assert calls == [("203.0.113.10", 443, "cdn.example.com", "h2,http/1.1")]


def test_xray_probe_builds_vless_reality_config() -> None:
    cfg = Config(
        protocol="vless",
        address="203.0.113.10",
        port=443,
        uuid_or_password="11111111-1111-4111-8111-111111111111",
        network="tcp",
        security="reality",
        sni="www.example.com",
        fp="chrome",
        pbk="public-key",
        sid="abcd",
        flow="xtls-rprx-vision",
    )

    built = xray_module.build_xray_config(cfg, 18080)

    assert built is not None
    outbound = built["outbounds"][0]
    assert outbound["protocol"] == "vless"
    assert outbound["settings"]["vnext"][0]["users"][0]["flow"] == "xtls-rprx-vision"
    assert outbound["streamSettings"]["security"] == "reality"
    assert outbound["streamSettings"]["realitySettings"]["publicKey"] == "public-key"
    assert built["inbounds"][0]["port"] == 18080


def test_xray_probe_rejects_unsupported_network() -> None:
    cfg = Config(
        protocol="vless",
        address="example.com",
        port=443,
        uuid_or_password="11111111-1111-4111-8111-111111111111",
        network="xhttp",
        security="tls",
    )

    assert xray_module.build_xray_config(cfg, 18080) is None
    assert xray_module.is_xray_supported(cfg) is False


def test_xray_http_status_code_accepts_only_http_status() -> None:
    assert xray_module._http_status_code(b"HTTP/1.1 204 No Content\r\n") == 204
    assert xray_module._http_status_code(b"HTTP/2 200\r\n") == 200
    assert xray_module._http_status_code(b"proxy error") is None
    assert xray_module._http_status_code(b"HTTP/1.1 nope\r\n") is None


def test_xray_probe_requires_multiple_successful_https_probes(monkeypatch) -> None:
    cfg = Config(
        protocol="vless",
        address="203.0.113.10",
        port=443,
        uuid_or_password="11111111-1111-4111-8111-111111111111",
        security="tls",
    )
    calls: list[str] = []

    monkeypatch.setattr(xray_module, "_free_local_port", lambda: 18080)

    async def fake_wait_for_port(*_args):
        return True

    monkeypatch.setattr(xray_module, "_wait_for_port", fake_wait_for_port)

    class DummyProc:
        returncode = None

        def terminate(self) -> None:
            self.returncode = 0

        async def wait(self) -> None:
            return None

        def kill(self) -> None:
            self.returncode = -9

    async def fake_create_subprocess_exec(*_args, **_kwargs):
        return DummyProc()

    async def fake_probe(_port, *, probe_url, timeout):
        calls.append(probe_url)
        return {
            "https://ok-1.example/generate_204": 204,
            "https://bad.example/generate_204": 503,
            "https://ok-2.example/trace": 200,
        }[probe_url]

    monkeypatch.setattr(
        xray_module.asyncio,
        "create_subprocess_exec",
        fake_create_subprocess_exec,
    )
    monkeypatch.setattr(xray_module, "_https_probe_via_socks", fake_probe)

    assert asyncio.run(
        xray_module.xray_probe_check(
            cfg,
            xray_path="/usr/bin/xray",
            probe_urls=[
                "https://ok-1.example/generate_204",
                "https://bad.example/generate_204",
                "https://ok-2.example/trace",
            ],
            min_probe_successes=2,
        )
    )
    assert calls == [
        "https://ok-1.example/generate_204",
        "https://bad.example/generate_204",
        "https://ok-2.example/trace",
    ]


def test_xray_validation_requires_repeated_successful_attempts(monkeypatch) -> None:
    stable = Config(
        protocol="vless",
        address="stable.example",
        port=443,
        uuid_or_password="11111111-1111-4111-8111-111111111111",
        security="tls",
    )
    flaky = Config(
        protocol="vless",
        address="flaky.example",
        port=443,
        uuid_or_password="11111111-1111-4111-8111-111111111112",
        security="tls",
    )
    outcomes = {
        "stable.example": [True, True, True],
        "flaky.example": [True, False],
    }

    async def fake_xray_probe_check(cfg, **_kwargs):
        return outcomes[cfg.address].pop(0)

    monkeypatch.setattr(xray_module, "xray_probe_check", fake_xray_probe_check)

    result = asyncio.run(
        xray_module.validate_configs_xray(
            [stable, flaky],
            xray_path="/usr/bin/xray",
            attempts_per_config=3,
            min_attempt_successes=3,
            concurrency=1,
        )
    )

    assert result == [stable]
    assert stable.is_alive is True
    assert flaky.is_alive is False
    assert outcomes == {"stable.example": [], "flaky.example": []}


def test_proxy_pool_parses_public_socks5_candidates() -> None:
    text = """
    socks5://8.8.8.8:1080
    1.1.1.1 9050
    10.0.0.1:1080
    192.168.1.1:1080
    8.8.8.8:1080
    999.1.1.1:1080
    """

    assert parse_proxy_candidates(text) == [
        "socks5://8.8.8.8:1080",
        "socks5://1.1.1.1:9050",
    ]


def test_proxy_pool_fetch_stops_after_candidate_limit(monkeypatch) -> None:
    fetched_urls = []

    async def fake_fetch_source(_client, url):
        fetched_urls.append(url)
        return "socks5://8.8.8.8:1080 socks5://1.1.1.1:9050"

    monkeypatch.setattr(proxy_pool_module, "_fetch_source", fake_fetch_source)

    result = asyncio.run(
        proxy_pool_module.fetch_proxy_candidates(
            ["https://first.example/list.txt", "https://second.example/list.txt"],
            max_candidates=1,
        )
    )

    assert result == ["socks5://8.8.8.8:1080"]
    assert fetched_urls == ["https://first.example/list.txt"]


def test_proxy_pool_limits_candidates_per_source(monkeypatch) -> None:
    async def fake_fetch_source(_client, url):
        if "first" in url:
            return " ".join(
                f"socks5://8.8.8.{i}:1080" for i in range(1, 5)
            )
        return " ".join(f"socks5://1.1.1.{i}:9050" for i in range(1, 5))

    monkeypatch.setattr(proxy_pool_module, "_fetch_source", fake_fetch_source)

    result = asyncio.run(
        proxy_pool_module.fetch_proxy_candidates(
            ["https://first.example/list.txt", "https://second.example/list.txt"],
            max_candidates=4,
            max_candidates_per_source=2,
        )
    )

    assert result == [
        "socks5://8.8.8.1:1080",
        "socks5://8.8.8.2:1080",
        "socks5://1.1.1.1:9050",
        "socks5://1.1.1.2:9050",
    ]


def test_proxy_pool_validation_waits_when_limit_not_reached(monkeypatch) -> None:
    async def fake_proxy_connects(proxy_url, **kwargs):
        await asyncio.sleep(0.01 if "8.8.8.8" in proxy_url else 0.03)
        return True

    monkeypatch.setattr(proxy_pool_module, "proxy_connects", fake_proxy_connects)

    result = asyncio.run(
        proxy_pool_module.validate_proxy_candidates(
            ["socks5://8.8.8.8:1080", "socks5://1.1.1.1:9050"],
            max_proxies=5,
            concurrency=2,
        )
    )

    assert result == ["socks5://8.8.8.8:1080", "socks5://1.1.1.1:9050"]


def test_runner_proxy_search_expands_candidates_until_minimum(tmp_path) -> None:
    settings = tmp_path / "settings.yaml"
    settings.write_text("", encoding="utf-8")
    runner = PipelineRunner(settings_path=str(settings), sources_path="missing.json")
    runner._liveness_stats = {}
    calls = []

    async def fake_load_proxy_pool(_sources, **kwargs):
        calls.append(kwargs)
        if len(calls) == 1:
            return ["socks5://8.8.8.8:1080"]
        return [
            "socks5://8.8.8.8:1080",
            "socks5://1.1.1.1:9050",
            "socks5://9.9.9.9:1080",
        ]

    result = asyncio.run(
        runner._search_validator_proxy_pool(
            fake_load_proxy_pool,
            ["https://first.example/list.txt"],
            {
                "min_proxies": 3,
                "max_proxies": 5,
                "search_rounds": 2,
                "max_candidates": 10,
                "max_candidates_per_source": 4,
                "candidate_growth_factor": 2,
            },
        )
    )

    assert len(result) == 3
    assert [call["max_candidates"] for call in calls] == [10, 20]
    assert [call["max_candidates_per_source"] for call in calls] == [4, 8]
    assert runner._liveness_stats["proxy_search_rounds"] == 2


def test_tcp_validator_rotates_proxy_pool(monkeypatch) -> None:
    seen_proxy_urls = []

    async def fake_tcp_check(host, port, timeout=3.0, proxy_url=None):
        seen_proxy_urls.append(proxy_url)
        return (True, 10.0 + len(seen_proxy_urls))

    monkeypatch.setattr(tcp_module, "tcp_check", fake_tcp_check)
    configs = [
        Config("vless", "a.example", 443, "11111111-1111-4111-8111-111111111111"),
        Config("vless", "b.example", 443, "11111111-1111-4111-8111-111111111112"),
        Config("vless", "c.example", 443, "11111111-1111-4111-8111-111111111113"),
    ]

    result = asyncio.run(
        tcp_module.validate_configs_tcp(
            configs,
            proxy_urls=["socks5://8.8.8.8:1080", "socks5://1.1.1.1:9050"],
        )
    )

    assert result == configs
    assert seen_proxy_urls == [
        "socks5://8.8.8.8:1080",
        "socks5://1.1.1.1:9050",
        "socks5://8.8.8.8:1080",
    ]


def test_tcp_validator_waits_for_all_when_no_max_alive(monkeypatch) -> None:
    seen_hosts = []

    async def fake_tcp_check(host, port, timeout=3.0, proxy_url=None):
        seen_hosts.append(host)
        await asyncio.sleep(0.01 if host == "a.example" else 0.03)
        return (True, 10.0)

    monkeypatch.setattr(tcp_module, "tcp_check", fake_tcp_check)
    configs = [
        Config("vless", "a.example", 443, "11111111-1111-4111-8111-111111111111"),
        Config("vless", "b.example", 443, "11111111-1111-4111-8111-111111111112"),
    ]

    result = asyncio.run(tcp_module.validate_configs_tcp(configs, max_alive=0))

    assert result == configs
    assert seen_hosts == ["a.example", "b.example"]


def test_tcp_validator_retries_multiple_proxies_per_config(monkeypatch) -> None:
    seen_proxy_urls = []

    async def fake_tcp_check(host, port, timeout=3.0, proxy_url=None):
        seen_proxy_urls.append(proxy_url)
        return (proxy_url == "socks5://1.1.1.1:9050", 20.0)

    monkeypatch.setattr(tcp_module, "tcp_check", fake_tcp_check)
    cfg = Config(
        "vless",
        "vpn.example",
        443,
        "11111111-1111-4111-8111-111111111111",
    )

    result = asyncio.run(
        tcp_module.validate_configs_tcp(
            [cfg],
            proxy_urls=["socks5://8.8.8.8:1080", "socks5://1.1.1.1:9050"],
            proxy_attempts_per_config=2,
        )
    )

    assert result == [cfg]
    assert cfg.is_alive is True
    assert seen_proxy_urls == ["socks5://8.8.8.8:1080", "socks5://1.1.1.1:9050"]


def test_runner_liveness_required_proxy_pool_fail_open(tmp_path, monkeypatch) -> None:
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        """
validator:
  allowed_countries: []
  tcp_enabled: true
  min_alive_to_filter: 1
  proxy_pool:
    enabled: true
    required: true
""",
        encoding="utf-8",
    )
    runner = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )

    async def no_proxies():
        return []

    async def should_not_check(*args, **kwargs):
        raise AssertionError("liveness must be skipped without required proxies")

    monkeypatch.setattr(runner, "_validator_proxy_urls", no_proxies)
    monkeypatch.setattr("src.validators.tcp_check.validate_configs_tcp", should_not_check)
    cfg = Config(
        "vless",
        "example.com",
        443,
        "11111111-1111-4111-8111-111111111111",
    )

    result = asyncio.run(
        runner._validate_liveness_configs(
            [cfg],
            label="blacklist",
            tcp_enabled=True,
            tls_enabled=False,
        )
    )

    assert result == [cfg]


def test_runner_liveness_uses_proxy_pool_and_filters_when_enough_alive(
    tmp_path, monkeypatch
) -> None:
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        """
validator:
  allowed_countries: []
  tcp_enabled: true
  tcp_timeout_seconds: 1
  tcp_concurrency: 2
  tcp_max_alive: 0
  min_alive_to_filter: 1
  proxy_pool:
    enabled: true
    required: true
""",
        encoding="utf-8",
    )
    runner = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    dead = Config(
        "vless",
        "dead.example",
        443,
        "11111111-1111-4111-8111-111111111111",
    )
    alive = Config(
        "vless",
        "alive.example",
        443,
        "11111111-1111-4111-8111-111111111112",
    )
    captured = {}

    async def fake_proxy_urls():
        return ["socks5://8.8.8.8:1080"]

    async def fake_validate_configs_tcp(configs, **kwargs):
        captured["proxy_urls"] = kwargs.get("proxy_urls")
        return [alive]

    monkeypatch.setattr(runner, "_validator_proxy_urls", fake_proxy_urls)
    monkeypatch.setattr(
        "src.validators.tcp_check.validate_configs_tcp",
        fake_validate_configs_tcp,
    )

    result = asyncio.run(
        runner._validate_liveness_configs(
            [dead, alive],
            label="blacklist",
            tcp_enabled=True,
            tls_enabled=False,
        )
    )

    assert result == [alive]
    assert captured["proxy_urls"] == ["socks5://8.8.8.8:1080"]


def test_runner_liveness_searches_more_tcp_candidates(
    tmp_path, monkeypatch
) -> None:
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        """
validator:
  allowed_countries: []
  tcp_enabled: true
  tcp_candidate_limit: 2
  tcp_search_rounds: 3
  tcp_max_alive: 3
  min_alive_to_filter: 1
  proxy_pool:
    enabled: true
    required: true
""",
        encoding="utf-8",
    )
    runner = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    configs = [
        Config("vless", f"{i}.example", 443, "11111111-1111-4111-8111-111111111111")
        for i in range(5)
    ]
    call_sizes = []

    async def fake_proxy_urls():
        return ["socks5://8.8.8.8:1080"]

    async def fake_validate_configs_tcp(batch, **kwargs):
        call_sizes.append(len(batch))
        return [batch[0]]

    monkeypatch.setattr(runner, "_validator_proxy_urls", fake_proxy_urls)
    monkeypatch.setattr(
        "src.validators.tcp_check.validate_configs_tcp",
        fake_validate_configs_tcp,
    )

    result = asyncio.run(
        runner._validate_liveness_configs(
            configs,
            label="blacklist",
            tcp_enabled=True,
            tls_enabled=False,
        )
    )

    stats = runner._liveness_stats["lists"]["blacklist"]
    assert result == [configs[0], configs[2], configs[4]]
    assert call_sizes == [2, 2, 1]
    assert stats["tcp_checked"] == 5
    assert stats["tcp_alive"] == 3
    assert stats["tcp_search_rounds"] == 3


def test_runner_liveness_keeps_original_when_alive_below_threshold(
    tmp_path, monkeypatch
) -> None:
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        """
validator:
  allowed_countries: []
  tcp_enabled: true
  min_alive_to_filter: 2
  proxy_pool:
    enabled: true
    required: true
""",
        encoding="utf-8",
    )
    runner = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    configs = [
        Config("vless", "a.example", 443, "11111111-1111-4111-8111-111111111111"),
        Config("vless", "b.example", 443, "11111111-1111-4111-8111-111111111112"),
    ]

    async def fake_proxy_urls():
        return ["socks5://8.8.8.8:1080"]

    async def fake_validate_configs_tcp(configs, **kwargs):
        return [configs[0]]

    monkeypatch.setattr(runner, "_validator_proxy_urls", fake_proxy_urls)
    monkeypatch.setattr(
        "src.validators.tcp_check.validate_configs_tcp",
        fake_validate_configs_tcp,
    )

    result = asyncio.run(
        runner._validate_liveness_configs(
            configs,
            label="blacklist",
            tcp_enabled=True,
            tls_enabled=False,
        )
    )

    assert result == configs


def test_runner_liveness_strict_mode_keeps_alive_when_below_threshold(
    tmp_path, monkeypatch
) -> None:
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        """
validator:
  allowed_countries: []
  tcp_enabled: true
  min_alive_to_filter: 2
  fail_open_on_low_alive: false
  proxy_pool:
    enabled: true
    required: true
""",
        encoding="utf-8",
    )
    runner = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    configs = [
        Config("vless", "a.example", 443, "11111111-1111-4111-8111-111111111111"),
        Config("vless", "b.example", 443, "11111111-1111-4111-8111-111111111112"),
    ]

    async def fake_proxy_urls():
        return ["socks5://8.8.8.8:1080"]

    async def fake_validate_configs_tcp(configs, **kwargs):
        return [configs[0]]

    monkeypatch.setattr(runner, "_validator_proxy_urls", fake_proxy_urls)
    monkeypatch.setattr(
        "src.validators.tcp_check.validate_configs_tcp",
        fake_validate_configs_tcp,
    )

    result = asyncio.run(
        runner._validate_liveness_configs(
            configs,
            label="blacklist",
            tcp_enabled=True,
            tls_enabled=False,
        )
    )

    stats = runner._liveness_stats["lists"]["blacklist"]
    assert result == [configs[0]]
    assert stats["fail_open"] is False
    assert stats["reason"] == "below_min_alive"


def test_runner_liveness_drops_tcp_only_after_tls(tmp_path, monkeypatch) -> None:
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        """
validator:
  allowed_countries: []
  tls_enabled: true
  drop_unchecked_after_tls: true
  min_alive_to_filter: 1
  proxy_pool:
    enabled: false
""",
        encoding="utf-8",
    )
    runner = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    tls_cfg = Config(
        "vless",
        "tls.example",
        443,
        "11111111-1111-4111-8111-111111111111",
        security="tls",
    )
    tcp_only = Config(
        "vless",
        "plain.example",
        80,
        "11111111-1111-4111-8111-111111111112",
        security="none",
    )

    async def fake_validate_configs_tls(configs, **kwargs):
        assert configs == [tls_cfg]
        return [tls_cfg]

    monkeypatch.setattr(
        "src.validators.tls_check.validate_configs_tls",
        fake_validate_configs_tls,
    )

    result = asyncio.run(
        runner._validate_liveness_configs(
            [tls_cfg, tcp_only],
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=True,
        )
    )

    stats = runner._liveness_stats["lists"]["blacklist"]
    assert result == [tls_cfg]
    assert stats["tls_unchecked_passthrough"] == 1
    assert stats["tls_drop_unchecked"] is True


def test_runner_liveness_filters_with_xray_probe(tmp_path, monkeypatch) -> None:
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        """
validator:
  allowed_countries: []
  xray_enabled: true
  xray_executable: /usr/bin/xray
  xray_concurrency: 2
  xray_max_alive: 0
  xray_attempts_per_config: 3
  xray_min_attempt_successes: 3
  xray_min_probe_successes: 2
  xray_probe_urls:
    - https://one.example/generate_204
    - https://two.example/trace
  proxy_pool:
    enabled: false
""",
        encoding="utf-8",
    )
    runner = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    alive = Config(
        "vless",
        "alive.example",
        443,
        "11111111-1111-4111-8111-111111111111",
        security="tls",
    )
    dead = Config(
        "vless",
        "dead.example",
        443,
        "11111111-1111-4111-8111-111111111112",
        security="tls",
    )

    monkeypatch.setattr(
        "src.validators.xray_probe.find_xray_executable",
        lambda explicit_path=None: "/usr/bin/xray",
    )
    monkeypatch.setattr(
        "src.validators.xray_probe.is_xray_supported",
        lambda cfg: True,
    )

    async def fake_validate_configs_xray(configs, **kwargs):
        assert kwargs["xray_path"] == "/usr/bin/xray"
        assert kwargs["concurrency"] == 2
        assert kwargs["probe_urls"] == [
            "https://one.example/generate_204",
            "https://two.example/trace",
        ]
        assert kwargs["min_probe_successes"] == 2
        assert kwargs["attempts_per_config"] == 3
        assert kwargs["min_attempt_successes"] == 3
        return [alive]

    monkeypatch.setattr(
        "src.validators.xray_probe.validate_configs_xray",
        fake_validate_configs_xray,
    )

    result = asyncio.run(
        runner._validate_liveness_configs(
            [alive, dead],
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
    )

    stats = runner._liveness_stats["lists"]["blacklist"]
    assert result == [alive]
    assert stats["xray_checked"] == 2
    assert stats["xray_alive"] == 1
    assert stats["xray_probe_count"] == 2
    assert stats["xray_min_probe_successes"] == 2
    assert stats["xray_attempts_per_config"] == 3
    assert stats["xray_min_attempt_successes"] == 3


def test_runner_xray_preselects_only_subscription_candidates(
    tmp_path, monkeypatch
) -> None:
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        """
validator:
  allowed_countries: []
  xray_enabled: true
  xray_executable: /usr/bin/xray
  xray_candidate_limit_by_list:
    blacklist: 200
  xray_max_alive: 0
  proxy_pool:
    enabled: false
aggregator:
  max_configs_in_output: 200
  sort_by: country
""",
        encoding="utf-8",
    )
    runner = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    configs = [
        Config(
            "vless",
            f"{i}.example",
            443,
            "11111111-1111-4111-8111-111111111111",
            security="tls",
            country="DE" if i % 2 else "CA",
        )
        for i in range(300)
    ]
    captured = {}

    monkeypatch.setattr(
        "src.validators.xray_probe.find_xray_executable",
        lambda explicit_path=None: "/usr/bin/xray",
    )
    monkeypatch.setattr("src.validators.xray_probe.is_xray_supported", lambda cfg: True)

    async def fake_validate_configs_xray(configs, **kwargs):
        captured["checked"] = len(configs)
        return configs[:123]

    monkeypatch.setattr(
        "src.validators.xray_probe.validate_configs_xray",
        fake_validate_configs_xray,
    )

    result = asyncio.run(
        runner._validate_liveness_configs(
            configs,
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
    )

    stats = runner._liveness_stats["lists"]["blacklist"]
    assert captured["checked"] == 200
    assert stats["xray_candidates"] == 300
    assert stats["xray_preselected"] == 200
    assert stats["xray_checked"] == 200
    assert stats["xray_alive"] == 123
    assert len(result) == 123
