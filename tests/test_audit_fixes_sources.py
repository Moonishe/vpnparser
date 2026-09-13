"""Audit-fix coverage: sources, net, repo_info, parse, runner, validators."""

from __future__ import annotations

import asyncio
import types
from pathlib import Path
from unittest import mock

import httpx
import pytest

import src.utils.net as net_module
from src.parsers.base import Config
from src.scheduler.context import PipelineContext, PipelineState
from src.scheduler.settings import Settings
from src.scheduler.stages.parse import LinkParser
from src.sources.github import GitHubClient, GitHubRateLimitError
from src.sources.manager import SourceManager


def _make_context(settings_dict: dict | None = None) -> PipelineContext:
    return PipelineContext(
        settings=Settings(settings_dict or {}),
        github_token=None,
        sources_path="missing.json",
    )


def _mk(addr: str = "1.2.3.4", **kw: object) -> Config:
    return Config(
        protocol=str(kw.get("protocol", "vless")),
        address=addr,
        port=int(kw.get("port", 443)),  # type: ignore[arg-type]
        uuid_or_password="11111111-1111-4111-8111-111111111111",
        remark=str(kw.get("remark", "DE-01")),
        raw_link=(f"vless://11111111-1111-4111-8111-111111111111@{addr}:443#DE-01"),
        country=kw.get("country", "DE"),  # type: ignore[arg-type]
    )


# ---------------------------------------------------------------------------
# sources/github.py — redirect / size guards / 5xx retry tail
# ---------------------------------------------------------------------------


class _FakeGHResponse:
    def __init__(
        self,
        status_code: int = 200,
        *,
        json_data: object = None,
        text_data: str = "",
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
    ):
        self.status_code = status_code
        self._json_data = json_data
        self.text = text_data
        self.headers = headers or {}
        self.encoding = "utf-8"
        self.content = content if content is not None else text_data.encode("utf-8")

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                f"{self.status_code} error",
                request=mock.MagicMock(),
                response=self,
            )

    def json(self) -> object:
        return self._json_data


class _FakeGHClient:
    def __init__(self, responses: list[_FakeGHResponse]):
        self._responses = iter(responses)
        self._last_url: str | None = None
        self._last_params: object = None
        self._call_count = 0

    async def request(self, method: str, url: str, **kwargs) -> _FakeGHResponse:
        self._call_count += 1
        self._last_url = url
        self._last_params = kwargs.get("params")
        return next(self._responses)


def _patch_gh(
    client: GitHubClient, monkeypatch: pytest.MonkeyPatch, fc: _FakeGHClient
) -> None:
    async def _fake_get_client():  # type: ignore[no-untyped-def]
        return fc

    monkeypatch.setattr(client, "_get_client", _fake_get_client)


class TestGithubAuditGuards:
    def test_redirect_check_raises(self) -> None:
        with pytest.raises(ValueError, match="refusing to follow"):
            GitHubClient._check_no_redirect(
                _FakeGHResponse(status_code=301), "https://api/x"
            )

    def test_content_length_oversized(self) -> None:
        big = str(10 * 1024 * 1024 + 1)
        with pytest.raises(ValueError, match="too large"):
            GitHubClient._check_response_size(
                _FakeGHResponse(headers={"Content-Length": big}), "https://api/x"
            )

    def test_content_length_unparseable_ignored(self) -> None:
        # garbage header must not raise, lowercase variant is also read
        GitHubClient._check_response_size(
            _FakeGHResponse(headers={"content-length": "not-a-number"}),
            "https://api/x",
        )

    def test_content_bytes_oversized(self) -> None:
        with pytest.raises(ValueError, match="too large"):
            GitHubClient._check_response_size(
                _FakeGHResponse(content=b"x" * (10 * 1024 * 1024 + 1)),
                "https://api/x",
            )

    def test_5xx_then_404_returns_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = GitHubClient()
        fc = _FakeGHClient(
            [_FakeGHResponse(status_code=503), _FakeGHResponse(status_code=404)]
        )
        _patch_gh(client, monkeypatch, fc)

        async def _sleep(_s: float) -> None:
            pass

        monkeypatch.setattr("src.sources.github.asyncio.sleep", _sleep)
        result = asyncio.run(client._request("GET", "/url"))
        assert result == []

    def test_5xx_then_ratelimit_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = GitHubClient()
        fc = _FakeGHClient(
            [
                _FakeGHResponse(status_code=503),
                _FakeGHResponse(
                    status_code=403,
                    headers={"X-RateLimit-Remaining": "0"},
                ),
            ]
        )
        _patch_gh(client, monkeypatch, fc)

        async def _sleep(_s: float) -> None:
            pass

        monkeypatch.setattr("src.sources.github.asyncio.sleep", _sleep)
        with pytest.raises(GitHubRateLimitError, match="retried"):
            asyncio.run(client._request("GET", "/url"))


# ---------------------------------------------------------------------------
# sources/manager.py
# ---------------------------------------------------------------------------


class TestManagerAudit:
    def test_safe_error_truncates(self) -> None:
        import src.sources.manager as m

        long_exc = ValueError("x" * 500)
        msg = m._safe_error_message(long_exc, limit=50)
        assert len(msg) <= 50
        assert msg.endswith("…")

    def test_fetch_direct_non_retryable_4xx(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sm = SourceManager(sources_file="missing.json", settings_file="missing.yaml")
        calls: list[str] = []

        async def _fail(_client: object, _url: str, _headers: dict) -> str:
            calls.append(_url)
            resp = mock.MagicMock()
            resp.status_code = 404
            raise httpx.HTTPStatusError("404", request=mock.MagicMock(), response=resp)

        monkeypatch.setattr(SourceManager, "_get_validated", staticmethod(_fail))

        async def _no_sleep(_s: float) -> None:
            pass

        monkeypatch.setattr(asyncio, "sleep", _no_sleep)
        with pytest.raises(httpx.HTTPStatusError):
            asyncio.run(
                sm._fetch_direct_url(
                    "https://example.com/f.txt",
                    attempts=3,
                    client=mock.MagicMock(),
                )
            )
        assert len(calls) == 1

    def test_fetch_direct_timeout_backoff_and_raise(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sm = SourceManager(sources_file="missing.json", settings_file="missing.yaml")
        calls: list[int] = []
        sleeps: list[float] = []

        async def _timeout(_client: object, _url: str, _headers: dict) -> str:
            calls.append(1)
            raise TimeoutError("slow")

        async def _sleep(s: float) -> None:
            sleeps.append(s)

        monkeypatch.setattr(SourceManager, "_get_validated", staticmethod(_timeout))
        monkeypatch.setattr(asyncio, "sleep", _sleep)
        with pytest.raises(TimeoutError, match="exceeded its"):
            asyncio.run(
                sm._fetch_direct_url(
                    "https://example.com/f.txt",
                    timeout=1.0,
                    attempts=2,
                    client=mock.MagicMock(),
                )
            )
        assert len(calls) == 2
        assert len(sleeps) == 1

    def test_fetch_direct_owned_client_non_retryable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sm = SourceManager(sources_file="missing.json", settings_file="missing.yaml")
        calls: list[str] = []

        async def _fail(_client: object, _url: str, _headers: dict) -> str:
            calls.append(_url)
            resp = mock.MagicMock()
            resp.status_code = 403
            raise httpx.HTTPStatusError("403", request=mock.MagicMock(), response=resp)

        monkeypatch.setattr(SourceManager, "_get_validated", staticmethod(_fail))

        async def _no_sleep(_s: float) -> None:
            pass

        monkeypatch.setattr(asyncio, "sleep", _no_sleep)
        with pytest.raises(httpx.HTTPStatusError):
            asyncio.run(sm._fetch_direct_url("https://example.com/f.txt", attempts=3))
        assert len(calls) == 1

    def test_stream_hop_empty_targets_raises(self) -> None:
        from src.sources.manager import _PinnedTarget

        pinned = _PinnedTarget(connect_urls=(), host_header="h", extensions={})
        with pytest.raises(RuntimeError):
            asyncio.run(
                SourceManager._stream_hop(mock.MagicMock(), pinned, {}, logical_url="u")
            )

    def test_filename_backslash(self, tmp_path: Path) -> None:
        sm = SourceManager(
            sources_file=str(tmp_path / "m.json"),
            settings_file=str(tmp_path / "m.yaml"),
        )
        assert sm._filename_from_url("https://h/dir\\file.txt") == "file.txt"
        assert sm._safe_filename("dir\\evil.txt") == "evil.txt"

    def test_url_list_early_break(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sm = SourceManager(
            sources_file=str(tmp_path / "m.json"),
            settings_file=str(tmp_path / "m.yaml"),
        )
        index = "\n".join(f"https://example.com/{i}.txt" for i in range(20))

        async def _fake(url: str, **kw: object) -> str:
            if str(url).endswith("index.txt"):
                return index
            return f"body-{url}"

        monkeypatch.setattr(sm, "_fetch_direct_url", _fake)
        result = asyncio.run(
            sm._fetch_url_list(
                {
                    "name": "cap",
                    "url": "https://example.com/index.txt",
                    "max_files": 2,
                },
                "cap",
                "mixed",
                None,
            )
        )
        assert result.ok is True
        assert len(result.files) == 2

    def test_url_list_no_extension_dedup(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sm = SourceManager(
            sources_file=str(tmp_path / "m.json"),
            settings_file=str(tmp_path / "m.yaml"),
        )

        async def _fake(url: str, **kw: object) -> str:
            if str(url).endswith("index.txt"):
                return "https://a.example.com/data\nhttps://b.example.com/data\n"
            return "content"

        monkeypatch.setattr(sm, "_fetch_direct_url", _fake)
        result = asyncio.run(
            sm._fetch_url_list(
                {"name": "dup", "url": "https://example.com/index.txt"},
                "dup",
                "mixed",
                None,
            )
        )
        assert result.ok is True
        names = [n for n, _c in result.files]
        assert names[0] == "data"
        assert names[1] == "data_1"


# ---------------------------------------------------------------------------
# source_options / net / repo_info
# ---------------------------------------------------------------------------


class TestOptionsNetRepo:
    def test_float_nonfinite_returns_default(self) -> None:
        from src.sources.source_options import _float_source_value

        assert _float_source_value({"k": float("inf")}, "k", 3.0) == 3.0
        assert _float_source_value({"k": float("nan")}, "k", 3.0) == 3.0

    def test_resolve_global_empty_answers(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def _empty(_host: str, *, timeout: float = 5.0):  # type: ignore[no-untyped-def]
            return []

        monkeypatch.setattr(net_module, "resolve_host_addresses", _empty)
        result = asyncio.run(net_module.resolve_global_ips("example.com"))
        assert result == []

    def test_safe_url_rejects_userinfo(self) -> None:
        assert (
            asyncio.run(
                net_module.is_safe_public_url("https://user:pass@example.com/x")
            )
            is False
        )

    def test_safe_url_bad_port(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from urllib.parse import urlsplit as _split

        real_split = _split

        class _BadPort:
            scheme = "https"
            hostname = "example.com"
            username = None
            password = None

            @property
            def port(self) -> int:
                raise ValueError("bad port")

        monkeypatch.setattr(net_module, "urlsplit", lambda _u: _BadPort())
        assert (
            asyncio.run(net_module.is_safe_public_url("https://example.com/")) is False
        )
        monkeypatch.setattr(net_module, "urlsplit", real_split)

    def test_safe_url_port_out_of_range(self) -> None:
        assert (
            asyncio.run(net_module.is_safe_public_url("https://example.com:0/"))
            is False
        )

    def test_repo_branch_guards(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import src.repo_info as ri

        assert ri._valid_branch("feature/x") is True
        assert ri._valid_branch("a..b") is False
        monkeypatch.setenv("GITHUB_BRANCH", "bad branch!")
        monkeypatch.delenv("GITHUB_REF_NAME", raising=False)
        monkeypatch.delenv("GITHUB_REF", raising=False)
        assert ri.github_branch() == "main"

    def test_slug_from_remote_variants(self) -> None:
        import src.repo_info as ri

        assert ri._slug_from_remote_url("git@evil.com:owner/repo.git") is None
        assert ri._slug_from_remote_url("https://evilgithub.com/owner/repo") is None
        assert ri._slug_from_remote_url("https://github.com/owner") is None
        assert ri._slug_from_remote_url("https://github.com/22/repo") is None
        assert ri._slug_from_remote_url("https://github.com/") is None
        # Invalid IPv6 URL -> urlsplit raises ValueError
        assert ri._slug_from_remote_url("https://[::1") is None


# ---------------------------------------------------------------------------
# scheduler/stages/parse.py
# ---------------------------------------------------------------------------


class TestParseAudit:
    def test_aclose_with_failing_closer(self) -> None:
        ctx = _make_context()

        async def _run() -> None:
            parser = LinkParser(ctx)

            class _Bad:
                async def aclose(self) -> None:
                    raise RuntimeError("boom")

            parser._llm_parser = _Bad()
            await parser.aclose()
            assert parser._llm_parser is None
            # no parser -> noop
            await parser.aclose()
            # parser without aclose -> noop
            parser._llm_parser = object()
            await parser.aclose()

        asyncio.run(_run())

    def test_link_cap_truncation(self) -> None:
        ctx = _make_context({"sources": {"max_links_per_file": 2}})
        parser = LinkParser(ctx)
        links = [
            "vless://11111111-1111-4111-8111-111111111111@1.2.3.4:443#x1",
            "vless://11111111-1111-4111-8111-111111111111@1.2.3.5:443#x2",
            "vless://11111111-1111-4111-8111-111111111111@1.2.3.6:443#x3",
        ]

        async def _fake_extract(_sub: object, _c: str, _f: str, _s: str) -> list[str]:
            return list(links)

        async def _run() -> None:
            parser.extract_links = _fake_extract  # type: ignore[method-assign]
            grouped = await parser.parse_all_by_list(
                [
                    types.SimpleNamespace(
                        list_type="mixed", files=[("f.txt", "body")], source_name="s"
                    )
                ]
            )
            assert sum(len(v) for v in grouped.values()) == 2

        asyncio.run(_run())

    def test_offline_geoip_success_and_failure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ctx = _make_context(
            {"validator": {"geoip_enabled": True, "geoip_mmdb_file": "geo.mmdb"}}
        )
        parser = LinkParser(ctx)
        cfg = _mk("9.9.9.9")
        cfg.remark = "zzz-no-country-here-xyz"
        results = [
            types.SimpleNamespace(
                list_type="mixed",
                files=[
                    (
                        "f.txt",
                        f"vless://11111111-1111-4111-8111-111111111111@{cfg.address}:443#x",
                    )
                ],
                source_name="s",
            )
        ]

        async def _fake_extract(_a: object, _b: str, _c: str, _d: str) -> list[str]:
            return [f"vless://11111111-1111-4111-8111-111111111111@{cfg.address}:443#x"]

        async def _offline_ok(_vcfg: dict, _path: str) -> str:
            return "/tmp/geo.mmdb"

        async def _enrich_ok(configs: list, _path: str) -> None:
            for c in configs:
                c.country = "DE"

        monkeypatch.setattr(parser, "extract_links", _fake_extract)
        monkeypatch.setattr(parser, "_ensure_offline_geoip", _offline_ok)
        monkeypatch.setattr(
            "src.validators.geoip.enrich_configs_geoip_offline", _enrich_ok
        )
        grouped = asyncio.run(parser.parse_all_by_list(results))
        assert sum(len(v) for v in grouped.values()) == 1

        async def _enrich_fail(configs: list, _path: str) -> None:
            raise RuntimeError("offline enrich down")

        # offline db ok but enrichment raises -> warning path (197-208 except)
        monkeypatch.setattr(
            "src.validators.geoip.enrich_configs_geoip_offline", _enrich_fail
        )
        grouped2 = asyncio.run(parser.parse_all_by_list(results))
        assert sum(len(v) for v in grouped2.values()) == 1

    def test_llm_budget_exhausted(self) -> None:
        ctx = _make_context({"llm": {"enabled": True, "max_calls_per_run": 0}})
        parser = LinkParser(ctx)
        assert asyncio.run(parser.llm_fallback("x" * 500, "f.txt", "s")) == []

    def test_llm_per_source_exhausted(self) -> None:
        import os

        os.environ["TEST_LLM_KEY_AUDIT"] = "k"
        ctx = _make_context(
            {
                "llm": {
                    "enabled": True,
                    "api_key_env": "TEST_LLM_KEY_AUDIT",
                    "max_calls_per_run": 50,
                    "max_calls_per_source": 1,
                    "min_text_length": 10,
                }
            }
        )
        parser = LinkParser(ctx)
        parser._llm_calls_per_source["s"] = 1
        assert asyncio.run(parser.llm_fallback("x" * 500, "f.txt", "s")) == []
        del os.environ["TEST_LLM_KEY_AUDIT"]

    def test_wireguard_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level("WARNING"):
            assert LinkParser.parse_one_link("wireguard://abc@1.2.3.4:51820") is None
        assert "No parser for scheme" in caplog.text


# ---------------------------------------------------------------------------
# liveness_pool / quality / stats_history
# ---------------------------------------------------------------------------


class TestPoolQualityStats:
    def test_pool_degraded_branches(self) -> None:
        from src.scheduler.context import PipelineContext
        from src.scheduler.settings import Settings
        from src.scheduler.stages.liveness import LivenessValidator

        ctx = PipelineContext(
            settings=Settings({}), github_token=None, sources_path="missing.json"
        )
        lv = LivenessValidator(ctx)
        assert lv._pool_degraded(0, 0) is False
        assert lv._pool_degraded(1, 20) is True
        assert lv._pool_degraded("bad", 5) is False  # type: ignore[arg-type]
        assert lv._pool_degraded(1, 5) is False
        assert lv._pool_degraded(1, 6) is True
        assert lv._pool_degraded(5, 5) is False

    def test_pool_died_degraded_warning(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from src.scheduler.context import PipelineContext
        from src.scheduler.settings import Settings
        from src.scheduler.stages.liveness import LivenessValidator

        ctx = PipelineContext(
            settings=Settings({"validator": {"proxy_pool": {"enabled": True}}}),
            github_token=None,
            sources_path="missing.json",
        )
        lv = LivenessValidator(ctx)
        lv._validator_proxy_urls_cache = [
            "socks5://10.0.0.1:1080",
            "socks5://10.0.0.2:1080",
        ]

        class _Hist:
            def record(self, *_a: object, **_k: object) -> None:
                pass

        lv._proxy_health_history = _Hist()

        async def _connects(url: str, **_k: object) -> bool:
            return url.endswith("1080") and "10.0.0.2" in url

        monkeypatch.setattr("src.validators.proxy_pool.proxy_connects", _connects)
        asyncio.run(
            lv._pool_died_after_empty_list("blacklist", alive_count=2, checked_count=10)
        )
        assert lv._validator_proxy_urls_cache == ["socks5://10.0.0.2:1080"]

    def test_pool_refetch_limit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from src.scheduler.context import PipelineContext
        from src.scheduler.settings import Settings
        from src.scheduler.stages.liveness import LivenessValidator

        ctx = PipelineContext(
            settings=Settings({"validator": {"proxy_pool": {"enabled": True}}}),
            github_token=None,
            sources_path="missing.json",
        )
        lv = LivenessValidator(ctx)
        lv._validator_proxy_urls_cache = ["socks5://10.0.0.1:1080"]
        lv._pool_refetch_count = 99

        async def _dead(_url: str, **_k: object) -> bool:
            return False

        monkeypatch.setattr("src.validators.proxy_pool.proxy_connects", _dead)
        asyncio.run(lv._pool_died_after_empty_list("blacklist"))
        assert lv._validator_proxy_urls_cache == ["socks5://10.0.0.1:1080"]

    def test_quality_effective_passes_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        from src.scheduler.stages.quality import QualityFilter

        ctx = _make_context(
            {
                "quality": {
                    "min_consecutive_passes": 10,
                    "health_recent_window": 3,
                }
            }
        )
        qf = QualityFilter(ctx)
        with caplog.at_level("WARNING"):
            out = qf.apply({"mixed": [_mk("1.1.1.1")]})
        assert "mixed" in out
        assert "exceeds" in caplog.text

    def test_run_stats_num_fallbacks(self) -> None:
        from src.scheduler.stats_history import run_stats_entry

        entry = run_stats_entry(
            {"lists": {"blacklist": {"xray_alive": "3.7", "xray_checked": "bad"}}},
            "ok",
            now=1,
        )
        assert entry["lists"]["blacklist"]["alive"] == 3
        entry2 = run_stats_entry(
            {"lists": {"blacklist": {"xray_alive": object()}}}, "ok", now=1
        )
        assert entry2["lists"]["blacklist"]["alive"] == 0

    def test_series_points_branches(self) -> None:
        from src.scheduler.stats_history import _series_points

        assert _series_points(
            [{"lists": {"blacklist": "bad"}}], "blacklist", points=5
        ) == [0]
        assert _series_points(
            [{"lists": {"blacklist": {"alive": "3.7"}}}], "blacklist", points=5
        ) == [3]
        assert _series_points(
            [{"lists": {"blacklist": {"alive": object()}}}], "blacklist", points=5
        ) == [0]


# ---------------------------------------------------------------------------
# runner.py
# ---------------------------------------------------------------------------


class TestRunnerAudit:
    def _runner(self, tmp_path: Path, extra: str = "") -> object:
        from src.scheduler.runner import PipelineRunner

        settings = tmp_path / "settings.yaml"
        settings.write_text(
            "validator:\n  allowed_countries: []\n" + extra, encoding="utf-8"
        )
        src = tmp_path / "sources.json"
        src.write_text('{"sources": []}', encoding="utf-8")
        return PipelineRunner(settings_path=str(settings), sources_path=str(src))

    def test_canonical_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from src.scheduler import runner as r

        monkeypatch.setattr(
            "src.utils.paths._find_project_root",
            mock.MagicMock(side_effect=RuntimeError("no root")),
        )
        assert r._canonical_output_path("output/x.txt").endswith("x.txt")

    def test_max_configs_negative(self, tmp_path: Path) -> None:
        r = self._runner(tmp_path, "aggregator:\n  max_configs_in_output: -5\n")
        assert r._max_configs() == 0  # type: ignore[attr-defined]

    def test_min_publish_negative(self, tmp_path: Path) -> None:
        r = self._runner(tmp_path, "publisher:\n  min_publish_configs: -3\n")
        assert r._min_publish_configs() == 10  # type: ignore[attr-defined]

    def test_repo_path_variants(self, tmp_path: Path) -> None:
        r = self._runner(tmp_path)
        assert r._repo_path_for("/definitely/outside/xyz123/file.txt") is None  # type: ignore[attr-defined]
        # windows drive-letter outside project
        assert r._repo_path_for("Z:/nope/file.txt") is None  # type: ignore[attr-defined]

    def test_degraded_reasons(self, tmp_path: Path) -> None:
        r = self._runner(tmp_path)
        r._liveness_stats = {
            "lists": {"blacklist": {"xray_checked": 60, "xray_alive": 0}}
        }  # type: ignore[attr-defined]
        assert r._degraded_reasons() != []  # type: ignore[attr-defined]

    def test_write_stats_history_tcp_tls(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / "pyproject.toml").write_text("", encoding="utf-8")
        r = self._runner(tmp_path)
        r._liveness_stats = {  # type: ignore[attr-defined]
            "proxy_count": 2,
            "lists": {
                "blacklist": {
                    "xray_alive": 0,
                    "xray_checked": 0,
                    "tcp_alive": 5,
                    "tcp_checked": 10,
                    "tls_alive": 3,
                    "tls_checked": 8,
                }
            },
        }
        r._context.liveness_stats.update(r._liveness_stats)  # type: ignore[attr-defined]
        files = r._write_stats_history("ok")  # type: ignore[attr-defined]
        assert isinstance(files, list)


# ---------------------------------------------------------------------------
# tcp / tls
# ---------------------------------------------------------------------------


class TestTcpTlsAudit:
    def test_tcp_sock_close_on_wrap_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import src.validators.tcp_check as t

        async def _resolve(host: str, *, timeout: float = 5.0) -> list[str]:
            return ["93.184.216.34"]

        from src.validators import address_guard

        monkeypatch.setattr(address_guard, "resolve_host_addresses", _resolve)
        fake_sock = mock.MagicMock()
        fake_proxy = mock.MagicMock()
        fake_proxy.connect = mock.AsyncMock(return_value=fake_sock)
        monkeypatch.setattr(
            "python_socks.async_.asyncio.Proxy.from_url", lambda _u: fake_proxy
        )

        async def _boom(*_a: object, **_k: object):  # type: ignore[no-untyped-def]
            raise RuntimeError("wrap boom")

        monkeypatch.setattr(t.asyncio, "open_connection", _boom)
        with pytest.raises(RuntimeError, match="wrap boom"):
            asyncio.run(
                t._open_connection_via_socks("h", 80, "socks5://p:1080", timeout=1.0)
            )
        fake_sock.close.assert_called()

    def test_tls_sock_close_on_wrap_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import ssl as _ssl

        import src.validators.tls_check as t

        fake_sock = mock.MagicMock()
        fake_proxy = mock.MagicMock()
        fake_proxy.connect = mock.AsyncMock(return_value=fake_sock)
        monkeypatch.setattr(
            "python_socks.async_.asyncio.Proxy.from_url", lambda _u: fake_proxy
        )

        async def _boom(*_a: object, **_k: object):  # type: ignore[no-untyped-def]
            raise RuntimeError("tls wrap boom")

        monkeypatch.setattr(t.asyncio, "open_connection", _boom)
        with pytest.raises(RuntimeError, match="tls wrap boom"):
            asyncio.run(
                t._open_connection_via_socks(
                    "h", 443, _ssl.create_default_context(), None, "socks5://p:1080"
                )
            )
        fake_sock.close.assert_called()

    def test_tls_refusal_summary_resets(self) -> None:
        import src.validators.tls_check as t

        t._refusals["non-public"] = 2
        t.log_refusal_summary()
        assert sum(t._refusals.values()) == 0

    def test_tcp_outer_except(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import src.validators.tcp_check as t

        async def _bad_pin(host: str, *, timeout: float = 5.0):  # type: ignore[no-untyped-def]
            return 123  # truthy non-iterable -> TypeError inside outer try

        monkeypatch.setattr(t, "resolve_pinned_addresses", _bad_pin)
        ok, lat = asyncio.run(t.tcp_check("example.com", 443))
        assert ok is False
        assert lat is None

    def test_tcp_none_breaks_proxy_loop(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import src.validators.tcp_check as t
        from src.validators import address_guard as ag

        async def _resolve(host: str, *, timeout: float = 5.0) -> list[str]:
            return ["93.184.216.34"]

        monkeypatch.setattr(ag, "resolve_host_addresses", _resolve)
        calls: list[str | None] = []

        async def _fake_tcp(host: str, port: int, **kw: object):  # type: ignore[no-untyped-def]
            calls.append(kw.get("proxy_url"))  # type: ignore[attr-defined]
            return (None, None)

        monkeypatch.setattr(t, "tcp_check", _fake_tcp)
        cfgs = [_mk("8.8.8.8"), _mk("1.1.1.1")]
        out = asyncio.run(
            t.validate_configs_tcp(
                cfgs, proxy_urls=["socks5://a:1080", "socks5://b:1080"]
            )
        )
        assert out == []
        assert len(calls) == 2

    def test_tls_none_breaks(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import src.validators.tls_check as t
        from src.validators import address_guard as ag

        async def _resolve(host: str, *, timeout: float = 5.0) -> list[str]:
            return ["93.184.216.34"]

        monkeypatch.setattr(ag, "resolve_host_addresses", _resolve)

        async def _fake_tls(*_a: object, **_k: object):  # type: ignore[no-untyped-def]
            return None

        monkeypatch.setattr(t, "tls_check", _fake_tls)
        cfg = _mk("8.8.8.8")
        cfg.security = "tls"
        out = asyncio.run(t.validate_configs_tls([cfg]))
        assert out == []


# ---------------------------------------------------------------------------
# xray easy branches
# ---------------------------------------------------------------------------


class TestXrayAudit:
    def test_cleanup_reclaims_old_dir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import tempfile
        import time as _time

        import src.validators.xray_probe as x

        monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
        old = tmp_path / "xray-probe-old123"
        old.mkdir()
        ancient = _time.time() - 100000
        import os

        os.utime(old, (ancient, ancient))
        assert (
            x._sweep_stale_probe_dirs(prefixes=("xray-probe-",), min_age_seconds=10)
            >= 1
        )

    def test_sweep_stat_and_rmtree_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import tempfile

        import src.validators.xray_probe as x

        monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
        victim = tmp_path / "xray-probe-victim"
        victim.mkdir()

        orig_stat = Path.stat

        def _boom_stat(self: Path, *a: object, **k: object):  # type: ignore[no-untyped-def]
            if self.name == "xray-probe-victim":
                raise OSError("stat boom")
            return orig_stat(self, *a, **k)

        monkeypatch.setattr(Path, "stat", _boom_stat)
        assert x._sweep_stale_probe_dirs(prefixes=("xray-probe-",)) >= 0

        monkeypatch.setattr(Path, "stat", orig_stat)
        monkeypatch.setattr(
            "src.validators.xray_probe.shutil.rmtree",
            mock.MagicMock(side_effect=OSError("rm boom")),
        )
        # fresh dirs are skipped; make it old enough by patching time
        import time as _time

        monkeypatch.setattr(_time, "time", lambda: orig_stat(victim).st_mtime + 100000)
        assert x._sweep_stale_probe_dirs(prefixes=("xray-probe-",)) >= 0

    def test_no_verdict_paths(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import src.validators.xray_probe as x

        async def _boom(*_a: object, **_k: object):  # type: ignore[no-untyped-def]
            raise x._NoVerdictError("infra")

        monkeypatch.setattr(x, "xray_probe_check", _boom)
        cfg = _mk("10.0.0.9")
        out = asyncio.run(
            x.validate_configs_xray(
                [cfg],
                xray_path="xray",
                probe_url="https://example.com/",
                timeout=1.0,
                startup_timeout=1.0,
            )
        )
        assert out == []
        assert cfg.is_alive is None


# ---------------------------------------------------------------------------
# publisher + report
# ---------------------------------------------------------------------------


class _FakePubResp:
    def __init__(
        self,
        status_code: int = 200,
        *,
        json_data: object = None,
        text_data: str = "",
        headers: dict[str, str] | None = None,
    ):
        self.status_code = status_code
        self._json = json_data
        self.text = text_data
        self.headers = headers or {}

    def json(self) -> object:
        return self._json

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("err", request=mock.MagicMock(), response=self)


class _FakePubClient:
    def __init__(self, puts: list[_FakePubResp]):
        self._puts = iter(puts)
        self.put_calls = 0

    async def put(self, _url: str, **_kw: object) -> _FakePubResp:
        self.put_calls += 1
        return next(self._puts)

    async def get(self, _url: str, **_kw: object) -> _FakePubResp:
        return _FakePubResp(status_code=404)


class TestPublisherReportAudit:
    def test_get_sha_auth_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from src.publisher.github import GitHubPublisher

        pub = GitHubPublisher(token="t", owner="o", repo="r")

        class _C:
            async def get(self, _u: str, **_k: object) -> _FakePubResp:
                return _FakePubResp(status_code=401)

        async def _client() -> _C:
            return _C()

        monkeypatch.setattr(pub, "_get_client", _client)
        with pytest.raises(Exception, match="auth failed"):
            asyncio.run(pub._get_file_sha("a.txt"))

    def test_publish_5xx_retry(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from src.publisher.github import GitHubPublisher

        pub = GitHubPublisher(token="t", owner="o", repo="r")
        fc = _FakePubClient(
            [_FakePubResp(status_code=503), _FakePubResp(status_code=201)]
        )

        async def _client() -> _FakePubClient:
            return fc

        async def _sha(_p: str) -> None:
            return None

        monkeypatch.setattr(pub, "_get_client", _client)
        monkeypatch.setattr(pub, "_get_file_sha", _sha)

        async def _no_sleep(_s: float) -> None:
            pass

        monkeypatch.setattr(asyncio, "sleep", _no_sleep)
        assert asyncio.run(pub.publish_file("a.txt", "hello", "msg")) is True
        assert fc.put_calls == 2

    def test_safe_int_bool(self) -> None:
        from src.notify.report import _mix_label, _safe_int

        assert _safe_int(True) == 1
        assert _safe_int(False) == 0
        assert _mix_label({"outputs": {"blacklist": {"count": True}}}) == "Mix"

    def test_format_country_counts_garbage(self) -> None:
        from src.notify.report import _format_country_counts

        assert _format_country_counts({}) == "страны не определены"
        # garbage count is dropped, valid one stays
        text = _format_country_counts({"DE": "bad", "US": 3})
        assert "США" in text

    def test_format_trend_tcp_fallback(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import json as _json

        from src.notify.report import _format_trend_alert

        monkeypatch.chdir(tmp_path)
        (tmp_path / "pyproject.toml").write_text("", encoding="utf-8")
        hist = [
            {
                "status": "ok",
                "proxy_count": 10,
                "lists": {"blacklist": {"alive": 0, "tcp_alive": 20}},
            },
            {
                "status": "ok",
                "proxy_count": 10,
                "lists": {"blacklist": {"alive": 0, "tcp_alive": 20}},
            },
        ]
        out_dir = tmp_path / "output"
        out_dir.mkdir()
        (out_dir / "stats-history.json").write_text(_json.dumps(hist), encoding="utf-8")
        assert isinstance(_format_trend_alert("output/run-summary.json"), str)

    def test_publish_state_skips(self, tmp_path: Path) -> None:
        r_runner = TestRunnerAudit()._runner(tmp_path)  # type: ignore[attr-defined]
        state = PipelineState()
        # _publish_files with no targets returns True (nothing to publish)
        assert (
            asyncio.run(
                r_runner._publish_files(
                    [], combined_output_file="output/subscription.txt"
                )
            )
            is True
        )  # type: ignore[attr-defined]
