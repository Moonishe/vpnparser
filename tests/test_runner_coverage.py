"""Coverage-completion tests for PipelineRunner — every uncovered line."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.aggregator.output import _watermark_link
from src.parsers.base import Config
from src.publisher.github import GitHubPublishError
from src.scheduler.runner import PipelineRunner
from src.scheduler.settings import load_settings
from src.scheduler.stages.aggregate import Aggregator
from src.scheduler.stages.filter import GarbageFilter
from src.scheduler.stages.write import OutputWriter
from src.utils.paths import resolve_safe_output_path

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _mk(addr: str, country: str = "DE", **kw: object) -> Config:
    return Config(
        protocol=kw.get("protocol", "vless"),  # type: ignore[arg-type]
        address=addr,
        port=int(kw.get("port", 443)),  # type: ignore[arg-type]
        uuid_or_password="11111111-1111-4111-8111-111111111111",
        remark=f"{country}-01",
        raw_link=f"vless://11111111-1111-4111-8111-111111111111@{addr}:443#{country}-01",
        country=country,
    )


def _make_runner(
    tmp_path: Path,
    extra_settings: str = "",
    sources: str = "",
    github_token: str | None = None,
) -> PipelineRunner:
    settings = tmp_path / "settings.yaml"
    text = "validator:\n  allowed_countries: []\n"
    if extra_settings:
        text += extra_settings
    settings.write_text(text, encoding="utf-8")
    src = tmp_path / "sources.json"
    src.write_text(sources or '{"sources": []}', encoding="utf-8")
    return PipelineRunner(
        settings_path=str(settings),
        sources_path=str(src),
        github_token=github_token,
    )


# ===================================================================
# load_settings (src/scheduler/settings.py)
# ===================================================================


def test_load_settings_static(tmp_path: Path) -> None:
    """load_settings parses a YAML file into a mapping."""
    f = tmp_path / "s.yaml"
    f.write_text("key: value\n", encoding="utf-8")
    result = load_settings(str(f))
    assert result == {"key": "value"}


# ===================================================================
# _max_configs  (lines 124-125)
# ===================================================================


def test_max_configs_invalid_value(tmp_path: Path) -> None:
    """_max_configs returns default 500 when value is not int-convertible."""
    r = _make_runner(tmp_path, "aggregator:\n  max_configs_in_output: invalid\n")
    assert r._max_configs() == 500


def test_max_configs_none_value(tmp_path: Path) -> None:
    """_max_configs returns default 500 when value is None."""
    r = _make_runner(tmp_path)
    assert r._max_configs() == 500


# ===================================================================
# GarbageFilter.filter_garbage (src/scheduler/stages/filter.py)
# ===================================================================


def test_filter_garbage_static() -> None:
    """filter_garbage removes placeholder configs."""
    c = _mk("1.2.3.4")
    clean, removed = GarbageFilter.filter_garbage([c])
    assert len(clean) == 1
    assert removed == 0


# ===================================================================
# Xray candidate preselect (whitelist vs. blacklist balancing)
# ===================================================================


def test_xray_candidate_preselect_whitelist(tmp_path: Path) -> None:
    """Whitelist list_type uses _whitelist_balance."""
    r = _make_runner(tmp_path)
    cfgs = [_mk("a.ru", "RU"), _mk("b.de", "DE")]
    result = r._whitelist_balance(cfgs, 10)
    assert len(result) <= 10


def test_xray_candidate_preselect_blacklist(tmp_path: Path) -> None:
    """Non-whitelist list_type uses _country_balanced_limit."""
    r = _make_runner(tmp_path)
    cfgs = [_mk("a.ru", "RU"), _mk("b.de", "DE")]
    result = r._country_balanced_limit(cfgs, 10)
    assert len(result) <= 10


# ===================================================================
# quality collaborators (QualityFilter / HealthHistory)
# ===================================================================


def test_quality_cfg(tmp_path: Path) -> None:
    """quality.settings.section('quality') returns the quality section."""
    r = _make_runner(tmp_path)
    result = r._quality.settings.section("quality")
    assert isinstance(result, dict)


def test_health_history_file(tmp_path: Path) -> None:
    """health._file() returns the configured health file path."""
    r = _make_runner(tmp_path)
    result = r._quality.health._file()
    assert result is None or isinstance(result, str)


def test_load_health_history(tmp_path: Path) -> None:
    """health.load() loads health data."""
    r = _make_runner(tmp_path)
    result = r._quality.health.load()
    assert isinstance(result, dict)


def test_source_run_stats(tmp_path: Path) -> None:
    """health.source_run_stats() returns per-source stats."""
    r = _make_runner(tmp_path)
    c = _mk("1.2.3.4")
    c.is_alive = True
    result = r._quality.health.source_run_stats([c])
    assert isinstance(result, dict)


def test_quality_score(tmp_path: Path) -> None:
    """health.score() returns a float score."""
    r = _make_runner(tmp_path)
    c = _mk("1.2.3.4")
    score = r._quality.health.score(c)
    assert isinstance(score, float)


# ===================================================================
# Aggregator._take_unique_configs
# ===================================================================


def test_take_unique_configs_static(tmp_path: Path) -> None:
    """_take_unique_configs takes up to target unique configs."""
    cfgs = [_mk("a.de", "DE"), _mk("b.de", "DE")]
    result = Aggregator._take_unique_configs(cfgs, 1, set())
    assert len(result) == 1


# ===================================================================
# OutputWriter._write_plain_fallback
# ===================================================================


def test_write_plain_fallback_static(tmp_path: Path) -> None:
    """_write_plain_fallback writes raw links."""
    out = tmp_path / "out.txt"
    c = _mk("1.2.3.4", "DE")
    count = OutputWriter._write_plain_fallback([c], str(out))
    assert count == 1
    assert out.read_text(encoding="utf-8").strip() == c.raw_link


# ===================================================================
# _split_output_files  (lines 557, 567)
# ===================================================================


def test_split_output_files_non_dict(tmp_path: Path) -> None:
    """_split_output_files returns {} when raw value is not a dict."""
    r = _make_runner(tmp_path, 'publisher:\n  split_output_files: "not-a-dict"\n')
    result = r._split_output_files("combined.txt")
    assert result == {}


def test_split_output_files_skip_combined_path(tmp_path: Path) -> None:
    """_split_output_files skips entries pointing to combined output file."""
    combined = str(tmp_path / "combined.txt")
    r = _make_runner(
        tmp_path,
        f"publisher:\n  split_output_files:\n    blacklist: {combined}\n",
    )
    result = r._split_output_files(combined)
    assert "blacklist" not in result


def test_split_output_files_normal(tmp_path: Path) -> None:
    """_split_output_files returns valid split files."""
    r = _make_runner(
        tmp_path,
        "publisher:\n  split_output_files:\n    blacklist: bl.txt\n    whitelist: wl.txt\n",
    )
    result = r._split_output_files("combined.txt")
    assert result.get("blacklist") == "bl.txt"
    assert result.get("whitelist") == "wl.txt"


# ===================================================================
# _mix_output_file  (lines 607-611, 615-620)
# ===================================================================


def test_mix_output_file_none(tmp_path: Path) -> None:
    """_mix_output_file returns None when not configured."""
    r = _make_runner(tmp_path)
    assert r._mix_output_file("out.txt") is None


def test_mix_output_file_conflict_combined(tmp_path: Path) -> None:
    """_mix_output_file returns None when path == combined_output_file."""
    r = _make_runner(
        tmp_path,
        "publisher:\n  mix_output_file: out.txt\n",
    )
    assert r._mix_output_file("out.txt") is None


def test_mix_output_file_conflict_split(tmp_path: Path) -> None:
    """_mix_output_file returns None when path collides with split path."""
    r = _make_runner(
        tmp_path,
        "publisher:\n"
        "  mix_output_file: mix.txt\n"
        "  split_output_files:\n"
        "    blacklist: mix.txt\n",
    )
    splits = r._split_output_files("combined.txt")
    assert r._mix_output_file("combined.txt", splits) is None


def test_mix_output_file_ok(tmp_path: Path) -> None:
    """_mix_output_file returns path when no conflicts."""
    r = _make_runner(
        tmp_path,
        "publisher:\n"
        "  mix_output_file: mix.txt\n"
        "  split_output_files:\n"
        "    blacklist: bl.txt\n",
    )
    splits = r._split_output_files("combined.txt")
    result = r._mix_output_file("combined.txt", splits)
    assert result == "mix.txt"


# ===================================================================
# OutputWriter._location_output_config
# ===================================================================


def test_location_output_config(tmp_path: Path) -> None:
    """_location_output_config reads the publisher location settings."""
    r = _make_runner(tmp_path)
    enabled, out_dir, limit = r._writer._location_output_config()
    assert isinstance(enabled, bool)
    assert isinstance(out_dir, str)
    assert isinstance(limit, int)


# ===================================================================
# OutputWriter._build_location_outputs
# ===================================================================


def test_build_location_outputs(tmp_path: Path) -> None:
    """_build_location_outputs groups configs per country."""
    r = _make_runner(tmp_path)
    cfgs = [_mk("a.de", "DE"), _mk("b.fr", "FR")]
    result = r._writer._build_location_outputs(cfgs, 50)
    assert isinstance(result, dict)
    assert "DE" in result or "FR" in result or not result


# ===================================================================
# _save_proxy_health_history  (lines 728, 736-737)
# ===================================================================


def test_save_proxy_health_history_noop(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """_save_proxy_health_history returns early when history is None."""
    r = _make_runner(tmp_path)
    r._proxy_health_history = None
    r._proxy_health_file = None
    r._save_proxy_health_history()
    # No exception = success


def test_save_proxy_health_history_exception(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """_save_proxy_health_history logs warning on save failure."""
    caplog.set_level(logging.WARNING)
    r = _make_runner(tmp_path)
    mock_history = MagicMock()
    mock_history.save = MagicMock(side_effect=RuntimeError("save failed"))
    r._proxy_health_history = mock_history
    r._proxy_health_file = str(tmp_path / "proxy-health.json")
    r._save_proxy_health_history()
    assert "Failed to save proxy health history" in caplog.text


def test_save_proxy_health_history_success(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """_save_proxy_health_history saves successfully."""
    caplog.set_level(logging.INFO)
    r = _make_runner(tmp_path)
    mock_history = MagicMock()
    mock_history.records = []
    mock_history.save = MagicMock()
    r._proxy_health_history = mock_history
    r._proxy_health_file = str(tmp_path / "proxy-health.json")
    r._save_proxy_health_history()
    assert "Saved proxy health history" in caplog.text


# ===================================================================
# _write_run_summary  (lines 782-784, 791-793)
# ===================================================================


def test_write_run_summary_unsafe_path(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """_write_run_summary returns None when resolve_safe_output_path raises."""
    caplog.set_level(logging.ERROR)
    r = _make_runner(
        tmp_path,
        'publisher:\n  status_output_file: "../escape.txt"\n',
    )
    result = r._write_run_summary("ok")
    assert result is None
    assert "Unsafe run summary path" in caplog.text


def test_write_run_summary_write_error(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """_write_run_summary handles write exceptions."""
    caplog.set_level(logging.WARNING)
    r = _make_runner(
        tmp_path,
        "publisher:\n  status_output_file: summary.json\n",
    )

    def bad_write(_path: object, _content: str) -> None:
        raise OSError("disk full")

    # The summary is written atomically via write_text_atomic; a failing
    # writer must surface as a logged warning, never as a crash.
    monkeypatch.setattr("src.scheduler.runner.write_text_atomic", bad_write)
    result = r._write_run_summary("ok")
    assert result is None
    assert "Could not write run summary" in caplog.text


def test_write_run_summary_success(tmp_path: Path) -> None:
    """_write_run_summary writes and returns path."""
    r = _make_runner(
        tmp_path,
        "publisher:\n  status_output_file: summary.json\n",
    )
    result = r._write_run_summary("ok")
    assert result is not None
    # settings hold a project-relative path, so the file lands under the
    # project root — not the current directory. Asserting on Path(result)
    # directly passed only when a stray summary.json sat in the CWD.
    assert resolve_safe_output_path(result).exists()


def test_degraded_reasons_flags_zero_alive_sweep(tmp_path: Path) -> None:
    """A full Xray sweep with zero survivors is reported as degraded, and so
    is a near-zero rate: 1/1668 alive has the same probe-infrastructure
    signature (the pool died under the sweep)."""
    r = _make_runner(tmp_path)
    r._liveness_stats = {
        "lists": {
            "blacklist": {"xray_checked": 4343, "xray_alive": 0},
            "whitelist": {"xray_checked": 1668, "xray_alive": 1},
        },
    }
    reasons = r._degraded_reasons()
    assert reasons == [
        "blacklist: 0 alive from 4343 Xray-checked configs",
        "whitelist: alive rate 1/1668 (0.1%) below 2% — suspected "
        "probe-infrastructure failure",
    ]


def test_degraded_reasons_ignores_small_checked(tmp_path: Path) -> None:
    """Below 50 checked configs a zero-alive list is not worth alarming."""
    r = _make_runner(tmp_path)
    r._liveness_stats = {
        "lists": {"blacklist": {"xray_checked": 10, "xray_alive": 0}},
    }
    assert r._degraded_reasons() == []


def test_run_summary_includes_generated_at_and_degraded(tmp_path: Path) -> None:
    """The summary carries a timestamp and the degraded block when set."""
    r = _make_runner(
        tmp_path,
        "publisher:\n  status_output_file: summary.json\n",
    )
    r._liveness_stats = {
        "lists": {"whitelist": {"xray_checked": 100, "xray_alive": 0}},
    }
    path = r._write_run_summary("ok")
    assert path is not None
    payload = json.loads(resolve_safe_output_path(path).read_text(encoding="utf-8"))
    assert payload.get("generated_at")
    assert payload["degraded"] is True
    assert payload["degraded_reasons"] == [
        "whitelist: 0 alive from 100 Xray-checked configs",
    ]


def test_run_summary_healthy_run_has_no_degraded_block(tmp_path: Path) -> None:
    """A normal run must not carry degraded fields (readers skip empty)."""
    r = _make_runner(
        tmp_path,
        "publisher:\n  status_output_file: summary.json\n",
    )
    r._liveness_stats = {
        "lists": {"whitelist": {"xray_checked": 100, "xray_alive": 20}},
    }
    path = r._write_run_summary("ok")
    assert path is not None
    payload = json.loads(resolve_safe_output_path(path).read_text(encoding="utf-8"))
    assert "degraded" not in payload
    assert "degraded_reasons" not in payload


# ===================================================================
# _finish_empty_run + publish  (line 690)
# ===================================================================


def test_finish_empty_run_with_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """_finish_empty_run with publish=True calls _publish_files (line 690)."""
    # Configure both status_output_file and health_history_file so
    # _write_run_summary and _write_health_history return paths.
    hh = str(tmp_path / "health-history.json")
    r = _make_runner(
        tmp_path,
        "publisher:\n"
        "  status_output_file: status.json\n"
        "  split_output_files:\n"
        "    blacklist: bl.txt\n"
        f"quality:\n"
        f"  health_history_file: {hh}\n"
        f"  health_history_enabled: true\n",
    )
    # Load health history first so save() has a cache to persist.
    r._quality.health.load()

    calls: list[str] = []

    async def fake_publish(paths: list[str], **kwargs: object) -> None:
        calls.append("publish_called")
        # Check that the publish paths include summary and health
        assert any("status.json" in p for p in paths), f"no status in {paths}"
        # health-history.json stays local-only: at 69k records the single
        # Contents API PUT exceeded the practical body size and failed on
        # every run, taking the whole publish batch (exit 3) with it.
        assert not any("health-history.json" in p for p in paths), (
            f"health must not be published: {paths}"
        )

    monkeypatch.setattr(r, "_publish_files", fake_publish)

    result = asyncio.run(
        r._finish_empty_run(
            str(tmp_path / "combined.txt"),
            status="no_sources",
            publish=True,
        )
    )
    assert result == 0
    assert "publish_called" in calls


# ===================================================================
# _publish_files  (line 827: calls _publish with repo_path)
# ===================================================================


def test_publish_files_calls_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """_publish_files calls _publish for each file."""
    r = _make_runner(tmp_path)
    published: list[tuple[str, str | None]] = []

    async def fake_publish(output_file: str, repo_path: str | None = None) -> None:
        published.append((output_file, repo_path))

    monkeypatch.setattr(r, "_publish", fake_publish)

    asyncio.run(r._publish_files(["a.txt", "b.txt"], combined_output_file="a.txt"))
    assert len(published) == 2
    # First file (combined) gets configured repo_path
    assert published[0][0] == "a.txt"


# ===================================================================
# _publish  (lines 832-891)
# ===================================================================


def test_publish_no_token(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    """_publish skips when github_token is not set (line 832-833)."""
    caplog.set_level(logging.WARNING)
    r = _make_runner(tmp_path)
    r.github_token = None
    asyncio.run(r._publish("dummy.txt"))
    assert "GITHUB_TOKEN is not set" in caplog.text


def test_publish_no_owner_repo(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """_publish skips when owner/repo not configured (lines 843-847)."""
    caplog.set_level(logging.WARNING)
    r = _make_runner(tmp_path, github_token="gh_test")
    asyncio.run(r._publish("dummy.txt"))
    assert "owner/repo not configured" in caplog.text


def test_publish_unsafe_path(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """_publish handles unsafe path ValueError (line 851-853)."""
    caplog.set_level(logging.ERROR)
    r = _make_runner(
        tmp_path,
        github_token="gh_test",
        extra_settings="publisher:\n  owner: test\n  repo: test\n",
    )
    asyncio.run(r._publish("../unsafe.txt"))
    assert "Unsafe output path for publish" in caplog.text


def test_publish_file_not_found(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_publish handles FileNotFoundError (line 857-861)."""
    caplog.set_level(logging.ERROR)
    r = _make_runner(
        tmp_path,
        github_token="gh_test",
        extra_settings="publisher:\n  owner: test\n  repo: test\n",
    )
    missing = tmp_path / "nonexistent.txt"
    monkeypatch.chdir(tmp_path)
    asyncio.run(r._publish("nonexistent.txt"))
    assert "does not exist" in caplog.text


def test_publish_read_error(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """_publish handles generic read error (lines 862-864)."""
    caplog.set_level(logging.ERROR)
    r = _make_runner(
        tmp_path,
        github_token="gh_test",
        extra_settings="publisher:\n  owner: test\n  repo: test\n",
    )
    out_file = resolve_safe_output_path("out.txt")
    out_file.write_text("content", encoding="utf-8")

    # Mock read_text to raise an exception
    def bad_read(*args: object, **kwargs: object) -> str:
        raise PermissionError("access denied")

    monkeypatch.setattr(Path, "read_text", bad_read)
    asyncio.run(r._publish("out.txt"))
    assert "Cannot read output file" in caplog.text


def test_publish_import_error(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_publish handles ImportError for GitHubPublisher (lines 873-875)."""
    caplog.set_level(logging.ERROR)
    r = _make_runner(
        tmp_path,
        github_token="gh_test",
        extra_settings="publisher:\n  owner: test\n  repo: test\n",
    )
    out_file = resolve_safe_output_path("out.txt")
    out_file.write_text("content", encoding="utf-8")

    # Trigger ImportError by removing the module from cache and patching __import__
    import builtins

    original_import = builtins.__import__

    def mock_import(name: str, *args: object, **kwargs: object) -> object:
        if name == "src.publisher.github":
            raise ImportError("Simulated import error")
        return original_import(name, *args, **kwargs)

    try:
        builtins.__import__ = mock_import  # type: ignore[assignment]
        asyncio.run(r._publish("out.txt"))
    finally:
        builtins.__import__ = original_import  # type: ignore[assignment]

    assert "Cannot import GitHubPublisher" in caplog.text


def test_publish_publish_fails(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_publish handles publish_file returning not-ok (lines 886-889)."""
    caplog.set_level(logging.ERROR)
    r = _make_runner(
        tmp_path,
        github_token="gh_test",
        extra_settings="publisher:\n  owner: test\n  repo: test\n",
    )
    out_file = resolve_safe_output_path("out.txt")
    out_file.write_text("content", encoding="utf-8")

    # Mock GitHubPublisher to return failure
    mock_publisher = AsyncMock()
    mock_publisher.publish_file = AsyncMock(return_value=False)
    mock_publisher.__aenter__ = AsyncMock(return_value=mock_publisher)
    mock_publisher.__aexit__ = AsyncMock(return_value=None)

    with patch("src.publisher.github.GitHubPublisher", return_value=mock_publisher):
        asyncio.run(r._publish("out.txt"))

    assert "reported failure" in caplog.text


def test_publish_exception(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_publish handles generic exception during publish (lines 890-891)."""
    caplog.set_level(logging.ERROR)
    r = _make_runner(
        tmp_path,
        github_token="gh_test",
        extra_settings="publisher:\n  owner: test\n  repo: test\n",
    )
    out_file = resolve_safe_output_path("out.txt")
    out_file.write_text("content", encoding="utf-8")

    mock_publisher = AsyncMock()
    mock_publisher.publish_file = AsyncMock(side_effect=RuntimeError("publish crash"))
    mock_publisher.__aenter__ = AsyncMock(return_value=mock_publisher)
    mock_publisher.__aexit__ = AsyncMock(return_value=None)

    with patch("src.publisher.github.GitHubPublisher", return_value=mock_publisher):
        asyncio.run(r._publish("out.txt"))

    assert "Publish failed" in caplog.text


# ===================================================================
# run() — early exit paths
# ===================================================================


@pytest.mark.asyncio
async def test_run_no_sources(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """run() returns 0 when no sources are fetched (lines 148-154)."""

    async def no_sources() -> list[object]:
        return []

    r = _make_runner(tmp_path)
    monkeypatch.setattr(r, "_fetch_sources", no_sources)
    count = await r.run(output_file=str(tmp_path / "out.txt"), publish=False)
    assert count == 0


@pytest.mark.asyncio
async def test_run_no_configs_parsed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """run() returns 0 when no configs parsed (lines 164-172)."""

    async def fake_fetch() -> list[str]:
        return ["data"]

    async def fake_parse(results: object) -> dict[str, list[Config]]:
        return {}

    r = _make_runner(tmp_path)
    monkeypatch.setattr(r, "_fetch_sources", fake_fetch)
    monkeypatch.setattr(r, "_parse_all_by_list", fake_parse)
    count = await r.run(output_file=str(tmp_path / "out.txt"), publish=False)
    assert count == 0


@pytest.mark.asyncio
async def test_run_no_allowed_countries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """run() returns 0 when all configs filtered by country (lines 186-191)."""

    async def fake_fetch() -> list[str]:
        return ["data"]

    async def fake_parse(results: object) -> dict[str, list[Config]]:
        return {"mixed": [_mk("a.de")]}

    r = _make_runner(tmp_path)
    monkeypatch.setattr(r, "_fetch_sources", fake_fetch)
    monkeypatch.setattr(r, "_parse_all_by_list", fake_parse)
    monkeypatch.setattr(r, "_preprocess_configs", lambda configs, **kw: [])
    count = await r.run(output_file=str(tmp_path / "out.txt"), publish=False)
    assert count == 0


@pytest.mark.asyncio
async def test_run_no_live_configs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """run() returns 0 when no configs survive liveness (lines 196-202)."""

    async def fake_fetch() -> list[str]:
        return ["data"]

    async def fake_parse(results: object) -> dict[str, list[Config]]:
        return {"mixed": [_mk("a.de")]}

    async def fake_validate(data: dict[str, list[Config]]) -> dict[str, list[Config]]:
        return {}

    r = _make_runner(tmp_path)
    monkeypatch.setattr(r, "_fetch_sources", fake_fetch)
    monkeypatch.setattr(r, "_parse_all_by_list", fake_parse)
    monkeypatch.setattr(r, "_preprocess_configs", lambda configs, **kw: [_mk("a.de")])
    monkeypatch.setattr(r, "_validate_liveness_by_list", fake_validate)
    count = await r.run(output_file=str(tmp_path / "out.txt"), publish=False)
    assert count == 0


@pytest.mark.asyncio
async def test_run_no_quality_configs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """run() returns 0 when quality filter removes all configs (lines 204-210)."""

    async def fake_fetch() -> list[str]:
        return ["data"]

    async def fake_parse(results: object) -> dict[str, list[Config]]:
        return {"mixed": [_mk("a.de")]}

    r = _make_runner(tmp_path)
    monkeypatch.setattr(r, "_fetch_sources", fake_fetch)
    monkeypatch.setattr(r, "_parse_all_by_list", fake_parse)
    monkeypatch.setattr(r, "_preprocess_configs", lambda configs, **kw: [_mk("a.de")])

    async def fake_validate(data: dict[str, list[Config]]) -> dict[str, list[Config]]:
        return data

    monkeypatch.setattr(r, "_validate_liveness_by_list", fake_validate)
    # Quality returns empty
    monkeypatch.setattr(r, "_apply_quality_filters", lambda data: {})
    count = await r.run(output_file=str(tmp_path / "out.txt"), publish=False)
    assert count == 0


# ===================================================================
# run() — full successful run with mix + split + publish
# ===================================================================


def _make_success_runner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    publish: bool = False,
) -> PipelineRunner:
    """Create a runner pre-configured for a successful pipeline run."""
    bl = str(tmp_path / "bl.txt")
    wl = str(tmp_path / "wl.txt")
    mix = str(tmp_path / "mix.txt")
    combined = str(tmp_path / "combined.txt")
    status = str(tmp_path / "status.json")
    extra = (
        f"aggregator:\n  max_configs_in_output: 100\n"
        f"publisher:\n"
        f"  output_file: {combined}\n"
        f"  mix_output_file: {mix}\n"
        f"  split_output_files:\n"
        f"    blacklist: {bl}\n"
        f"    whitelist: {wl}\n"
        f"  status_output_file: {status}\n"
        f"  owner: test_owner\n"
        f"  repo: test_repo\n"
    )
    r = _make_runner(tmp_path, extra_settings=extra)

    async def fake_fetch() -> list[str]:
        return ["data"]

    async def fake_parse(results: object) -> dict[str, list[Config]]:
        return {
            "blacklist": [_mk("bl1.de", "DE"), _mk("bl2.fr", "FR")],
            "whitelist": [_mk("wl1.ru", "RU"), _mk("wl2.de", "DE")],
        }

    async def fake_publish(output_file: str, repo_path: str | None = None) -> None:
        pass

    async def fake_publish_files(output_files: list[str], **kwargs: object) -> None:
        pass

    async def fake_validate_by_list(
        data: dict[str, list[Config]],
    ) -> dict[str, list[Config]]:
        return data

    monkeypatch.setattr(r, "_fetch_sources", fake_fetch)
    monkeypatch.setattr(r, "_parse_all_by_list", fake_parse)
    monkeypatch.setattr(
        r,
        "_preprocess_configs",
        lambda configs, **kw: list(configs),
    )
    monkeypatch.setattr(r, "_validate_liveness_by_list", fake_validate_by_list)
    monkeypatch.setattr(
        r,
        "_apply_quality_filters",
        lambda data: data,
    )
    if publish:
        monkeypatch.setattr(r, "_publish", fake_publish)
        monkeypatch.setattr(r, "_publish_files", fake_publish_files)

    return r


@pytest.mark.asyncio
async def test_run_full_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """run() completes full pipeline with mix + split outputs (lines 238-278)."""
    r = _make_success_runner(tmp_path, monkeypatch, publish=False)
    combined = str(tmp_path / "combined.txt")
    count = await r.run(output_file=combined, publish=False)
    assert count > 0
    # Combined output was written
    assert Path(combined).exists()
    # Split outputs were written
    assert Path(tmp_path / "bl.txt").exists()
    assert Path(tmp_path / "wl.txt").exists()
    # Mix output was written
    assert Path(tmp_path / "mix.txt").exists()


@pytest.mark.asyncio
async def test_run_full_success_with_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """run() completes full pipeline with publish (line 287)."""
    r = _make_success_runner(tmp_path, monkeypatch, publish=True)
    combined = str(tmp_path / "combined.txt")
    count = await r.run(output_file=combined, publish=True)
    assert count > 0


def _runner_with_min_publish(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    min_publish: int,
    *,
    extra_publisher: str = "",
) -> tuple[PipelineRunner, list[list[str]]]:
    """Runner whose publish step records the files it was asked to publish."""
    bl = str(tmp_path / "bl.txt")
    wl = str(tmp_path / "wl.txt")
    mix = str(tmp_path / "mix.txt")
    combined = str(tmp_path / "combined.txt")
    status = str(tmp_path / "status.json")
    extra = (
        f"aggregator:\n  max_configs_in_output: 100\n"
        f"publisher:\n"
        f"  output_file: {combined}\n"
        f"  mix_output_file: {mix}\n"
        f"  split_output_files:\n"
        f"    blacklist: {bl}\n"
        f"    whitelist: {wl}\n"
        f"  status_output_file: {status}\n"
        f"  owner: test_owner\n"
        f"  repo: test_repo\n"
        f"  min_publish_configs: {min_publish}\n"
        f"{extra_publisher}"
    )
    r = _make_runner(tmp_path, extra_settings=extra)

    async def fake_fetch() -> list[str]:
        return ["data"]

    async def fake_parse(results: object) -> dict[str, list[Config]]:
        return {
            "blacklist": [_mk("bl1.de", "DE"), _mk("bl2.fr", "FR")],
            "whitelist": [_mk("wl1.ru", "RU"), _mk("wl2.de", "DE")],
        }

    async def fake_validate(data: dict[str, list[Config]]) -> dict[str, list[Config]]:
        return data

    monkeypatch.setattr(r, "_fetch_sources", fake_fetch)
    monkeypatch.setattr(r, "_parse_all_by_list", fake_parse)
    monkeypatch.setattr(r, "_preprocess_configs", lambda configs, **kw: list(configs))
    monkeypatch.setattr(r, "_validate_liveness_by_list", fake_validate)
    monkeypatch.setattr(r, "_apply_quality_filters", lambda data: data)

    published: list[list[str]] = []

    async def record_publish_files(output_files: list[str], **kwargs: object) -> bool:
        published.append(list(output_files))
        return True

    monkeypatch.setattr(r, "_publish_files", record_publish_files)
    return r, published


@pytest.mark.asyncio
async def test_run_publish_floor_skips_subscription_below_min(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Below min_publish_configs the subscription is not published (floor)."""
    combined = str(tmp_path / "combined.txt")
    status = str(tmp_path / "status.json")
    r, published = _runner_with_min_publish(tmp_path, monkeypatch, min_publish=100)
    count = await r.run(output_file=combined, publish=True)
    assert count > 0  # 4 configs survive locally
    assert published, "publish was not invoked"
    sent = published[0]
    # The near-empty combined subscription must NOT be published: publishing it
    # would overwrite a working subscription with only 4 configs (< min 100).
    assert combined not in sent
    # Metadata (run summary) is still published so tooling sees the status.
    assert status in sent


@pytest.mark.asyncio
async def test_run_publish_floor_disabled_when_min_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With min_publish_configs=0 the subscription is published normally."""
    combined = str(tmp_path / "combined.txt")
    r, published = _runner_with_min_publish(tmp_path, monkeypatch, min_publish=0)
    count = await r.run(output_file=combined, publish=True)
    assert count > 0
    assert published, "publish was not invoked"
    assert combined in published[0]


def test_filter_empty_subscription_slices_skips_empty(
    tmp_path: Path,
) -> None:
    """An empty split/mix slice is not published over a working file.

    The combined floor already drops every subscription file when the whole
    run is too small; this per-file floor stops a single empty slice (while
    the combined output is fine) from wiping a previously published slice.
    """
    runner = _make_runner(tmp_path)
    combined = tmp_path / "subscription.txt"
    combined.write_text("vless://x@1.2.3.4:443#c\n", encoding="utf-8")
    blacklist = tmp_path / "subscription-blacklist.txt"
    blacklist.write_text("", encoding="utf-8")  # empty slice
    whitelist = tmp_path / "subscription-whitelist.txt"
    whitelist.write_text("vless://y@5.6.7.8:443#w\n", encoding="utf-8")
    # Drive the helper with an explicit set of subscription slices so the test
    # does not depend on the operator's split configuration.
    runner._configured_subscription_output_paths = lambda _: [  # type: ignore[method-assign]
        str(combined),
        str(blacklist),
        str(whitelist),
    ]
    out = runner._filter_empty_subscription_slices(
        [str(combined), str(blacklist), str(whitelist)],
        str(combined),
    )
    assert str(blacklist) not in out
    assert str(combined) in out
    assert str(whitelist) in out


@pytest.mark.asyncio
async def test_run_no_mix_configs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """run() handles empty mix output gracefully (line 244-246)."""
    extra = (
        "aggregator:\n  max_configs_in_output: 100\n"
        "publisher:\n"
        "  output_file: combined.txt\n"
        "  mix_output_file: mix.txt\n"
    )
    r = _make_runner(tmp_path, extra_settings=extra)

    async def fake_fetch() -> list[str]:
        return ["data"]

    async def fake_parse(results: object) -> dict[str, list[Config]]:
        return {"blacklist": [_mk("bl.de", "DE")]}

    monkeypatch.setattr(r, "_fetch_sources", fake_fetch)
    monkeypatch.setattr(r, "_parse_all_by_list", fake_parse)
    monkeypatch.setattr(r, "_preprocess_configs", lambda configs, **kw: list(configs))

    async def fake_validate(data: dict[str, list[Config]]) -> dict[str, list[Config]]:
        return data

    monkeypatch.setattr(r, "_validate_liveness_by_list", fake_validate)
    monkeypatch.setattr(r, "_apply_quality_filters", lambda data: data)
    # No whitelist configs -> mix output is empty
    monkeypatch.setattr(r, "_build_mixed_output", lambda a, b: [])

    combined = str(tmp_path / "combined.txt")
    count = await r.run(output_file=combined, publish=False)
    assert count > 0


@pytest.mark.asyncio
async def test_run_empty_split_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """run() handles empty split output (lines 268-270)."""
    bl = str(tmp_path / "bl.txt")
    wl = str(tmp_path / "wl.txt")
    extra = (
        f"aggregator:\n  max_configs_in_output: 100\n"
        f"publisher:\n"
        f"  output_file: combined.txt\n"
        f"  split_output_files:\n"
        f"    blacklist: {bl}\n"
        f"    whitelist: {wl}\n"
    )
    r = _make_runner(tmp_path, extra_settings=extra)

    async def fake_fetch() -> list[str]:
        return ["data"]

    async def fake_parse(results: object) -> dict[str, list[Config]]:
        # Only blacklist, no whitelist
        return {"blacklist": [_mk("bl.de", "DE")]}

    monkeypatch.setattr(r, "_fetch_sources", fake_fetch)
    monkeypatch.setattr(r, "_parse_all_by_list", fake_parse)
    monkeypatch.setattr(r, "_preprocess_configs", lambda configs, **kw: list(configs))

    async def fake_validate(data: dict[str, list[Config]]) -> dict[str, list[Config]]:
        return data

    monkeypatch.setattr(r, "_validate_liveness_by_list", fake_validate)
    monkeypatch.setattr(r, "_apply_quality_filters", lambda data: data)

    combined = str(tmp_path / "combined.txt")
    count = await r.run(output_file=combined, publish=False)
    assert count > 0
    # Both split files should exist (whitelist written empty)
    assert Path(tmp_path / "bl.txt").exists()
    assert Path(tmp_path / "wl.txt").exists()


@pytest.mark.asyncio
async def test_run_summary_drops_location_stats_of_previous_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A second run() must not report location outputs from the first run."""
    extra = (
        "aggregator:\n  max_configs_in_output: 100\n"
        "publisher:\n"
        "  output_file: output/combined.txt\n"
        "  location_output_dir: output/locations\n"
        "  location_output_limit: 5\n"
        "  location_outputs_enabled: true\n"
        "  status_output_file: output/status.json\n"
    )
    r = _make_runner(tmp_path, extra_settings=extra)
    parsed: dict[str, list[Config]] = {"blacklist": [_mk("de.example", "DE")]}

    async def fake_fetch() -> list[str]:
        return ["data"]

    async def fake_parse(results: object) -> dict[str, list[Config]]:
        return {key: list(value) for key, value in parsed.items()}

    async def fake_validate(data: dict[str, list[Config]]) -> dict[str, list[Config]]:
        return data

    monkeypatch.setattr(r, "_fetch_sources", fake_fetch)
    monkeypatch.setattr(r, "_parse_all_by_list", fake_parse)
    monkeypatch.setattr(r, "_preprocess_configs", lambda configs, **kw: list(configs))
    monkeypatch.setattr(r, "_validate_liveness_by_list", fake_validate)
    monkeypatch.setattr(r, "_apply_quality_filters", lambda data: data)

    summary_path = resolve_safe_output_path("output/status.json")

    await r.run(output_file="output/combined.txt", publish=False)
    first = json.loads(summary_path.read_text(encoding="utf-8"))
    assert "location_de" in first["outputs"]

    parsed["blacklist"] = [_mk("ru.example", "RU")]
    await r.run(output_file="output/combined.txt", publish=False)
    second = json.loads(summary_path.read_text(encoding="utf-8"))

    assert "location_ru" in second["outputs"]
    # The vanished country is reported with the count it now has (0), never
    # with the first run's numbers — the file is rewritten and republished.
    assert second["outputs"]["location_de"]["count"] == 0
    # The vanished country keeps an *empty* file: it is republished so the copy
    # already served from the repo stops handing out the first run's configs.
    stale = resolve_safe_output_path("output/locations/subscription-DE.txt")
    assert stale.exists()
    decoded = base64.b64decode(stale.read_text(encoding="utf-8")).decode("utf-8")
    assert "de.example" not in decoded


# ===================================================================
# _notify_error — related to error notification
# ===================================================================


def test_record_output_stats(tmp_path: Path) -> None:
    """_record_output_stats stores structured output stats."""
    r = _make_runner(tmp_path)
    cfgs = [_mk("a.de", "DE"), _mk("b.fr", "FR")]
    r._record_output_stats("combined", "out.txt", cfgs)
    stats = r._output_stats["combined"]
    assert stats["count"] == 2
    assert "DE" in stats["countries"]


# ===================================================================
# _process_and_write_configs  (lines 533-540)
# ===================================================================


def test_process_and_write_configs_empty(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """_process_and_write_configs returns 0 when no configs survive."""
    caplog.set_level(logging.WARNING)
    r = _make_runner(tmp_path)
    monkeypatch.setattr(r, "_process_configs", lambda configs, **kw: [])
    result = r._process_and_write_configs([], str(tmp_path / "out.txt"), label="test")
    assert result == 0
    assert "No configs for" in caplog.text


def test_process_and_write_configs_success(tmp_path: Path) -> None:
    """_process_and_write_configs writes output and returns count."""
    r = _make_runner(tmp_path)
    cfgs = [_mk("a.de", "DE")]
    result = r._process_and_write_configs(cfgs, str(tmp_path / "out.txt"), label="test")
    assert result > 0


# ===================================================================
# _write_empty_secondary_outputs
# ===================================================================


def test_write_empty_secondary_outputs(tmp_path: Path) -> None:
    """_write_empty_secondary_outputs creates empty split/mix files."""
    mix_file = str(tmp_path / "mix.txt")
    bl_file = str(tmp_path / "bl.txt")
    combined = str(tmp_path / "combined.txt")
    r = _make_runner(
        tmp_path,
        f"publisher:\n"
        f"  output_file: {combined}\n"
        f"  mix_output_file: {mix_file}\n"
        f"  split_output_files:\n"
        f"    blacklist: {bl_file}\n",
    )
    r._write_empty_secondary_outputs(combined)
    assert Path(mix_file).exists()
    assert Path(bl_file).exists()


@pytest.mark.asyncio
async def test_finish_empty_run_publishes_emptied_location_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Opt-out (min_publish_configs: 0) restores full-set placeholder publishing."""
    r = _make_runner(
        tmp_path,
        "publisher:\n"
        "  output_file: output/combined.txt\n"
        "  min_publish_configs: 0\n"
        "  location_output_dir: output/locations\n"
        "  location_output_limit: 5\n"
        "  location_outputs_enabled: true\n",
    )
    loc_dir = resolve_safe_output_path("output/locations")
    loc_dir.mkdir(parents=True)
    stale = loc_dir / "subscription-DE.txt"
    stale.write_text("stale-live-list", encoding="utf-8")

    published: list[str] = []

    async def fake_publish(paths: list[str], **_kwargs: object) -> bool:
        published.extend(paths)
        return True

    monkeypatch.setattr(r, "_publish_files", fake_publish)

    count = await r._finish_empty_run(
        "output/combined.txt",
        status="no_sources",
        publish=True,
    )

    assert count == 0
    assert any("subscription-DE.txt" in path for path in published)
    assert stale.exists()
    assert stale.read_text(encoding="utf-8") != "stale-live-list"


@pytest.mark.asyncio
async def test_finish_empty_run_keeps_remote_subscription_by_default(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Default empty-run floor keeps the previous remote subscription intact.

    The old behavior published watermark-only placeholders for every file,
    wiping the live subscription on what is usually an infrastructure
    failure; the workflow's "<10" check ran only after that publication.
    """
    r = _make_runner(
        tmp_path,
        "publisher:\n"
        "  output_file: output/combined.txt\n"
        "  status_output_file: output/status.json\n"
        "  location_output_dir: output/locations\n"
        "  location_output_limit: 5\n"
        "  location_outputs_enabled: true\n",
    )
    loc_dir = resolve_safe_output_path("output/locations")
    loc_dir.mkdir(parents=True)
    stale = loc_dir / "subscription-DE.txt"
    stale.write_text("stale-live-list", encoding="utf-8")

    published: list[str] = []

    async def fake_publish(paths: list[str], **_kwargs: object) -> bool:
        published.extend(paths)
        return True

    monkeypatch.setattr(r, "_publish_files", fake_publish)

    count = await r._finish_empty_run(
        "output/combined.txt",
        status="no_sources",
        publish=True,
    )

    assert count == 0
    # Subscription artifacts stay unpublished...
    assert not any("combined.txt" in path for path in published)
    assert not any("subscription-DE.txt" in path for path in published)
    # ...but metadata still goes out so tooling sees the empty status.
    assert any(path.endswith("status.json") for path in published)
    # The local placeholders were still written (workflow verify step reads them).
    assert stale.exists()
    assert stale.read_text(encoding="utf-8") != "stale-live-list"


@pytest.mark.asyncio
async def test_finish_empty_run_keeps_location_stats_in_summary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An empty run still reports every emptied location file in run-summary.

    The stats reset used to happen AFTER ``_write_empty_secondary_outputs``
    recorded the location_* entries, so they vanished from the summary of
    every empty run while the emptied files were still written and published.
    """
    r = _make_runner(
        tmp_path,
        "publisher:\n"
        "  status_output_file: output/status.json\n"
        "  location_output_dir: output/locations\n"
        "  location_output_limit: 5\n"
        "  location_outputs_enabled: true\n",
    )
    loc_dir = resolve_safe_output_path("output/locations")
    loc_dir.mkdir(parents=True)
    (loc_dir / "subscription-DE.txt").write_text("stale", encoding="utf-8")

    await r._finish_empty_run(
        "output/combined.txt",
        status="no_sources",
        publish=False,
    )
    summary = json.loads(
        resolve_safe_output_path("output/status.json").read_text(encoding="utf-8"),
    )
    assert "location_de" in summary["outputs"]
    assert summary["outputs"]["location_de"]["count"] == 0


# ===================================================================
# _configured_subscription_output_paths
# ===================================================================


def test_configured_subscription_output_paths(tmp_path: Path) -> None:
    """Returns all subscription paths including mix and splits."""
    r = _make_runner(
        tmp_path,
        "publisher:\n"
        "  output_file: combined.txt\n"
        "  mix_output_file: mix.txt\n"
        "  split_output_files:\n"
        "    blacklist: bl.txt\n",
    )
    paths = r._configured_subscription_output_paths("combined.txt")
    assert "combined.txt" in paths
    assert "mix.txt" in paths
    assert "bl.txt" in paths


# ===================================================================
# regressions: publish bookkeeping, settings guard, fetch reporting
# ===================================================================


@pytest.mark.asyncio
async def test_finish_empty_run_records_publish_outcome(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An empty run must report whether its artifacts really were published.

    ``_finish_empty_run`` threw the ``_publish_files`` result away, so an empty
    run always looked like a failed publish and the CLI had to treat every
    ``count == 0`` run as successful — hiding the one case that matters: empty
    local files that never reached the repository, leaving the previous, dead
    subscription live.
    """
    r = _make_runner(
        tmp_path,
        "publisher:\n  status_output_file: output/status.json\n",
        github_token="t",
    )
    outcome = True

    async def fake_publish(output_file: str, repo_path: str | None = None) -> bool:
        return outcome

    monkeypatch.setattr(r, "_publish", fake_publish)
    r._publish_ok = False

    await r._finish_empty_run("output/combined.txt", status="no_sources", publish=True)
    assert r._publish_ok is True

    outcome = False
    await r._finish_empty_run("output/combined.txt", status="no_sources", publish=True)
    assert r._publish_ok is False


@pytest.mark.asyncio
async def test_publish_files_dedups_separator_variants(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The same file spelled with both separators is published once.

    Location files are built with ``pathlib`` (``output\\x.txt`` on Windows)
    while configured outputs keep the ``output/x.txt`` spelling, so a plain
    string dedup let one repo path be committed twice per run.
    """
    r = _make_runner(tmp_path, github_token="t")
    published: list[str] = []

    async def fake_publish(output_file: str, repo_path: str | None = None) -> bool:
        published.append(output_file)
        return True

    monkeypatch.setattr(r, "_publish", fake_publish)
    ok = await r._publish_files(
        ["output/subscription-mix.txt", "output\\subscription-mix.txt"],
    )
    assert ok is True
    assert published == ["output/subscription-mix.txt"]


@pytest.mark.asyncio
async def test_publish_files_reuses_one_publisher(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """All files of one batch go through a single GitHubPublisher.

    A publisher per file meant a fresh ``httpx.AsyncClient`` (CA bundle parse
    plus TLS handshake) for every output — tens of seconds of blocked event
    loop on a run with per-country files.
    """
    r = _make_runner(
        tmp_path,
        "publisher:\n  owner: o\n  repo: rp\n",
        github_token="t",
    )
    created: list[MagicMock] = []
    # Repo paths must be project-relative: an absolute path outside the
    # project root is refused (_repo_path_for) rather than committed as a
    # garbage path like C:/Users/... The isolated project root (conftest)
    # is where relative outputs resolve.
    root = Path(resolve_safe_output_path("."))
    (root / "out").mkdir()
    first = root / "out" / "first.txt"
    first.write_text("data", encoding="utf-8")
    second = root / "out" / "second.txt"
    second.write_text("data", encoding="utf-8")

    def _factory(**_kwargs: object) -> MagicMock:
        publisher = MagicMock()
        publisher.publish_file = AsyncMock(return_value=True)
        publisher.__aenter__ = AsyncMock(return_value=publisher)
        publisher.__aexit__ = AsyncMock(return_value=False)
        created.append(publisher)
        return publisher

    module = MagicMock()
    module.GitHubPublisher = _factory
    monkeypatch.setitem(sys.modules, "src.publisher.github", module)

    ok = await r._publish_files([str(first), str(second)])
    assert ok is True
    assert len(created) == 1
    assert created[0].publish_file.await_count == 2


@pytest.mark.asyncio
async def test_publish_files_warns_when_repo_path_differs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """publisher.output_file only renames the repo copy — say so.

    The key is documented as "combined output path", but the local file always
    follows ``--output``; without the warning the repo keeps two combined
    files, one of which is never refreshed again.
    """
    r = _make_runner(
        tmp_path,
        "publisher:\n  output_file: output/all-configs.txt\n",
        github_token="t",
    )

    async def fake_publish(output_file: str, repo_path: str | None = None) -> bool:
        return True

    monkeypatch.setattr(r, "_publish", fake_publish)
    caplog.set_level(logging.WARNING)
    await r._publish_files(
        ["output/subscription.txt"],
        combined_output_file="output/subscription.txt",
    )
    assert "only renames the combined subscription" in caplog.text


@pytest.mark.asyncio
async def test_run_refuses_missing_settings_file(tmp_path: Path) -> None:
    """A mistyped --settings path must stop the run, not silently use defaults.

    On defaults ``tcp/tls/xray_enabled`` are false and ``allowed_countries`` is
    empty, so the run published unvalidated configs and still exited 0.
    """
    r = PipelineRunner(
        settings_path=str(tmp_path / "typo.yaml"),
        sources_path=str(tmp_path / "sources.json"),
    )
    with pytest.raises(FileNotFoundError, match="Settings file not found"):
        await r.run(output_file=str(tmp_path / "out.txt"))


def test_write_run_summary_warns_without_status_file(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """No status_output_file means no run summary at all — warn about it."""
    r = _make_runner(tmp_path)
    caplog.set_level(logging.WARNING)
    assert r._write_run_summary("ok") is None
    assert "status_output_file is not configured" in caplog.text


def test_source_fetcher_reports_failed_sources(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A source that returned an error is logged and counted.

    ``SourceResult.error`` was read nowhere: a 404 counted as a fetched result,
    its subscription silently became empty and the run still reported "ok".
    """
    from src.scheduler.stages.fetch import SourceFetcher
    from src.sources.manager import SourceResult

    caplog.set_level(logging.WARNING)
    stats = SourceFetcher._report_failures(
        [
            SourceResult(source_name="good", files=[("a.txt", "x")]),
            SourceResult(source_name="dead", error="url source is empty or not found"),
        ],
    )
    assert stats == {
        "total": 2,
        "ok": 1,
        "failed": 1,
        "errors": [
            {"source": "dead", "error": "url source is empty or not found"},
        ],
    }
    assert "dead" in caplog.text


@pytest.mark.asyncio
async def test_run_summary_reports_source_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """run-summary.json carries the fetch outcome, not only the outputs."""
    r = _make_runner(
        tmp_path,
        "publisher:\n  status_output_file: output/status.json\n",
    )
    # The summary reads the per-run snapshot captured by _fetch_sources (the
    # context attribute is cleared mid-run); set the snapshot directly here.
    r._run_source_stats = {
        "total": 2,
        "ok": 1,
        "failed": 1,
        "errors": [{"source": "dead", "error": "404"}],
    }
    monkeypatch.setattr(r._writer, "_write_location_outputs", lambda *a, **k: [])
    summary_file = r._write_run_summary("ok")
    assert summary_file is not None
    payload = json.loads(
        resolve_safe_output_path(summary_file).read_text(encoding="utf-8"),
    )
    assert payload["sources"]["failed"] == 1
    assert payload["sources"]["errors"][0]["source"] == "dead"


@pytest.mark.asyncio
async def test_publish_files_without_paths_opens_nothing(tmp_path: Path) -> None:
    """An empty batch must not open a GitHub client just to close it."""
    r = _make_runner(tmp_path, "publisher:\n  owner: o\n  repo: rp\n", github_token="t")
    assert await r._publish_files([]) is True


@pytest.mark.asyncio
async def test_publish_files_falls_back_when_publisher_cannot_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A publisher that cannot be built must not stop the per-file path."""
    r = _make_runner(tmp_path, "publisher:\n  owner: o\n  repo: rp\n", github_token="t")
    published: list[str] = []

    async def fake_publish(output_file: str, repo_path: str | None = None) -> bool:
        published.append(output_file)
        return True

    def _boom(**_kwargs: object) -> object:
        msg = "no client"
        raise RuntimeError(msg)

    module = MagicMock()
    module.GitHubPublisher = _boom
    monkeypatch.setitem(sys.modules, "src.publisher.github", module)
    monkeypatch.setattr(r, "_publish", fake_publish)
    caplog.set_level(logging.ERROR)

    assert await r._publish_files(["output/x.txt"]) is True
    assert published == ["output/x.txt"]
    assert "shared GitHub publisher" in caplog.text


# ===================================================================
# benchmark: run all existing + new tests
# ===================================================================


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s", "--tb=short"])


# ===================================================================
# rerun_published() — fast-track revalidation mode
# ===================================================================


def _ss_link(host: str, remark: str) -> str:
    import base64

    # A literal "password" credential is filtered as a placeholder by
    # is_garbage_config, so the fixture uses a realistic one.
    userinfo = base64.b64encode(b"aes-256-gcm:S3cure-Credential-9x7").decode("ascii")
    return f"ss://{userinfo}@{host}:443#{remark}"


def _write_b64_subscription(path: Path, links: list[str]) -> None:
    path.write_text(
        base64.b64encode("\n".join(links).encode("utf-8")).decode("ascii"),
        encoding="utf-8",
    )


@pytest.mark.asyncio
async def test_rerun_published_raises_without_split_files(tmp_path: Path) -> None:
    """Nothing published yet -> refuse instead of wiping the subscription."""
    r = _make_runner(tmp_path)
    with pytest.raises(FileNotFoundError):
        await r.rerun_published(output_file=str(tmp_path / "out.txt"))


@pytest.mark.asyncio
async def test_rerun_published_revalidates_and_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Published split files are re-parsed, re-validated and rewritten."""
    bl = tmp_path / "bl-published.txt"
    wl = tmp_path / "wl-published.txt"
    _write_b64_subscription(
        bl,
        [
            _watermark_link(),  # display-only marker must be dropped
            _ss_link("1.2.3.4", "DE-01"),
            _ss_link("5.6.7.8", "NL-02"),
        ],
    )
    _write_b64_subscription(wl, [_ss_link("9.9.9.9", "RU-03")])

    settings = tmp_path / "settings.yaml"
    settings.write_text(
        "validator:\n"
        "  allowed_countries: []\n"
        "aggregator:\n"
        "  max_configs_in_output: 100\n"
        "publisher:\n"
        f"  split_output_files:\n    blacklist: {bl}\n    whitelist: {wl}\n",
        encoding="utf-8",
    )
    src = tmp_path / "sources.json"
    src.write_text('{"sources": []}', encoding="utf-8")
    r = PipelineRunner(settings_path=str(settings), sources_path=str(src))

    seen_lists: dict[str, list[Config]] = {}

    async def fake_validate(
        data: dict[str, list[Config]],
    ) -> dict[str, list[Config]]:
        seen_lists.update(data)
        return data

    monkeypatch.setattr(r, "_validate_liveness_by_list", fake_validate)
    monkeypatch.setattr(r, "_apply_quality_filters", lambda data: data)

    out = tmp_path / "out.txt"
    count = await r.rerun_published(output_file=str(out), publish=False)

    assert count == 3
    assert set(seen_lists) == {"blacklist", "whitelist"}
    # The synthetic sources carry the published list types, so per-list
    # country rules and stats stay intact.
    assert all(c.source_name == "published-blacklist" for c in seen_lists["blacklist"])
    assert all(c.source_name == "published-whitelist" for c in seen_lists["whitelist"])
    # count == 3 already proves the input watermark was dropped as a config;
    # the writer legitimately prepends its own fresh watermark to the output.


@pytest.mark.asyncio
async def test_published_source_results_skips_unusable_splits(tmp_path: Path) -> None:
    """Unreadable / linkless splits are FATAL: partial republish wipes half the subscription.

    The old behavior skipped unusable splits with a warning, so one dead file
    let rerun_published revalidate just the other list and overwrite the
    healthy subscription with half of it. Non-list entries (mix) are still
    skipped — only blacklist+whitelist participate in fast-track.
    """
    import base64 as _b64

    linkless = tmp_path / "bl.txt"
    linkless.write_text(
        _b64.b64encode(b"no proxy links in this blob").decode("ascii"),
        encoding="utf-8",
    )
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        "validator:\n"
        "  allowed_countries: []\n"
        "publisher:\n"
        f"  split_output_files:\n    blacklist: {linkless}\n"
        f"    whitelist: {tmp_path / 'missing.txt'}\n"
        f"    mix: {tmp_path / 'mix.txt'}\n",
        encoding="utf-8",
    )
    src = tmp_path / "sources.json"
    src.write_text('{"sources": []}', encoding="utf-8")
    r = PipelineRunner(settings_path=str(settings), sources_path=str(src))

    with pytest.raises(FileNotFoundError, match="unreadable or link-less"):
        r._published_source_results(str(tmp_path / "out.txt"))


# ===================================================================
# recent src/ changes: run-summary predicate, clash stats, publish floor
# ===================================================================


def test_record_output_stats_matches_writer_predicate(tmp_path: Path) -> None:
    """The run summary counts exactly what the writer would write.

    The writer skips dead configs (``is_alive is False``) and raw links
    carrying control characters; counting them made a fail-open run report
    more configs than the published file holds.
    """
    r = _make_runner(tmp_path)
    alive = _mk("a.de", "DE")
    dead = _mk("b.de", "DE")
    dead.is_alive = False
    injected = _mk("c.de", "DE")
    injected.raw_link = "vless://x@5.6.7.8:443#bad\nvless://y@6.6.6.6:443#injected"
    r._record_output_stats("combined", "out.txt", [alive, dead, injected])
    assert r._output_stats["combined"]["count"] == 1


def test_rerun_published_raises_when_nothing_to_revalidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revalidating "nothing" must refuse, not publish an empty run."""
    r = _make_runner(tmp_path)
    monkeypatch.setattr(r, "_published_source_results", lambda _out: [])
    with pytest.raises(FileNotFoundError, match="nothing to revalidate"):
        asyncio.run(r.rerun_published(output_file=str(tmp_path / "out.txt")))


@pytest.mark.asyncio
async def test_run_records_clash_output_stats_on_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A successful run records the clash output like every other output.

    Only _finish_empty_run used to record a clash entry, so the two summary
    shapes were not comparable.
    """
    clash = str(tmp_path / "clash.yaml")
    r, published = _runner_with_min_publish(
        tmp_path,
        monkeypatch,
        min_publish=0,
        extra_publisher=f"  clash_output_file: {clash}\n",
    )
    combined = str(tmp_path / "combined.txt")
    count = await r.run(output_file=combined, publish=True)
    assert count > 0
    assert Path(clash).exists()
    assert r._output_stats["clash"]["count"] == r._output_stats["combined"]["count"]
    assert clash in published[0]


@pytest.mark.asyncio
async def test_run_publish_floor_drops_clash_below_min(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Below the publish floor the clash twin is not published either."""
    clash = str(tmp_path / "clash.yaml")
    status = str(tmp_path / "status.json")
    r, published = _runner_with_min_publish(
        tmp_path,
        monkeypatch,
        min_publish=100,
        extra_publisher=f"  clash_output_file: {clash}\n",
    )
    combined = str(tmp_path / "combined.txt")
    count = await r.run(output_file=combined, publish=True)
    assert count > 0
    assert published, "publish was not invoked"
    sent = published[0]
    assert clash not in sent
    assert combined not in sent
    assert status in sent


def test_published_source_results_skips_non_split_lists(tmp_path: Path) -> None:
    """Only blacklist/whitelist feed the fast-track revalidation."""
    bl = tmp_path / "bl.txt"
    wl = tmp_path / "wl.txt"
    _write_b64_subscription(bl, [_ss_link("1.2.3.4", "DE-01")])
    _write_b64_subscription(wl, [_ss_link("9.9.9.9", "RU-03")])
    mix = tmp_path / "mix.txt"
    mix.write_text("https://not-a-proxy.example/sub", encoding="utf-8")
    r = _make_runner(tmp_path)
    r._split_output_files = lambda _out: {  # type: ignore[method-assign]
        "blacklist": str(bl),
        "whitelist": str(wl),
        "mix": str(mix),
    }
    results = r._published_source_results(str(tmp_path / "out.txt"))
    assert {str(res.list_type) for res in results} == {"blacklist", "whitelist"}


@pytest.mark.asyncio
async def test_validate_liveness_by_list_binds_context_stats(tmp_path: Path) -> None:
    """The runner's stats snapshot aliases the shared context dict."""
    r = _make_runner(tmp_path)
    configs = [_mk("a.de", "DE")]
    result = await r._validate_liveness_by_list({"blacklist": configs})
    # tcp/tls/xray are all off: fail-closed, nothing marked alive.
    assert result["blacklist"] is configs
    assert all(cfg.is_alive is False for cfg in configs)
    assert r._liveness_stats is r._context.liveness_stats
    assert r._liveness_stats["status"] == "disabled"


def test_min_publish_configs_invalid_value(tmp_path: Path) -> None:
    """_min_publish_configs falls back to the default 10 on a bad value."""
    r = _make_runner(tmp_path, "publisher:\n  min_publish_configs: invalid\n")
    assert r._min_publish_configs() == 10


@pytest.mark.asyncio
async def test_finish_empty_run_records_empty_clash_and_mix_stats(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Empty runs mirror the successful run's summary shape (clash + mix).

    The clash twin is emptied locally, recorded in the summary, and — like
    every subscription artifact — kept off the remote by the publish floor.
    """
    clash = str(tmp_path / "clash.yaml")
    mix = str(tmp_path / "mix.txt")
    status = str(tmp_path / "status.json")
    r = _make_runner(
        tmp_path,
        "publisher:\n"
        f"  status_output_file: {status}\n"
        f"  clash_output_file: {clash}\n"
        f"  mix_output_file: {mix}\n"
        # Invalid value exercises the fallback to the default floor (10).
        "  min_publish_configs: invalid\n",
    )
    published: list[str] = []

    async def fake_publish(paths: list[str], **_kwargs: object) -> bool:
        published.extend(paths)
        return True

    monkeypatch.setattr(r, "_publish_files", fake_publish)
    count = await r._finish_empty_run(
        str(tmp_path / "combined.txt"),
        status="no_sources",
        publish=True,
    )
    assert count == 0
    assert Path(clash).read_text(encoding="utf-8") == "proxies: []\n"
    summary = json.loads(Path(status).read_text(encoding="utf-8"))
    assert summary["outputs"]["clash"]["count"] == 0
    assert summary["outputs"]["mix"]["count"] == 0
    assert clash not in published
    assert mix not in published
    assert status in published


def test_degraded_reasons_skips_non_dict_list_stats(tmp_path: Path) -> None:
    """A malformed list entry is skipped instead of crashing the summary."""
    r = _make_runner(tmp_path)
    r._liveness_stats = {
        "lists": {
            "garbage": "not-a-dict",
            "blacklist": {"xray_checked": 100, "xray_alive": 0},
        },
    }
    assert r._degraded_reasons() == [
        "blacklist: 0 alive from 100 Xray-checked configs",
    ]


def test_write_stats_history_writes_next_to_status_file(tmp_path: Path) -> None:
    """Trend files live next to the run summary, not in default output/."""
    r = _make_runner(
        tmp_path,
        "publisher:\n  status_output_file: output/status.json\n",
    )
    r._liveness_stats = {
        "lists": {"blacklist": {"xray_alive": 3, "xray_checked": 5}},
    }
    files = r._write_stats_history("ok")
    # str(Path("output") / name) uses the platform separator on Windows.
    assert [f.replace("\\", "/") for f in files] == [
        "output/stats-history.json",
        "output/alive-trend.svg",
    ]
    assert resolve_safe_output_path("output/stats-history.json").exists()
    assert resolve_safe_output_path("output/alive-trend.svg").exists()


def test_write_stats_history_survives_write_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A failing trend write is a warning, never a crash."""
    caplog.set_level(logging.WARNING)
    r = _make_runner(tmp_path)
    r._liveness_stats = {
        "lists": {"blacklist": {"xray_alive": 1, "xray_checked": 2}},
    }

    def boom(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("disk gone")

    monkeypatch.setattr("src.scheduler.stats_history.append_run_stats", boom)
    assert r._write_stats_history("ok") == []
    assert "Stats history write failed" in caplog.text


def test_rewrite_summary_status_unsafe_path(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """An unsafe summary path is rejected with an error log, no crash."""
    caplog.set_level(logging.ERROR)
    r = _make_runner(tmp_path)
    r._rewrite_summary_status("../escape.json", "publish_failed")
    assert "Unsafe run summary path" in caplog.text


def test_rewrite_summary_status_survives_read_error(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A corrupt summary file is left alone with a warning, no crash."""
    caplog.set_level(logging.WARNING)
    summary = resolve_safe_output_path("summary.json")
    summary.write_text("{not json", encoding="utf-8")
    r = _make_runner(tmp_path)
    r._rewrite_summary_status("summary.json", "publish_failed")
    assert "Could not rewrite run summary" in caplog.text


def test_is_empty_output_file_handles_stat_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stat failure reads as "not empty" instead of crashing the filter."""
    r = _make_runner(tmp_path)
    monkeypatch.setattr(Path, "exists", lambda self: True)

    def boom(self: Path) -> object:
        raise OSError("stat failed")

    monkeypatch.setattr(Path, "stat", boom)
    assert r._is_empty_output_file("whatever.txt") is False


@pytest.mark.asyncio
async def test_publish_propagates_githubpublisherror(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A deliberate publisher abort must not be swallowed per file.

    Swallowing the exception made every remaining file of the batch issue
    GET+PUT pairs against an already exhausted rate limit; the exception IS
    the batch abort.
    """
    r = _make_runner(tmp_path, "publisher:\n  owner: o\n  repo: r\n", github_token="t")
    out_file = resolve_safe_output_path("out.txt")
    out_file.write_text("content", encoding="utf-8")

    mock_publisher = MagicMock()
    mock_publisher.publish_file = AsyncMock(
        side_effect=GitHubPublishError("rate limit exhausted; aborting publish"),
    )
    mock_publisher.__aenter__ = AsyncMock(return_value=mock_publisher)
    mock_publisher.__aexit__ = AsyncMock(return_value=None)

    with patch("src.publisher.github.GitHubPublisher", return_value=mock_publisher):
        with pytest.raises(GitHubPublishError):
            await r._publish(str(out_file))


class TestRepoPathFor:
    """Publish paths must be repo-relative; absolute local paths are mapped
    or refused — committing C:/Users/... garbage used to replace the real
    subscription."""

    def _make(self, tmp_path: Path) -> PipelineRunner:
        return _make_runner(tmp_path, "publisher:\n  owner: o\n  repo: r\n")

    def test_relative_passthrough(self, tmp_path: Path) -> None:
        r = self._make(tmp_path)
        assert r._repo_path_for("output/subscription.txt") == "output/subscription.txt"

    def test_absolute_inside_root_is_mapped(self, tmp_path: Path) -> None:
        r = self._make(tmp_path)
        root = Path(resolve_safe_output_path("."))
        target = root / "output" / "subscription-DE.txt"
        result = r._repo_path_for(str(target))
        assert result is not None
        assert result.replace("\\", "/") == "output/subscription-DE.txt"

    def test_absolute_outside_root_is_refused(self, tmp_path: Path) -> None:
        r = self._make(tmp_path)
        assert r._repo_path_for("C:/Windows/system32/evil.txt") is None

    def test_traversal_is_refused(self, tmp_path: Path) -> None:
        r = self._make(tmp_path)
        assert r._repo_path_for("../evil.txt") is None

    def test_backslashes_normalised(self, tmp_path: Path) -> None:
        r = self._make(tmp_path)
        assert r._repo_path_for("output\\subscription.txt") == (
            "output/subscription.txt"
        )
