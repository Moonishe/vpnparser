"""Coverage-completion tests for PipelineRunner — every uncovered line."""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.parsers.base import Config
from src.scheduler.runner import PipelineRunner

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
# _load_settings  (line 105)
# ===================================================================


def test_load_settings_static(tmp_path: Path) -> None:
    """_load_settings static method delegates to load_settings."""
    f = tmp_path / "s.yaml"
    f.write_text("key: value\n", encoding="utf-8")
    result = PipelineRunner._load_settings(str(f))
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
# _filter_garbage  (line 314)
# ===================================================================


def test_filter_garbage_static() -> None:
    """_filter_garbage delegates to GarbageFilter."""
    c = _mk("1.2.3.4")
    clean, removed = PipelineRunner._filter_garbage([c])
    assert len(clean) == 1
    assert removed == 0


# ===================================================================
# _xray_candidate_preselect  (lines 394-396)
# ===================================================================


def test_xray_candidate_preselect_whitelist(tmp_path: Path) -> None:
    """Whitelist list_type uses _whitelist_balance."""
    r = _make_runner(tmp_path)
    cfgs = [_mk("a.ru", "RU"), _mk("b.de", "DE")]
    result = r._xray_candidate_preselect(cfgs, 10, "whitelist")
    assert len(result) <= 10


def test_xray_candidate_preselect_blacklist(tmp_path: Path) -> None:
    """Non-whitelist list_type uses _country_balanced_limit."""
    r = _make_runner(tmp_path)
    cfgs = [_mk("a.ru", "RU"), _mk("b.de", "DE")]
    result = r._xray_candidate_preselect(cfgs, 10, "blacklist")
    assert len(result) <= 10


# ===================================================================
# _quality_cfg  (line 416)
# ===================================================================


def test_quality_cfg(tmp_path: Path) -> None:
    """_quality_cfg returns quality section."""
    r = _make_runner(tmp_path)
    result = r._quality_cfg()
    assert isinstance(result, dict)


# ===================================================================
# _health_history_file  (line 419)
# ===================================================================


def test_health_history_file(tmp_path: Path) -> None:
    """_health_history_file returns health file path."""
    r = _make_runner(tmp_path)
    result = r._health_history_file()
    assert result is None or isinstance(result, str)


# ===================================================================
# _load_health_history  (line 423)
# ===================================================================


def test_load_health_history(tmp_path: Path) -> None:
    """_load_health_history loads health data."""
    r = _make_runner(tmp_path)
    result = r._load_health_history()
    assert isinstance(result, dict)


# ===================================================================
# _source_run_stats  (line 443)
# ===================================================================


def test_source_run_stats(tmp_path: Path) -> None:
    """_source_run_stats returns source stats."""
    r = _make_runner(tmp_path)
    c = _mk("1.2.3.4")
    c.is_alive = True
    result = r._source_run_stats([c])
    assert isinstance(result, dict)


# ===================================================================
# _quality_score  (line 459)
# ===================================================================


def test_quality_score(tmp_path: Path) -> None:
    """_quality_score returns a float score."""
    r = _make_runner(tmp_path)
    c = _mk("1.2.3.4")
    score = r._quality_score(c)
    assert isinstance(score, float)


# ===================================================================
# _take_unique_configs  (line 498)
# ===================================================================


def test_take_unique_configs_static(tmp_path: Path) -> None:
    """_take_unique_configs delegates to Aggregator."""
    cfgs = [_mk("a.de", "DE"), _mk("b.de", "DE")]
    result = PipelineRunner._take_unique_configs(cfgs, 1, set())
    assert len(result) == 1


# ===================================================================
# _write_plain_fallback  (line 809)
# ===================================================================


def test_write_plain_fallback_static(tmp_path: Path) -> None:
    """_write_plain_fallback writes raw links."""
    out = tmp_path / "out.txt"
    c = _mk("1.2.3.4", "DE")
    count = PipelineRunner._write_plain_fallback([c], str(out))
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
# _location_output_config  (line 703)
# ===================================================================


def test_location_output_config(tmp_path: Path) -> None:
    """_location_output_config delegates to writer."""
    r = _make_runner(tmp_path)
    enabled, out_dir, limit = r._location_output_config()
    assert isinstance(enabled, bool)
    assert isinstance(out_dir, str)
    assert isinstance(limit, int)


# ===================================================================
# _build_location_outputs  (line 717)
# ===================================================================


def test_build_location_outputs(tmp_path: Path) -> None:
    """_build_location_outputs delegates to writer."""
    r = _make_runner(tmp_path)
    cfgs = [_mk("a.de", "DE"), _mk("b.fr", "FR")]
    result = r._build_location_outputs(cfgs, 50)
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
    # Monkeypatch path.write_text to raise
    original_write_text = Path.write_text

    def bad_write(self, *args: object, **kwargs: object) -> None:
        if "summary" in str(self):
            raise OSError("disk full")
        return original_write_text(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "write_text", bad_write)
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
    assert Path(result).exists()


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
    r._load_health_history()

    calls: list[str] = []

    async def fake_publish(paths: list[str], **kwargs: object) -> None:
        calls.append("publish_called")
        # Check that the publish paths include summary and health
        assert any("status.json" in p for p in paths), f"no status in {paths}"
        # Check that health file path is included (line 690)
        assert any("health-history.json" in p for p in paths), f"no health in {paths}"

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
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """_publish handles FileNotFoundError (line 857-861)."""
    caplog.set_level(logging.ERROR)
    r = _make_runner(
        tmp_path,
        github_token="gh_test",
        extra_settings="publisher:\n  owner: test\n  repo: test\n",
    )
    missing = tmp_path / "nonexistent.txt"
    asyncio.run(r._publish(str(missing)))
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
    out_file = tmp_path / "out.txt"
    out_file.write_text("content", encoding="utf-8")

    # Mock read_text to raise an exception
    def bad_read(*args: object, **kwargs: object) -> str:
        raise PermissionError("access denied")

    monkeypatch.setattr(Path, "read_text", bad_read)
    asyncio.run(r._publish(str(out_file)))
    assert "Cannot read output file" in caplog.text


def test_publish_import_error(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    """_publish handles ImportError for GitHubPublisher (lines 873-875)."""
    caplog.set_level(logging.ERROR)
    r = _make_runner(
        tmp_path,
        github_token="gh_test",
        extra_settings="publisher:\n  owner: test\n  repo: test\n",
    )
    out_file = tmp_path / "out.txt"
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
        asyncio.run(r._publish(str(out_file)))
    finally:
        builtins.__import__ = original_import  # type: ignore[assignment]

    assert "Cannot import GitHubPublisher" in caplog.text


def test_publish_publish_fails(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """_publish handles publish_file returning not-ok (lines 886-889)."""
    caplog.set_level(logging.ERROR)
    r = _make_runner(
        tmp_path,
        github_token="gh_test",
        extra_settings="publisher:\n  owner: test\n  repo: test\n",
    )
    out_file = tmp_path / "out.txt"
    out_file.write_text("content", encoding="utf-8")

    # Mock GitHubPublisher to return failure
    mock_publisher = AsyncMock()
    mock_publisher.publish_file = AsyncMock(return_value=False)
    mock_publisher.__aenter__ = AsyncMock(return_value=mock_publisher)
    mock_publisher.__aexit__ = AsyncMock(return_value=None)

    with patch("src.publisher.github.GitHubPublisher", return_value=mock_publisher):
        asyncio.run(r._publish(str(out_file)))

    assert "reported failure" in caplog.text


def test_publish_exception(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    """_publish handles generic exception during publish (lines 890-891)."""
    caplog.set_level(logging.ERROR)
    r = _make_runner(
        tmp_path,
        github_token="gh_test",
        extra_settings="publisher:\n  owner: test\n  repo: test\n",
    )
    out_file = tmp_path / "out.txt"
    out_file.write_text("content", encoding="utf-8")

    mock_publisher = AsyncMock()
    mock_publisher.publish_file = AsyncMock(side_effect=RuntimeError("publish crash"))
    mock_publisher.__aenter__ = AsyncMock(return_value=mock_publisher)
    mock_publisher.__aexit__ = AsyncMock(return_value=None)

    with patch("src.publisher.github.GitHubPublisher", return_value=mock_publisher):
        asyncio.run(r._publish(str(out_file)))

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
# benchmark: run all existing + new tests
# ===================================================================


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s", "--tb=short"])
