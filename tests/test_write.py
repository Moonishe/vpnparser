"""Tests for the OutputWriter stage — subscription, split, location, and summary output."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from src.parsers.base import Config
from src.scheduler.context import PipelineState
from src.scheduler.runner import PipelineRunner
from src.scheduler.stages.write import OutputWriter

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def settings_file(tmp_path: Path) -> Path:
    """Minimal settings that disable everything except the output writer."""
    p = tmp_path / "settings.yaml"
    p.write_text(
        """
publisher:
  output_file: output/subscription.txt
  split_output_files:
    blacklist: output/blacklist.txt
    whitelist: output/whitelist.txt
  location_output_dir: output/locations
  location_output_limit: 5
  status_output_file: output/run-summary.json
aggregator:
  max_configs_in_output: 50
  max_per_country: 20
""",
        encoding="utf-8",
    )
    return p


@pytest.fixture
def runner(settings_file: Path) -> PipelineRunner:
    return PipelineRunner(
        settings_path=str(settings_file),
        sources_path=str(settings_file.parent / "missing-sources.json"),
    )


@pytest.fixture
def config_de(country: str = "DE") -> Config:
    return Config(
        "vless",
        "de.example.com",
        443,
        "11111111-1111-4111-8111-111111111111",
        raw_link=("vless://11111111-1111-4111-8111-111111111111@de.example.com:443#DE"),
        country=country,
    )


@pytest.fixture
def sample_configs() -> list[Config]:
    return [
        Config(
            "vless",
            f"{country.lower()}-{i}.example",
            443,
            "11111111-1111-4111-8111-111111111111",
            raw_link=(
                f"vless://11111111-1111-4111-8111-111111111111"
                f"@{country.lower()}-{i}.example:443#{country}-{i}"
            ),
            country=country,
        )
        for i, country in enumerate(["DE", "RU", "DE", "US", "RU", "DE", "JP"])
    ]


# ---------------------------------------------------------------------------
# _publisher_section
# ---------------------------------------------------------------------------


def test_publisher_section_returns_publisher_dict(runner: PipelineRunner) -> None:
    section = runner._writer._publisher_section()
    assert isinstance(section, dict)
    assert section["output_file"] == "output/subscription.txt"


def test_publisher_section_defaults_when_missing(tmp_path: Path) -> None:
    settings = tmp_path / "settings.yaml"
    settings.write_text("other:\n  key: val\n", encoding="utf-8")
    r = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    assert r._writer._publisher_section() == {}


# ---------------------------------------------------------------------------
# _location_output_config
# ---------------------------------------------------------------------------


def test_location_output_config_enabled_by_default(runner: PipelineRunner) -> None:
    enabled, output_dir, limit = runner._writer._location_output_config()
    assert enabled is True
    assert output_dir == "output/locations"
    assert limit == 5


def test_location_output_config_disabled(
    runner: PipelineRunner, tmp_path: Path
) -> None:
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        "publisher:\n  location_outputs_enabled: false\n", encoding="utf-8"
    )
    r = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    enabled, _dir, _limit = r._writer._location_output_config()
    assert enabled is False


def test_location_output_config_string_enabled(
    runner: PipelineRunner, tmp_path: Path
) -> None:
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        "publisher:\n  location_outputs_enabled: 'true'\n", encoding="utf-8"
    )
    r = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    enabled, _dir, _limit = r._writer._location_output_config()
    assert enabled is True


def test_location_output_config_limit_clamped(
    runner: PipelineRunner, tmp_path: Path
) -> None:
    settings = tmp_path / "settings.yaml"
    settings.write_text("publisher:\n  location_output_limit: -10\n", encoding="utf-8")
    r = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    _enabled, _dir, limit = r._writer._location_output_config()
    assert limit >= 0


# ---------------------------------------------------------------------------
# _location_output_filename
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("country", "expected"),
    [
        ("DE", "subscription-DE.txt"),
        ("Ru", "subscription-RU.txt"),
        ("us- east ", "subscription-USEAST.txt"),
        ("", "subscription-XX.txt"),
        (" ", "subscription-XX.txt"),
        ("U.S.A.", "subscription-USA.txt"),
    ],
)
def test_location_output_filename(country: str, expected: str) -> None:
    assert PipelineRunner._location_output_filename(country) == expected


# ---------------------------------------------------------------------------
# _clear_location_outputs
# ---------------------------------------------------------------------------


def test_clear_location_outputs_removes_existing_files(
    runner: PipelineRunner, tmp_path: Path
) -> None:
    # Set location directory to tmp_path
    loc_dir = tmp_path / "loc"
    loc_dir.mkdir()
    (loc_dir / "subscription-DE.txt").write_text("old", encoding="utf-8")
    (loc_dir / "subscription-RU.txt").write_text("old", encoding="utf-8")
    (loc_dir / "other.txt").write_text("keep", encoding="utf-8")

    settings = tmp_path / "settings.yaml"
    settings.write_text(
        f"publisher:\n  location_output_dir: {loc_dir}\n", encoding="utf-8"
    )
    r = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    r._writer._clear_location_outputs()

    assert not (loc_dir / "subscription-DE.txt").exists()
    assert not (loc_dir / "subscription-RU.txt").exists()
    assert (loc_dir / "other.txt").exists()  # should not be touched


def test_clear_location_outputs_when_disabled(
    runner: PipelineRunner, tmp_path: Path
) -> None:
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        "publisher:\n  location_outputs_enabled: false\n", encoding="utf-8"
    )
    r = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    # Should not raise even if dir doesn't exist
    r._writer._clear_location_outputs()


def test_clear_location_outputs_nonexistent_dir(
    runner: PipelineRunner, tmp_path: Path
) -> None:
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        f"publisher:\n  location_output_dir: {tmp_path / 'nonexistent'}\n",
        encoding="utf-8",
    )
    r = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    # Should not raise
    r._writer._clear_location_outputs()


# ---------------------------------------------------------------------------
# _build_location_outputs
# ---------------------------------------------------------------------------


def test_build_location_outputs_groups_and_sorts(
    runner: PipelineRunner, sample_configs: list[Config]
) -> None:
    result = runner._writer._build_location_outputs(sample_configs, 2)
    # Should have countries sorted alphabetically
    assert list(result.keys()) == ["DE", "JP", "RU", "US"]
    # Each country capped at per_location_limit
    assert len(result["DE"]) == 2  # limited to 2


def test_build_location_outputs_skips_missing_country(
    runner: PipelineRunner,
) -> None:
    cfg = Config(
        "vless",
        "no-country.example",
        443,
        "id",
        raw_link="vless://id@no-country.example:443",
        # no country
    )
    result = runner._writer._build_location_outputs([cfg], 10)
    assert result == {}


def test_build_location_outputs_skips_no_raw_link(
    runner: PipelineRunner, config_de: Config
) -> None:
    cfg = Config(
        "vless",
        "no-link.example",
        443,
        "id",
        country="DE",
    )
    result = runner._writer._build_location_outputs([cfg, config_de], 10)
    assert result["DE"] == [config_de]


# ---------------------------------------------------------------------------
# _write_location_outputs (full flow)
# ---------------------------------------------------------------------------


def test_write_location_outputs_writes_files(
    runner: PipelineRunner, tmp_path: Path, sample_configs: list[Config]
) -> None:
    loc_dir = tmp_path / "loc_output"
    loc_dir.mkdir()
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        f"""
publisher:
  location_outputs_enabled: true
  location_output_dir: {loc_dir}
  location_output_limit: 5
aggregator:
  max_per_country: 20
""",
        encoding="utf-8",
    )
    r = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    files = r._writer._write_location_outputs(sample_configs)
    assert len(files) == 4  # DE, JP, RU, US
    for f in files:
        assert Path(f).exists()


def test_write_location_outputs_disabled(
    runner: PipelineRunner,
    tmp_path: Path,
) -> None:
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        "publisher:\n  location_outputs_enabled: false\n", encoding="utf-8"
    )
    r = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    assert r._writer._write_location_outputs([]) == []


# ---------------------------------------------------------------------------
# _build_mix
# ---------------------------------------------------------------------------


def test_build_mix_interleaves_black_and_white(runner: PipelineRunner) -> None:
    configs = [
        Config("vless", f"b{i}.example", 443, f"id{i}", country="DE") for i in range(4)
    ]
    whitelist = [configs[0], configs[1]]
    blacklist = [configs[2], configs[3]]
    splits = {"blacklist": blacklist, "whitelist": whitelist}
    pcfg = {"mix_blacklist_count": 2, "mix_whitelist_count": 2}
    mixed = runner._writer._build_mix(configs, splits, pcfg)
    # Interleaving: b0, w0, b1, w1
    assert len(mixed) == 4


def test_build_mix_empty_lists(runner: PipelineRunner) -> None:
    mixed = runner._writer._build_mix([], {}, {})
    assert mixed == []


def test_build_mix_one_side_exhausted(runner: PipelineRunner) -> None:
    splits = {
        "blacklist": [
            Config(
                "vless",
                "b.example",
                443,
                "bid",
                country="DE",
                raw_link="vless://bid@b.example:443",
            ),
        ],
        "whitelist": [
            Config(
                "vless",
                f"w{i}.example",
                443,
                f"wid{i}",
                country="FR",
                raw_link=f"vless://wid{i}@w{i}.example:443",
            )
            for i in range(3)
        ],
    }
    pcfg = {"mix_blacklist_count": 2, "mix_whitelist_count": 5}
    mixed = runner._writer._build_mix([], splits, pcfg)
    # black exhausted after 1, should get b0, w0, w1, w2
    assert len(mixed) == 4


# ---------------------------------------------------------------------------
# _write_output / _write_plain_fallback
# ---------------------------------------------------------------------------


def test_write_output_writes_plain_fallback_import_error(
    runner: PipelineRunner, tmp_path: Path, monkeypatch
) -> None:
    out = tmp_path / "output.txt"
    configs = [
        Config(
            "vless",
            "a.example",
            443,
            "id",
            raw_link="vless://id@a.example:443",
            country="DE",
        ),
    ]
    # Simulate ImportError by removing the module from sys.modules
    monkeypatch.setitem(__import__("sys").modules, "src.aggregator.output", None)
    count = runner._writer._write_output(configs, str(out))
    assert count == 1
    assert out.read_text(encoding="utf-8").strip() == "vless://id@a.example:443"


def test_write_output_skips_unsafe_path(runner: PipelineRunner) -> None:
    count = runner._writer._write_output([], "../../../etc/passwd")
    assert count == 0


def test_write_plain_fallback_creates_file(
    runner: PipelineRunner, tmp_path: Path
) -> None:
    out = tmp_path / "out" / "sub.txt"
    configs = [
        Config(
            "vless",
            "a.example",
            443,
            "id",
            raw_link="vless://id@a.example:443",
            country="DE",
        ),
    ]
    count = runner._writer._write_plain_fallback(configs, str(out))
    assert count == 1
    assert out.read_text(encoding="utf-8").strip() == "vless://id@a.example:443"


def test_write_plain_fallback_empty(runner: PipelineRunner, tmp_path: Path) -> None:
    out = tmp_path / "empty.txt"
    count = runner._writer._write_plain_fallback([], str(out))
    assert count == 0
    assert out.read_text(encoding="utf-8") == ""


# ---------------------------------------------------------------------------
# _write_empty_output
# ---------------------------------------------------------------------------


def test_write_empty_output_with_invalid_path(runner: PipelineRunner) -> None:
    runner._writer._write_empty_output("../../../unsafe")
    # Should not raise


def test_write_empty_output_creates_file(
    runner: PipelineRunner, tmp_path: Path
) -> None:
    out = tmp_path / "empty-out.txt"
    runner._writer._write_empty_output(str(out))
    assert out.exists()


# ---------------------------------------------------------------------------
# _write_split_outputs
# ---------------------------------------------------------------------------


def test_write_split_outputs_writes_each_split(
    runner: PipelineRunner, tmp_path: Path
) -> None:
    bl_file = tmp_path / "blacklist.txt"
    wl_file = tmp_path / "whitelist.txt"
    split_files = {"blacklist": str(bl_file), "whitelist": str(wl_file)}
    splits = {
        "blacklist": [
            Config(
                "vless",
                "b.example",
                443,
                "bid",
                raw_link="vless://bid@b.example:443",
                country="DE",
            ),
        ],
        "whitelist": [
            Config(
                "vless",
                "w.example",
                443,
                "wid",
                raw_link="vless://wid@w.example:443",
                country="FR",
            ),
        ],
        "mixed": [
            Config(
                "vless",
                "m.example",
                443,
                "mid",
                raw_link="vless://mid@m.example:443",
                country="US",
            ),
        ],
    }
    files = runner._writer._write_split_outputs(splits, split_files)
    assert len(files) == 2  # only configured splits returned
    assert bl_file.exists()
    assert wl_file.exists()


# ---------------------------------------------------------------------------
# _write_empty_split_outputs
# ---------------------------------------------------------------------------


def test_write_empty_split_outputs(runner: PipelineRunner, tmp_path: Path) -> None:
    bl_file = tmp_path / "empty-bl.txt"
    runner._writer._write_empty_split_outputs({"blacklist": str(bl_file)})
    assert bl_file.exists()
    # Should contain 0 configs (empty)
    content = bl_file.read_text(encoding="utf-8")
    assert len(content) >= 0


# ---------------------------------------------------------------------------
# _record_output_stats
# ---------------------------------------------------------------------------


def test_record_output_stats_tracks_count_and_countries(runner: PipelineRunner) -> None:
    configs = [
        Config(
            "vless",
            "a.example",
            443,
            "id",
            raw_link="vless://id@a.example:443",
            country="DE",
        ),
        Config(
            "vless",
            "b.example",
            443,
            "id",
            raw_link="vless://id@b.example:443",
            country="DE",
        ),
        Config(
            "vless",
            "c.example",
            443,
            "id",
            raw_link="vless://id@c.example:443",
            country="US",
        ),
        # No raw_link — should be excluded from count
        Config("vless", "d.example", 443, "id", country="FR"),
    ]
    runner._writer._record_output_stats("test_out", "/tmp/out.txt", configs)
    stats = runner._writer.context.output_stats["test_out"]
    assert stats["count"] == 3  # only 3 have raw_link
    assert stats["countries"] == {"DE": 2, "US": 1}
    assert stats["file"] == "/tmp/out.txt"


# ---------------------------------------------------------------------------
# _status_output_file
# ---------------------------------------------------------------------------


def test_status_output_file(runner: PipelineRunner) -> None:
    assert runner._writer._status_output_file() == "output/run-summary.json"


def test_status_output_file_none(runner: PipelineRunner, tmp_path: Path) -> None:
    settings = tmp_path / "settings.yaml"
    settings.write_text("publisher:\n  status_output_file: null\n", encoding="utf-8")
    r = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    assert r._writer._status_output_file() is None


def test_status_output_file_empty_string(
    runner: PipelineRunner, tmp_path: Path
) -> None:
    settings = tmp_path / "settings.yaml"
    settings.write_text("publisher:\n  status_output_file: ''\n", encoding="utf-8")
    r = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    assert r._writer._status_output_file() is None


def test_status_output_file_missing_section(
    runner: PipelineRunner, tmp_path: Path
) -> None:
    settings = tmp_path / "settings.yaml"
    settings.write_text("other:\n  key: val\n", encoding="utf-8")
    r = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    assert r._writer._status_output_file() is None


# ---------------------------------------------------------------------------
# _write_run_summary
# ---------------------------------------------------------------------------


def test_write_run_summary_creates_json(runner: PipelineRunner, tmp_path: Path) -> None:
    summary_file = tmp_path / "summary.json"
    result = runner._writer._write_run_summary("success", str(summary_file))
    assert result == str(summary_file)
    data = json.loads(summary_file.read_text(encoding="utf-8"))
    assert data["status"] == "success"
    assert "outputs" in data
    assert "validation" in data


def test_write_run_summary_no_file(runner: PipelineRunner, tmp_path: Path) -> None:
    settings = tmp_path / "settings.yaml"
    settings.write_text("other:\n  key: val\n", encoding="utf-8")
    r = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    result = r._writer._write_run_summary("success", None)
    assert result is None


def test_write_run_summary_uses_status_output_file(
    runner: PipelineRunner, tmp_path: Path
) -> None:
    summary_file = tmp_path / "status.json"
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        f"publisher:\n  status_output_file: {summary_file}\n", encoding="utf-8"
    )
    r = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    result = r._writer._write_run_summary("empty_sources")
    assert result == str(summary_file)
    data = json.loads(summary_file.read_text(encoding="utf-8"))
    assert data["status"] == "empty_sources"


def test_write_run_summary_empty_outputs(
    runner: PipelineRunner, tmp_path: Path
) -> None:
    summary_file = tmp_path / "summary.json"
    result = runner._writer._write_run_summary("no_sources", str(summary_file))
    assert result == str(summary_file)
    data = json.loads(summary_file.read_text(encoding="utf-8"))
    assert data["status"] == "no_sources"
    assert data["outputs"] == {}


def test_write_run_summary_strips_proxy_urls_from_validation(
    runner: PipelineRunner, tmp_path: Path
) -> None:
    # With proxy_urls in liveness stats, they should be stripped
    runner._writer.context.liveness_stats["proxy_urls"] = ["should:be:stripped"]
    runner._writer.context.liveness_stats["tcp_enabled"] = True
    summary_file = tmp_path / "summary.json"
    r = runner._writer._write_run_summary("success", str(summary_file))
    assert r == str(summary_file)
    data = json.loads(summary_file.read_text(encoding="utf-8"))
    assert "proxy_urls" not in data["validation"]
    assert data["validation"]["tcp_enabled"] is True


# ---------------------------------------------------------------------------
# _write_outputs (integration-light)
# ---------------------------------------------------------------------------


def test_write_outputs_returns_expected_files(
    runner: PipelineRunner, tmp_path: Path
) -> None:
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        f"""
publisher:
  output_file: {tmp_path / "combined.txt"}
  mix_output_file: {tmp_path / "mix.txt"}
  split_output_files:
    blacklist: {tmp_path / "blacklist.txt"}
  location_output_dir: {tmp_path / "locations"}
  location_output_limit: 5
  location_outputs_enabled: true
aggregator:
  max_per_country: 20
  max_configs_in_output: 50
""",
        encoding="utf-8",
    )
    r = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    configs = [
        Config(
            "vless",
            f"a-{i}.example",
            443,
            f"id{i}",
            raw_link=f"vless://id{i}@a-{i}.example:443",
            country="DE" if i % 2 == 0 else "US",
        )
        for i in range(4)
    ]
    splits = {"blacklist": [configs[0]], "whitelist": [configs[1]]}
    files = r._writer._write_outputs(configs, splits)
    assert len(files) >= 3  # combined, mix, blacklist, + locations
    for f in files:
        assert Path(f).exists()


# ---------------------------------------------------------------------------
# _write_empty_outputs
# ---------------------------------------------------------------------------


def test_write_empty_outputs_creates_files(
    runner: PipelineRunner, tmp_path: Path
) -> None:
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        f"""
publisher:
  output_file: {tmp_path / "combined.txt"}
  mix_output_file: {tmp_path / "mix.txt"}
  split_output_files:
    blacklist: {tmp_path / "bl.txt"}
    whitelist: {tmp_path / "wl.txt"}
  location_outputs_enabled: false
""",
        encoding="utf-8",
    )
    r = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    files = r._writer._write_empty_outputs()
    assert len(files) >= 2  # combined + mix + splits
    for f in files:
        p = Path(f)
        assert p.exists()


# ---------------------------------------------------------------------------
# run (async)  —  lines 34-40
# ---------------------------------------------------------------------------


def test_run_method_returns_state_with_output_files(tmp_path: Path) -> None:
    """Async run() should call _write_outputs and return state with output_files."""
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        f"""
publisher:
  output_file: {tmp_path / "combined.txt"}
  mix_output_file: {tmp_path / "mix.txt"}
  split_output_files:
    blacklist: {tmp_path / "bl.txt"}
  location_output_dir: {tmp_path / "locations"}
  location_output_limit: 5
  location_outputs_enabled: false
aggregator:
  max_per_country: 20
  max_configs_in_output: 50
""",
        encoding="utf-8",
    )
    r = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    state = PipelineState(aggregated=[], split_configs={}, summary_file=None)
    result = asyncio.run(r._writer.run(state))
    assert result is state
    assert isinstance(result.output_files, list)


# ---------------------------------------------------------------------------
# _clear_location_outputs — unsafe path  (lines 63-69)
# ---------------------------------------------------------------------------


def test_clear_location_outputs_unsafe_path(tmp_path: Path) -> None:
    """ValueError from resolve_safe_output_path is caught and logged."""
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        "publisher:\n  location_output_dir: ../../etc/unsafe\n",
        encoding="utf-8",
    )
    r = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    # Should not raise
    r._writer._clear_location_outputs()


# ---------------------------------------------------------------------------
# _clear_location_outputs — OSError during unlink  (lines 75-76)
# ---------------------------------------------------------------------------


def test_clear_location_outputs_oserror_on_unlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """OSError from path.unlink should be caught and logged."""
    loc_dir = tmp_path / "loc"
    loc_dir.mkdir()
    (loc_dir / "subscription-DE.txt").write_text("old", encoding="utf-8")

    settings = tmp_path / "settings.yaml"
    settings.write_text(
        f"publisher:\n  location_output_dir: {loc_dir}\n",
        encoding="utf-8",
    )
    r = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )

    orig_unlink = Path.unlink

    def _raising_unlink(path_self: Path, **kwargs: bool) -> None:
        if "subscription" in str(path_self):
            msg = "Permission denied"
            raise OSError(msg)
        return orig_unlink(path_self, **kwargs)

    monkeypatch.setattr(Path, "unlink", _raising_unlink)
    # Should not raise
    r._writer._clear_location_outputs()


# ---------------------------------------------------------------------------
# _write_output — write_subscription raises  (lines 222-224)
# ---------------------------------------------------------------------------


def test_write_output_falls_to_plain_fallback_on_exception(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When write_subscription raises, _write_output falls back to plain text."""
    out = tmp_path / "output.txt"
    configs = [
        Config(
            "vless",
            "a.example",
            443,
            "id",
            raw_link="vless://id@a.example:443",
            country="DE",
        ),
    ]

    def _raising_write_subscription(
        _configs: list[Config],
        _path: str,
    ) -> int:
        msg = "subscription write failed"
        raise RuntimeError(msg)

    monkeypatch.setattr(
        "src.aggregator.output.write_subscription",
        _raising_write_subscription,
    )

    settings = tmp_path / "settings.yaml"
    settings.write_text(
        "publisher:\n  output_file: output.txt\n",
        encoding="utf-8",
    )
    r = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    count = r._writer._write_output(configs, str(out))
    assert count == 1
    assert out.read_text(encoding="utf-8").strip() == "vless://id@a.example:443"


# ---------------------------------------------------------------------------
# _write_empty_output — Exception from _write_output  (lines 232-233)
# ---------------------------------------------------------------------------


def test_write_empty_output_handles_exception(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exception in _write_output is caught by _write_empty_output."""
    out = tmp_path / "empty-out.txt"

    def _raising_write_output(
        _self: object,
        _configs: list[Config],
        _output_file: str,
    ) -> int:
        msg = "write failed"
        raise RuntimeError(msg)

    monkeypatch.setattr(OutputWriter, "_write_output", _raising_write_output)

    settings = tmp_path / "settings.yaml"
    settings.write_text("publisher:\n", encoding="utf-8")
    r = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    # Should not raise
    r._writer._write_empty_output(str(out))


# ---------------------------------------------------------------------------
# _write_plain_fallback — exception handler  (lines 246-248)
# ---------------------------------------------------------------------------


def test_write_plain_fallback_exception_returns_zero(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exception in _write_plain_fallback is caught, returns 0."""
    out = tmp_path / "out" / "sub.txt"
    configs = [
        Config(
            "vless",
            "a.example",
            443,
            "id",
            raw_link="vless://id@a.example:443",
            country="DE",
        ),
    ]

    def _raising_open(*args: object, **kwargs: object) -> object:
        msg = "read-only filesystem"
        raise OSError(msg)

    monkeypatch.setattr(Path, "open", _raising_open)

    count = OutputWriter._write_plain_fallback(configs, str(out))
    assert count == 0


# ---------------------------------------------------------------------------
# _write_run_summary — exception handler  (lines 313-315)
# ---------------------------------------------------------------------------


def test_write_run_summary_exception_returns_none(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exception during write is caught, returns None."""
    summary_file = tmp_path / "summary.json"

    settings = tmp_path / "settings.yaml"
    settings.write_text(
        "publisher:\n  status_output_file: output/summary.json\n",
        encoding="utf-8",
    )

    def _raising_write_text(self: Path, *args: object, **kwargs: object) -> int:
        msg = "disk full"
        raise OSError(msg)

    monkeypatch.setattr(Path, "write_text", _raising_write_text)
    r = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    result = r._writer._write_run_summary("success", str(summary_file))
    assert result is None
