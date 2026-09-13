"""Tests for the OutputWriter stage — subscription, split, location, and summary output."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
from pathlib import Path

import pytest
import yaml

from src.parsers.base import Config
from src.scheduler.context import PipelineState
from src.scheduler.runner import PipelineRunner
from src.scheduler.stages.write import OutputWriter
from src.utils.paths import resolve_safe_output_path

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
    assert OutputWriter._location_output_filename(country) == expected


# ---------------------------------------------------------------------------
# _clear_location_outputs
# ---------------------------------------------------------------------------


def test_clear_location_outputs_removes_existing_files(
    runner: PipelineRunner, tmp_path: Path
) -> None:
    # Project-relative dir: resolves inside the isolated project root.
    loc_dir = resolve_safe_output_path("output/loc")
    loc_dir.mkdir(parents=True)
    (loc_dir / "subscription-DE.txt").write_text("old", encoding="utf-8")
    (loc_dir / "subscription-RU.txt").write_text("old", encoding="utf-8")
    (loc_dir / "other.txt").write_text("keep", encoding="utf-8")

    settings = tmp_path / "settings.yaml"
    settings.write_text(
        "publisher:\n  location_output_dir: output/loc\n", encoding="utf-8"
    )
    r = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    r._writer._clear_location_outputs()

    assert not (loc_dir / "subscription-DE.txt").exists()
    assert not (loc_dir / "subscription-RU.txt").exists()
    assert (loc_dir / "other.txt").exists()  # should not be touched


def test_clear_location_outputs_keeps_files_outside_project(tmp_path: Path) -> None:
    """An absolute dir outside the project must never have files removed."""
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    victim = outside_dir / "subscription-DE.txt"
    victim.write_text("someone else's file", encoding="utf-8")

    settings = tmp_path / "settings.yaml"
    settings.write_text(
        f"publisher:\n  location_output_dir: {outside_dir}\n",
        encoding="utf-8",
    )
    r = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    r._writer._clear_location_outputs()

    assert victim.exists()


def test_removable_location_root_rejects_unsafe_dir() -> None:
    """A traversing dir is not resolvable, so nothing may be unlinked in it."""
    assert OutputWriter._removable_location_root("../../etc/unsafe") is None


def test_clear_location_outputs_skips_non_files(runner: PipelineRunner) -> None:
    """A directory matching the glob is neither reported nor removed."""
    loc_dir = resolve_safe_output_path("output/locations")
    (loc_dir / "subscription-DIR.txt").mkdir(parents=True)

    assert runner._writer._clear_location_outputs() == []
    assert (loc_dir / "subscription-DIR.txt").is_dir()


def test_write_location_outputs_retires_vanished_country(
    runner: PipelineRunner,
    config_de: Config,
) -> None:
    """A country that disappears is republished empty, not silently orphaned."""
    ru = Config(
        "vless",
        "ru-1.example",
        443,
        "11111111-1111-4111-8111-111111111111",
        raw_link="vless://11111111-1111-4111-8111-111111111111@ru-1.example:443#RU",
        country="RU",
    )

    first = runner._writer._write_location_outputs([config_de, ru])
    assert sorted(Path(path).name for path in first) == [
        "subscription-DE.txt",
        "subscription-RU.txt",
    ]

    second = runner._writer._write_location_outputs([ru])

    # DE must stay in the published set, otherwise the repo copy keeps serving
    # the configs of the previous run forever.
    assert sorted(Path(path).name for path in second) == [
        "subscription-DE.txt",
        "subscription-RU.txt",
    ]
    de_path = resolve_safe_output_path("output/locations/subscription-DE.txt")
    assert de_path.exists()
    decoded = base64.b64decode(de_path.read_text(encoding="utf-8")).decode("utf-8")
    assert "de.example.com" not in decoded
    ru_path = resolve_safe_output_path("output/locations/subscription-RU.txt")
    assert "ru-1.example" in base64.b64decode(
        ru_path.read_text(encoding="utf-8"),
    ).decode("utf-8")


def test_write_location_outputs_retires_dir_outside_project(tmp_path: Path) -> None:
    """Stale files in an absolute dir are emptied even though never unlinked."""
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    stale = outside_dir / "subscription-DE.txt"
    stale.write_text("dead-configs", encoding="utf-8")

    settings = tmp_path / "settings.yaml"
    settings.write_text(
        f"publisher:\n"
        f"  location_output_dir: {outside_dir}\n"
        f"  location_output_limit: 5\n",
        encoding="utf-8",
    )
    r = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )

    files = r._writer._write_location_outputs([])

    assert [Path(path).name for path in files] == ["subscription-DE.txt"]
    # Writing there is allowed, so the cleanup must not leave dead configs.
    assert stale.exists()
    assert "dead-configs" not in stale.read_text(encoding="utf-8")


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
# _build_mixed_output (Aggregator, driven via the runner)
# ---------------------------------------------------------------------------


def test_build_mix_interleaves_black_and_white(runner: PipelineRunner) -> None:
    """The mix draws from both lists: blacklist half first, then whitelist."""
    blacklist = [
        Config("vless", f"b{i}.example", 443, f"id{i}", country="DE") for i in range(4)
    ]
    whitelist = [
        Config("vless", f"w{i}.example", 443, f"wid{i}", country="RU") for i in range(4)
    ]
    max_total = 4  # 50/50 split of the runner default: 2 + 2
    mixed = runner._build_mixed_output(
        {"blacklist": blacklist, "whitelist": whitelist},
        max_total,
    )
    assert len(mixed) == 4
    assert sum(1 for cfg in mixed if cfg.country == "DE") == 2
    assert sum(1 for cfg in mixed if cfg.country == "RU") == 2


def test_build_mix_empty_lists(runner: PipelineRunner) -> None:
    mixed = runner._build_mixed_output({}, runner._max_configs())
    assert mixed == []


def test_build_mix_one_side_exhausted(runner: PipelineRunner) -> None:
    """A short blacklist does not stop the whitelist side from filling."""
    blacklist = [
        Config(
            "vless",
            "b.example",
            443,
            "bid",
            country="DE",
            raw_link="vless://bid@b.example:443",
        ),
    ]
    whitelist = [
        Config(
            "vless",
            f"w{i}.example",
            443,
            f"wid{i}",
            country="RU",
            raw_link=f"vless://wid{i}@w{i}.example:443",
        )
        for i in range(3)
    ]
    mixed = runner._build_mixed_output(
        {"blacklist": blacklist, "whitelist": whitelist},
        runner._max_configs(),
    )
    # black exhausted after 1, whitelist fills the rest
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
# split outputs (runner composition)
# ---------------------------------------------------------------------------


def test_write_split_outputs_writes_each_split(
    runner: PipelineRunner, tmp_path: Path
) -> None:
    """Each configured split is written with its own list's configs."""
    bl_file = tmp_path / "blacklist.txt"
    wl_file = tmp_path / "whitelist.txt"
    runner.settings["publisher"]["split_output_files"] = {
        "blacklist": str(bl_file),
        "whitelist": str(wl_file),
        # "mixed" normalizes away and must never be written
        "mixed": str(tmp_path / "mixed.txt"),
    }
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
    split_files = runner._split_output_files(str(tmp_path / "combined.txt"))
    assert set(split_files) == {"blacklist", "whitelist"}
    for list_type, split_file in split_files.items():
        runner._write_output(splits[list_type], split_file)
    assert bl_file.exists()
    assert wl_file.exists()
    assert not (tmp_path / "mixed.txt").exists()


# ---------------------------------------------------------------------------
# _write_empty_split_outputs
# ---------------------------------------------------------------------------


def test_write_empty_split_outputs(runner: PipelineRunner, tmp_path: Path) -> None:
    """The combined path derives every configured split file to empty."""
    bl_file = tmp_path / "empty-bl.txt"
    runner.settings["publisher"]["split_output_files"] = {
        "blacklist": str(bl_file),
    }
    runner._write_empty_split_outputs(str(tmp_path / "combined.txt"))
    assert bl_file.exists()
    # Should contain 0 configs (empty)
    content = bl_file.read_text(encoding="utf-8")
    assert len(content) >= 0


# ---------------------------------------------------------------------------
# _record_output_stats
# ---------------------------------------------------------------------------


def test_record_output_stats_tracks_count_and_countries(runner: PipelineRunner) -> None:
    """Count follows the writer predicate: no raw_link means not counted."""
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
        # No raw_link — excluded from the count by the writer predicate
        Config("vless", "d.example", 443, "id", country="FR"),
    ]
    out_file = "/tmp/out.txt"
    runner._record_output_stats("test_out", out_file, configs)
    stats = runner._output_stats["test_out"]
    assert stats["count"] == 3  # only 3 have raw_link
    assert stats["countries"] == {"DE": 2, "US": 1}
    assert stats["file"] == out_file


# ---------------------------------------------------------------------------
# _status_output_file
# ---------------------------------------------------------------------------


def test_status_output_file(runner: PipelineRunner) -> None:
    assert runner._status_output_file() == "output/run-summary.json"


def test_status_output_file_none(runner: PipelineRunner, tmp_path: Path) -> None:
    settings = tmp_path / "settings.yaml"
    settings.write_text("publisher:\n  status_output_file: null\n", encoding="utf-8")
    r = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    assert r._status_output_file() is None


def test_status_output_file_empty_string(
    runner: PipelineRunner, tmp_path: Path
) -> None:
    settings = tmp_path / "settings.yaml"
    settings.write_text("publisher:\n  status_output_file: ''\n", encoding="utf-8")
    r = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    assert r._status_output_file() is None


def test_status_output_file_missing_section(
    runner: PipelineRunner, tmp_path: Path
) -> None:
    settings = tmp_path / "settings.yaml"
    settings.write_text("other:\n  key: val\n", encoding="utf-8")
    r = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    assert r._status_output_file() is None


# ---------------------------------------------------------------------------
# _write_run_summary (runner)
# ---------------------------------------------------------------------------


def _runner_with_status_file(tmp_path: Path, status_file: Path) -> PipelineRunner:
    """Runner whose run summary lands in the given tmp file."""
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        f"publisher:\n  status_output_file: {status_file}\n",
        encoding="utf-8",
    )
    return PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )


def test_write_run_summary_creates_json(runner: PipelineRunner, tmp_path: Path) -> None:
    summary_file = tmp_path / "summary.json"
    r = _runner_with_status_file(tmp_path, summary_file)
    result = r._write_run_summary("success")
    assert result == str(summary_file)
    data = json.loads(summary_file.read_text(encoding="utf-8"))
    assert data["status"] == "success"
    # Richer runner payload: check the documented keys exist rather than
    # exact dict equality (generated_at/sources change every run).
    assert "outputs" in data
    assert "validation" in data
    assert "generated_at" in data
    assert "sources" in data


def test_write_run_summary_no_file(runner: PipelineRunner, tmp_path: Path) -> None:
    settings = tmp_path / "settings.yaml"
    settings.write_text("other:\n  key: val\n", encoding="utf-8")
    r = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    result = r._write_run_summary("success")
    assert result is None


def test_write_run_summary_uses_status_output_file(
    runner: PipelineRunner, tmp_path: Path
) -> None:
    summary_file = tmp_path / "status.json"
    r = _runner_with_status_file(tmp_path, summary_file)
    result = r._write_run_summary("empty_sources")
    assert result == str(summary_file)
    data = json.loads(summary_file.read_text(encoding="utf-8"))
    assert data["status"] == "empty_sources"


def test_write_run_summary_empty_outputs(
    runner: PipelineRunner, tmp_path: Path
) -> None:
    summary_file = tmp_path / "summary.json"
    r = _runner_with_status_file(tmp_path, summary_file)
    result = r._write_run_summary("no_sources")
    assert result == str(summary_file)
    data = json.loads(summary_file.read_text(encoding="utf-8"))
    assert data["status"] == "no_sources"
    assert data["outputs"] == {}


def test_write_run_summary_strips_proxy_urls_from_validation(
    runner: PipelineRunner, tmp_path: Path
) -> None:
    # With proxy_urls in liveness stats, they should be stripped
    summary_file = tmp_path / "summary.json"
    r = _runner_with_status_file(tmp_path, summary_file)
    r._liveness_stats["proxy_urls"] = ["should:be:stripped"]
    r._liveness_stats["tcp_enabled"] = True
    result = r._write_run_summary("success")
    assert result == str(summary_file)
    data = json.loads(summary_file.read_text(encoding="utf-8"))
    assert "proxy_urls" not in data["validation"]
    assert data["validation"]["tcp_enabled"] is True


# ---------------------------------------------------------------------------
# run (async)  —  lines 34-40
# ---------------------------------------------------------------------------


def test_run_method_raises_not_implemented(tmp_path: Path) -> None:
    """OutputWriter.run is a stage-contract stub: the runner composes writes.

    The generic ``run(state)`` form and the second output assembly it used to
    carry were dead code; the end-to-end flow is covered by the runner's
    ``run()`` (see test_runner_coverage.py::test_run_full_success).
    """
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        f"publisher:\n  output_file: {tmp_path / 'combined.txt'}\n",
        encoding="utf-8",
    )
    r = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    with pytest.raises(NotImplementedError):
        asyncio.run(r._writer.run(PipelineState()))


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
    loc_dir = resolve_safe_output_path("output/loc")
    loc_dir.mkdir(parents=True)
    (loc_dir / "subscription-DE.txt").write_text("old", encoding="utf-8")

    settings = tmp_path / "settings.yaml"
    settings.write_text(
        "publisher:\n  location_output_dir: output/loc\n",
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

    def _raising_write(*args: object, **kwargs: object) -> object:
        msg = "read-only filesystem"
        raise OSError(msg)

    monkeypatch.setattr("src.scheduler.stages.write.write_text_atomic", _raising_write)

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

    def _raising_write_text(_path: object, _content: str) -> None:
        msg = "disk full"
        raise OSError(msg)

    monkeypatch.setattr("src.scheduler.runner.write_text_atomic", _raising_write_text)
    r = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    result = r._write_run_summary("success")
    assert result is None


# ---------------------------------------------------------------------------
# _write_run_summary — unsafe path
# ---------------------------------------------------------------------------


def test_write_run_summary_rejects_traversal_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A status_output_file escaping the project is refused, like in the runner."""
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        'publisher:\n  status_output_file: "../../run-summary.json"\n',
        encoding="utf-8",
    )
    r = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    written: list[object] = []

    def _record_write_text(_path: object, _content: str) -> None:
        written.append(_path)

    monkeypatch.setattr("src.scheduler.runner.write_text_atomic", _record_write_text)

    assert r._write_run_summary("success") is None
    assert written == []


# ---------------------------------------------------------------------------
# location cleanup must not eat the split/mix subscriptions
# ---------------------------------------------------------------------------


def test_clear_location_outputs_keeps_configured_subscriptions(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A location_output_dir shared with the splits must not delete them.

    ``subscription-blacklist.txt`` / ``-whitelist.txt`` / ``-mix.txt`` all match
    the ``subscription-*.txt`` cleanup mask, so pointing location_output_dir at
    the directory holding them deleted the files written moments earlier and
    published empty placeholders instead — while run-summary still reported the
    counts of the deleted content.
    """
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        "publisher:\n"
        "  output_file: output/subscription.txt\n"
        "  mix_output_file: output/subscription-mix.txt\n"
        "  location_output_dir: output\n"
        "  split_output_files:\n"
        "    blacklist: output/subscription-blacklist.txt\n"
        "    whitelist: output/subscription-whitelist.txt\n",
        encoding="utf-8",
    )
    out_dir = resolve_safe_output_path("output")
    out_dir.mkdir(parents=True, exist_ok=True)
    for name in (
        "subscription-blacklist.txt",
        "subscription-whitelist.txt",
        "subscription-mix.txt",
    ):
        (out_dir / name).write_text("live-list", encoding="utf-8")
    (out_dir / "subscription-DE.txt").write_text("old-location", encoding="utf-8")

    r = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    caplog.set_level(logging.WARNING)
    stale = r._writer._clear_location_outputs()

    assert (out_dir / "subscription-blacklist.txt").read_text(encoding="utf-8") == (
        "live-list"
    )
    assert (out_dir / "subscription-whitelist.txt").exists()
    assert (out_dir / "subscription-mix.txt").exists()
    assert not (out_dir / "subscription-DE.txt").exists()
    assert stale == [str(Path("output") / "subscription-DE.txt")]
    assert "also holds the subscription output" in caplog.text


def test_clear_location_outputs_keeps_caller_reserved_paths(tmp_path: Path) -> None:
    """The combined output comes from --output, so the caller reserves it."""
    settings = tmp_path / "settings.yaml"
    settings.write_text("publisher:\n  location_output_dir: output\n", encoding="utf-8")
    out_dir = resolve_safe_output_path("output")
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "subscription-cli.txt").write_text("live-list", encoding="utf-8")

    r = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    stale = r._writer._clear_location_outputs(["output/subscription-cli.txt"])

    assert (out_dir / "subscription-cli.txt").exists()
    assert stale == []


def test_write_location_outputs_records_retired_files(tmp_path: Path) -> None:
    """Retired per-country files belong in the run summary as empty outputs.

    They are rewritten and republished on every run, so leaving them out of
    ``outputs`` made an empty run look like the location files were untouched.
    """
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        "publisher:\n  location_output_dir: output/locations\n",
        encoding="utf-8",
    )
    loc_dir = resolve_safe_output_path("output/locations")
    loc_dir.mkdir(parents=True, exist_ok=True)
    (loc_dir / "subscription-DE.txt").write_text("old", encoding="utf-8")

    r = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    written = r._writer._write_location_outputs([])

    # Forward slashes even on Windows: location paths land in run-summary.json
    # and must stay portable across platforms.
    assert written == ["output/locations/subscription-DE.txt"]
    assert r._writer.context.output_stats["location_de"]["count"] == 0
    assert (
        r._writer.context.output_stats["location_de"]["file"]
        == "output/locations/subscription-DE.txt"
    )


def test_reserved_output_paths_ignores_unsafe_entries(tmp_path: Path) -> None:
    """A configured path that escapes the project cannot be protected.

    It is never written either, so it is simply skipped instead of raising
    inside the location cleanup.
    """
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        'publisher:\n  output_file: "../../evil.txt"\n'
        "  mix_output_file: output/subscription-mix.txt\n",
        encoding="utf-8",
    )
    r = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    reserved = r._writer._reserved_output_paths()
    assert reserved == {resolve_safe_output_path("output/subscription-mix.txt")}


# ---------------------------------------------------------------------------
# Clash YAML twin output
# ---------------------------------------------------------------------------


def test_write_outputs_includes_clash_yaml(
    runner: PipelineRunner, tmp_path: Path
) -> None:
    """The clash twin is written from the combined configs and stats-recorded."""
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        f"""
publisher:
  output_file: {tmp_path / "combined.txt"}
  mix_output_file: {tmp_path / "mix.txt"}
  clash_output_file: {tmp_path / "clash.yaml"}
  split_output_files:
    blacklist: {tmp_path / "blacklist.txt"}
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
    configs = [
        Config(
            "vless",
            f"a-{i}.example",
            443,
            f"id{i}",
            raw_link=f"vless://id{i}@a-{i}.example:443",
            country="DE",
            security="tls",
        )
        for i in range(2)
    ]
    clash_file = r._writer._write_clash_output(configs)
    clash = tmp_path / "clash.yaml"
    assert clash_file == str(clash)
    assert clash.exists()
    data = yaml.safe_load(clash.read_text(encoding="utf-8"))
    assert [p["type"] for p in data["proxies"]] == ["vless", "vless"]
    r._record_output_stats("clash", clash_file, configs)
    assert r._output_stats["clash"]["count"] == 2


def test_write_empty_clash_output_writes_valid_placeholder(
    runner: PipelineRunner, tmp_path: Path
) -> None:
    """_write_empty_clash_output leaves a valid empty YAML document behind."""
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        f"""
publisher:
  output_file: {tmp_path / "combined.txt"}
  clash_output_file: {tmp_path / "clash.yaml"}
""",
        encoding="utf-8",
    )
    r = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    r._writer._write_empty_clash_output()
    clash = tmp_path / "clash.yaml"
    assert yaml.safe_load(clash.read_text(encoding="utf-8")) == {"proxies": []}


def test_write_clash_output_failure_returns_none(
    runner: PipelineRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed Clash write must not hand the empty placeholder to publish.

    Returning ``None`` keeps the placeholder out of the publish set so the
    last good Clash twin stays on the remote instead of being wiped by an
    empty one.
    """
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        f"""
publisher:
  output_file: {tmp_path / "combined.txt"}
  clash_output_file: {tmp_path / "clash.yaml"}
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
            "a.example",
            443,
            "id",
            raw_link="vless://id@a.example:443",
            country="DE",
        ),
    ]

    def _raising_write(configs: object, path: object) -> int:
        msg = "disk full"
        raise OSError(msg)

    monkeypatch.setattr("src.aggregator.clash.write_clash_subscription", _raising_write)

    result = r._writer._write_clash_output(configs)
    assert result is None
    # The local placeholder is still written (a valid empty YAML document).
    clash = tmp_path / "clash.yaml"
    assert yaml.safe_load(clash.read_text(encoding="utf-8")) == {"proxies": []}
    # The stats entry keeps the failure visible in the run summary.
    assert r._writer.context.output_stats["clash"]["count"] == 0


def test_write_clash_output_success_still_returns_path(
    runner: PipelineRunner, tmp_path: Path
) -> None:
    """A successful Clash write keeps returning the path for publishing."""
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        f"""
publisher:
  output_file: {tmp_path / "combined.txt"}
  clash_output_file: {tmp_path / "clash.yaml"}
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
            "a.example",
            443,
            "id",
            raw_link="vless://id@a.example:443",
            country="DE",
        ),
    ]
    result = r._writer._write_clash_output(configs)
    assert result == str(tmp_path / "clash.yaml")
    assert r._writer.context.output_stats["clash"]["count"] == 1


def test_write_outputs_without_clash_key_skips_yaml(
    runner: PipelineRunner, tmp_path: Path
) -> None:
    """Without clash_output_file the clash stage writes nothing."""
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        f"""
publisher:
  output_file: {tmp_path / "combined.txt"}
  mix_output_file: {tmp_path / "mix.txt"}
  location_outputs_enabled: false
aggregator:
  max_configs_in_output: 5
""",
        encoding="utf-8",
    )
    r = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    assert r._writer._write_clash_output([]) is None
