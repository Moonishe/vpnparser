"""Tests for the run-over-run stats history and the trend SVG."""

from __future__ import annotations

import json

import src.scheduler.stats_history as stats_history_module
from src.scheduler.stats_history import (
    append_run_stats,
    load_stats_history,
    render_trend_svg,
    run_stats_entry,
)


def test_run_stats_entry_shape(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "pyproject.toml").write_text("", encoding="utf-8")
    stats = {
        "proxy_count": 28,
        "proxy_networks": 7,
        "lists": {
            "blacklist": {"xray_alive": 190, "xray_checked": 624},
            "whitelist": {"xray_alive": 45, "xray_checked": 300},
            "garbage": "not-a-dict",
        },
    }
    entry = run_stats_entry(stats, "ok", now=1700000000)
    assert entry["ts"] == 1700000000
    assert entry["status"] == "ok"
    assert entry["proxy_count"] == 28
    assert entry["lists"]["blacklist"]["alive"] == 190
    assert entry["lists"]["blacklist"]["checked"] == 624
    # TCP/TLS counters ride along for non-Xray runs (see run_stats_entry).
    assert entry["lists"]["blacklist"]["tcp_alive"] == 0
    assert entry["lists"]["blacklist"]["tls_alive"] == 0
    assert "garbage" not in entry["lists"]


def test_append_loads_appends_and_caps(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "pyproject.toml").write_text("", encoding="utf-8")
    path = str(tmp_path / "stats.json")
    for index in range(5):
        history, written = append_run_stats(
            run_stats_entry({}, "ok", now=1700000000 + index),
            path,
            limit=3,
        )
    assert written == path
    stored = load_stats_history(path)
    assert len(stored) == 3
    assert len(history) == 3
    assert stored[-1]["ts"] == 1700000004


def test_append_run_stats_self_heals_corrupt_bytes(tmp_path, monkeypatch) -> None:
    """One undecodable byte must not kill the history forever.

    UnicodeDecodeError used to escape the loader: the corrupt file survived
    (and rode the Actions cache) while every later run silently stopped
    appending. The loader now treats it as no history and the next append
    overwrites it.
    """
    monkeypatch.chdir(tmp_path)
    (tmp_path / "pyproject.toml").write_text("", encoding="utf-8")
    path = str(tmp_path / "stats.json")
    with open(path, "wb") as fh:
        fh.write(b'\xff\xfe{"truncated"')
    history, written = append_run_stats(run_stats_entry({}, "ok", now=1700000000), path)
    assert written == path
    assert history == [
        {
            "ts": 1700000000,
            "status": "ok",
            "proxy_count": 0,
            "proxy_networks": 0,
            "lists": {},
        }
    ]
    stored = load_stats_history(path)
    assert len(stored) == 1


def test_load_stats_history_garbage(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "pyproject.toml").write_text("", encoding="utf-8")
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert load_stats_history(str(bad)) == []
    bad.write_text(json.dumps({"not": "a list"}), encoding="utf-8")
    assert load_stats_history(str(bad)) == []
    assert load_stats_history(str(tmp_path / "missing.json")) == []


def test_render_trend_svg_writes_file(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "pyproject.toml").write_text("", encoding="utf-8")
    history = [
        run_stats_entry(
            {
                "lists": {
                    "blacklist": {"xray_alive": 10},
                    "whitelist": {"xray_alive": 4},
                }
            },
            "ok",
            now=1700000000,
        ),
        run_stats_entry(
            {
                "lists": {
                    "blacklist": {"xray_alive": 20},
                    "whitelist": {"xray_alive": 6},
                }
            },
            "ok",
            now=1700003600,
        ),
    ]
    svg_path = str(tmp_path / "trend.svg")
    assert render_trend_svg(history, svg_path) == svg_path
    content = (tmp_path / "trend.svg").read_text(encoding="utf-8")
    assert "<svg" in content and "</svg>" in content
    assert "blacklist: 20" in content
    assert "whitelist: 6" in content
    assert "max 20" in content


def test_render_trend_svg_empty_history(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "pyproject.toml").write_text("", encoding="utf-8")
    assert render_trend_svg([], str(tmp_path / "trend.svg")) is None


def test_svg_is_well_formed_xml(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "pyproject.toml").write_text("", encoding="utf-8")
    history = [
        run_stats_entry({"lists": {"blacklist": {"xray_alive": i}}}, "ok")
        for i in range(1, 8)
    ]
    svg_path = str(tmp_path / "trend.svg")
    render_trend_svg(history, svg_path)
    import xml.etree.ElementTree as ET

    ET.parse(svg_path)  # noqa: S314


# ---------------------------------------------------------------------------
# Failure paths
# ---------------------------------------------------------------------------


def test_load_stats_history_unsafe_path(caplog) -> None:
    """A traversal path is refused loudly and counts as no history."""
    caplog.set_level("WARNING")
    assert load_stats_history("../../evil.json") == []
    assert "Unsafe stats history path" in caplog.text


def test_append_run_stats_write_failure(tmp_path, monkeypatch, caplog) -> None:
    """A failed write returns the in-memory history with a None path."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "pyproject.toml").write_text("", encoding="utf-8")
    caplog.set_level("WARNING")

    def _failing_write(_path: object, _content: str, **_kw: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(stats_history_module, "write_text_atomic", _failing_write)
    history, written = append_run_stats(
        run_stats_entry({}, "ok", now=1700000000),
        str(tmp_path / "stats.json"),
    )
    assert written is None
    assert [entry["ts"] for entry in history] == [1700000000]
    assert "Cannot write stats history" in caplog.text


def test_render_trend_svg_skips_series_without_points(tmp_path, monkeypatch) -> None:
    """A series with no drawable points is omitted from the SVG."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "pyproject.toml").write_text("", encoding="utf-8")
    real_points = stats_history_module._series_points

    def _no_whitelist(history, key, *, points):
        return real_points(history, key, points=points) if key == "blacklist" else []

    monkeypatch.setattr(stats_history_module, "_series_points", _no_whitelist)
    history = [
        run_stats_entry(
            {
                "lists": {
                    "blacklist": {"xray_alive": 12},
                    "whitelist": {"xray_alive": 3},
                }
            },
            "ok",
            now=1700000000,
        )
    ]
    svg_path = str(tmp_path / "trend.svg")
    assert render_trend_svg(history, svg_path) == svg_path
    content = (tmp_path / "trend.svg").read_text(encoding="utf-8")
    assert "blacklist: 12" in content
    assert "whitelist:" not in content


def test_render_trend_svg_write_failure(tmp_path, monkeypatch, caplog) -> None:
    """A failed SVG write logs a warning and returns None."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "pyproject.toml").write_text("", encoding="utf-8")
    caplog.set_level("WARNING")

    def _failing_write(_path: object, _content: str, **_kw: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(stats_history_module, "write_text_atomic", _failing_write)
    history = [run_stats_entry({"lists": {"blacklist": {"xray_alive": 1}}}, "ok")]
    assert render_trend_svg(history, str(tmp_path / "trend.svg")) is None
    assert "Cannot write trend SVG" in caplog.text
