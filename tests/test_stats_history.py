"""Tests for the run-over-run stats history and the trend SVG."""

from __future__ import annotations

import json

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
    assert entry["lists"]["blacklist"] == {"alive": 190, "checked": 624}
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
