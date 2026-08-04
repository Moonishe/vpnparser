"""Tests for health_history.py — 100% coverage."""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.parsers.base import Config
from src.scheduler.health_history import HealthHistory
from src.scheduler.settings import Settings

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(
    address: str = "test.example",
    port: int = 443,
    *,
    is_alive: bool | None = None,
    source_name: str | None = None,
    country: str | None = None,
    latency_ms: float | None = None,
) -> Config:
    return Config(
        protocol="vless",
        address=address,
        port=port,
        uuid_or_password="11111111-1111-4111-8111-111111111111",
        is_alive=is_alive,
        source_name=source_name,
        country=country,
        latency_ms=latency_ms,
    )


def _make_settings(extra: dict | None = None) -> Settings:
    base = {
        "health_history_enabled": True,
        "health_history_file": "output/health-history.json",
        "source_health_enabled": True,
        "ban_after_consecutive_failures": 2,
        "ban_cooldown_hours": 12,
        "source_min_checked": 50,
        "source_bad_alive_rate": 0.02,
        "source_bad_runs_to_ban": 2,
        "source_ban_cooldown_hours": 12,
        "source_good_alive_rate": 0.2,
        "max_latency_ms": 10000.0,
        "health_recent_window": 5,
    }
    if extra:
        base.update(extra)
    return Settings({"quality": base})


# ---------------------------------------------------------------------------
# load()
# ---------------------------------------------------------------------------


class TestLoad:
    """Cover lines 42-43, 50."""

    def test_load_empty_path_returns_empty_cache(self) -> None:
        """load() with falsy path returns {"configs": {}, "sources": {}}."""
        h = HealthHistory(_make_settings({"health_history_file": None}))
        result = h.load()
        assert result == {"configs": {}, "sources": {}}
        assert h._cache == {"configs": {}, "sources": {}}

    def test_load_non_dict_data_coerces_to_empty(self, tmp_path: Path) -> None:
        """load() coerces non-dict JSON to empty dict before setdefault."""
        f = tmp_path / "health.json"
        f.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
        h = HealthHistory(_make_settings({"health_history_file": str(f)}))
        result = h.load()
        assert result == {"configs": {}, "sources": {}}

    def test_load_section_of_wrong_type_is_replaced(
        self,
        tmp_path: Path,
        caplog,
    ) -> None:
        """A list under "configs" is dropped so update() cannot crash on it."""
        caplog.set_level("WARNING")
        f = tmp_path / "health.json"
        f.write_text(json.dumps({"configs": [], "sources": []}), encoding="utf-8")
        h = HealthHistory(_make_settings({"health_history_file": str(f)}))
        assert h.load() == {"configs": {}, "sources": {}}
        assert "expected object" in caplog.text
        # The whole run used to die here with AttributeError.
        h.update([_make_config(is_alive=True)])
        assert not h.is_banned(_make_config(source_name="src"))

    def test_load_drops_malformed_records(self, tmp_path: Path, caplog) -> None:
        """Non-dict records inside a section are dropped with a warning."""
        caplog.set_level("WARNING")
        f = tmp_path / "health.json"
        f.write_text(
            json.dumps(
                {
                    "configs": {"key": "junk", "good": {"passes": 1}},
                    "sources": {"src": ["junk"]},
                },
            ),
            encoding="utf-8",
        )
        h = HealthHistory(_make_settings({"health_history_file": str(f)}))
        data = h.load()
        assert data["configs"] == {"good": {"passes": 1}}
        assert data["sources"] == {}
        assert "malformed record" in caplog.text
        cfg = _make_config(source_name="src", is_alive=False)
        assert h.is_banned(cfg) is False
        h.update([cfg])

    def test_load_zeroes_non_numeric_record_fields(
        self,
        tmp_path: Path,
        caplog,
    ) -> None:
        """A hand-edited numeric field must not abort every following run.

        Editing ``banned_until`` to a date (or any non-number) used to make
        ``is_banned()``/``score()``/``update_sources()`` raise inside the
        pipeline, so every hourly run died until the file was deleted.
        """
        caplog.set_level("WARNING")
        cfg = _make_config(source_name="src-a")
        f = tmp_path / "health.json"
        f.write_text(
            json.dumps(
                {
                    "configs": {
                        HealthHistory.config_key(cfg): {
                            "banned_until": "2026-01-01",
                            "passes": {"a": 1},
                            "recent": "yes",
                        },
                    },
                    "sources": {
                        "src-a": {
                            "banned_until": "later",
                            "runs": "x",
                            "last_alive_rate": "high",
                        },
                    },
                },
            ),
            encoding="utf-8",
        )
        h = HealthHistory(_make_settings({"health_history_file": str(f)}))

        assert h.is_banned(cfg) is False
        assert h.score(cfg) == 0.0
        h.update([cfg])
        h.update_sources([cfg], {})
        assert "non-numeric" in caplog.text

    def test_load_keeps_numeric_strings(self, tmp_path: Path) -> None:
        """Values ``int()`` accepts stay meaningful instead of being zeroed."""
        cfg = _make_config(source_name="src-a")
        f = tmp_path / "health.json"
        f.write_text(
            json.dumps(
                {
                    "configs": {
                        HealthHistory.config_key(cfg): {"banned_until": "9999999999"}
                    }
                },
            ),
            encoding="utf-8",
        )
        h = HealthHistory(_make_settings({"health_history_file": str(f)}))
        assert h.is_banned(cfg) is True

    def test_load_keeps_null_numeric_fields(self, tmp_path: Path) -> None:
        """``null`` stays ``null``: every reader already treats it as zero."""
        cfg = _make_config(source_name="src-a")
        f = tmp_path / "health.json"
        f.write_text(
            json.dumps(
                {
                    "configs": {
                        HealthHistory.config_key(cfg): {"banned_until": None},
                    },
                    "sources": {"src-a": {"last_alive_rate": None}},
                },
            ),
            encoding="utf-8",
        )
        h = HealthHistory(_make_settings({"health_history_file": str(f)}))
        data = h.load()
        assert data["configs"][HealthHistory.config_key(cfg)] == {"banned_until": None}
        assert data["sources"]["src-a"] == {"last_alive_rate": None}
        assert h.is_banned(cfg) is False
        assert h.score(cfg) == 0.0


# ---------------------------------------------------------------------------
# save()
# ---------------------------------------------------------------------------


class TestSave:
    """Cover lines 59, 69-71, 72."""

    def test_save_no_path_returns_none(self) -> None:
        """save() returns None when health_history_file is falsy."""
        h = HealthHistory(_make_settings({"health_history_file": None}))
        assert h.save() is None

    def test_save_no_cache_returns_none(self) -> None:
        """save() returns None when _cache is None (load not called)."""
        h = HealthHistory(_make_settings({"health_history_file": "output/h.json"}))
        # _cache is None because load() was never called
        assert h.save() is None

    def test_save_success(self, tmp_path: Path) -> None:
        """save() writes file and returns the path string."""
        f = tmp_path / "health-history.json"
        h = HealthHistory(_make_settings({"health_history_file": str(f)}))
        h.load()  # populate _cache
        result = h.save()
        assert result is not None
        assert Path(result).exists()

    def test_save_prunes_records_unseen_past_retention(self, tmp_path: Path) -> None:
        """Stale records are dropped so the published file stops growing."""
        now = int(time.time())
        f = tmp_path / "health-history.json"
        f.write_text(
            json.dumps(
                {
                    "configs": {
                        "fresh": {"last_seen": now - 3600, "banned_until": 0},
                        "stale": {"last_seen": now - 40 * 86400, "banned_until": 0},
                        # Still banned: the ban is why the config is skipped,
                        # so dropping it would silently unban it.
                        "stale_but_banned": {
                            "last_seen": now - 40 * 86400,
                            "banned_until": now + 3600,
                        },
                    },
                    "sources": {},
                },
            ),
            encoding="utf-8",
        )
        h = HealthHistory(
            _make_settings(
                {"health_history_file": str(f), "health_history_retention_days": 30},
            ),
        )
        h.load()

        assert h.save() is not None

        kept = json.loads(f.read_text(encoding="utf-8"))["configs"]
        assert set(kept) == {"fresh", "stale_but_banned"}

    def test_prune_drops_stale_source_records(self, tmp_path: Path) -> None:
        """Stale source records age out; recent and still-banned sources stay."""
        now = int(time.time())
        f = tmp_path / "health-history.json"
        h = HealthHistory(
            _make_settings(
                {"health_history_file": str(f), "health_history_retention_days": 30},
            ),
        )
        h.load()
        h._cache["configs"] = {
            "a": {"last_seen": now - 3600, "banned_until": 0},
        }
        h._cache["sources"] = {
            "fresh": {"updated_at": now - 3600, "banned_until": 0},
            "stale": {"updated_at": now - 40 * 86400, "banned_until": 0},
            # Still banned: the ban is why the source is skipped, so dropping it
            # would silently unban it.
            "stale_but_banned": {
                "updated_at": now - 40 * 86400,
                "banned_until": now + 3600,
            },
        }

        assert h.prune(now=now) == 1  # only the stale, unbanned source
        assert set(h._cache["sources"]) == {"fresh", "stale_but_banned"}

    def test_prune_keeps_everything_within_retention(self, tmp_path: Path) -> None:
        """A short-lived history is left untouched."""
        now = int(time.time())
        f = tmp_path / "health-history.json"
        f.write_text(
            json.dumps(
                {"configs": {"a": {"last_seen": now - 86400}}, "sources": {}},
            ),
            encoding="utf-8",
        )
        h = HealthHistory(_make_settings({"health_history_file": str(f)}))
        h.load()

        assert h.prune(now=now) == 0

    def test_save_exception_logs_warning(self, monkeypatch, caplog) -> None:
        """save() catches OSError, logs warning, returns None."""
        h = HealthHistory(_make_settings({"health_history_file": "output/h.json"}))
        h.load()  # populate _cache

        mock_path = MagicMock()
        mock_path.parent = mock_path
        mock_path.write_text.side_effect = OSError("mock write error")
        monkeypatch.setattr(
            "src.scheduler.health_history.resolve_safe_output_path",
            lambda p: mock_path,
        )

        result = h.save()
        assert result is None
        assert "Could not write health history" in caplog.text


# ---------------------------------------------------------------------------
# is_banned()
# ---------------------------------------------------------------------------


class TestIsBanned:
    """Cover lines 94, 104-105."""

    def test_is_banned_disabled(self) -> None:
        """is_banned returns False when health_history_enabled=False."""
        h = HealthHistory(_make_settings({"health_history_enabled": False}))
        cfg = _make_config()
        assert h.is_banned(cfg) is False

    def test_is_banned_source_ban(self) -> None:
        """is_banned returns True when source record has banned_until > now."""
        h = HealthHistory(_make_settings())
        cfg = _make_config(source_name="bad_source")
        h.load()["sources"]["bad_source"] = {"banned_until": 9_999_999_999}
        assert h.is_banned(cfg) is True
        assert cfg.quality_block_reason == "source_ban"


# ---------------------------------------------------------------------------
# update()
# ---------------------------------------------------------------------------


class TestUpdate:
    """Cover lines 110, 153-155."""

    def test_update_disabled(self) -> None:
        """update returns early when health_history_enabled=False."""
        h = HealthHistory(_make_settings({"health_history_enabled": False}))
        h.update([_make_config(is_alive=True)])
        # No exception means success
        assert h._cache is None  # cache never populated

    def test_update_alive_config(self) -> None:
        """update increments passes, resets consecutive_failures and ban."""
        h = HealthHistory(
            _make_settings(
                {"ban_after_consecutive_failures": 2, "health_recent_window": 3}
            ),
        )
        cfg = _make_config(is_alive=True)
        h.update([cfg])
        record = cfg.health_record
        assert record is not None
        assert record["passes"] == 1
        assert record["consecutive_failures"] == 0
        assert record["banned_until"] == 0
        assert record["recent"] == [True]
        assert record["last_alive"] > 0


# ---------------------------------------------------------------------------
# update_sources()
# ---------------------------------------------------------------------------


class TestUpdateSources:
    """Cover lines 186, 226-228, 230-231."""

    def test_update_sources_disabled_returns_early(self) -> None:
        """update_sources returns early when source_health_enabled=False."""
        h = HealthHistory(
            _make_settings(
                {"source_health_enabled": False, "health_history_enabled": True}
            ),
        )
        cfg = _make_config(is_alive=True, source_name="test_src")
        list_stats: dict = {}
        h.update_sources([cfg], list_stats)
        # sources key IS set before the early return
        assert "sources" in list_stats

    def test_update_sources_bans_bad_source(self) -> None:
        """update_sources bans a source with consistently bad alive rate."""
        h = HealthHistory(
            _make_settings(
                {
                    "source_min_checked": 1,
                    "source_bad_alive_rate": 0.5,
                    "source_bad_runs_to_ban": 2,
                }
            ),
        )
        cfg = _make_config(is_alive=False, source_name="bad_src")

        # First run: bad_runs becomes 1
        h.update_sources([cfg], {})
        history = h.load()
        assert history["sources"]["bad_src"]["bad_runs"] == 1
        assert history["sources"]["bad_src"]["banned_until"] == 0

        # Second run: bad_runs becomes 2, source gets banned
        h.update_sources([cfg], {})
        history = h.load()
        assert history["sources"]["bad_src"]["bad_runs"] == 2
        assert history["sources"]["bad_src"]["banned_until"] > 0

    def test_update_sources_good_source_resets_bad_runs(self) -> None:
        """update_sources resets bad_runs for a good source (covers else branch)."""
        h = HealthHistory(
            _make_settings(
                {
                    "source_min_checked": 1,
                    "source_bad_alive_rate": 0.5,
                    "source_bad_runs_to_ban": 2,
                }
            ),
        )
        cfg = _make_config(is_alive=True, source_name="good_src")

        # First run: good rate (1/1 = 1.0 > 0.5) → else branch
        h.update_sources([cfg], {})
        history = h.load()
        assert history["sources"]["good_src"]["bad_runs"] == 0
        assert history["sources"]["good_src"]["banned_until"] == 0

    def test_update_sources_small_sample_keeps_ban(self) -> None:
        """A run with too few checks neither lifts the ban nor clears bad_runs."""
        h = HealthHistory(
            _make_settings(
                {
                    "source_min_checked": 50,
                    "source_bad_alive_rate": 0.02,
                    "source_bad_runs_to_ban": 2,
                }
            ),
        )
        banned_until = 9_999_999_999
        h.load()["sources"]["banned_src"] = {
            "runs": 5,
            "bad_runs": 2,
            "banned_until": banned_until,
        }
        cfg = _make_config(is_alive=True, source_name="banned_src")

        h.update_sources([cfg], {})

        record = h.load()["sources"]["banned_src"]
        assert record["bad_runs"] == 2
        assert record["banned_until"] == banned_until
        assert record["runs"] == 6
        assert h.is_banned(_make_config(source_name="banned_src")) is True

    def test_update_sources_confirmed_good_run_lifts_ban(self) -> None:
        """A run with a sufficient sample and good rate clears the ban."""
        h = HealthHistory(
            _make_settings(
                {
                    "source_min_checked": 3,
                    "source_bad_alive_rate": 0.02,
                    "source_bad_runs_to_ban": 2,
                }
            ),
        )
        h.load()["sources"]["banned_src"] = {
            "runs": 5,
            "bad_runs": 2,
            "banned_until": 9_999_999_999,
        }
        configs = [
            _make_config(
                f"h{i}.example", 4000 + i, is_alive=True, source_name="banned_src"
            )
            for i in range(3)
        ]

        h.update_sources(configs, {})

        record = h.load()["sources"]["banned_src"]
        assert record["bad_runs"] == 0
        assert record["banned_until"] == 0


# ---------------------------------------------------------------------------
# score()
# ---------------------------------------------------------------------------


class TestScore:
    """Cover lines 239, 258, 262."""

    def test_score_recent_alive_bonus(self) -> None:
        """score adds 20 when >=2 of last 3 recent entries are alive."""
        h = HealthHistory(_make_settings())
        cfg = _make_config(is_alive=True)
        history = h.load()
        history["configs"][h.config_key(cfg)] = {"recent": [True, True, False]}
        s = h.score(cfg)
        # base 60 (alive) + 20 (recent bonus) = 80
        assert s == pytest.approx(80.0)

    def test_score_source_rate_bonus(self) -> None:
        """score adds 5 when source last_alive_rate >= 0.2."""
        h = HealthHistory(_make_settings())
        cfg = _make_config(is_alive=True, source_name="good_src", country="DE")
        history = h.load()
        history["sources"]["good_src"] = {"last_alive_rate": 0.5}
        s = h.score(cfg)
        # base 60 + 5 (country) + 5 (source_rate) = 70
        assert s == pytest.approx(70.0)

    def test_score_proxy_checks_bonus(self) -> None:
        """score adds up to 5 based on proxy success ratio."""
        h = HealthHistory(_make_settings())
        cfg = _make_config(is_alive=True)
        cfg.xray_proxy_checks = 10
        cfg.xray_proxy_successes = 5
        s = h.score(cfg)
        # base 60 + (5/10 * 5 = 2.5) = 62.5
        assert s == pytest.approx(62.5)

    # ---- Remaining uncovered lines ----

    def test_is_banned_config_ban(self, tmp_path) -> None:
        """is_banned returns True when config health_ban is active."""
        f = tmp_path / "ban" / "health.json"
        f.parent.mkdir(parents=True, exist_ok=True)
        cfg = _make_config(address="banned.example.com")
        key = HealthHistory.config_key(cfg)
        now = int(__import__("time").time())
        f.write_text(
            json.dumps(
                {
                    "configs": {
                        key: {
                            "banned_until": now + 3600,
                        },
                    },
                }
            ),
            encoding="utf-8",
        )
        hh = HealthHistory(Settings({"quality": {"health_history_file": str(f)}}))
        assert hh.is_banned(cfg)
        assert cfg.quality_block_reason == "health_ban"

    def test_is_banned_no_ban(self, tmp_path) -> None:
        """is_banned returns False when health enabled but no bans exist."""
        f = tmp_path / "noban" / "health.json"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(json.dumps({"configs": {}, "sources": {}}), encoding="utf-8")
        hh = HealthHistory(Settings({"quality": {"health_history_file": str(f)}}))
        cfg = _make_config(address="clean.example.com")
        assert not hh.is_banned(cfg)

    def test_update_dead_config_banned(self, tmp_path) -> None:
        """update with dead config increments failures and bans when threshold met."""
        f = tmp_path / "dead" / "health.json"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(json.dumps({"configs": {}, "sources": {}}), encoding="utf-8")
        settings = Settings(
            {
                "quality": {
                    "health_history_file": str(f),
                    "ban_after_consecutive_failures": 1,
                    "cooldown_seconds": 60,
                },
            }
        )
        hh = HealthHistory(settings)
        cfg = _make_config(address="dead.example.com")
        cfg.is_alive = False
        hh.update([cfg])
        key = HealthHistory.config_key(cfg)
        record = hh.load()["configs"][key]
        assert record["consecutive_failures"] == 1
        assert record["banned_until"] > 0

    def test_score_latency_bonus(self) -> None:
        """score adds latency bonus when latency_ms is below max_latency."""
        h = HealthHistory(_make_settings())
        cfg = _make_config(is_alive=True)
        cfg.latency_ms = 100.0
        s = h.score(cfg)
        # base 60 + latency: 10*(1 - 100/10000) = 10*0.99 = 9.9
        assert s == pytest.approx(69.9, rel=1e-3)


# ---------------------------------------------------------------------------
# load() — a broken history file must never vanish silently
# ---------------------------------------------------------------------------


class TestLoadReportsUnreadableFile:
    """A truncated file is overwritten by the next save(), so it must be logged."""

    def test_corrupt_json_is_reported(self, tmp_path: Path, caplog) -> None:
        """Every accumulated ban used to disappear without a single message."""
        caplog.set_level("WARNING")
        f = tmp_path / "health.json"
        f.write_text('{"configs": {"aaa": {"passes": 5, "conse', encoding="utf-8")
        h = HealthHistory(_make_settings({"health_history_file": str(f)}))

        assert h.load() == {"configs": {}, "sources": {}}
        assert "Failed to load health history" in caplog.text

    def test_unsafe_path_is_reported(self, caplog) -> None:
        """A traversal path is refused loudly instead of loading nothing."""
        caplog.set_level("WARNING")
        h = HealthHistory(_make_settings({"health_history_file": "../../evil.json"}))

        assert h.load() == {"configs": {}, "sources": {}}
        assert "Unsafe health history path" in caplog.text

    def test_missing_file_stays_silent(self, tmp_path: Path, caplog) -> None:
        """A first run has no history file — that is not a problem."""
        caplog.set_level("WARNING")
        h = HealthHistory(
            _make_settings({"health_history_file": str(tmp_path / "none.json")}),
        )

        assert h.load() == {"configs": {}, "sources": {}}
        assert "health history" not in caplog.text
