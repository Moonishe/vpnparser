"""Regression tests for quality/health stage being too aggressive.

Task 0001: ensure the pipeline does not drop the last alive configs as "slow",
relax health history bans when few Xray configs survive, and still publishes
configs when Xray proves any of them work.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.parsers.base import Config
from src.scheduler.runner import PipelineRunner


def _vless(addr: str, latency_ms: float | None = None, is_alive: bool = True) -> Config:
    return Config(
        protocol="vless",
        address=addr,
        port=443,
        uuid_or_password="11111111-1111-4111-8111-111111111111",
        country="DE",
        security="tls",
        raw_link=f"vless://11111111-1111-4111-8111-111111111111@{addr}:443#DE-01",
        latency_ms=latency_ms,
        is_alive=is_alive,
    )


def test_quality_preserves_last_slow_configs(tmp_path) -> None:
    """If all surviving configs exceed max_latency, the last ones are kept."""
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        """
quality:
  health_history_enabled: true
  max_latency_ms: 10000
  drop_slow_configs: true
  min_alive_to_skip_slow_drop: 1
""",
        encoding="utf-8",
    )
    runner = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    slow1 = _vless("slow1.example", latency_ms=20000)
    slow2 = _vless("slow2.example", latency_ms=30000)

    filtered = runner._apply_quality_filters({"whitelist": [slow1, slow2]})

    assert "whitelist" in filtered
    assert len(filtered["whitelist"]) == 2
    assert runner._liveness_stats["quality"]["whitelist"]["slow_dropped"] == 0
    assert runner._liveness_stats["quality"]["slow_preserved"]["whitelist"] == 2


def test_quality_still_drops_slow_when_fast_configs_exist(tmp_path) -> None:
    """Slow configs are still dropped when fast configs keep the list alive."""
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        """
quality:
  health_history_enabled: true
  max_latency_ms: 10000
  drop_slow_configs: true
  min_alive_to_skip_slow_drop: 1
""",
        encoding="utf-8",
    )
    runner = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    fast = _vless("fast.example", latency_ms=1000)
    slow = _vless("slow.example", latency_ms=20000)

    filtered = runner._apply_quality_filters({"blacklist": [slow, fast]})

    assert filtered == {"blacklist": [fast]}
    assert runner._liveness_stats["quality"]["blacklist"]["slow_dropped"] == 1


def _setup_banned_config(runner, cfg) -> None:
    """Seed a health-history ban on cfg and freeze it for the Xray stage."""
    cfg.is_alive = False
    runner._update_health_history([cfg])
    runner._update_health_history([cfg])
    assert runner._is_health_or_source_banned(cfg) is True


def test_health_ban_skipped_when_few_xray_alive(tmp_path, monkeypatch) -> None:
    """Health/source bans are not applied when Xray finds few alive configs."""
    settings = tmp_path / "settings.yaml"
    health_file = tmp_path / "health-history.json"
    settings.write_text(
        f"""
quality:
  health_history_enabled: true
  health_history_file: {health_file}
  ban_after_consecutive_failures: 2
  ban_cooldown_hours: 12
  health_ban_min_alive: 3
validator:
  allowed_countries: []
  xray_enabled: true
  xray_executable: /usr/bin/xray
  proxy_pool:
    enabled: false
""",
        encoding="utf-8",
    )
    runner = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    cfg = _vless("banned.example")
    _setup_banned_config(runner, cfg)
    # Preserve the pre-existing ban during the Xray stage (a real prior run
    # would have written this to disk and the current run would load it).
    monkeypatch.setattr(runner, "_update_health_history", lambda _configs: None)
    monkeypatch.setattr(runner, "_update_source_health", lambda _c, _s: None)

    async def fake_validate_configs_xray(configs, **kwargs):
        for item in configs:
            item.xray_was_checked = True
            item.is_alive = True
        return list(configs)

    monkeypatch.setattr(
        "src.validators.xray_probe.find_xray_executable",
        lambda explicit_path=None: "/usr/bin/xray",
    )
    monkeypatch.setattr("src.validators.xray_probe.is_xray_supported", lambda cfg: True)
    monkeypatch.setattr(
        "src.validators.xray_probe.validate_configs_xray",
        fake_validate_configs_xray,
    )

    result = asyncio.run(
        runner._validate_liveness_configs(
            [cfg],
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
    )

    stats = runner._liveness_stats["lists"]["blacklist"]
    assert result == [cfg]
    assert stats["xray_alive"] == 1
    assert stats["output_after_health"] == 1


def test_health_ban_applied_when_many_xray_alive(tmp_path, monkeypatch) -> None:
    """Health/source bans are applied when Xray finds more than the threshold."""
    settings = tmp_path / "settings.yaml"
    health_file = tmp_path / "health-history.json"
    settings.write_text(
        f"""
quality:
  health_history_enabled: true
  health_history_file: {health_file}
  ban_after_consecutive_failures: 2
  ban_cooldown_hours: 12
  health_ban_min_alive: 3
validator:
  allowed_countries: []
  xray_enabled: true
  xray_executable: /usr/bin/xray
  proxy_pool:
    enabled: false
""",
        encoding="utf-8",
    )
    runner = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(tmp_path / "missing.json"),
    )
    cfg = _vless("banned.example")
    _setup_banned_config(runner, cfg)
    monkeypatch.setattr(runner, "_update_health_history", lambda _configs: None)
    monkeypatch.setattr(runner, "_update_source_health", lambda _c, _s: None)

    others = [_vless(f"other{i}.example") for i in range(3)]
    all_configs = [cfg, *others]

    async def fake_validate_configs_xray(configs, **kwargs):
        for item in configs:
            item.xray_was_checked = True
            item.is_alive = True
        return list(configs)

    monkeypatch.setattr(
        "src.validators.xray_probe.find_xray_executable",
        lambda explicit_path=None: "/usr/bin/xray",
    )
    monkeypatch.setattr("src.validators.xray_probe.is_xray_supported", lambda cfg: True)
    monkeypatch.setattr(
        "src.validators.xray_probe.validate_configs_xray",
        fake_validate_configs_xray,
    )

    result = asyncio.run(
        runner._validate_liveness_configs(
            all_configs,
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
    )

    # 4 alive configs > health_ban_min_alive=3, so the banned config is removed.
    assert len(result) == 3
    assert cfg not in result


if __name__ == "__main__":
    import pytest

    pytest.main([__file__, "-v", "-s"])
