"""Tests for liveness.py — 100% coverage."""

from __future__ import annotations

import asyncio
import logging
import time
from unittest.mock import MagicMock

import pytest

from src.parsers.base import Config
from src.scheduler.context import PipelineContext, PipelineState
from src.scheduler.health_history import HealthHistory
from src.scheduler.settings import Settings
from src.scheduler.stages.liveness import LivenessValidator

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_context(settings_dict: dict | None = None) -> PipelineContext:
    return PipelineContext(
        settings=Settings(settings_dict or {}),
        github_token=None,
        sources_path="missing.json",
    )


def _make_config(
    address: str = "test.example",
    port: int = 443,
    *,
    protocol: str = "vless",
    security: str = "none",
    is_alive: bool | None = None,
    source_name: str | None = None,
    country: str | None = None,
    latency_ms: float | None = None,
) -> Config:
    return Config(
        protocol=protocol,
        address=address,
        port=port,
        uuid_or_password="11111111-1111-4111-8111-111111111111",
        security=security,
        is_alive=is_alive,
        source_name=source_name,
        country=country,
        latency_ms=latency_ms,
    )


def _make_liveness(
    settings_dict: dict | None = None,
    **kwargs,
) -> LivenessValidator:
    context = _make_context(settings_dict)
    return LivenessValidator(context, **kwargs)


async def _empty_proxy_list() -> list[str]:
    return []


async def _mock_validate_tcp_returns(configs_to_return: list[Config] | None = None):
    """Return an async mock for validate_configs_tcp."""
    if configs_to_return is None:
        configs_to_return = []

    async def mock_tcp(batch, **kwargs):
        return list(configs_to_return)

    return mock_tcp


async def _mock_validate_tls_returns(configs_to_return: list[Config] | None = None):
    """Return an async mock for validate_configs_tls."""
    if configs_to_return is None:
        configs_to_return = []

    async def mock_tls(configs, **kwargs):
        return list(configs_to_return)

    return mock_tls


# ============================================================================
# LivenessValidator.run (lines 48-49)
# ============================================================================


class TestRun:
    """The generic ``run(state)`` form is not part of the liveness contract."""

    async def test_default_run_raises_not_implemented(self) -> None:
        """The runner calls validate_by_list directly; run() must not pretend otherwise."""
        lv = _make_liveness()
        state = PipelineState(preprocessed={"blacklist": []})
        with pytest.raises(NotImplementedError):
            await lv.run(state)


# ============================================================================
# _source_list (lines 70-77)
# ============================================================================


class TestSourceList:
    """Cover lines 70-77."""

    def test_source_list_none_returns_none(self) -> None:
        lv = _make_liveness()
        assert lv._source_list(None) is None

    def test_source_list_str_nonempty(self) -> None:
        lv = _make_liveness()
        assert lv._source_list("abc") == ["abc"]

    def test_source_list_str_empty(self) -> None:
        lv = _make_liveness()
        assert lv._source_list("  ") == []

    def test_source_list_list_filters_empty(self) -> None:
        lv = _make_liveness()
        assert lv._source_list(["a", "", "b", "  "]) == ["a", "b"]

    def test_source_list_other_type(self) -> None:
        lv = _make_liveness()
        assert lv._source_list(42) == []


# ============================================================================
# _liveness_min_alive (line 81)
# ============================================================================


class TestBanPrefilter:
    """Configs with an active health ban are skipped before any probing."""

    def _seed_health(self, tmp_path, configs_to_ban):
        settings = Settings(
            {
                "quality": {
                    "health_history_enabled": True,
                    "health_history_file": str(tmp_path / "health.json"),
                    "source_health_enabled": False,
                    "ban_after_consecutive_failures": 2,
                },
            },
        )
        health = HealthHistory(settings)
        for cfg in configs_to_ban:
            cfg.is_alive = False
            # Two consecutive failed runs is the ban threshold (see settings).
            health.update([cfg])
            health.update([cfg])
        return health

    async def test_banned_configs_skipped_before_tcp(
        self, tmp_path, monkeypatch
    ) -> None:
        """A config-level ban keeps the config out of the TCP batch entirely."""
        banned = _make_config("banned.example", 443, protocol="vless")
        health = self._seed_health(tmp_path, [banned])
        assert health.is_config_banned(banned) is True

        lv = LivenessValidator(
            _make_context(
                {
                    "validator": {
                        "tcp_enabled": True,
                        "tcp_candidate_limit": 0,
                    },
                    "quality": {
                        # Exempt the small-list guard so the two-config list
                        # still exercises the pre-filter.
                        "health_ban_min_alive": 0,
                    },
                },
            ),
            health=health,
            proxy_url_getter=_empty_proxy_list,
        )
        seen_batches: list[list[Config]] = []

        async def mock_tcp(batch, **kwargs):
            seen_batches.append(list(batch))
            return list(batch)

        monkeypatch.setattr(
            "src.validators.tcp_check.validate_configs_tcp",
            mock_tcp,
        )

        fresh = _make_config("fresh.example", 443, protocol="vless")
        result = await lv.validate_configs(
            [banned, fresh],
            label="blacklist",
            tcp_enabled=True,
            tls_enabled=False,
        )
        assert all(banned not in batch for batch in seen_batches)
        assert fresh in seen_batches[0]
        assert fresh in result
        stats = lv.context.liveness_stats["lists"]["blacklist"]
        assert stats["ban_prefiltered"] == 1

    async def test_source_banned_configs_are_not_prefiltered(
        self, tmp_path, monkeypatch
    ) -> None:
        """A source ban must not pre-filter: a live probe outranks it."""
        health = HealthHistory(
            Settings(
                {
                    "quality": {
                        "health_history_enabled": True,
                        "health_history_file": str(tmp_path / "health.json"),
                        "source_health_enabled": True,
                        "source_health_history_file": str(tmp_path / "health.json"),
                    },
                },
            ),
        )
        health.load()["sources"]["dead_src"] = {"banned_until": 9_999_999_999}

        lv = LivenessValidator(
            _make_context(
                {
                    "validator": {
                        "tcp_enabled": True,
                        "tcp_candidate_limit": 0,
                    },
                },
            ),
            health=health,
            proxy_url_getter=_empty_proxy_list,
        )
        seen: list[Config] = []

        async def mock_tcp(batch, **kwargs):
            seen.extend(batch)
            return list(batch)

        monkeypatch.setattr(
            "src.validators.tcp_check.validate_configs_tcp",
            mock_tcp,
        )

        cfg = _make_config("from-banned-source.example", 443, source_name="dead_src")
        await lv.validate_configs(
            [cfg],
            label="blacklist",
            tcp_enabled=True,
            tls_enabled=False,
        )
        assert cfg in seen
        assert "ban_prefiltered" not in lv.context.liveness_stats["lists"]["blacklist"]


class TestLivenessMinAlive:
    """Cover line 81."""

    def test_total_zero_returns_zero(self) -> None:
        lv = _make_liveness()
        assert lv._liveness_min_alive(0) == 0


# ============================================================================
# _proxy_health_config (line 103)
# ============================================================================


class TestProxyHealthConfig:
    """Cover line 103."""

    def test_health_not_dict_defaults_to_empty(self) -> None:
        lv = _make_liveness(
            {
                "validator": {
                    "proxy_pool": {
                        "health": "not-a-dict",
                    },
                },
            }
        )
        cfg = lv._proxy_health_config()
        assert cfg["health_enabled"] is True


# ============================================================================
# _init_proxy_health_history (lines 111-112, 115)
# ============================================================================


class TestInitProxyHealthHistory:
    """Cover lines 111-112, 115."""

    def test_import_error_returns_early(self, monkeypatch) -> None:
        lv = _make_liveness()
        # Reset so we can verify the import error path clears nothing
        lv._proxy_health_history = None
        import src.validators.proxy_health as ph_mod

        monkeypatch.delattr(ph_mod, "ProxyHealthHistory", raising=False)
        lv._init_proxy_health_history()
        assert lv._proxy_health_history is None

    def test_health_disabled_returns_early(self, monkeypatch) -> None:
        lv = _make_liveness(
            {
                "validator": {
                    "proxy_pool": {
                        "health": {"health_enabled": False},
                    },
                },
            }
        )
        mock_history = MagicMock()
        monkeypatch.setattr(
            "src.validators.proxy_health.ProxyHealthHistory",
            mock_history,
        )
        lv._init_proxy_health_history()
        assert lv._proxy_health_history is None


# ============================================================================
# save_proxy_health_history (lines 133-138)
# ============================================================================


class TestSaveProxyHealthHistory:
    """Cover lines 133-138."""

    def test_history_none_returns_early(self) -> None:
        lv = _make_liveness()
        lv._proxy_health_history = None
        lv._proxy_health_file = "some/path"
        lv.save_proxy_health_history()  # should not raise

    def test_no_file_returns_early(self) -> None:
        lv = _make_liveness()
        lv._proxy_health_history = MagicMock()
        lv._proxy_health_file = None
        lv.save_proxy_health_history()  # should not raise

    def test_save_success(self) -> None:
        lv = _make_liveness()
        mock_history = MagicMock()
        lv._proxy_health_history = mock_history
        lv._proxy_health_file = "/tmp/test.json"
        lv.save_proxy_health_history()
        mock_history.save.assert_called_once_with("/tmp/test.json")

    def test_save_exception_logs_warning(self, caplog) -> None:
        lv = _make_liveness()
        mock_history = MagicMock()
        mock_history.save.side_effect = OSError("mock error")
        lv._proxy_health_history = mock_history
        lv._proxy_health_file = "/tmp/test.json"
        caplog.set_level(logging.WARNING)
        lv.save_proxy_health_history()
        assert "Could not save proxy health history" in caplog.text


# ============================================================================
# _redact_proxy_url (lines 142-155, especially 146)
# ============================================================================


class TestRedactProxyUrl:
    """Cover lines 142-155, especially 146."""

    def test_invalid_url(self) -> None:
        result = LivenessValidator._redact_proxy_url("not-a-url")
        assert result == "<invalid-proxy-url>"

    def test_valid_url_no_port(self) -> None:
        result = LivenessValidator._redact_proxy_url("socks5://proxy.example.com")
        assert result == "socks5://proxy.example.com"

    def test_valid_url_with_port(self) -> None:
        result = LivenessValidator._redact_proxy_url("socks5://proxy.example.com:1080")
        assert result == "socks5://proxy.example.com:1080"

    def test_ipv6_host(self) -> None:
        result = LivenessValidator._redact_proxy_url("socks5://[::1]:1080")
        assert result == "socks5://[::1]:1080"


# ============================================================================
# _search_validator_proxy_pool (lines 164-261, especially 251, 254)
# ============================================================================


class TestSearchValidatorProxyPool:
    """Cover lines 164-261, especially 251, 254."""

    async def test_retry_delay_sleeps_on_retry(self, monkeypatch) -> None:
        """retry_delay > 0 triggers sleep between rounds."""
        lv = _make_liveness()
        pool_cfg: dict = {
            "max_proxies": 20,
            "min_proxies": 5,
            "search_rounds": 2,
            "candidate_growth_factor": 2.0,
            "retry_delay_seconds": 0.01,
            "max_candidates": 200,
            "max_candidates_per_source": 80,
            "fetch_timeout_seconds": 10.0,
            "validate": True,
            "validation_timeout_seconds": 5.0,
            "validation_concurrency": 50,
        }

        call_count = 0

        async def mock_load(sources=None, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return []
            # Distinct URLs: the real loader deduplicates, and the search's
            # monotonic merge keeps first-seen order per unique proxy.
            return [f"socks5://p{i}:1080" for i in range(10)]

        sleep_log: list[float] = []
        original_sleep = asyncio.sleep

        async def track_sleep(delay):
            sleep_log.append(delay)
            await original_sleep(delay)

        monkeypatch.setattr(asyncio, "sleep", track_sleep)

        result = await lv._search_validator_proxy_pool(mock_load, None, pool_cfg)
        assert len(result) >= 5
        assert len(sleep_log) == 1

    async def test_warning_when_below_min_proxies(self, caplog) -> None:
        """Warning logged when pool search returns too few proxies."""
        lv = _make_liveness()
        pool_cfg: dict = {
            "max_proxies": 20,
            "min_proxies": 5,
            "search_rounds": 1,
            "candidate_growth_factor": 2.0,
            "retry_delay_seconds": 0.0,
            "max_candidates": 200,
            "max_candidates_per_source": 80,
            "fetch_timeout_seconds": 10.0,
            "validate": True,
            "validation_timeout_seconds": 5.0,
            "validation_concurrency": 50,
        }

        async def mock_load(sources=None, **kwargs):
            return []

        caplog.set_level(logging.WARNING)
        result = await lv._search_validator_proxy_pool(mock_load, None, pool_cfg)
        assert result == []
        assert "Proxy pool search found only" in caplog.text

    async def test_stats_are_updated(self) -> None:
        """liveness_stats are updated with search metadata."""
        lv = _make_liveness()
        pool_cfg: dict = {
            "max_proxies": 20,
            "min_proxies": 5,
            "search_rounds": 1,
            "candidate_growth_factor": 2.0,
            "retry_delay_seconds": 0.0,
            "max_candidates": 200,
            "max_candidates_per_source": 80,
            "fetch_timeout_seconds": 10.0,
            "validate": True,
            "validation_timeout_seconds": 5.0,
            "validation_concurrency": 50,
        }

        async def mock_load(sources=None, **kwargs):
            return ["socks5://p1:1080"] * 10

        await lv._search_validator_proxy_pool(mock_load, None, pool_cfg)
        stats = lv.context.liveness_stats
        assert stats["proxy_search_rounds"] == 1
        assert len(stats["proxy_search"]) == 1


# ============================================================================
# _validator_proxy_urls (lines 266, 277, 289-306, 311)
# ============================================================================


class TestXrayPoolRefill:
    """A depleted probe pool is rebuilt from fresh sources before Xray."""

    async def test_refill_when_fewer_than_half_alive(self, monkeypatch) -> None:
        """Recheck leaving <probe_count/2 alive triggers a pool rebuild."""
        calls: list[str] = []

        async def _pool() -> list[str]:
            calls.append("getter")
            return [f"socks5://fresh{i}:1080" for i in range(8)]

        async def _fake_revalidate(proxies, *, max_proxies, history=None, **kwargs):
            # Only 2 of 8 rechecked proxies survive (< half of probe_count=8).
            return proxies[:2]

        lv = _make_liveness(
            {
                "validator": {
                    "xray_enabled": True,
                    "xray_executable": "/usr/bin/xray",
                    "xray_probe_via_proxies": True,
                    "xray_proxy_probe_count": 8,
                },
                "proxy_pool": {"enabled": True, "required": True},
            },
            proxy_url_getter=_pool,
        )
        lv._validator_proxy_urls_cache = [f"socks5://stale{i}:1080" for i in range(8)]
        monkeypatch.setattr(
            "src.validators.proxy_pool.validate_proxy_candidates",
            _fake_revalidate,
        )

        async def mock_xray(configs, **kwargs):
            # The stage must probe through the REFILLED pool slice.
            assert list(kwargs.get("probe_proxy_urls") or []) == [
                f"socks5://fresh{i}:1080" for i in range(8)
            ]
            return []

        monkeypatch.setattr(
            "src.validators.xray_probe.find_xray_executable",
            lambda p: "/usr/bin/xray",
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.is_xray_supported",
            lambda cfg: True,
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.validate_configs_xray",
            mock_xray,
        )

        configs = [_make_config("h.example", 443, protocol="vless")]
        await lv.validate_configs(
            configs,
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
        assert calls == ["getter", "getter"]  # resolve + refill
        stats = lv.context.liveness_stats["lists"]["blacklist"]
        assert stats["xray_pool_refilled"] == 8
        assert lv._pool_refetch_used is True

    async def test_no_refill_when_pool_healthy(self, monkeypatch) -> None:
        """A recheck keeping >= half the probes never triggers a rebuild."""
        calls: list[str] = []

        async def _pool() -> list[str]:
            calls.append("getter")
            return [f"socks5://p{i}:1080" for i in range(8)]

        async def _fake_revalidate(proxies, *, max_proxies, history=None, **kwargs):
            # 8 of 8 alive — healthy, no refill needed.
            return proxies[:8]

        lv = _make_liveness(
            {
                "validator": {
                    "xray_enabled": True,
                    "xray_executable": "/usr/bin/xray",
                    "xray_probe_via_proxies": True,
                    "xray_proxy_probe_count": 8,
                },
                "proxy_pool": {"enabled": True, "required": True},
            },
            proxy_url_getter=_pool,
        )
        lv._validator_proxy_urls_cache = [f"socks5://p{i}:1080" for i in range(8)]
        monkeypatch.setattr(
            "src.validators.proxy_pool.validate_proxy_candidates",
            _fake_revalidate,
        )

        async def mock_xray(configs, **kwargs):
            return []

        monkeypatch.setattr(
            "src.validators.xray_probe.find_xray_executable",
            lambda p: "/usr/bin/xray",
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.is_xray_supported",
            lambda cfg: True,
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.validate_configs_xray",
            mock_xray,
        )

        configs = [_make_config("h.example", 443, protocol="vless")]
        await lv.validate_configs(
            configs,
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
        assert len(calls) == 1  # pool resolve only — no refill getter call
        assert (
            "xray_pool_refilled"
            not in (lv.context.liveness_stats["lists"]["blacklist"])
        )


class TestValidatorProxyUrls:
    """Cover lines 264-319."""

    async def test_cached_returns_cached(self) -> None:
        """Cached proxy URLs are returned directly."""
        lv = _make_liveness()
        lv._validator_proxy_urls_cache = ["socks5://cached:1080"]
        result = await lv._validator_proxy_urls()
        assert result == ["socks5://cached:1080"]

    async def test_explicit_proxy_url(self, monkeypatch) -> None:
        """Explicit proxy_url from settings is used."""
        monkeypatch.delenv("VALIDATOR_PROXY", raising=False)
        lv = _make_liveness(
            {
                "validator": {
                    "proxy_url": "socks5://explicit:1080",
                },
            }
        )
        result = await lv._validator_proxy_urls()
        assert "socks5://explicit:1080" in result
        assert lv.context.liveness_stats["explicit_proxy"] is True

    async def test_pool_import_error_logs_warning(self, monkeypatch, caplog) -> None:
        """ImportError during pool load is caught and logged."""
        lv = _make_liveness(
            {
                "validator": {
                    "proxy_url": "",
                    "proxy_pool": {"enabled": True},
                },
            }
        )
        caplog.set_level(logging.WARNING)
        # Make the import fail by removing attribute from module
        import src.validators.proxy_pool as pp_mod

        monkeypatch.delattr(pp_mod, "load_proxy_pool", raising=False)
        result = await lv._validator_proxy_urls()
        assert "Proxy pool unavailable" in caplog.text
        assert result == []

    async def test_pool_search_error_logs_warning(self, monkeypatch, caplog) -> None:
        """Exception from _search_validator_proxy_pool is caught."""
        lv = _make_liveness(
            {
                "validator": {
                    "proxy_url": "",
                    "proxy_pool": {"enabled": True, "sources": ["test"]},
                },
            }
        )

        async def _raise(*args, **kwargs):
            raise RuntimeError("search failed")

        monkeypatch.setattr(lv, "_search_validator_proxy_pool", _raise)
        caplog.set_level(logging.WARNING)
        result = await lv._validator_proxy_urls()
        assert "Proxy pool load failed" in caplog.text
        assert result == []

    async def test_pool_success_adds_urls(self, monkeypatch) -> None:
        """Working pool search adds URLs to the list."""
        lv = _make_liveness(
            {
                "validator": {
                    "proxy_url": "socks5://explicit:1080",
                    "proxy_pool": {"enabled": True, "sources": ["test"]},
                },
            }
        )

        async def mock_search(*args, **kwargs):
            return ["socks5://pool1:1080", "socks5://pool2:1080"]

        monkeypatch.setattr(lv, "_search_validator_proxy_pool", mock_search)
        result = await lv._validator_proxy_urls()
        assert "socks5://explicit:1080" in result
        assert "socks5://pool1:1080" in result
        assert "socks5://pool2:1080" in result
        assert lv.context.liveness_stats["proxy_count"] == 3

    async def test_stats_explicit_proxy_hidden(self, monkeypatch) -> None:
        """Explicit proxy URLs are hidden in stats as '<explicit-proxy-hidden>'."""
        lv = _make_liveness(
            {
                "validator": {
                    "proxy_url": "socks5://secret:1080",
                    "proxy_pool": {"enabled": True, "sources": ["test"]},
                },
            }
        )

        async def mock_search(*args, **kwargs):
            return ["socks5://pool1:1080"]

        monkeypatch.setattr(lv, "_search_validator_proxy_pool", mock_search)
        await lv._validator_proxy_urls()
        stats_urls = lv.context.liveness_stats["proxy_urls"]
        assert "<explicit-proxy-hidden>" in stats_urls
        assert "socks5://secret:1080" not in str(stats_urls)

    async def test_pool_search_is_monotonic_across_rounds(self) -> None:
        """A wider later round that validates FEWER proxies must not erase the
        earlier round's working set (used to end the widest search with the
        poorest pool)."""
        lv = _make_liveness(
            {
                "validator": {
                    "proxy_pool": {
                        "enabled": True,
                        "sources": ["test"],
                        "min_proxies": 10,
                        "max_proxies": 20,
                        "retry_delay_seconds": 0,
                    },
                },
            }
        )
        lv._proxy_health_history = None

        async def fake_load(
            sources,
            *,
            max_candidates,
            max_candidates_per_source,
            **_kwargs,
        ):
            if max_candidates <= 200:
                return [
                    "socks5://p1:1080",
                    "socks5://p2:1080",
                    "socks5://p3:1080",
                    "socks5://p4:1080",
                    "socks5://p5:1080",
                ]
            return ["socks5://p9:1080"]

        pool = await lv._search_validator_proxy_pool(
            fake_load,
            ["test"],
            dict(
                lv._proxy_pool_config(),
                min_proxies=10,
                max_proxies=20,
                retry_delay_seconds=0,
            ),
        )
        assert set(pool) == {
            "socks5://p1:1080",
            "socks5://p2:1080",
            "socks5://p3:1080",
            "socks5://p4:1080",
            "socks5://p5:1080",
            "socks5://p9:1080",
        }

    async def test_pool_recovery_self_check_uses_configured_target(
        self, monkeypatch
    ) -> None:
        """The mid-run recovery check must probe the same configured target as
        the initial search — the hardcoded api.github.com default disagreed
        with it and could invalidate a pool the search had just proven."""
        lv = _make_liveness(
            {
                "validator": {
                    "proxy_url": "socks5://explicit:1080",
                    "proxy_pool": {
                        "enabled": True,
                        "sources": ["test"],
                        "probe_host": "probe.example",
                        "probe_port": 8443,
                        "probe_extra_targets": [["alt.example", 8080]],
                    },
                },
            }
        )
        lv._proxy_health_history = None
        lv._validator_proxy_urls_cache = [
            "socks5://p1:1080",
            "socks5://p2:1080",
        ]
        seen: list[dict] = []

        async def fake_connects(proxy_url, **kwargs):
            seen.append(kwargs)
            return proxy_url == "socks5://p1:1080"

        monkeypatch.setattr("src.validators.proxy_pool.proxy_connects", fake_connects)
        await lv._pool_died_after_empty_list("whitelist")
        assert seen and all(
            kwargs.get("probe_host") == "probe.example"
            and kwargs.get("probe_port") == 8443
            and kwargs.get("extra_probe_targets") == [("alt.example", 8080)]
            for kwargs in seen
        )


# ============================================================================
# validate_by_list (lines 325-374)
# ============================================================================


class TestValidateByList:
    """Cover lines 325-374."""

    async def test_all_disabled_marks_configs_not_alive(self) -> None:
        """When all validators disabled, configs are marked not-alive (fail-closed).

        Publishing unverified configs would put dead/N-A entries in the
        subscription, so a fully-disabled validation stage refuses to vouch for
        any config: each is marked ``is_alive=False`` and dropped downstream.
        """
        lv = _make_liveness()
        config = _make_config("a.com")
        configs = {"whitelist": [config]}
        result = await lv.validate_by_list(configs)
        assert result is configs
        assert lv.context.liveness_stats["status"] == "disabled"
        assert config.is_alive is False

    async def test_enabled_loops_over_lists(self, monkeypatch) -> None:
        """Enabled validation iterates over lists and returns alive only."""
        lv = _make_liveness(
            {
                "validator": {
                    "tcp_enabled": True,
                    "tcp_timeout_seconds": 5.0,
                    "tcp_concurrency": 300,
                },
            },
            proxy_url_getter=_empty_proxy_list,
        )

        async def mock_tcp(batch, **kwargs):
            # Return only the first config
            return [batch[0]] if batch else []

        monkeypatch.setattr(
            "src.validators.tcp_check.validate_configs_tcp",
            mock_tcp,
        )

        configs = {
            "blacklist": [
                _make_config("alive.com", 443),
                _make_config("dead.com", 444),
            ],
        }
        result = await lv.validate_by_list(configs)
        assert lv.context.liveness_stats["status"] == "enabled"
        assert "blacklist" in result
        assert len(result["blacklist"]) == 1


# ============================================================================
# validate_configs — empty / passthrough (line 386)
# ============================================================================


class TestValidateConfigsEmpty:
    """Cover line 386."""

    async def test_empty_configs_returns_empty(self) -> None:
        lv = _make_liveness()
        result = await lv.validate_configs(
            [],
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
        )
        assert result == []


# ============================================================================
# validate_configs — TCP (lines 430-550, especially 449, 464-465, 476, 486, 516)
# ============================================================================


class TestValidateConfigsTCP:
    """Cover TCP validation branches."""

    async def test_tcp_per_list_max_alive(self, monkeypatch) -> None:
        """tcp_max_alive_by_list overrides global tcp_max_alive."""
        lv = _make_liveness(
            {
                "validator": {
                    "tcp_enabled": True,
                    "tcp_timeout_seconds": 5.0,
                    "tcp_concurrency": 300,
                    "tcp_max_alive": 0,
                    "tcp_max_alive_by_list": {"blacklist": 2},
                    "tcp_candidate_limit": 100,
                },
            },
            proxy_url_getter=_empty_proxy_list,
        )

        async def mock_tcp(batch, **kwargs):
            return batch[:2]

        monkeypatch.setattr(
            "src.validators.tcp_check.validate_configs_tcp",
            mock_tcp,
        )

        configs = [
            _make_config(f"h{i}.com", 4000 + i, protocol="vless") for i in range(5)
        ]
        result = await lv.validate_configs(
            configs,
            label="blacklist",
            tcp_enabled=True,
            tls_enabled=False,
        )
        stats = lv.context.liveness_stats["lists"]["blacklist"]
        assert stats["tcp_max_alive"] == 2

    async def test_tcp_candidate_limit_zero(self, monkeypatch) -> None:
        """candidate_limit <= 0 forces single round with full list."""
        lv = _make_liveness(
            {
                "validator": {
                    "tcp_enabled": True,
                    "tcp_timeout_seconds": 5.0,
                    "tcp_concurrency": 300,
                    "tcp_candidate_limit": 0,
                    "tcp_search_rounds": 5,
                },
            },
            proxy_url_getter=_empty_proxy_list,
        )

        async def mock_tcp(batch, **kwargs):
            return batch[:1]

        monkeypatch.setattr(
            "src.validators.tcp_check.validate_configs_tcp",
            mock_tcp,
        )

        configs = [_make_config(f"h{i}.com", 4000 + i) for i in range(3)]
        result = await lv.validate_configs(
            configs,
            label="blacklist",
            tcp_enabled=True,
            tls_enabled=False,
        )
        stats = lv.context.liveness_stats["lists"]["blacklist"]
        assert stats["tcp_search_rounds"] == 1

    async def test_tcp_remaining_alive_zero_breaks_early(self, monkeypatch) -> None:
        """When tcp_max_alive > 0 and remaining_alive <= 0, loop breaks."""
        lv = _make_liveness(
            {
                "validator": {
                    "tcp_enabled": True,
                    "tcp_timeout_seconds": 5.0,
                    "tcp_concurrency": 300,
                    "tcp_max_alive": 1,
                    "tcp_candidate_limit": 10,
                },
            },
            proxy_url_getter=_empty_proxy_list,
        )

        async def mock_tcp(batch, **kwargs):
            return batch[:1]

        monkeypatch.setattr(
            "src.validators.tcp_check.validate_configs_tcp",
            mock_tcp,
        )

        configs = [
            _make_config(f"h{i}.com", 4000 + i, protocol="vless") for i in range(10)
        ]
        result = await lv.validate_configs(
            configs,
            label="blacklist",
            tcp_enabled=True,
            tls_enabled=False,
        )
        stats = lv.context.liveness_stats["lists"]["blacklist"]
        # Only 1 alive config found
        assert stats["tcp_alive"] == 1

    async def test_tcp_dedup_key_skips_duplicates(self, monkeypatch) -> None:
        """Configs with same dedup_key are skipped (continue)."""
        lv = _make_liveness(
            {
                "validator": {
                    "tcp_enabled": True,
                    "tcp_timeout_seconds": 5.0,
                    "tcp_concurrency": 300,
                },
            },
            proxy_url_getter=_empty_proxy_list,
        )

        async def mock_tcp_return_dupes(batch, **kwargs):
            # Return two configs with same address:port
            return [
                _make_config("same.host", 443),
                _make_config("same.host", 443),
            ]

        monkeypatch.setattr(
            "src.validators.tcp_check.validate_configs_tcp",
            mock_tcp_return_dupes,
        )

        configs = [_make_config("dummy.host", 443)]
        result = await lv.validate_configs(
            configs,
            label="blacklist",
            tcp_enabled=True,
            tls_enabled=False,
        )
        # Only one should survive dedup
        assert len(result) == 1

    async def test_tcp_passthrough_skipped_protocols(self, monkeypatch) -> None:
        """Protocols in _TCP_SKIP_PROTOCOLS bypass TCP check."""
        lv = _make_liveness(
            {
                "validator": {
                    "tcp_enabled": True,
                    "tcp_timeout_seconds": 5.0,
                    "tcp_concurrency": 300,
                    "fail_open_on_low_alive": False,
                },
            },
            proxy_url_getter=_empty_proxy_list,
        )

        async def mock_tcp(batch, **kwargs):
            return []

        monkeypatch.setattr(
            "src.validators.tcp_check.validate_configs_tcp",
            mock_tcp,
        )

        configs = [
            _make_config("tcp-checked.com", 443, protocol="vless"),
            _make_config("skipped.com", 444, protocol="hysteria2"),
        ]
        result = await lv.validate_configs(
            configs,
            label="blacklist",
            tcp_enabled=True,
            tls_enabled=False,
        )
        # TCP returns 0 alive → strict mode keeps only alive (empty) + passthrough
        assert len(result) == 1
        assert result[0].protocol == "hysteria2"

    async def test_tcp_below_min_alive_fail_open(self, monkeypatch, caplog) -> None:
        """Below min_alive with fail_open keeps all configs."""
        lv = _make_liveness(
            {
                "validator": {
                    "tcp_enabled": True,
                    "tcp_timeout_seconds": 5.0,
                    "tcp_concurrency": 300,
                    "min_alive_to_filter": 10,
                    "fail_open_on_low_alive": True,
                },
            },
            proxy_url_getter=_empty_proxy_list,
        )

        async def mock_tcp(batch, **kwargs):
            return []

        monkeypatch.setattr(
            "src.validators.tcp_check.validate_configs_tcp",
            mock_tcp,
        )

        configs = [_make_config(f"h{i}.com", 4000 + i) for i in range(3)]
        caplog.set_level(logging.WARNING)
        result = await lv.validate_configs(
            configs,
            label="blacklist",
            tcp_enabled=True,
            tls_enabled=False,
        )
        # fail_open returns the original full configs list
        assert len(result) == 3
        stats = lv.context.liveness_stats["lists"]["blacklist"]
        assert stats["fail_open"] is True
        assert "below_min_alive" in stats.get("reason", "")


# ============================================================================
# validate_configs — TLS (lines 558-657)
# ============================================================================


class TestValidateConfigsTLS:
    """Cover TLS validation branches."""

    async def test_tls_candidate_limit_truncates(self, monkeypatch) -> None:
        """TLS candidate_limit truncates the checkable list."""
        lv = _make_liveness(
            {
                "validator": {
                    "tls_enabled": True,
                    "tls_timeout_seconds": 5.0,
                    "tls_concurrency": 120,
                    "tls_candidate_limit": 2,
                },
            },
            proxy_url_getter=_empty_proxy_list,
        )

        async def mock_tls(configs, **kwargs):
            return configs[:1]

        monkeypatch.setattr(
            "src.validators.tls_check.validate_configs_tls",
            mock_tls,
        )

        configs = [
            _make_config(f"h{i}.com", 4000 + i, security="tls") for i in range(5)
        ]
        result = await lv.validate_configs(
            configs,
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=True,
        )
        stats = lv.context.liveness_stats["lists"]["blacklist"]
        assert stats["tls_candidates"] == 5

    async def test_tls_below_min_alive_fail_open(self, monkeypatch, caplog) -> None:
        """TLS below min_alive with fail_open returns pre-TLS configs."""
        lv = _make_liveness(
            {
                "validator": {
                    "tls_enabled": True,
                    "tls_timeout_seconds": 5.0,
                    "tls_concurrency": 120,
                    "min_alive_to_filter": 10,
                    "fail_open_on_low_alive": True,
                },
            },
            proxy_url_getter=_empty_proxy_list,
        )

        async def mock_tls(configs, **kwargs):
            return []

        monkeypatch.setattr(
            "src.validators.tls_check.validate_configs_tls",
            mock_tls,
        )

        configs = [
            _make_config("a.com", 443, security="tls"),
            _make_config("b.com", 444, security="none"),
        ]
        caplog.set_level(logging.WARNING)
        result = await lv.validate_configs(
            configs,
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=True,
        )
        # fail_open returns the before_tls configs (all original after TCP)
        assert len(result) == 2
        stats = lv.context.liveness_stats["lists"]["blacklist"]
        assert stats["fail_open"] is True
        assert "below_min_alive_tls" in stats.get("reason", "")

    async def test_tls_no_candidates_drop_unchecked(self, monkeypatch, caplog) -> None:
        """No TLS candidates with drop_unchecked_after_tls clears current."""
        lv = _make_liveness(
            {
                "validator": {
                    "tls_enabled": True,
                    "drop_unchecked_after_tls": True,
                },
            },
            proxy_url_getter=_empty_proxy_list,
        )

        configs = [
            _make_config("a.com", 443, security="none"),
        ]
        caplog.set_level(logging.WARNING)
        result = await lv.validate_configs(
            configs,
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=True,
        )
        # All configs dropped because no TLS candidates
        assert result == []
        assert "TLS validation has no TLS/REALITY candidates" in caplog.text

    async def test_tls_with_tcp_and_passthrough(self, monkeypatch) -> None:
        """TLS validation after TCP keeps TLS-passthrough configs."""
        lv = _make_liveness(
            {
                "validator": {
                    "tcp_enabled": True,
                    "tls_enabled": True,
                    "tcp_timeout_seconds": 5.0,
                    "tcp_concurrency": 300,
                    "tls_timeout_seconds": 5.0,
                    "tls_concurrency": 120,
                },
            },
            proxy_url_getter=_empty_proxy_list,
        )

        async def mock_tcp(batch, **kwargs):
            return batch  # all alive

        async def mock_tls(configs, **kwargs):
            return [c for c in configs if c.security == "tls"]

        monkeypatch.setattr(
            "src.validators.tcp_check.validate_configs_tcp",
            mock_tcp,
        )
        monkeypatch.setattr(
            "src.validators.tls_check.validate_configs_tls",
            mock_tls,
        )

        configs = [
            _make_config("tls.com", 443, security="tls", protocol="vless"),
            _make_config("none.com", 444, security="none", protocol="vless"),
        ]
        result = await lv.validate_configs(
            configs,
            label="blacklist",
            tcp_enabled=True,
            tls_enabled=True,
        )
        # After TCP: both alive. After TLS: only tls.com is alive, none.com passthrough
        assert len(result) == 2

    async def test_tls_strict_mode_below_min_alive(self, monkeypatch, caplog) -> None:
        """TLS below min_alive without fail_open keeps only TLS-alive."""
        lv = _make_liveness(
            {
                "validator": {
                    "tls_enabled": True,
                    "tls_timeout_seconds": 5.0,
                    "tls_concurrency": 120,
                    "min_alive_to_filter": 10,
                    "fail_open_on_low_alive": False,
                },
            },
            proxy_url_getter=_empty_proxy_list,
        )

        async def mock_tls(configs, **kwargs):
            return []

        monkeypatch.setattr(
            "src.validators.tls_check.validate_configs_tls",
            mock_tls,
        )

        configs = [
            _make_config("a.com", 443, security="tls"),
            _make_config("b.com", 444, security="none"),
        ]
        caplog.set_level(logging.WARNING)
        result = await lv.validate_configs(
            configs,
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=True,
        )
        # Strict mode: only TLS-alive (empty) + passthrough (security="none")
        assert len(result) == 1
        assert result[0].security == "none"


# ============================================================================
# validate_configs — Xray (lines 658-866)
# ============================================================================


class TestValidateConfigsXray:
    """Cover Xray validation branches."""

    async def test_xray_unavailable_required_drops_all(
        self, monkeypatch, caplog
    ) -> None:
        """Xray required but executable unavailable → return []."""
        lv = _make_liveness(
            {
                "validator": {
                    "xray_enabled": True,
                    "xray_required": True,
                    "xray_executable": "",
                },
            },
            proxy_url_getter=_empty_proxy_list,
        )

        monkeypatch.setattr(
            "src.validators.xray_probe.find_xray_executable",
            lambda p: None,
        )

        caplog.set_level(logging.WARNING)
        result = await lv.validate_configs(
            [_make_config("a.com")],
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
        assert result == []
        assert "xray executable is unavailable" in caplog.text

    async def test_xray_unavailable_not_required_returns_current(
        self,
        monkeypatch,
        caplog,
    ) -> None:
        """Xray not required and unavailable → return current configs."""
        lv = _make_liveness(
            {
                "validator": {
                    "xray_enabled": True,
                    "xray_required": False,
                    "xray_executable": "",
                },
            },
            proxy_url_getter=_empty_proxy_list,
        )

        monkeypatch.setattr(
            "src.validators.xray_probe.find_xray_executable",
            lambda p: None,
        )

        caplog.set_level(logging.WARNING)
        configs = [_make_config("a.com")]
        result = await lv.validate_configs(
            configs,
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
        assert result == configs
        assert "Xray validation skipped" in caplog.text

    async def test_xray_no_supported_configs(self, monkeypatch) -> None:
        """No Xray-supported configs with drop_unsupported=True → return []."""
        lv = _make_liveness(
            {
                "validator": {
                    "xray_enabled": True,
                    "xray_executable": "/usr/bin/xray",
                    "xray_drop_unsupported": True,
                },
            },
            proxy_url_getter=_empty_proxy_list,
        )

        monkeypatch.setattr(
            "src.validators.xray_probe.find_xray_executable",
            lambda p: "/usr/bin/xray",
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.is_xray_supported",
            lambda cfg: False,
        )

        configs = [_make_config("a.com")]
        result = await lv.validate_configs(
            configs,
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
        assert result == []

    async def test_xray_no_supported_configs_keep_unsupported(
        self,
        monkeypatch,
    ) -> None:
        """No Xray-supported configs with drop_unsupported=False → return current."""
        lv = _make_liveness(
            {
                "validator": {
                    "xray_enabled": True,
                    "xray_executable": "/usr/bin/xray",
                    "xray_drop_unsupported": False,
                },
            },
            proxy_url_getter=_empty_proxy_list,
        )

        monkeypatch.setattr(
            "src.validators.xray_probe.find_xray_executable",
            lambda p: "/usr/bin/xray",
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.is_xray_supported",
            lambda cfg: False,
        )

        configs = [_make_config("a.com")]
        result = await lv.validate_configs(
            configs,
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
        assert result == configs

    async def test_xray_per_list_max_alive(self, monkeypatch) -> None:
        """xray_max_alive_by_list overrides global max_alive."""
        lv = _make_liveness(
            {
                "validator": {
                    "xray_enabled": True,
                    "xray_executable": "/usr/bin/xray",
                    "xray_max_alive": 0,
                    "xray_max_alive_by_list": {"blacklist": 2},
                    "xray_probe_url": "https://example.com/probe",
                    "xray_timeout_seconds": 12.0,
                    "xray_startup_timeout_seconds": 4.0,
                    "xray_concurrency": 6,
                },
            },
            proxy_url_getter=_empty_proxy_list,
        )

        monkeypatch.setattr(
            "src.validators.xray_probe.find_xray_executable",
            lambda p: "/usr/bin/xray",
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.is_xray_supported",
            lambda cfg: True,
        )

        async def mock_xray(configs, **kwargs):
            for cfg in configs:
                cfg.xray_was_checked = True
                cfg.is_alive = True
            return list(configs[:2])

        monkeypatch.setattr(
            "src.validators.xray_probe.validate_configs_xray",
            mock_xray,
        )

        configs = [_make_config(f"h{i}.com", 4000 + i) for i in range(5)]
        result = await lv.validate_configs(
            configs,
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
        stats = lv.context.liveness_stats["lists"]["blacklist"]
        assert stats["xray_max_alive"] == 2

    async def test_xray_probe_urls_as_string(self, monkeypatch) -> None:
        """xray_probe_urls as a string is parsed correctly."""
        lv = _make_liveness(
            {
                "validator": {
                    "xray_enabled": True,
                    "xray_executable": "/usr/bin/xray",
                    "xray_probe_urls": "https://p1.com/probe;https://p2.com/probe",
                    "xray_timeout_seconds": 12.0,
                    "xray_startup_timeout_seconds": 4.0,
                    "xray_concurrency": 6,
                },
            },
            proxy_url_getter=_empty_proxy_list,
        )

        monkeypatch.setattr(
            "src.validators.xray_probe.find_xray_executable",
            lambda p: "/usr/bin/xray",
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.is_xray_supported",
            lambda cfg: True,
        )

        async def mock_xray(configs, **kwargs):
            for cfg in configs:
                cfg.xray_was_checked = True
                cfg.is_alive = True
            return list(configs)

        monkeypatch.setattr(
            "src.validators.xray_probe.validate_configs_xray",
            mock_xray,
        )

        configs = [_make_config("a.com")]
        result = await lv.validate_configs(
            configs,
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
        assert len(result) == 1

    async def test_xray_full_health_fallback(self, monkeypatch) -> None:
        """Xray health update falls back to self.health (no callbacks)."""
        mock_health = MagicMock(spec=HealthHistory)
        lv = _make_liveness(
            {
                "validator": {
                    "xray_enabled": True,
                    "xray_executable": "/usr/bin/xray",
                    "xray_probe_url": "https://example.com/probe",
                    "xray_timeout_seconds": 12.0,
                    "xray_startup_timeout_seconds": 4.0,
                    "xray_concurrency": 6,
                },
            },
            proxy_url_getter=_empty_proxy_list,
            health=mock_health,
        )

        monkeypatch.setattr(
            "src.validators.xray_probe.find_xray_executable",
            lambda p: "/usr/bin/xray",
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.is_xray_supported",
            lambda cfg: True,
        )

        async def mock_xray(configs, **kwargs):
            for cfg in configs:
                cfg.xray_was_checked = True
                cfg.is_alive = True
            return list(configs)

        monkeypatch.setattr(
            "src.validators.xray_probe.validate_configs_xray",
            mock_xray,
        )

        configs = [_make_config("a.com")]
        result = await lv.validate_configs(
            configs,
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
        assert len(result) == 1
        # Verify health.update was called (the fallback path)
        mock_health.update.assert_called_once()
        mock_health.update_sources.assert_called_once()

    async def test_xray_health_ban_threshold(self, monkeypatch) -> None:
        """A fresh Xray pass overrides stale bans even above the threshold."""
        mock_health = MagicMock(spec=HealthHistory)
        mock_health.is_banned.return_value = True
        # The pre-filter runs on config-level bans only; this scenario keeps
        # the configs in the probe batch (e.g. source-level bans), so it must
        # not short-circuit the stage before Xray.
        mock_health.is_config_banned.return_value = False
        mock_health.update.return_value = None
        mock_health.update_sources.return_value = None

        lv = _make_liveness(
            {
                "validator": {
                    "xray_enabled": True,
                    "xray_executable": "/usr/bin/xray",
                    "xray_probe_url": "https://example.com/probe",
                    "xray_timeout_seconds": 12.0,
                    "xray_startup_timeout_seconds": 4.0,
                    "xray_concurrency": 6,
                },
                "quality": {
                    "health_ban_min_alive": 2,
                },
            },
            proxy_url_getter=_empty_proxy_list,
            health=mock_health,
        )

        monkeypatch.setattr(
            "src.validators.xray_probe.find_xray_executable",
            lambda p: "/usr/bin/xray",
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.is_xray_supported",
            lambda cfg: True,
        )

        async def mock_xray(configs, **kwargs):
            for cfg in configs:
                cfg.xray_was_checked = True
                cfg.is_alive = True
            return list(configs)

        monkeypatch.setattr(
            "src.validators.xray_probe.validate_configs_xray",
            mock_xray,
        )

        configs = [_make_config(f"h{i}.com", 4000 + i) for i in range(5)]
        result = await lv.validate_configs(
            configs,
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
        # All 5 are "banned" in the history, but each just passed its Xray
        # probe: fresh evidence wins and nothing alive is erased.
        assert len(result) == 5
        stats = lv.context.liveness_stats["lists"]["blacklist"]
        assert stats["output_after_health"] == 5

    async def test_xray_probe_via_proxies_wiring(self, monkeypatch) -> None:
        """xray_probe_via_proxies reaches validate_configs_xray with the pool."""

        async def _pool() -> list[str]:
            return [
                "socks5://p1:1080",
                "socks5://p2:1080",
                "socks5://p3:1080",
            ]

        captured: dict = {}

        async def mock_xray(configs, **kwargs):
            captured.update(kwargs)
            for cfg in configs:
                cfg.xray_was_checked = True
                cfg.is_alive = True
            return list(configs)

        lv = _make_liveness(
            _xray_settings(
                xray_probe_via_proxies=True,
                xray_proxy_probe_count=3,
            ),
            proxy_url_getter=_pool,
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.find_xray_executable",
            lambda p: "/usr/bin/xray",
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.is_xray_supported",
            lambda cfg: True,
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.validate_configs_xray",
            mock_xray,
        )

        result = await lv.validate_configs(
            [_make_config("h1.com", 4001)],
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
        assert len(result) == 1
        assert captured["probe_via_proxies"] is True
        assert captured["probe_proxy_urls"] == [
            "socks5://p1:1080",
            "socks5://p2:1080",
            "socks5://p3:1080",
        ]
        stats = lv.context.liveness_stats["lists"]["blacklist"]
        assert stats["xray_probe_via_proxies"] is True

    @pytest.mark.parametrize(
        ("label", "expected"),
        [("whitelist", False), ("blacklist", True)],
    )
    async def test_xray_probe_via_proxies_by_list_override(
        self,
        monkeypatch,
        label: str,
        expected: bool,
    ) -> None:
        """The per-list map overrides the global via-proxy flag per list."""

        async def _pool() -> list[str]:
            return [
                "socks5://p1:1080",
                "socks5://p2:1080",
                "socks5://p3:1080",
            ]

        captured: dict = {}

        async def mock_xray(configs, **kwargs):
            captured.update(kwargs)
            for cfg in configs:
                cfg.xray_was_checked = True
                cfg.is_alive = True
            return list(configs)

        lv = _make_liveness(
            _xray_settings(
                xray_probe_via_proxies=True,
                xray_probe_via_proxies_by_list={"whitelist": False},
                xray_proxy_probe_count=3,
            ),
            proxy_url_getter=_pool,
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.find_xray_executable",
            lambda p: "/usr/bin/xray",
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.is_xray_supported",
            lambda cfg: True,
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.validate_configs_xray",
            mock_xray,
        )

        result = await lv.validate_configs(
            [_make_config("h1.com", 4001)],
            label=label,
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
        assert len(result) == 1
        assert captured["probe_via_proxies"] is expected
        assert captured["probe_proxy_urls"] == [
            "socks5://p1:1080",
            "socks5://p2:1080",
            "socks5://p3:1080",
        ]
        stats = lv.context.liveness_stats["lists"][label]
        assert stats["xray_probe_via_proxies"] is expected

    async def test_xray_probe_via_proxies_by_list_uppercase_key(
        self, monkeypatch
    ) -> None:
        """Override keys are case-insensitive: YAML ``WHITELIST: false`` used
        to configure nothing (the lookup key is the lowercase list name)."""

        async def _pool() -> list[str]:
            return ["socks5://p1:1080"]

        captured: dict = {}

        async def mock_xray(configs, **kwargs):
            captured.update(kwargs)
            for cfg in configs:
                cfg.xray_was_checked = True
                cfg.is_alive = True
            return list(configs)

        lv = _make_liveness(
            _xray_settings(
                xray_probe_via_proxies=True,
                xray_probe_via_proxies_by_list={"WHITELIST": False},
                xray_proxy_probe_count=1,
            ),
            proxy_url_getter=_pool,
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.find_xray_executable",
            lambda p: "/usr/bin/xray",
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.is_xray_supported",
            lambda cfg: True,
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.validate_configs_xray",
            mock_xray,
        )
        await lv.validate_configs(
            [_make_config("h1.com", 4001)],
            label="whitelist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
        assert captured["probe_via_proxies"] is False

    @pytest.mark.parametrize("empty_map", [False, True])
    async def test_xray_probe_via_proxies_by_list_missing_keeps_global(
        self,
        monkeypatch,
        empty_map: bool,
    ) -> None:
        """A missing or empty per-list map leaves the global flag untouched."""

        async def _pool() -> list[str]:
            return ["socks5://p1:1080", "socks5://p2:1080"]

        captured: dict = {}

        async def mock_xray(configs, **kwargs):
            captured.update(kwargs)
            for cfg in configs:
                cfg.xray_was_checked = True
                cfg.is_alive = True
            return list(configs)

        extra = {
            "xray_probe_via_proxies": True,
            "xray_proxy_probe_count": 2,
        }
        if empty_map:
            extra["xray_probe_via_proxies_by_list"] = {}
        lv = _make_liveness(
            _xray_settings(**extra),
            proxy_url_getter=_pool,
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.find_xray_executable",
            lambda p: "/usr/bin/xray",
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.is_xray_supported",
            lambda cfg: True,
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.validate_configs_xray",
            mock_xray,
        )

        result = await lv.validate_configs(
            [_make_config("w1.com", 4101)],
            label="whitelist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
        assert len(result) == 1
        assert captured["probe_via_proxies"] is True
        stats = lv.context.liveness_stats["lists"]["whitelist"]
        assert stats["xray_probe_via_proxies"] is True

    async def test_xray_pool_required_no_proxies(
        self,
        monkeypatch,
        caplog,
    ) -> None:
        """pool_required=True and no proxies returns configs when xray also enabled."""
        lv = _make_liveness(
            {
                "validator": {
                    "tcp_enabled": False,
                    "tls_enabled": False,
                    "xray_enabled": True,
                    "xray_executable": "/usr/bin/xray",
                    "xray_probe_url": "https://example.com/probe",
                    "xray_timeout_seconds": 12.0,
                    "xray_startup_timeout_seconds": 4.0,
                    "xray_concurrency": 6,
                    "proxy_pool": {
                        "enabled": True,
                        "required": True,
                    },
                },
            },
            proxy_url_getter=_empty_proxy_list,
        )

        # xray_path not None (the xray required-but-no-proxies path)
        monkeypatch.setattr(
            "src.validators.xray_probe.find_xray_executable",
            lambda p: "/usr/bin/xray",
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.is_xray_supported",
            lambda cfg: True,
        )

        async def mock_xray(configs, **kwargs):
            for cfg in configs:
                cfg.xray_was_checked = True
                cfg.is_alive = True
            return list(configs)

        monkeypatch.setattr(
            "src.validators.xray_probe.validate_configs_xray",
            mock_xray,
        )

        caplog.set_level(logging.WARNING)
        configs = [_make_config("a.com")]
        result = await lv.validate_configs(
            configs,
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
        assert len(result) == 1

    async def test_xray_candidate_preselect_whitelist(self, monkeypatch) -> None:
        """_xray_candidate_preselect whitelist branch is exercised."""
        lv = _make_liveness(
            {
                "validator": {
                    "xray_enabled": True,
                    "xray_executable": "/usr/bin/xray",
                    "xray_candidate_limit": 1,
                    "xray_probe_url": "https://example.com/probe",
                    "xray_timeout_seconds": 12.0,
                    "xray_startup_timeout_seconds": 4.0,
                    "xray_concurrency": 6,
                },
            },
            proxy_url_getter=_empty_proxy_list,
        )

        monkeypatch.setattr(
            "src.validators.xray_probe.find_xray_executable",
            lambda p: "/usr/bin/xray",
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.is_xray_supported",
            lambda cfg: True,
        )

        async def mock_xray(configs, **kwargs):
            for cfg in configs:
                cfg.xray_was_checked = True
                cfg.is_alive = True
            return list(configs)

        monkeypatch.setattr(
            "src.validators.xray_probe.validate_configs_xray",
            mock_xray,
        )
        # Mock the aggregate to avoid complex dependency
        mock_aggregator = MagicMock()
        mock_aggregator._whitelist_balance.return_value = [
            _make_config("selected.com", 443),
        ]
        monkeypatch.setattr(
            "src.scheduler.stages.aggregate.Aggregator",
            lambda ctx: mock_aggregator,
        )

        configs = [_make_config(f"h{i}.com", 4000 + i) for i in range(3)]
        result = await lv.validate_configs(
            configs,
            label="whitelist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
        assert len(result) == 1


# ============================================================================
# Remaining uncovered lines
# ============================================================================


class TestRemainingLines:
    """Cover edge-case branches not exercised by earlier tests."""

    # ---- _redact_proxy_url ValueError (line 152-153) ----

    def test_redact_proxy_url_value_error(self) -> None:
        """parsed.port raises ValueError → <invalid-proxy-url>."""
        result = LivenessValidator._redact_proxy_url("socks5://host:abc")
        assert result == "<invalid-proxy-url>"

    # ---- pool required + no proxies + xray disabled (lines 415-420) ----

    async def test_pool_required_no_proxies_no_xray(self, monkeypatch, caplog) -> None:
        """pool_required, no proxies, xray disabled drops configs (fail-closed)."""
        lv = _make_liveness(
            {
                "validator": {
                    "proxy_url": "",
                    "proxy_pool": {
                        "enabled": True,
                        "required": True,
                    },
                },
            }
        )

        # Mock _validator_proxy_urls to return empty (no proxies)
        async def mock_empty():
            return []

        monkeypatch.setattr(lv, "_validator_proxy_urls", mock_empty)

        caplog.set_level(logging.WARNING)
        configs = [_make_config("a.com")]
        result = await lv.validate_configs(
            configs,
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=False,
        )
        # Fail-closed: with no proxy pool and Xray disabled there is no
        # validator left, so unvalidated configs must not be published.
        assert len(result) == 0
        assert (
            "dropping the list instead of publishing unvalidated configs" in caplog.text
        )

    # ---- TLS drop_unchecked_after_tls with checkable configs (line 575) ----

    async def test_tls_drop_unchecked_with_checkable(self, monkeypatch) -> None:
        """drop_unchecked_after_tls=True with TLS checkables clears passthrough."""
        lv = _make_liveness(
            {
                "validator": {
                    "tls_enabled": True,
                    "tls_timeout_seconds": 5.0,
                    "tls_concurrency": 120,
                    "drop_unchecked_after_tls": True,
                },
            },
            proxy_url_getter=_empty_proxy_list,
        )

        async def mock_tls(configs, **kwargs):
            return [c for c in configs if c.security == "tls"]

        monkeypatch.setattr(
            "src.validators.tls_check.validate_configs_tls",
            mock_tls,
        )

        configs = [
            _make_config("tls.com", 443, security="tls"),
            _make_config("none.com", 444, security="none"),
        ]
        result = await lv.validate_configs(
            configs,
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=True,
        )
        # TLS passthrough (none.com) is DROPPED because drop_unchecked=True
        # Only TLS-checked configs survive
        assert len(result) == 1
        assert result[0].security == "tls"

    # ---- TLS stage must not TCP-handshake QUIC protocols ----

    async def test_tls_skips_quic_protocols(self, monkeypatch) -> None:
        """hysteria2/tuic cannot answer a TLS-over-TCP handshake — passthrough."""
        lv = _make_liveness(
            {
                "validator": {
                    "tls_enabled": True,
                    "tls_timeout_seconds": 5.0,
                    "tls_concurrency": 120,
                    "drop_unchecked_after_tls": False,
                },
            },
            proxy_url_getter=_empty_proxy_list,
        )

        seen: list[list[str]] = []

        async def mock_tls(configs, **kwargs):
            seen.append([c.address for c in configs])
            return list(configs)

        monkeypatch.setattr(
            "src.validators.tls_check.validate_configs_tls",
            mock_tls,
        )

        configs = [
            _make_config("tls.com", 443, security="tls"),
            _make_config("hy.com", 444, protocol="hysteria2", security="tls"),
            _make_config("tuic.com", 445, protocol="tuic", security="tls"),
        ]
        result = await lv.validate_configs(
            configs,
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=True,
            xray_enabled=False,
        )
        # Only the TCP/TLS-capable config reaches the handshake probe; the
        # QUIC ones survive as passthrough instead of dying there.
        assert seen == [["tls.com"]]
        assert [c.address for c in result] == ["tls.com", "hy.com", "tuic.com"]
        stats = lv.context.liveness_stats["lists"]["blacklist"]
        assert stats["tls_unchecked_passthrough"] == 2

    # ---- xray_candidate_limit_by_list (line 707) ----

    async def test_xray_candidate_limit_by_list(self, monkeypatch) -> None:
        """xray_candidate_limit_by_list overrides candidate_limit."""
        lv = _make_liveness(
            {
                "validator": {
                    "xray_enabled": True,
                    "xray_executable": "/usr/bin/xray",
                    "xray_candidate_limit": 100,
                    "xray_candidate_limit_by_list": {"blacklist": 1},
                    "xray_probe_url": "https://example.com/probe",
                    "xray_timeout_seconds": 12.0,
                    "xray_startup_timeout_seconds": 4.0,
                    "xray_concurrency": 6,
                },
            },
            proxy_url_getter=_empty_proxy_list,
        )

        monkeypatch.setattr(
            "src.validators.xray_probe.find_xray_executable",
            lambda p: "/usr/bin/xray",
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.is_xray_supported",
            lambda cfg: True,
        )

        async def mock_xray(configs, **kwargs):
            for cfg in configs:
                cfg.xray_was_checked = True
                cfg.is_alive = True
            return list(configs)

        monkeypatch.setattr(
            "src.validators.xray_probe.validate_configs_xray",
            mock_xray,
        )
        # Mock Aggregator to avoid real country_balanced_limit dependency
        mock_agg = MagicMock()
        mock_agg._country_balanced_limit.return_value = [
            _make_config("selected.com", 443),
        ]
        monkeypatch.setattr(
            "src.scheduler.stages.aggregate.Aggregator",
            lambda ctx: mock_agg,
        )

        configs = [_make_config(f"h{i}.com", 4000 + i) for i in range(5)]
        result = await lv.validate_configs(
            configs,
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
        # Only 1 candidate should be preselected (due to per-list limit)
        assert len(result) == 1

    # ---- xray_probe_urls as list (line 743) ----

    async def test_xray_probe_urls_as_list(self, monkeypatch) -> None:
        """xray_probe_urls as a list is processed correctly."""
        lv = _make_liveness(
            {
                "validator": {
                    "xray_enabled": True,
                    "xray_executable": "/usr/bin/xray",
                    "xray_probe_urls": [
                        "https://p1.com/probe",
                        "https://p2.com/probe",
                    ],
                    "xray_timeout_seconds": 12.0,
                    "xray_startup_timeout_seconds": 4.0,
                    "xray_concurrency": 6,
                    "xray_min_attempt_successes": 1,
                },
            },
            proxy_url_getter=_empty_proxy_list,
        )

        monkeypatch.setattr(
            "src.validators.xray_probe.find_xray_executable",
            lambda p: "/usr/bin/xray",
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.is_xray_supported",
            lambda cfg: True,
        )

        async def mock_xray(configs, **kwargs):
            for cfg in configs:
                cfg.xray_was_checked = True
                cfg.is_alive = True
            return list(configs)

        monkeypatch.setattr(
            "src.validators.xray_probe.validate_configs_xray",
            mock_xray,
        )

        configs = [_make_config("a.com")]
        result = await lv.validate_configs(
            configs,
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
        assert len(result) == 1

    # ---- _update_health_callback called (line 839) ----

    async def test_xray_health_callback_invoked(self, monkeypatch) -> None:
        """_update_health_callback is called when provided."""
        callback = MagicMock()
        lv = _make_liveness(
            {
                "validator": {
                    "xray_enabled": True,
                    "xray_executable": "/usr/bin/xray",
                    "xray_probe_url": "https://example.com/probe",
                    "xray_timeout_seconds": 12.0,
                    "xray_startup_timeout_seconds": 4.0,
                    "xray_concurrency": 6,
                },
            },
            proxy_url_getter=_empty_proxy_list,
            update_health_callback=callback,
        )

        monkeypatch.setattr(
            "src.validators.xray_probe.find_xray_executable",
            lambda p: "/usr/bin/xray",
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.is_xray_supported",
            lambda cfg: True,
        )

        async def mock_xray(configs, **kwargs):
            for cfg in configs:
                cfg.xray_was_checked = True
                cfg.is_alive = True
            return list(configs)

        monkeypatch.setattr(
            "src.validators.xray_probe.validate_configs_xray",
            mock_xray,
        )

        configs = [_make_config("a.com")]
        result = await lv.validate_configs(
            configs,
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
        assert len(result) == 1
        callback.assert_called_once()

    # ---- _update_source_health_callback called (line 843) ----

    async def test_xray_source_health_callback_invoked(self, monkeypatch) -> None:
        """_update_source_health_callback is called when provided."""
        source_callback = MagicMock()
        lv = _make_liveness(
            {
                "validator": {
                    "xray_enabled": True,
                    "xray_executable": "/usr/bin/xray",
                    "xray_probe_url": "https://example.com/probe",
                    "xray_timeout_seconds": 12.0,
                    "xray_startup_timeout_seconds": 4.0,
                    "xray_concurrency": 6,
                },
            },
            proxy_url_getter=_empty_proxy_list,
            update_source_health_callback=source_callback,
        )

        monkeypatch.setattr(
            "src.validators.xray_probe.find_xray_executable",
            lambda p: "/usr/bin/xray",
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.is_xray_supported",
            lambda cfg: True,
        )

        async def mock_xray(configs, **kwargs):
            for cfg in configs:
                cfg.xray_was_checked = True
                cfg.is_alive = True
            return list(configs)

        monkeypatch.setattr(
            "src.validators.xray_probe.validate_configs_xray",
            mock_xray,
        )

        configs = [_make_config("a.com")]
        result = await lv.validate_configs(
            configs,
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
        assert len(result) == 1
        source_callback.assert_called_once()

    # ---- _xray_candidate_preselect non-whitelist (line 880) ----

    async def test_xray_candidate_preselect_non_whitelist(self, monkeypatch) -> None:
        """_xray_candidate_preselect non-whitelist uses country_balanced_limit."""
        lv = _make_liveness(
            {
                "validator": {
                    "xray_enabled": True,
                    "xray_executable": "/usr/bin/xray",
                    "xray_candidate_limit": 1,
                    "xray_probe_url": "https://example.com/probe",
                    "xray_timeout_seconds": 12.0,
                    "xray_startup_timeout_seconds": 4.0,
                    "xray_concurrency": 6,
                },
            },
            proxy_url_getter=_empty_proxy_list,
        )

        monkeypatch.setattr(
            "src.validators.xray_probe.find_xray_executable",
            lambda p: "/usr/bin/xray",
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.is_xray_supported",
            lambda cfg: True,
        )

        async def mock_xray(configs, **kwargs):
            for cfg in configs:
                cfg.xray_was_checked = True
                cfg.is_alive = True
            return list(configs)

        monkeypatch.setattr(
            "src.validators.xray_probe.validate_configs_xray",
            mock_xray,
        )
        # Mock Aggregator to return only 1 config
        mock_agg = MagicMock()
        mock_agg._country_balanced_limit.return_value = [
            _make_config("selected.com", 443),
        ]
        monkeypatch.setattr(
            "src.scheduler.stages.aggregate.Aggregator",
            lambda ctx: mock_agg,
        )

        configs = [_make_config(f"h{i}.com", 4000 + i) for i in range(3)]
        result = await lv.validate_configs(
            configs,
            label="blacklist",  # not whitelist
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
        assert len(result) == 1

    # ---- TCP remaining_alive break (line 486) ----

    async def test_tcp_remaining_alive_break(self, monkeypatch) -> None:
        """remaining_alive <= 0 break after finding max_alive."""
        lv = _make_liveness(
            {
                "validator": {
                    "tcp_enabled": True,
                    "tcp_timeout_seconds": 5.0,
                    "tcp_concurrency": 300,
                    "tcp_max_alive": 1,
                    "tcp_candidate_limit": 1,
                },
            },
            proxy_url_getter=_empty_proxy_list,
        )

        async def mock_tcp_single(batch, **kwargs):
            """Treat the first config as alive, but we only get 1 per batch."""
            return list(batch)

        monkeypatch.setattr(
            "src.validators.tcp_check.validate_configs_tcp",
            mock_tcp_single,
        )

        configs = [_make_config("a.com"), _make_config("b.com")]
        result = await lv.validate_configs(
            configs,
            label="blacklist",
            tcp_enabled=True,
            tls_enabled=False,
        )
        # max_alive=1 means only 1 config checked (strict mode, no passthrough)
        assert len(result) == 1
        assert result[0].address == "a.com"


# ============================================================================
# Regression: xray_drop_unsupported=false with a mixed protocol list
# ============================================================================


def _xray_settings(**extra) -> dict:
    validator = {
        "xray_enabled": True,
        "xray_executable": "/usr/bin/xray",
        "xray_probe_url": "https://example.com/probe",
        "xray_timeout_seconds": 12.0,
        "xray_startup_timeout_seconds": 4.0,
        "xray_concurrency": 6,
    }
    validator.update(extra)
    return {"validator": validator}


def _patch_xray(monkeypatch, alive_prefix: str = "ok") -> None:
    """Patch the xray probe so only ``alive_prefix`` vless configs pass."""
    monkeypatch.setattr(
        "src.validators.xray_probe.find_xray_executable",
        lambda p: "/usr/bin/xray",
    )
    monkeypatch.setattr(
        "src.validators.xray_probe.is_xray_supported",
        lambda cfg: cfg.protocol == "vless",
    )

    async def mock_xray(configs, **kwargs):
        alive = []
        for cfg in configs:
            cfg.xray_was_checked = True
            if cfg.address.startswith(alive_prefix):
                cfg.is_alive = True
                alive.append(cfg)
        return alive

    monkeypatch.setattr(
        "src.validators.xray_probe.validate_configs_xray",
        mock_xray,
    )


class TestXrayUnsupportedHandling:
    """xray_drop_unsupported must be honoured for mixed protocol lists."""

    @staticmethod
    def _mixed_configs() -> list[Config]:
        return [
            _make_config("ok0.com", 4000, protocol="vless"),
            _make_config("hy0.com", 4001, protocol="hysteria2"),
            _make_config("dead1.com", 4002, protocol="vless"),
            _make_config("hy1.com", 4003, protocol="hysteria2"),
            _make_config("ok2.com", 4004, protocol="vless"),
        ]

    async def test_unsupported_kept_when_drop_disabled(self, monkeypatch) -> None:
        """Unsupported protocols survive in original order when kept."""
        lv = _make_liveness(
            _xray_settings(xray_drop_unsupported=False),
            proxy_url_getter=_empty_proxy_list,
        )
        _patch_xray(monkeypatch)

        result = await lv.validate_configs(
            self._mixed_configs(),
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )

        assert [cfg.address for cfg in result] == [
            "ok0.com",
            "hy0.com",
            "hy1.com",
            "ok2.com",
        ]
        stats = lv.context.liveness_stats["lists"]["blacklist"]
        assert stats["xray_unsupported"] == 2
        assert stats["xray_unsupported_kept"] == 2

    async def test_unsupported_dropped_when_drop_enabled(self, monkeypatch) -> None:
        """The default (drop) behaviour keeps only Xray-alive configs."""
        lv = _make_liveness(
            _xray_settings(xray_drop_unsupported=True),
            proxy_url_getter=_empty_proxy_list,
        )
        _patch_xray(monkeypatch)

        result = await lv.validate_configs(
            self._mixed_configs(),
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )

        assert [cfg.address for cfg in result] == ["ok0.com", "ok2.com"]
        stats = lv.context.liveness_stats["lists"]["blacklist"]
        assert "xray_unsupported_kept" not in stats

    async def test_kept_unsupported_counted_in_stage_output(self, monkeypatch) -> None:
        """output_after_* must describe the merged list the stage returns."""
        lv = _make_liveness(
            _xray_settings(xray_drop_unsupported=False),
            proxy_url_getter=_empty_proxy_list,
        )
        _patch_xray(monkeypatch)

        result = await lv.validate_configs(
            self._mixed_configs(),
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )

        stats = lv.context.liveness_stats["lists"]["blacklist"]
        assert len(result) == 4
        assert stats["xray_alive"] == 2
        assert stats["output_after_xray"] == len(result)
        assert stats["output_after_health"] == len(result)

    async def test_kept_unsupported_still_obey_source_ban(self, monkeypatch) -> None:
        """A banned source must not slip back in via an unprobed protocol.

        A config that passed its Xray probe overrides the ban (fresh
        evidence), but an unsupported protocol carries no such evidence.
        """
        settings = _xray_settings(xray_drop_unsupported=False)
        settings["quality"] = {"health_ban_min_alive": 0}
        lv = _make_liveness(settings, proxy_url_getter=_empty_proxy_list)
        _patch_xray(monkeypatch)
        lv.health.load()["sources"]["bad-src"] = {"banned_until": 9_999_999_999}

        configs = [
            _make_config("ok0.com", 4000, protocol="vless", source_name="bad-src"),
            _make_config("hy0.com", 4001, protocol="hysteria2", source_name="bad-src"),
            _make_config("ok1.com", 4002, protocol="vless", source_name="good-src"),
            _make_config("hy1.com", 4003, protocol="hysteria2", source_name="good-src"),
        ]
        result = await lv.validate_configs(
            configs,
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )

        # ok0 passed Xray right now and survives despite the source ban;
        # hy0 was never probed and stays banned.
        assert [cfg.address for cfg in result] == ["ok0.com", "ok1.com", "hy1.com"]
        stats = lv.context.liveness_stats["lists"]["blacklist"]
        assert stats["output_after_health"] == 3


# ============================================================================
# Regression: fail-open must not bypass the Xray stage
# ============================================================================


class TestFailOpenDoesNotSkipXray:
    """A TCP/TLS fail-open keeps configs unfiltered but still runs Xray."""

    async def test_tcp_fail_open_still_requires_xray(self, monkeypatch) -> None:
        """Required-but-missing xray drops everything even after a TCP fail-open."""
        lv = _make_liveness(
            _xray_settings(
                tcp_enabled=True,
                tcp_timeout_seconds=5.0,
                tcp_concurrency=300,
                min_alive_to_filter=10,
                fail_open_on_low_alive=True,
                xray_required=True,
            ),
            proxy_url_getter=_empty_proxy_list,
        )

        async def mock_tcp(batch, **kwargs):
            return []

        monkeypatch.setattr("src.validators.tcp_check.validate_configs_tcp", mock_tcp)
        monkeypatch.setattr(
            "src.validators.xray_probe.find_xray_executable",
            lambda p: None,
        )

        result = await lv.validate_configs(
            [_make_config(f"h{i}.com", 4000 + i) for i in range(3)],
            label="blacklist",
            tcp_enabled=True,
            tls_enabled=False,
            xray_enabled=True,
        )

        assert result == []
        stats = lv.context.liveness_stats["lists"]["blacklist"]
        assert stats["fail_open"] is True
        assert stats["reason"] == "xray_unavailable"

    async def test_tcp_fail_open_configs_reach_xray(self, monkeypatch) -> None:
        """All configs — not only TCP-alive ones — are handed to Xray."""
        lv = _make_liveness(
            _xray_settings(
                tcp_enabled=True,
                tcp_timeout_seconds=5.0,
                tcp_concurrency=300,
                min_alive_to_filter=10,
                fail_open_on_low_alive=True,
            ),
            proxy_url_getter=_empty_proxy_list,
        )

        async def mock_tcp(batch, **kwargs):
            return []

        monkeypatch.setattr("src.validators.tcp_check.validate_configs_tcp", mock_tcp)
        _patch_xray(monkeypatch)

        configs = [
            _make_config("ok0.com", 4000, protocol="vless"),
            _make_config("dead1.com", 4001, protocol="vless"),
        ]
        result = await lv.validate_configs(
            configs,
            label="blacklist",
            tcp_enabled=True,
            tls_enabled=False,
            xray_enabled=True,
        )

        assert [cfg.address for cfg in result] == ["ok0.com"]
        stats = lv.context.liveness_stats["lists"]["blacklist"]
        assert stats["fail_open"] is True
        assert stats["xray_checked"] == 2

    async def test_tcp_fail_open_without_xray_keeps_old_behaviour(
        self,
        monkeypatch,
    ) -> None:
        """Without Xray a TCP fail-open still returns the untouched input list."""
        lv = _make_liveness(
            {
                "validator": {
                    "tcp_enabled": True,
                    "tls_enabled": True,
                    "tcp_timeout_seconds": 5.0,
                    "tcp_concurrency": 300,
                    "min_alive_to_filter": 10,
                    "fail_open_on_low_alive": True,
                },
            },
            proxy_url_getter=_empty_proxy_list,
        )

        async def mock_tcp(batch, **kwargs):
            return []

        async def mock_tls(configs, **kwargs):
            msg = "TLS must not run after a TCP fail-open"
            raise AssertionError(msg)

        monkeypatch.setattr("src.validators.tcp_check.validate_configs_tcp", mock_tcp)
        monkeypatch.setattr("src.validators.tls_check.validate_configs_tls", mock_tls)

        configs = [
            _make_config(f"h{i}.com", 4000 + i, security="tls") for i in range(3)
        ]
        result = await lv.validate_configs(
            configs,
            label="blacklist",
            tcp_enabled=True,
            tls_enabled=True,
        )

        assert result == configs

    async def test_tls_fail_open_still_runs_xray(self, monkeypatch) -> None:
        """A TLS fail-open no longer returns pre-TLS configs unvalidated."""
        lv = _make_liveness(
            _xray_settings(
                tls_enabled=True,
                tls_timeout_seconds=5.0,
                tls_concurrency=120,
                min_alive_to_filter=10,
                fail_open_on_low_alive=True,
            ),
            proxy_url_getter=_empty_proxy_list,
        )

        async def mock_tls(configs, **kwargs):
            return []

        monkeypatch.setattr("src.validators.tls_check.validate_configs_tls", mock_tls)
        _patch_xray(monkeypatch)

        configs = [
            _make_config("ok0.com", 4000, protocol="vless", security="tls"),
            _make_config("dead1.com", 4001, protocol="vless", security="tls"),
        ]
        result = await lv.validate_configs(
            configs,
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=True,
            xray_enabled=True,
        )

        assert [cfg.address for cfg in result] == ["ok0.com"]
        stats = lv.context.liveness_stats["lists"]["blacklist"]
        assert stats["fail_open"] is True
        assert stats["xray_checked"] == 2

    async def test_tcp_fail_open_records_step_output(self, monkeypatch) -> None:
        """A TCP fail-open must report the unfiltered list as its output."""
        lv = _make_liveness(
            _xray_settings(
                tcp_enabled=True,
                tcp_timeout_seconds=5.0,
                tcp_concurrency=300,
                min_alive_to_filter=10,
                fail_open_on_low_alive=True,
            ),
            proxy_url_getter=_empty_proxy_list,
        )

        async def mock_tcp(batch, **kwargs):
            return []

        monkeypatch.setattr("src.validators.tcp_check.validate_configs_tcp", mock_tcp)
        _patch_xray(monkeypatch)

        configs = [
            _make_config("ok0.com", 4000, protocol="vless"),
            _make_config("dead1.com", 4001, protocol="vless"),
        ]
        await lv.validate_configs(
            configs,
            label="blacklist",
            tcp_enabled=True,
            tls_enabled=False,
            xray_enabled=True,
        )

        stats = lv.context.liveness_stats["lists"]["blacklist"]
        assert stats["fail_open"] is True
        assert stats["output_after_tcp"] == 2

    async def test_tls_fail_open_records_step_output(self, monkeypatch) -> None:
        """A fail-open must still report how many configs left TCP and TLS."""
        lv = _make_liveness(
            _xray_settings(
                tcp_enabled=True,
                tls_enabled=True,
                tcp_timeout_seconds=5.0,
                tcp_concurrency=300,
                tls_timeout_seconds=5.0,
                tls_concurrency=120,
                min_alive_to_filter=10,
                fail_open_on_low_alive=True,
            ),
            proxy_url_getter=_empty_proxy_list,
        )

        async def mock_tcp(batch, **kwargs):
            return list(batch)

        async def mock_tls(configs, **kwargs):
            return []

        monkeypatch.setattr("src.validators.tcp_check.validate_configs_tcp", mock_tcp)
        monkeypatch.setattr("src.validators.tls_check.validate_configs_tls", mock_tls)
        _patch_xray(monkeypatch)

        configs = [
            _make_config("ok0.com", 4000, protocol="vless", security="tls"),
            _make_config("dead1.com", 4001, protocol="vless", security="tls"),
        ]
        result = await lv.validate_configs(
            configs,
            label="blacklist",
            tcp_enabled=True,
            tls_enabled=True,
            xray_enabled=True,
        )

        assert [cfg.address for cfg in result] == ["ok0.com"]
        stats = lv.context.liveness_stats["lists"]["blacklist"]
        # TCP passed 2 through, then the TLS fail-open kept the same 2.
        assert stats["output_after_tcp"] == 2
        assert stats["output_after_tls"] == 2


# ============================================================================
# Regression: liveness_stats defaults must match the effective defaults
# ============================================================================


class TestLivenessStatsDefaults:
    """run-summary.json must not report proxy settings that were never used."""

    async def test_defaults_match_effective_values(self) -> None:
        """Without a validator.proxy_pool section the pool is off, not on."""
        lv = _make_liveness({"validator": {"tcp_enabled": True}})

        await lv.validate_by_list({})

        stats = lv.context.liveness_stats
        assert stats["proxy_pool_enabled"] is False
        assert stats["proxy_pool_required"] is False
        assert stats["proxy_attempts_per_config"] == 5
        assert stats["tls_proxy_attempts_per_config"] == 5


# ============================================================================
# Regression: health history, thresholds and reasons outside the Xray branch
# ============================================================================


class TestHealthHistoryWithoutXray:
    """The quality block must not depend on the Xray stage running."""

    async def test_tcp_only_run_updates_health_and_sources(self, monkeypatch) -> None:
        """health.update()/update_sources() ran only inside the Xray branch.

        With xray_enabled: false the history file was rewritten empty on every
        run, so ban_after_consecutive_failures, ban_cooldown_hours and
        source_bad_runs_to_ban never had anything to work with.
        """
        lv = _make_liveness(
            {
                "validator": {"tcp_enabled": True, "min_alive_to_filter": 1},
                "quality": {"health_history_enabled": True},
            },
            proxy_url_getter=_empty_proxy_list,
        )

        async def mock_tcp(batch, **kwargs):
            alive = []
            for index, cfg in enumerate(batch):
                cfg.is_alive = index == 0
                if cfg.is_alive:
                    alive.append(cfg)
            return alive

        monkeypatch.setattr("src.validators.tcp_check.validate_configs_tcp", mock_tcp)

        configs = [
            _make_config(f"h{i}.com", 4000 + i, source_name="src-a") for i in range(3)
        ]
        await lv.validate_configs(
            configs,
            label="blacklist",
            tcp_enabled=True,
            tls_enabled=False,
        )

        history = lv.health.load()
        assert len(history["configs"]) == 3
        records = list(history["configs"].values())
        assert sum(1 for r in records if r["passes"] == 1) == 1
        assert sum(1 for r in records if r["fails"] == 1) == 2
        stats = lv.context.liveness_stats["lists"]["blacklist"]
        assert stats["sources"]["src-a"] == {"checked": 3, "alive": 1}

    async def test_source_ban_keeps_freshly_probed_configs(self, monkeypatch) -> None:
        """A source ban must not erase configs probed alive in this pass.

        ``_drop_banned`` used to feed every survivor — including configs that
        had just passed their TCP probe — through ``is_banned``, so one
        source-level ban wiped an entire freshly validated list.
        """
        lv = _make_liveness(
            {
                "validator": {"tcp_enabled": True, "min_alive_to_filter": 1},
                "quality": {
                    "health_history_enabled": True,
                    "health_ban_min_alive": 0,
                },
            },
            proxy_url_getter=_empty_proxy_list,
        )
        configs = [
            _make_config(f"h{i}.com", 4000 + i, source_name="bad-src") for i in range(3)
        ]
        lv.health._cache = {
            "configs": {},
            "sources": {"bad-src": {"banned_until": 4102444800}},
        }

        async def mock_tcp(batch, **kwargs):
            for cfg in batch:
                cfg.is_alive = True
            return list(batch)

        monkeypatch.setattr("src.validators.tcp_check.validate_configs_tcp", mock_tcp)

        result = await lv.validate_configs(
            configs,
            label="blacklist",
            tcp_enabled=True,
            tls_enabled=False,
        )
        # Fresh evidence outranks the stale source-level ban.
        assert [cfg.address for cfg in result] == ["h0.com", "h1.com", "h2.com"]
        assert configs[0].quality_block_reason is None

    async def test_source_ban_still_drops_unprobed_configs(self, monkeypatch) -> None:
        """Recorded bans stay enforced for configs the probes never judged.

        The fresh-verdict exemption covers configs probed in this pass only:
        an unprobed config (here: a TCP skip-list protocol riding through as
        passthrough) from a banned source is still dropped.
        """
        lv = _make_liveness(
            {
                "validator": {"tcp_enabled": True, "min_alive_to_filter": 1},
                "quality": {
                    "health_history_enabled": True,
                    "health_ban_min_alive": 0,
                },
            },
            proxy_url_getter=_empty_proxy_list,
        )
        lv.health._cache = {
            "configs": {},
            "sources": {"bad-src": {"banned_until": 4102444800}},
        }

        async def mock_tcp(batch, **kwargs):
            for cfg in batch:
                if cfg.protocol == "vless":
                    cfg.is_alive = True
            return [cfg for cfg in batch if cfg.protocol == "vless"]

        monkeypatch.setattr("src.validators.tcp_check.validate_configs_tcp", mock_tcp)

        configs = [
            _make_config("fresh.com", 4000, source_name="bad-src"),
            _make_config(
                "unprobed.com",
                4001,
                protocol="hysteria2",
                source_name="bad-src",
            ),
        ]
        result = await lv.validate_configs(
            configs,
            label="blacklist",
            tcp_enabled=True,
            tls_enabled=False,
        )
        assert [cfg.address for cfg in result] == ["fresh.com"]
        assert configs[1].quality_block_reason == "source_ban"

    async def test_health_updates_go_through_injected_callbacks(
        self,
        monkeypatch,
    ) -> None:
        """The runner injects its own health callbacks; they must be used."""
        recorded: list[list[Config]] = []
        source_calls: list[dict] = []
        lv = _make_liveness(
            {
                "validator": {"tcp_enabled": True, "min_alive_to_filter": 1},
                "quality": {"health_history_enabled": True},
            },
            proxy_url_getter=_empty_proxy_list,
            update_health_callback=recorded.append,
            update_source_health_callback=lambda cfgs, stats: source_calls.append(
                stats,
            ),
        )

        async def mock_tcp(batch, **kwargs):
            for cfg in batch:
                cfg.is_alive = True
            return list(batch)

        monkeypatch.setattr("src.validators.tcp_check.validate_configs_tcp", mock_tcp)

        await lv.validate_configs(
            [_make_config("h1.com", 443)],
            label="blacklist",
            tcp_enabled=True,
            tls_enabled=False,
        )
        assert len(recorded) == 1
        assert len(recorded[0]) == 1
        list_stats = lv.context.liveness_stats["lists"]["blacklist"]
        assert source_calls == [list_stats]

    async def test_unprobed_configs_are_not_recorded(self, monkeypatch) -> None:
        """Only configs a validator actually judged reach the history."""
        lv = _make_liveness(
            {
                "validator": {"tcp_enabled": True, "min_alive_to_filter": 1},
                "quality": {"health_history_enabled": True},
            },
            proxy_url_getter=_empty_proxy_list,
        )

        async def mock_tcp(batch, **kwargs):
            # Emulates the address guard: the second config never gets a socket.
            batch[0].is_alive = True
            return [batch[0]]

        monkeypatch.setattr("src.validators.tcp_check.validate_configs_tcp", mock_tcp)

        configs = [_make_config("h0.com", 4000), _make_config("h1.com", 4001)]
        await lv.validate_configs(
            configs,
            label="blacklist",
            tcp_enabled=True,
            tls_enabled=False,
        )
        assert len(lv.health.load()["configs"]) == 1


class TestLivenessReportingRegressions:
    """Per-list statistics must describe what really happened."""

    async def test_no_proxies_reason_cleared_when_xray_validates(
        self,
        monkeypatch,
    ) -> None:
        """An empty required pool plus Xray still validates the list in full.

        Leaving reason="no_proxies" told every run-summary reader that nothing
        was checked while TCP/TLS/Xray had run.
        """
        lv = _make_liveness(
            {
                "validator": {
                    "xray_enabled": True,
                    "xray_executable": "/usr/bin/xray",
                    "proxy_pool": {"enabled": True, "required": True},
                },
            },
            proxy_url_getter=_empty_proxy_list,
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.find_xray_executable",
            lambda p: "/usr/bin/xray",
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.is_xray_supported",
            lambda cfg: True,
        )

        async def mock_xray(configs, **kwargs):
            for cfg in configs:
                cfg.xray_was_checked = True
                cfg.is_alive = True
            return list(configs)

        monkeypatch.setattr(
            "src.validators.xray_probe.validate_configs_xray",
            mock_xray,
        )

        await lv.validate_configs(
            [_make_config("h1.com", 443)],
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
        stats = lv.context.liveness_stats["lists"]["blacklist"]
        assert stats["reason"] != "no_proxies"
        assert stats["proxy_pool_empty"] is True
        assert stats["xray_checked"] == 1

    async def test_min_alive_counts_only_checked_candidates(
        self,
        monkeypatch,
        caplog,
    ) -> None:
        """The fail-open threshold must not include candidates never tried.

        With tcp_candidate_limit * tcp_search_rounds below the candidate count
        the untried remainder was counted as dead, which made the threshold
        unreachable and fired the fail-open on every run.
        """
        lv = _make_liveness(
            {
                "validator": {
                    "tcp_enabled": True,
                    "tcp_candidate_limit": 2,
                    "tcp_search_rounds": 1,
                    "min_alive_to_filter": 5,
                    "fail_open_on_low_alive": True,
                },
            },
            proxy_url_getter=_empty_proxy_list,
        )

        async def mock_tcp(batch, **kwargs):
            for cfg in batch:
                cfg.is_alive = True
            return list(batch)

        monkeypatch.setattr("src.validators.tcp_check.validate_configs_tcp", mock_tcp)

        caplog.set_level(logging.WARNING)
        configs = [_make_config(f"h{i}.com", 4000 + i) for i in range(10)]
        result = await lv.validate_configs(
            configs,
            label="blacklist",
            tcp_enabled=True,
            tls_enabled=False,
        )
        stats = lv.context.liveness_stats["lists"]["blacklist"]
        assert stats["tcp_checked"] == 2
        assert stats["min_alive_to_filter_tcp"] == 2
        assert stats["fail_open"] is False
        assert len(result) == 2

    async def test_tls_skip_after_tcp_fail_open_is_recorded(self, monkeypatch) -> None:
        """A TLS stage skipped by the fail-open must leave a trace."""
        lv = _make_liveness(
            {
                "validator": {
                    "tcp_enabled": True,
                    "tls_enabled": True,
                    "xray_enabled": True,
                    "xray_executable": "/usr/bin/xray",
                    "min_alive_to_filter": 10,
                    "fail_open_on_low_alive": True,
                },
            },
            proxy_url_getter=_empty_proxy_list,
        )

        async def mock_tcp(batch, **kwargs):
            for cfg in batch:
                cfg.is_alive = False
            return []

        monkeypatch.setattr("src.validators.tcp_check.validate_configs_tcp", mock_tcp)
        monkeypatch.setattr(
            "src.validators.xray_probe.find_xray_executable",
            lambda p: "",
        )

        await lv.validate_configs(
            [_make_config("h1.com", 443, security="tls")],
            label="blacklist",
            tcp_enabled=True,
            tls_enabled=True,
            xray_enabled=True,
        )
        stats = lv.context.liveness_stats["lists"]["blacklist"]
        assert stats["tls_skipped"] == "tcp_fail_open"


# ============================================================================
# sing-box integration (hysteria2/tuic L3 probe)
# ============================================================================


class TestSingboxIntegration:
    async def test_hy2_probed_by_singbox(self, monkeypatch) -> None:
        """hysteria2 configs go through sing-box instead of dying unsupported."""
        lv = _make_liveness(
            _xray_settings(singbox_enabled=True),
            proxy_url_getter=_empty_proxy_list,
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.find_xray_executable",
            lambda p: "/usr/bin/xray",
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.is_xray_supported",
            lambda cfg: cfg.protocol == "vless",
        )
        monkeypatch.setattr(
            "src.validators.singbox_probe.find_singbox_executable",
            lambda p: "/usr/bin/sing-box",
        )

        async def mock_xray(configs, **kwargs):
            for cfg in configs:
                cfg.xray_was_checked = True
                cfg.is_alive = True
            return list(configs)

        async def mock_singbox(configs, **kwargs):
            for cfg in configs:
                cfg.xray_was_checked = True
                cfg.is_alive = True
            return list(configs)

        monkeypatch.setattr(
            "src.validators.xray_probe.validate_configs_xray",
            mock_xray,
        )
        monkeypatch.setattr(
            "src.validators.singbox_probe.validate_configs_singbox",
            mock_singbox,
        )

        configs = [
            _make_config("ok.com", 4000, protocol="vless"),
            _make_config("hy.com", 4001, protocol="hysteria2", security="tls"),
        ]
        result = await lv.validate_configs(
            configs,
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
        assert [cfg.protocol for cfg in result] == ["vless", "hysteria2"]
        stats = lv.context.liveness_stats["lists"]["blacklist"]
        assert stats["singbox_alive"] == 1
        assert stats["xray_alive"] == 2

    async def test_singbox_unavailable_drops_hy2(self, monkeypatch) -> None:
        """No sing-box binary -> hy2 keeps the old 'unsupported' fate."""
        lv = _make_liveness(
            _xray_settings(singbox_enabled=True),
            proxy_url_getter=_empty_proxy_list,
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.find_xray_executable",
            lambda p: "/usr/bin/xray",
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.is_xray_supported",
            lambda cfg: cfg.protocol == "vless",
        )
        monkeypatch.setattr(
            "src.validators.singbox_probe.find_singbox_executable",
            lambda p: None,
        )

        async def mock_xray(configs, **kwargs):
            return list(configs)

        monkeypatch.setattr(
            "src.validators.xray_probe.validate_configs_xray",
            mock_xray,
        )

        result = await lv.validate_configs(
            [
                _make_config("ok.com", 4000, protocol="vless"),
                _make_config("hy.com", 4001, protocol="hysteria2", security="tls"),
            ],
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
        assert [cfg.protocol for cfg in result] == ["vless"]
        stats = lv.context.liveness_stats["lists"]["blacklist"]
        assert stats.get("singbox_alive") is None

    async def test_singbox_disabled_by_default_drops_hy2(self, monkeypatch) -> None:
        lv = _make_liveness(
            _xray_settings(),
            proxy_url_getter=_empty_proxy_list,
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.find_xray_executable",
            lambda p: "/usr/bin/xray",
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.is_xray_supported",
            lambda cfg: cfg.protocol == "vless",
        )

        async def mock_xray(configs, **kwargs):
            return list(configs)

        monkeypatch.setattr(
            "src.validators.xray_probe.validate_configs_xray",
            mock_xray,
        )
        monkeypatch.setattr(
            "src.validators.singbox_probe.find_singbox_executable",
            lambda p: "/usr/bin/sing-box",
        )

        result = await lv.validate_configs(
            [_make_config("hy.com", 4001, protocol="hysteria2", security="tls")],
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
        assert result == []

    async def test_singbox_skipped_when_budget_full(self, monkeypatch) -> None:
        """A saturated Xray budget must not turn into 'unlimited' for sing-box."""
        lv = _make_liveness(
            _xray_settings(singbox_enabled=True, xray_max_alive=1),
            proxy_url_getter=_empty_proxy_list,
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.find_xray_executable",
            lambda p: "/usr/bin/xray",
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.is_xray_supported",
            lambda cfg: cfg.protocol == "vless",
        )
        monkeypatch.setattr(
            "src.validators.singbox_probe.find_singbox_executable",
            lambda p: "/usr/bin/sing-box",
        )

        async def mock_xray(configs, **kwargs):
            for cfg in configs:
                cfg.xray_was_checked = True
                cfg.is_alive = True
            return list(configs)

        async def mock_singbox(configs, **kwargs):  # pragma: no cover - must not run
            raise AssertionError("sing-box must not run with a full budget")

        monkeypatch.setattr(
            "src.validators.xray_probe.validate_configs_xray",
            mock_xray,
        )
        monkeypatch.setattr(
            "src.validators.singbox_probe.validate_configs_singbox",
            mock_singbox,
        )

        result = await lv.validate_configs(
            [
                _make_config("ok.com", 4000, protocol="vless"),
                _make_config("ok2.com", 4002, protocol="vless"),
                _make_config("hy.com", 4001, protocol="hysteria2", security="tls"),
            ],
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
        assert all(cfg.protocol == "vless" for cfg in result)
        stats = lv.context.liveness_stats["lists"]["blacklist"]
        assert stats["singbox_skipped"] == "budget_full"


# ============================================================================
# Verification TTL cache
# ============================================================================


class TestVerificationTtl:
    async def test_fresh_configs_get_single_attempt(self, monkeypatch) -> None:
        lv = _make_liveness(
            _xray_settings(verification_ttl_minutes=60, xray_attempts_per_config=2),
            proxy_url_getter=_empty_proxy_list,
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.find_xray_executable",
            lambda p: "/usr/bin/xray",
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.is_xray_supported",
            lambda cfg: True,
        )
        # Record a pass "just now" for one config.
        fresh_cfg = _make_config("fresh.com", 4000, is_alive=True)
        stale_cfg = _make_config("stale.com", 4001)
        lv.health.update([fresh_cfg])
        record = lv.health.load()["configs"][lv.health.config_key(fresh_cfg)]
        record["last_alive"] = int(time.time())

        attempts_seen: list[int] = []

        async def mock_xray(configs, **kwargs):
            attempts_seen.append(int(kwargs.get("attempts_per_config", 0)))
            for cfg in configs:
                cfg.xray_was_checked = True
                cfg.is_alive = True
            return list(configs)

        monkeypatch.setattr(
            "src.validators.xray_probe.validate_configs_xray",
            mock_xray,
        )

        result = await lv.validate_configs(
            [fresh_cfg, stale_cfg],
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
        assert len(result) == 2
        # One call for fresh (1 attempt), one for stale (full attempts).
        assert sorted(attempts_seen) == [1, 2]
        stats = lv.context.liveness_stats["lists"]["blacklist"]
        assert stats["xray_fresh_verified"] == 1

    async def test_fresh_budget_reserved_for_new_candidates(self, monkeypatch) -> None:
        """Fresh re-probes must not consume the whole alive budget."""
        lv = _make_liveness(
            _xray_settings(verification_ttl_minutes=60, xray_max_alive=4),
            proxy_url_getter=_empty_proxy_list,
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.find_xray_executable",
            lambda p: "/usr/bin/xray",
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.is_xray_supported",
            lambda cfg: True,
        )
        fresh_cfg = _make_config("fresh.com", 4000, is_alive=True)
        stale_cfg = _make_config("stale.com", 4001)
        lv.health.update([fresh_cfg])
        record = lv.health.load()["configs"][lv.health.config_key(fresh_cfg)]
        record["last_alive"] = int(time.time())

        budgets: list[int] = []

        async def mock_xray(configs, **kwargs):
            budgets.append(int(kwargs.get("max_alive", 0)))
            for cfg in configs:
                cfg.xray_was_checked = True
                cfg.is_alive = True
            return list(configs)

        monkeypatch.setattr(
            "src.validators.xray_probe.validate_configs_xray",
            mock_xray,
        )
        await lv.validate_configs(
            [fresh_cfg, stale_cfg],
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
        # Fresh gets at most half of max_alive (4 -> 2); the unused headroom
        # plus the reserved half flows to the stale (new-candidate) call.
        assert budgets == [2, 3]

    async def test_ttl_zero_disables_split(self, monkeypatch) -> None:
        lv = _make_liveness(
            _xray_settings(),
            proxy_url_getter=_empty_proxy_list,
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.find_xray_executable",
            lambda p: "/usr/bin/xray",
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.is_xray_supported",
            lambda cfg: True,
        )
        fresh_cfg = _make_config("fresh.com", 4000, is_alive=True)
        lv.health.update([fresh_cfg])

        calls: list[list[str]] = []

        async def mock_xray(configs, **kwargs):
            calls.append([cfg.address for cfg in configs])
            for cfg in configs:
                cfg.xray_was_checked = True
                cfg.is_alive = True
            return list(configs)

        monkeypatch.setattr(
            "src.validators.xray_probe.validate_configs_xray",
            mock_xray,
        )
        await lv.validate_configs(
            [fresh_cfg],
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
        assert len(calls) == 1
        stats = lv.context.liveness_stats["lists"]["blacklist"]
        assert "xray_fresh_verified" not in stats

    async def test_ttl_fresh_failure_gets_standard_retry(self, monkeypatch) -> None:
        """A failed fast re-probe must be retried before it counts toward a ban.

        The TTL path probes with attempts_per_config=1; without the retry,
        two unlucky single-probe runs in a row banned exactly the servers
        that had recently passed (2 consecutive failures -> 12h ban).
        """
        lv = _make_liveness(
            _xray_settings(
                verification_ttl_minutes=60,
                xray_attempts_per_config=2,
            ),
            proxy_url_getter=_empty_proxy_list,
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.find_xray_executable",
            lambda p: "/usr/bin/xray",
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.is_xray_supported",
            lambda cfg: True,
        )
        fresh_cfg = _make_config("fresh.com", 4000, is_alive=True)
        lv.health.update([fresh_cfg])
        record = lv.health.load()["configs"][lv.health.config_key(fresh_cfg)]
        record["last_alive"] = int(time.time())

        calls: list[tuple[list[str], int | None]] = []

        async def mock_xray(configs, **kwargs):
            calls.append(
                ([c.address for c in configs], kwargs.get("attempts_per_config"))
            )
            if len(calls) == 1:
                # The cheap single re-probe transiently fails.
                return []
            for cfg in configs:
                cfg.xray_was_checked = True
                cfg.is_alive = True
            return list(configs)

        monkeypatch.setattr(
            "src.validators.xray_probe.validate_configs_xray",
            mock_xray,
        )
        result = await lv.validate_configs(
            [fresh_cfg],
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
        # Second call happened, with standard attempts, and the config survived.
        assert [addr for addr, _ in calls] == [["fresh.com"], ["fresh.com"]]
        assert calls[0][1] == 1
        assert calls[1][1] == 2
        assert [cfg.address for cfg in result] == ["fresh.com"]
        stats = lv.context.liveness_stats["lists"]["blacklist"]
        assert stats["xray_fresh_retried"] == 1


# ============================================================================
# Mid-run pool death check (_pool_died_after_empty_list)
# ============================================================================


class TestPoolDiedAfterEmptyList:
    async def test_partial_death_prunes_dead_proxies(self, monkeypatch) -> None:
        lv = _make_liveness(
            {"validator": {"proxy_pool": {"enabled": True}}},
        )
        lv._validator_proxy_urls_cache = [
            "socks5://10.0.0.1:1080",
            "socks5://10.0.0.2:1080",
        ]
        recorded: list[tuple[str, bool]] = []

        class FakeHistory:
            def record(self, proxy_url: str, success: bool, latency_ms=None):
                recorded.append((proxy_url, success))

        lv._proxy_health_history = FakeHistory()

        async def fake_connects(proxy_url, **kwargs):
            return proxy_url == "socks5://10.0.0.2:1080"

        monkeypatch.setattr(
            "src.validators.proxy_pool.proxy_connects",
            fake_connects,
        )

        await lv._pool_died_after_empty_list("blacklist")

        assert lv._validator_proxy_urls_cache == ["socks5://10.0.0.2:1080"]
        assert sorted(recorded) == [
            ("socks5://10.0.0.1:1080", False),
            ("socks5://10.0.0.2:1080", True),
        ]

    async def test_total_death_invalidates_cache_once(self, monkeypatch) -> None:
        lv = _make_liveness(
            {"validator": {"proxy_pool": {"enabled": True}}},
        )
        lv._validator_proxy_urls_cache = ["socks5://10.0.0.1:1080"]

        connect_calls: list[str] = []

        async def fake_connects(proxy_url, **kwargs):
            connect_calls.append(proxy_url)
            return False

        monkeypatch.setattr(
            "src.validators.proxy_pool.proxy_connects",
            fake_connects,
        )

        await lv._pool_died_after_empty_list("blacklist")
        assert lv._validator_proxy_urls_cache is None
        assert lv._pool_refetch_used is True

        # A second zero-alive list in the same run does not re-fetch again.
        await lv._pool_died_after_empty_list("whitelist")
        assert len(connect_calls) == 1

    async def test_disabled_pool_is_a_noop(self, monkeypatch) -> None:
        lv = _make_liveness({"validator": {"proxy_pool": {"enabled": False}}})
        called = False

        async def fake_connects(proxy_url, **kwargs):
            nonlocal called
            called = True
            return False

        monkeypatch.setattr(
            "src.validators.proxy_pool.proxy_connects",
            fake_connects,
        )
        lv._pool_refetch_used = False
        lv._validator_proxy_urls_cache = None
        await lv._pool_died_after_empty_list("blacklist")
        assert not called

    async def test_refresh_knob_disabled_is_a_noop(self, monkeypatch) -> None:
        lv = _make_liveness(
            {
                "validator": {
                    "proxy_pool": {
                        "enabled": True,
                        "health": {"refresh_if_below_min": False},
                    },
                },
            },
        )
        called = False

        async def fake_connects(proxy_url, **kwargs):
            nonlocal called
            called = True
            return False

        monkeypatch.setattr(
            "src.validators.proxy_pool.proxy_connects",
            fake_connects,
        )
        lv._validator_proxy_urls_cache = ["socks5://10.0.0.1:1080"]
        await lv._pool_died_after_empty_list("blacklist")
        assert not called
        assert lv._validator_proxy_urls_cache == ["socks5://10.0.0.1:1080"]

    async def test_explicit_only_cache_is_a_noop(self, monkeypatch) -> None:
        import os

        lv = _make_liveness(
            {
                "validator": {
                    "proxy_pool": {"enabled": True},
                    "proxy_url": "socks5://exp:1",
                }
            },
        )
        called = False

        async def fake_connects(proxy_url, **kwargs):
            nonlocal called
            called = True
            return False

        monkeypatch.setattr(
            "src.validators.proxy_pool.proxy_connects",
            fake_connects,
        )
        monkeypatch.setattr(os, "environ", {**os.environ})
        lv._validator_proxy_urls_cache = ["socks5://exp:1"]
        await lv._pool_died_after_empty_list("blacklist")
        assert not called

    async def test_healthy_pool_untouched(self, monkeypatch) -> None:
        """All proxies respond → the zero-alive verdict is the lists', cache stays."""
        lv = _make_liveness(
            {"validator": {"proxy_pool": {"enabled": True}}},
        )
        lv._validator_proxy_urls_cache = ["socks5://10.0.0.1:1080"]

        async def fake_connects(proxy_url, **kwargs):
            return True

        monkeypatch.setattr(
            "src.validators.proxy_pool.proxy_connects",
            fake_connects,
        )
        await lv._pool_died_after_empty_list("blacklist")
        assert lv._validator_proxy_urls_cache == ["socks5://10.0.0.1:1080"]

    async def test_selfcheck_without_history_still_prunes(self, monkeypatch) -> None:
        lv = _make_liveness(
            {"validator": {"proxy_pool": {"enabled": True}}},
        )
        lv._proxy_health_history = None
        lv._validator_proxy_urls_cache = [
            "socks5://10.0.0.1:1080",
            "socks5://10.0.0.2:1080",
        ]

        async def fake_connects(proxy_url, **kwargs):
            return proxy_url.endswith(":1080") and "10.0.0.2" in proxy_url

        monkeypatch.setattr(
            "src.validators.proxy_pool.proxy_connects",
            fake_connects,
        )
        await lv._pool_died_after_empty_list("blacklist")
        assert lv._validator_proxy_urls_cache == ["socks5://10.0.0.2:1080"]


# ============================================================================
# _extra_probe_targets (lines 324-332)
# ============================================================================


class TestExtraProbeTargets:
    def test_valid_and_invalid_entries(self) -> None:
        """Failover targets parse [[host, port], ...] and skip unusable rows."""
        lv = _make_liveness(
            {
                "validator": {
                    "proxy_pool": {
                        "probe_extra_targets": [
                            ["h1.example", 443],
                            ["bad.example", "notaport"],
                            ["", 443],
                            ["h2.example", 0],
                            ["h3.example", 70000],
                            ["h4.example"],
                            ["h5.example", 8443],
                        ],
                    },
                },
            },
        )
        targets = lv._extra_probe_targets(lv._proxy_pool_config())
        assert targets == [("h1.example", 443), ("h5.example", 8443)]

    def test_non_list_raw_yields_no_targets(self) -> None:
        lv = _make_liveness(
            {"validator": {"proxy_pool": {"probe_extra_targets": "nope"}}},
        )
        assert lv._extra_probe_targets(lv._proxy_pool_config()) == []


# ============================================================================
# _validator_proxy_urls — single-network warning (line 391)
# ============================================================================


class TestValidatorProxyNetworkWarning:
    async def test_all_proxies_in_one_network_warns(
        self,
        monkeypatch,
        caplog,
    ) -> None:
        """A pool sitting in one /16 is one network event away from empty."""
        lv = _make_liveness(
            {
                "validator": {
                    "proxy_url": "socks5://10.0.0.1:1080",
                    "proxy_pool": {"enabled": True, "sources": ["test"]},
                },
            },
        )

        async def mock_search(*args, **kwargs):
            return ["socks5://10.0.0.2:1080", "socks5://10.0.0.3:1080"]

        monkeypatch.setattr(lv, "_search_validator_proxy_pool", mock_search)
        caplog.set_level(logging.WARNING)
        await lv._validator_proxy_urls()
        assert "one network event empties the subscription" in caplog.text
        assert lv.context.liveness_stats["proxy_networks"] == 1


# ============================================================================
# validate_by_list — empty list triggers the pool-death check (line 484)
# ============================================================================


class TestEmptyListPoolDeathCheck:
    async def test_list_validating_to_zero_notifies_pool_watchdog(
        self,
        monkeypatch,
    ) -> None:
        lv = _make_liveness(
            {"validator": {"tcp_enabled": True, "tcp_candidate_limit": 0}},
            proxy_url_getter=_empty_proxy_list,
        )
        labels: list[str] = []

        async def mock_tcp(batch, **kwargs):
            return []

        async def fake_pool_death(label: str) -> None:
            labels.append(label)

        monkeypatch.setattr("src.validators.tcp_check.validate_configs_tcp", mock_tcp)
        monkeypatch.setattr(lv, "_pool_died_after_empty_list", fake_pool_death)
        result = await lv.validate_by_list(
            {"blacklist": [_make_config("h.com", 443)]},
        )
        assert result == {}
        assert labels == ["blacklist"]


# ============================================================================
# _pool_died_after_empty_list — refetch already spent (lines 559-563)
# ============================================================================


class TestPoolDeathRefetchSpent:
    async def test_fully_dead_pool_keeps_cache_when_refetch_already_used(
        self,
        monkeypatch,
        caplog,
    ) -> None:
        """A second full pool death in one run must not re-fetch again."""
        lv = _make_liveness({"validator": {"proxy_pool": {"enabled": True}}})
        lv._pool_refetch_used = True
        lv._validator_proxy_urls_cache = ["socks5://10.0.0.1:1080"]

        async def fake_connects(proxy_url, **kwargs):
            return False

        monkeypatch.setattr("src.validators.proxy_pool.proxy_connects", fake_connects)
        caplog.set_level(logging.WARNING)
        await lv._pool_died_after_empty_list("blacklist")
        assert lv._validator_proxy_urls_cache == ["socks5://10.0.0.1:1080"]
        assert lv._pool_refetch_used is True
        assert "already rebuilt once this run" in caplog.text


# ============================================================================
# _record_probe_health — one verdict per config per run (lines 656, 660)
# ============================================================================


class TestProbeHealthDedup:
    async def test_two_lists_sharing_a_config_get_one_verdict(
        self,
        monkeypatch,
    ) -> None:
        """A server riding in two lists produces one `recent` entry per run."""
        recorded: list[list[str]] = []
        lv = _make_liveness(
            {"validator": {"tcp_enabled": True, "tcp_candidate_limit": 0}},
            proxy_url_getter=_empty_proxy_list,
            update_health_callback=lambda cfgs: recorded.append(
                [c.address for c in cfgs],
            ),
            update_source_health_callback=lambda cfgs, stats: None,
        )

        async def mock_tcp(batch, **kwargs):
            for cfg in batch:
                cfg.is_alive = True
            return list(batch)

        monkeypatch.setattr("src.validators.tcp_check.validate_configs_tcp", mock_tcp)

        shared = _make_config("shared.example", 443)
        await lv.validate_configs(
            [shared, _make_config("a.example", 443)],
            label="blacklist",
            tcp_enabled=True,
            tls_enabled=False,
        )
        await lv.validate_configs(
            [shared, _make_config("b.example", 443)],
            label="whitelist",
            tcp_enabled=True,
            tls_enabled=False,
        )
        # A fresh object with the same identity is recognised as already seen.
        await lv.validate_configs(
            [_make_config("shared.example", 443)],
            label="blacklist",
            tcp_enabled=True,
            tls_enabled=False,
        )
        assert recorded[0] == ["shared.example", "a.example"]
        assert recorded[1] == ["b.example"]
        # The third run recorded nothing new: every verdict was already given.
        assert len(recorded) == 2


# ============================================================================
# TCP stage — pool latency baselines (lines 860-865)
# ============================================================================


async def _pooled_proxy_list() -> list[str]:
    return ["socks5://p1:1080"]


async def _two_proxy_list() -> list[str]:
    return ["socks5://p1:1080", "socks5://p2:1080"]


class TestTcpProxyLatencyBaseline:
    async def test_pool_average_latency_reaches_tcp_validator(
        self,
        monkeypatch,
    ) -> None:
        lv = _make_liveness(
            {"validator": {"tcp_enabled": True, "tcp_candidate_limit": 0}},
            proxy_url_getter=_pooled_proxy_list,
        )
        fake_history = MagicMock()
        fake_history.average_latency.return_value = 123.0
        lv._proxy_health_history = fake_history

        seen: dict = {}

        async def mock_tcp(batch, **kwargs):
            seen.update(kwargs)
            return list(batch)

        monkeypatch.setattr("src.validators.tcp_check.validate_configs_tcp", mock_tcp)
        await lv.validate_configs(
            [_make_config("h.com", 443)],
            label="blacklist",
            tcp_enabled=True,
            tls_enabled=False,
        )
        assert seen["proxy_latency_ms"] == {"socks5://p1:1080": 123.0}


# ============================================================================
# Xray pool refill — failure paths (lines 1408-1411, 1429-1430)
# ============================================================================


class TestXrayPoolRefillFailures:
    """A failed pool rebuild must not leave the cache empty or lie in stats."""

    _SETTINGS = {
        "validator": {
            "xray_enabled": True,
            "xray_executable": "/usr/bin/xray",
            "xray_probe_via_proxies": True,
            "xray_proxy_probe_count": 8,
        },
        "proxy_pool": {"enabled": True, "required": True},
    }

    @staticmethod
    def _patch_revalidate(monkeypatch) -> None:
        async def fake_revalidate(proxies, **kwargs):
            return list(proxies[:2])

        monkeypatch.setattr(
            "src.validators.proxy_pool.validate_proxy_candidates",
            fake_revalidate,
        )

    @staticmethod
    def _patch_xray_stage(monkeypatch) -> list[list[str]]:
        seen_slices: list[list[str]] = []

        async def mock_xray(configs, **kwargs):
            seen_slices.append(list(kwargs.get("probe_proxy_urls") or []))
            for cfg in configs:
                cfg.xray_was_checked = True
                cfg.is_alive = True
            return list(configs)

        monkeypatch.setattr(
            "src.validators.xray_probe.find_xray_executable",
            lambda p: "/usr/bin/xray",
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.is_xray_supported",
            lambda cfg: True,
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.validate_configs_xray",
            mock_xray,
        )
        return seen_slices

    async def test_refill_invalidates_cache_before_getter(
        self,
        monkeypatch,
    ) -> None:
        """The refill getter must run against an invalidated cache."""
        stale = [f"socks5://stale{i}:1080" for i in range(8)]
        cache_states: list = []

        async def _pool() -> list[str]:
            cache_states.append(lv._validator_proxy_urls_cache)
            return [f"socks5://fresh{i}:1080" for i in range(8)]

        lv = _make_liveness(self._SETTINGS, proxy_url_getter=_pool)
        lv._validator_proxy_urls_cache = list(stale)
        self._patch_xray_stage(monkeypatch)
        self._patch_revalidate(monkeypatch)

        await lv.validate_configs(
            [_make_config("h.example", 443)],
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
        # Initial resolve rides the stale cache; the refill getter runs only
        # after reset_proxy_cache() — otherwise it would return the corpses.
        assert cache_states[0] == stale
        assert cache_states[1] is None
        assert lv._pool_refetch_used is True

    async def test_refill_getter_returning_empty_restores_stale_pool(
        self,
        monkeypatch,
    ) -> None:
        stale = [f"socks5://stale{i}:1080" for i in range(8)]
        cache_states: list = []

        async def _pool() -> list[str]:
            cache_states.append(lv._validator_proxy_urls_cache)
            return list(stale) if len(cache_states) == 1 else []

        lv = _make_liveness(self._SETTINGS, proxy_url_getter=_pool)
        lv._validator_proxy_urls_cache = list(stale)
        seen_slices = self._patch_xray_stage(monkeypatch)
        self._patch_revalidate(monkeypatch)

        await lv.validate_configs(
            [_make_config("h.example", 443)],
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
        assert cache_states[1] is None
        # The failed rebuild restored the stale pool and claimed no refill.
        assert lv._validator_proxy_urls_cache == stale
        assert lv._pool_refetch_used is False
        stats = lv.context.liveness_stats["lists"]["blacklist"]
        assert "xray_pool_refilled" not in stats
        # Without an applied refill the rechecked survivors are probed.
        assert seen_slices == [stale[:2]]

    async def test_refill_getter_raising_restores_stale_pool(
        self,
        monkeypatch,
        caplog,
    ) -> None:
        stale = [f"socks5://stale{i}:1080" for i in range(8)]
        cache_states: list = []

        async def _pool() -> list[str]:
            cache_states.append(lv._validator_proxy_urls_cache)
            if len(cache_states) > 1:
                raise RuntimeError("pool source exploded")
            return list(stale)

        lv = _make_liveness(self._SETTINGS, proxy_url_getter=_pool)
        lv._validator_proxy_urls_cache = list(stale)
        seen_slices = self._patch_xray_stage(monkeypatch)
        self._patch_revalidate(monkeypatch)
        caplog.set_level(logging.WARNING)

        await lv.validate_configs(
            [_make_config("h.example", 443)],
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
        assert cache_states[1] is None
        assert lv._validator_proxy_urls_cache == stale
        assert "pool refill failed" in caplog.text
        assert seen_slices == [stale[:2]]

    async def test_recheck_failure_keeps_preselected_slice(
        self,
        monkeypatch,
        caplog,
    ) -> None:
        pool = [f"socks5://p{i}:1080" for i in range(8)]

        async def _pool() -> list[str]:
            return list(pool)

        lv = _make_liveness(self._SETTINGS, proxy_url_getter=_pool)
        seen_slices = self._patch_xray_stage(monkeypatch)

        async def _boom(*args, **kwargs):
            raise RuntimeError("recheck exploded")

        monkeypatch.setattr(
            "src.validators.proxy_pool.validate_proxy_candidates",
            _boom,
        )
        caplog.set_level(logging.WARNING)
        await lv.validate_configs(
            [_make_config("h.example", 443)],
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
        assert "Xray probe recheck failed" in caplog.text
        assert seen_slices == [pool[:8]]


# ============================================================================
# Xray stage — probe-proxy latency baselines (lines 1450-1463)
# ============================================================================


class TestXrayProxyLatencyBaselines:
    @staticmethod
    def _patch_xray_stage(monkeypatch) -> dict:
        captured: dict = {}

        async def mock_xray(configs, **kwargs):
            captured.update(kwargs)
            for cfg in configs:
                cfg.xray_was_checked = True
                cfg.is_alive = True
            return list(configs)

        monkeypatch.setattr(
            "src.validators.xray_probe.find_xray_executable",
            lambda p: "/usr/bin/xray",
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.is_xray_supported",
            lambda cfg: True,
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.validate_configs_xray",
            mock_xray,
        )
        return captured

    async def test_baselines_come_from_in_memory_history(
        self,
        monkeypatch,
    ) -> None:
        """Baselines read the in-memory history, not a fresh disk load.

        The in-memory instance already carries the recheck verdicts recorded
        seconds earlier; re-reading the file per list both dropped those and
        re-parsed the JSON on every list.
        """
        captured = self._patch_xray_stage(monkeypatch)
        lv = _make_liveness(
            _xray_settings(
                xray_probe_via_proxies=True,
                xray_proxy_probe_count=2,
                proxy_pool={"health": {"health_history_file": "unused.json"}},
            ),
            proxy_url_getter=_two_proxy_list,
        )

        class FakePoolHistory:
            def average_latency(self, proxy_url: str):
                return 250.0

        lv._proxy_health_history = FakePoolHistory()
        await lv.validate_configs(
            [_make_config("h.example", 443)],
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
        assert captured["proxy_latency_ms"] == {
            "socks5://p1:1080": 250.0,
            "socks5://p2:1080": 250.0,
        }

    async def test_baseline_history_failure_is_logged(
        self,
        monkeypatch,
        caplog,
    ) -> None:
        """A failing in-memory history degrades to no baselines, loudly."""
        self._patch_xray_stage(monkeypatch)
        lv = _make_liveness(
            _xray_settings(
                xray_probe_via_proxies=True,
                xray_proxy_probe_count=2,
                proxy_pool={"health": {"health_history_file": "unused.json"}},
            ),
            proxy_url_getter=_two_proxy_list,
        )

        class _ExplodingHistory:
            def average_latency(self, *args, **kwargs):
                raise OSError("disk gone")

        lv._proxy_health_history = _ExplodingHistory()
        caplog.set_level(logging.WARNING)
        await lv.validate_configs(
            [_make_config("h.example", 443)],
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
        assert "Cannot load proxy latency baselines" in caplog.text

    async def test_baseline_fallback_builds_empty_history(self, monkeypatch) -> None:
        """Without any loaded history the baselines dict stays empty, not None."""
        captured = self._patch_xray_stage(monkeypatch)
        lv = _make_liveness(
            _xray_settings(
                xray_probe_via_proxies=True,
                xray_proxy_probe_count=2,
            ),
            proxy_url_getter=_two_proxy_list,
        )
        lv._proxy_health_history = None
        await lv.validate_configs(
            [_make_config("h.example", 443)],
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
        assert captured["proxy_latency_ms"] == {}


# ============================================================================
# _run_xray_stage — probe-proxy latency baselines via direct stage entry
# ============================================================================


class TestXrayBaselinesDirectStageEntry:
    """The baselines block must not depend on the orchestrator's probe path.

    The ``validate_configs`` entry reaches ``_run_xray_stage`` through pool
    pre-selection, recheck and refill whose outcome varies by platform (live
    socket behaviour), which left the baselines fallback branches uncovered
    on Linux. Calling the stage directly with explicit proxy URLs pins the
    inputs, so every branch is covered deterministically on all platforms.
    """

    @staticmethod
    def _patch_stage(monkeypatch) -> dict:
        captured: dict = {}

        async def mock_xray(configs, **kwargs):
            captured.update(kwargs)
            for cfg in configs:
                cfg.xray_was_checked = True
                cfg.is_alive = True
            return list(configs)

        monkeypatch.setattr(
            "src.validators.xray_probe.find_xray_executable",
            lambda p: "/usr/bin/xray",
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.is_xray_supported",
            lambda cfg: True,
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.validate_configs_xray",
            mock_xray,
        )
        return captured

    @staticmethod
    def _stage_settings(**extra) -> dict:
        settings = _xray_settings(
            xray_probe_via_proxies=True,
            xray_proxy_probe_count=2,
            **extra,
        )
        return settings["validator"]

    async def _run_stage(self, lv, vcfg, monkeypatch):
        captured = self._patch_stage(monkeypatch)
        list_stats: dict = {}
        result = await lv._run_xray_stage(
            [_make_config("h.example", 443)],
            label="blacklist",
            list_key="blacklist",
            vcfg=vcfg,
            proxy_urls=["socks5://p1:1080", "socks5://p2:1080"],
            check_hostnames=False,
            resolve_timeout=5.0,
            list_stats=list_stats,
        )
        return result, captured

    async def test_direct_entry_builds_empty_history_when_none(
        self, monkeypatch
    ) -> None:
        """No loaded history: an empty in-memory history is built, not None."""
        lv = _make_liveness(
            _xray_settings(
                xray_probe_via_proxies=True,
                xray_proxy_probe_count=2,
            ),
            proxy_url_getter=_two_proxy_list,
        )
        lv._proxy_health_history = None
        _, captured = await self._run_stage(lv, self._stage_settings(), monkeypatch)
        assert captured["proxy_latency_ms"] == {}

    async def test_direct_entry_reads_in_memory_history(self, monkeypatch) -> None:
        """A loaded history supplies per-proxy latency baselines."""

        class FakePoolHistory:
            def average_latency(self, proxy_url: str):
                return 250.0

        lv = _make_liveness(
            _xray_settings(
                xray_probe_via_proxies=True,
                xray_proxy_probe_count=2,
            ),
            proxy_url_getter=_two_proxy_list,
        )
        lv._proxy_health_history = FakePoolHistory()
        _, captured = await self._run_stage(lv, self._stage_settings(), monkeypatch)
        assert captured["proxy_latency_ms"] == {
            "socks5://p1:1080": 250.0,
            "socks5://p2:1080": 250.0,
        }

    async def test_direct_entry_history_failure_is_logged(
        self, monkeypatch, caplog
    ) -> None:
        """A failing history degrades to no baselines, loudly."""

        class _ExplodingHistory:
            def average_latency(self, *args, **kwargs):
                raise OSError("disk gone")

        lv = _make_liveness(
            _xray_settings(
                xray_probe_via_proxies=True,
                xray_proxy_probe_count=2,
            ),
            proxy_url_getter=_two_proxy_list,
        )
        lv._proxy_health_history = _ExplodingHistory()
        caplog.set_level(logging.WARNING)
        _, captured = await self._run_stage(lv, self._stage_settings(), monkeypatch)
        assert captured["proxy_latency_ms"] == {}
        assert "Cannot load proxy latency baselines" in caplog.text


# ============================================================================
# Alive budget full — fresh retry and stale pass skipped (lines 1577-1579,
# 1625-1626)
# ============================================================================


class TestAliveBudgetFullSkips:
    async def test_fresh_retry_and_stale_pass_skipped_when_budget_full(
        self,
        monkeypatch,
    ) -> None:
        """A saturated alive budget must not re-probe or run the stale pass."""
        lv = _make_liveness(
            _xray_settings(verification_ttl_minutes=60, xray_max_alive=1),
            proxy_url_getter=_empty_proxy_list,
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.find_xray_executable",
            lambda p: "/usr/bin/xray",
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.is_xray_supported",
            lambda cfg: True,
        )
        calls: list[list[str]] = []

        async def mock_xray(configs, **kwargs):
            calls.append([c.address for c in configs])
            for cfg in configs:
                cfg.xray_was_checked = True
                cfg.is_alive = True
            # The alive budget (1) is filled by the first config.
            return list(configs[:1])

        monkeypatch.setattr(
            "src.validators.xray_probe.validate_configs_xray",
            mock_xray,
        )
        fresh1 = _make_config("fresh1.example", 4001, is_alive=True)
        fresh2 = _make_config("fresh2.example", 4002, is_alive=True)
        stale = _make_config("stale.example", 4003)
        lv.health.update([fresh1])
        lv.health.update([fresh2])
        for cfg in (fresh1, fresh2):
            lv.health.load()["configs"][lv.health.config_key(cfg)]["last_alive"] = int(
                time.time()
            )

        result = await lv.validate_configs(
            [fresh1, fresh2, stale],
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
        stats = lv.context.liveness_stats["lists"]["blacklist"]
        assert stats["xray_fresh_verified"] == 2
        # The retry pass must not run: the alive budget is already full.
        assert stats["xray_fresh_retry_skipped"] == "budget_full"
        assert stats["xray_fresh_retried"] == 0
        assert stats["xray_stale_skipped"] == "budget_full"
        assert calls == [["fresh1.example", "fresh2.example"]]
        assert [c.address for c in result] == ["fresh1.example"]


# ============================================================================
# Xray branch — one health verdict per config across lists (line 1753)
# ============================================================================


class TestXrayHealthDedupAcrossLists:
    async def test_shared_config_gets_one_xray_verdict(
        self,
        tmp_path,
        monkeypatch,
    ) -> None:
        settings = {
            "validator": {
                "xray_enabled": True,
                "xray_executable": "/usr/bin/xray",
                "xray_probe_url": "https://example.com/probe",
                "xray_timeout_seconds": 12.0,
                "xray_startup_timeout_seconds": 4.0,
                "xray_concurrency": 6,
            },
            "quality": {
                "health_history_enabled": True,
                "health_history_file": str(tmp_path / "health.json"),
                "source_health_enabled": False,
            },
        }
        lv = _make_liveness(settings, proxy_url_getter=_empty_proxy_list)
        _patch_xray(monkeypatch, alive_prefix="shared")

        await lv.validate_configs(
            [_make_config("shared.example", 443)],
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
        await lv.validate_configs(
            [_make_config("shared.example", 443)],
            label="whitelist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
        history = lv.health.load()
        assert len(history["configs"]) == 1
        record = next(iter(history["configs"].values()))
        # Two lists riding the same server must not double its `recent` log.
        assert record["recent"].count(True) == 1


# ============================================================================
# Xray enabled but binary missing — TCP verdicts still recorded and bans
# still applied (the validate_configs finally path)
# ============================================================================


class TestXrayMissingBinaryStillRecords:
    async def test_tcp_verdicts_recorded_and_bans_applied_without_xray(
        self,
        tmp_path,
        monkeypatch,
        caplog,
    ) -> None:
        settings = Settings(
            {
                "validator": {
                    "tcp_enabled": True,
                    "tcp_candidate_limit": 0,
                    "xray_enabled": True,
                    "xray_required": False,
                },
                "quality": {
                    "health_history_enabled": True,
                    "health_history_file": str(tmp_path / "health.json"),
                    "source_health_enabled": True,
                    "source_health_history_file": str(tmp_path / "health.json"),
                    "health_ban_min_alive": 0,
                },
            },
        )
        health = HealthHistory(settings)
        health.load()["sources"]["bad-src"] = {"banned_until": 9_999_999_999}
        lv = LivenessValidator(
            _make_context(settings),
            health=health,
            proxy_url_getter=_empty_proxy_list,
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.find_xray_executable",
            lambda p: None,
        )

        async def mock_tcp(batch, **kwargs):
            for cfg in batch:
                cfg.is_alive = True
            return list(batch)

        monkeypatch.setattr("src.validators.tcp_check.validate_configs_tcp", mock_tcp)
        caplog.set_level(logging.WARNING)
        configs = [
            _make_config(f"bad{i}.example", 4000 + i, source_name="bad-src")
            for i in range(2)
        ]
        unprobed = _make_config(
            "unprobed.example",
            4002,
            protocol="hysteria2",
            source_name="bad-src",
        )
        configs += [
            unprobed,
            _make_config("good.example", 4003, source_name="good-src"),
        ]
        result = await lv.validate_configs(
            configs,
            label="blacklist",
            tcp_enabled=True,
            tls_enabled=False,
            xray_enabled=True,
        )
        # The Xray branch never consumed the probe log, so the finally block
        # recorded the TCP verdicts in the health history...
        assert len(lv.health.load()["configs"]) == 3
        # ...the freshly probed configs outrank the stale source ban...
        assert [c.address for c in result] == [
            "bad0.example",
            "bad1.example",
            "good.example",
        ]
        # ...and the run still ban-filtered the config no probe ever judged.
        assert unprobed.quality_block_reason == "source_ban"
        assert "Xray validation skipped" in caplog.text


# ============================================================================
# Xray enabled — TCP/TLS verdicts still reach health.update (idempotent per
# run via _health_update_seen)
# ============================================================================


class TestTcpVerdictsRecordedWithXray:
    async def test_tcp_dead_config_accumulates_failures_and_bans(
        self,
        tmp_path,
        monkeypatch,
    ) -> None:
        """A config killed at the TCP stage bans even when Xray is enabled.

        The old gate skipped _record_probe_health whenever the Xray branch
        had consumed the probe log, and that branch only records its own
        attempted subset: TCP-dead configs never reached health.update(),
        consecutive_failures never grew and bans never fired for them.
        """
        settings = {
            "validator": {
                "tcp_enabled": True,
                "tcp_candidate_limit": 0,
                "xray_enabled": True,
                "xray_executable": "/usr/bin/xray",
                "xray_probe_url": "https://example.com/probe",
            },
            "quality": {
                "health_history_enabled": True,
                "health_history_file": str(tmp_path / "health.json"),
                "source_health_enabled": False,
                "ban_after_consecutive_failures": 2,
            },
        }
        lv = _make_liveness(settings, proxy_url_getter=_empty_proxy_list)

        async def mock_tcp(batch, **kwargs):
            for cfg in batch:
                cfg.is_alive = cfg.address == "alive.example"
            return [cfg for cfg in batch if cfg.is_alive]

        monkeypatch.setattr("src.validators.tcp_check.validate_configs_tcp", mock_tcp)

        async def mock_xray(configs, **kwargs):
            for cfg in configs:
                cfg.xray_was_checked = True
                cfg.is_alive = True
            return list(configs)

        monkeypatch.setattr(
            "src.validators.xray_probe.find_xray_executable",
            lambda p: "/usr/bin/xray",
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.is_xray_supported",
            lambda cfg: True,
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.validate_configs_xray",
            mock_xray,
        )

        # Run 1: dead.example fails the TCP check and never reaches Xray;
        # alive.example passes TCP and gets its verdict from the Xray branch.
        dead = _make_config("dead.example", 4000)
        alive = _make_config("alive.example", 4001)
        await lv.validate_by_list({"blacklist": [dead, alive]})
        history = lv.health.load()
        dead_record = history["configs"][lv.health.config_key(dead)]
        # The TCP verdict was recorded although the Xray branch consumed the
        # probe log for its own subset.
        assert dead_record["fails"] == 1
        assert dead_record["recent"] == [False]
        # One verdict per config per run: TCP and Xray must not both append.
        assert history["configs"][lv.health.config_key(alive)]["recent"] == [True]

        # Run 2: the second consecutive TCP failure triggers the ban.
        dead2 = _make_config("dead.example", 4000)
        await lv.validate_by_list({"blacklist": [dead2]})
        dead_record = lv.health.load()["configs"][lv.health.config_key(dead2)]
        assert dead_record["fails"] == 2
        assert dead_record["consecutive_failures"] == 2
        assert dead_record["banned_until"] > 0


# ============================================================================
# Xray pool refill — fully dead pool probes directly (audit round 2)
# ============================================================================


class TestXrayPoolFullyDeadProbesDirectly:
    """An empty recheck must not fall back to the pre-selected corpses."""

    _SETTINGS = {
        "validator": {
            "xray_enabled": True,
            "xray_executable": "/usr/bin/xray",
            "xray_probe_via_proxies": True,
            "xray_proxy_probe_count": 8,
        },
        "proxy_pool": {"enabled": True, "required": True},
    }

    @staticmethod
    def _patch_xray_stage(monkeypatch) -> list[list[str]]:
        seen_slices: list[list[str]] = []

        async def mock_xray(configs, **kwargs):
            seen_slices.append(list(kwargs.get("probe_proxy_urls") or []))
            for cfg in configs:
                cfg.xray_was_checked = True
                cfg.is_alive = True
            return list(configs)

        monkeypatch.setattr(
            "src.validators.xray_probe.find_xray_executable",
            lambda p: "/usr/bin/xray",
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.is_xray_supported",
            lambda cfg: True,
        )
        monkeypatch.setattr(
            "src.validators.xray_probe.validate_configs_xray",
            mock_xray,
        )
        return seen_slices

    async def test_empty_recheck_probes_directly(self, monkeypatch) -> None:
        """Every pre-selected proxy failed and no refill applied: probing
        through known-dead proxies records false deaths (+health bans), so
        the stage must hand over an empty pool (direct probing)."""
        stale = [f"socks5://stale{i}:1080" for i in range(8)]

        async def _pool() -> list[str]:
            return []

        lv = _make_liveness(self._SETTINGS, proxy_url_getter=_pool)
        lv._validator_proxy_urls_cache = list(stale)
        seen_slices = self._patch_xray_stage(monkeypatch)

        async def _all_dead(proxies, **kwargs):
            return []

        monkeypatch.setattr(
            "src.validators.proxy_pool.validate_proxy_candidates",
            _all_dead,
        )
        await lv.validate_configs(
            [_make_config("h.example", 443)],
            label="blacklist",
            tcp_enabled=False,
            tls_enabled=False,
            xray_enabled=True,
        )
        assert seen_slices == [[]]
