"""Tests for liveness.py — 100% coverage."""

from __future__ import annotations

import asyncio
import logging
from unittest.mock import MagicMock

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
    """Cover lines 48-49."""

    async def test_run_calls_validate_by_list(self) -> None:
        """run() delegates to validate_by_list and sets validated state."""
        lv = _make_liveness()
        state = PipelineState(preprocessed={"blacklist": []})
        result = await lv.run(state)
        assert result is state
        # Default config: all validators disabled → configs pass through
        assert result.validated == {"blacklist": []}


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
            return ["socks5://p1:1080"] * 10

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


# ============================================================================
# validate_by_list (lines 325-374)
# ============================================================================


class TestValidateByList:
    """Cover lines 325-374."""

    async def test_all_disabled_returns_as_is(self) -> None:
        """When all validators disabled, configs pass through unchanged."""
        lv = _make_liveness()
        configs = {"whitelist": [_make_config("a.com")]}
        result = await lv.validate_by_list(configs)
        assert result == configs
        assert lv.context.liveness_stats["status"] == "disabled"

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
        """Health bans are applied when alive > health_ban_min_alive."""
        mock_health = MagicMock(spec=HealthHistory)
        mock_health.is_banned.return_value = True
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
        # All 5 are banned → result empty
        assert len(result) == 0

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
        """pool_required, no proxies, xray disabled returns configs."""
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
        assert len(result) == 1
        assert "no proxies are available" in caplog.text

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
