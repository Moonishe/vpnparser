"""Liveness validation stage: TCP/TLS/Xray checks."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from src.parsers.base import Config
from src.scheduler.context import PipelineContext, PipelineState
from src.scheduler.health_history import HealthHistory
from src.scheduler.stages.base import PipelineStage
from src.sources.list_types import normalize_list_type
from src.validators.address_guard import clear_verdict_cache

logger = logging.getLogger(__name__)

_TCP_SKIP_PROTOCOLS = {"tuic", "hysteria2"}


def _is_tls_checkable(cfg: Config) -> bool:
    """Whether a TCP TLS handshake probe can say anything about the config.

    QUIC-based protocols (hysteria2/tuic) answer on UDP only, so a
    TLS-over-TCP probe fails for every living server of theirs; their
    parsers still set ``security="tls"``, so they must be filtered out
    here and not just at the TCP stage.
    """
    return (
        str(cfg.security or "").lower() in ("tls", "reality")
        and cfg.protocol not in _TCP_SKIP_PROTOCOLS
    )


@dataclass
class _ProbeLog:
    """Configs a TCP/TLS check actually judged, plus the list's statistics.

    Only the validators set ``Config.is_alive``, and only for the configs they
    really connected to, so the flag is what separates "checked and dead" from
    "never tried" (candidate cap, early stop, address guard).
    """

    configs: list[Config] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)

    def add(self, configs: Iterable[Config]) -> None:
        """Remember every config that carries a verdict, without duplicates."""
        seen = {id(cfg) for cfg in self.configs}
        for cfg in configs:
            if cfg.is_alive is None or id(cfg) in seen:
                continue
            seen.add(id(cfg))
            self.configs.append(cfg)


class LivenessValidator(PipelineStage):
    """Validate configs via TCP/TLS/Xray and update health history."""

    def __init__(
        self,
        context: PipelineContext,
        health: HealthHistory | None = None,
        *,
        proxy_url_getter: Any | None = None,
        update_health_callback: Any | None = None,
        update_source_health_callback: Any | None = None,
    ) -> None:
        self.context = context
        self.settings = context.settings
        self.health = health or HealthHistory(self.settings)
        self._proxy_url_getter = proxy_url_getter
        self._update_health_callback = update_health_callback
        self._update_source_health_callback = update_source_health_callback
        #: Config keys already given a health verdict in this run — see the
        #: dedup comment where update() is called.
        self._health_update_seen: set[str] = set()
        self._validator_proxy_urls_cache: list[str] | None = None
        self._proxy_health_history: Any | None = None
        self._proxy_health_file: str | None = None
        self._init_proxy_health_history()

    async def run(
        self,
        state: PipelineState,
        context: PipelineContext | None = None,
    ) -> PipelineState:
        state.validated = await self.validate_by_list(state.preprocessed)
        return state

    def _section(self, name: str) -> dict[str, Any]:
        return self.settings.section(name)

    def _as_bool(self, value: Any, default: bool = False) -> bool:
        return self.settings.as_bool(value, default)

    def _as_int(self, value: Any, default: int, *, minimum: int | None = None) -> int:
        return self.settings.as_int(value, default, minimum=minimum)

    def _as_float(
        self,
        value: Any,
        default: float,
        *,
        minimum: float | None = None,
    ) -> float:
        return self.settings.as_float(value, default, minimum=minimum)

    def _source_list(self, value: Any) -> list[str] | None:
        if value is None:
            return None
        if isinstance(value, str):
            text = value.strip()
            return [text] if text else []
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        return []

    def _liveness_min_alive(self, total: int) -> int:
        if total <= 0:
            return 0
        vcfg = self._section("validator")
        raw = vcfg.get("min_alive_to_filter", 1)
        threshold = self._as_int(raw, 1, minimum=1)
        return min(threshold, total)

    def _proxy_pool_config(self) -> dict[str, Any]:
        raw = self._section("validator").get("proxy_pool", {})
        return raw if isinstance(raw, dict) else {}

    def reset_proxy_cache(self) -> None:
        """Clear cached proxy URLs so they are re-fetched on the next run."""
        self._validator_proxy_urls_cache = None

    def _proxy_health_config(self) -> dict[str, Any]:
        pool_cfg = self._proxy_pool_config()
        defaults = {
            "health_enabled": True,
            "health_history_file": "output/proxy-health-history.json",
            "ban_after_consecutive_failures": 3,
            "latency_window": 5,
            "max_latency_ms": 8000.0,
            "refresh_if_below_min": True,
        }
        provided = pool_cfg.get("health", {})
        if not isinstance(provided, dict):
            provided = {}
        merged = dict(defaults)
        merged.update(provided)
        return merged

    def _init_proxy_health_history(self) -> None:
        try:
            from src.validators.proxy_health import ProxyHealthHistory
        except ImportError:
            return
        hcfg = self._proxy_health_config()
        if not self._as_bool(hcfg.get("health_enabled"), True):
            return
        self._proxy_health_file = str(hcfg.get("health_history_file") or "")
        self._proxy_health_history = ProxyHealthHistory.load(
            self._proxy_health_file,
            window=self._as_int(hcfg.get("latency_window"), 5, minimum=1),
            ban_after_consecutive_failures=self._as_int(
                hcfg.get("ban_after_consecutive_failures"),
                3,
                minimum=1,
            ),
            max_latency_ms=self._as_float(
                hcfg.get("max_latency_ms"),
                8000.0,
                minimum=1.0,
            ),
        )

    def save_proxy_health_history(self) -> None:
        if self._proxy_health_history is None or not self._proxy_health_file:
            return
        try:
            self._proxy_health_history.save(self._proxy_health_file)
        except Exception as exc:
            logger.warning("Could not save proxy health history: %s", exc)

    @staticmethod
    def _redact_proxy_url(proxy_url: str) -> str:
        from urllib.parse import urlparse

        parsed = urlparse(proxy_url)
        if not parsed.scheme or not parsed.hostname:
            return "<invalid-proxy-url>"
        host = parsed.hostname
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        try:
            parsed_port = parsed.port
        except ValueError:
            return "<invalid-proxy-url>"
        port = f":{parsed_port}" if parsed_port else ""
        return f"{parsed.scheme}://{host}{port}"

    async def _search_validator_proxy_pool(
        self,
        load_proxy_pool: Any,
        sources: list[str] | None,
        pool_cfg: dict[str, Any],
    ) -> list[str]:
        """Search for working SOCKS5 proxies, widening candidates on retries."""
        max_proxies = self._as_int(pool_cfg.get("max_proxies"), 20, minimum=1)
        min_proxies = self._as_int(
            pool_cfg.get("min_proxies"),
            min(10, max_proxies),
            minimum=1,
        )
        max_proxies = max(max_proxies, min_proxies)

        search_rounds = self._as_int(pool_cfg.get("search_rounds"), 3, minimum=1)
        candidate_growth = self._as_float(
            pool_cfg.get("candidate_growth_factor"),
            2.0,
            minimum=1.0,
        )
        retry_delay = self._as_float(
            pool_cfg.get("retry_delay_seconds"),
            0.0,
            minimum=0.0,
        )
        base_max_candidates = self._as_int(
            pool_cfg.get("max_candidates"),
            200,
            minimum=1,
        )
        base_per_source = self._as_int(
            pool_cfg.get("max_candidates_per_source"),
            80,
            minimum=1,
        )

        self.context.liveness_stats.update(
            {
                "proxy_min_proxies": min_proxies,
                "proxy_search_round_limit": search_rounds,
                "proxy_search_rounds": 0,
                "proxy_search": [],
            },
        )

        pool_urls: list[str] = []
        for round_index in range(search_rounds):
            multiplier = candidate_growth**round_index
            max_candidates = max(
                base_max_candidates,
                int(base_max_candidates * multiplier),
            )
            max_candidates_per_source = max(
                base_per_source,
                int(base_per_source * multiplier),
            )
            pool_urls = await load_proxy_pool(
                sources,
                fetch_timeout=self._as_float(
                    pool_cfg.get("fetch_timeout_seconds"),
                    10.0,
                    minimum=1.0,
                ),
                max_candidates=max_candidates,
                max_candidates_per_source=max_candidates_per_source,
                max_proxies=max_proxies,
                validate=self._as_bool(pool_cfg.get("validate"), True),
                validation_timeout=self._as_float(
                    pool_cfg.get("validation_timeout_seconds"),
                    5.0,
                    minimum=1.0,
                ),
                validation_concurrency=self._as_int(
                    pool_cfg.get("validation_concurrency"),
                    50,
                    minimum=1,
                ),
                probe_host=str(pool_cfg.get("probe_host") or "api.github.com"),
                probe_port=self._as_int(pool_cfg.get("probe_port"), 443, minimum=1),
                history=self._proxy_health_history,
                extra_probe_targets=self._extra_probe_targets(pool_cfg),
            )
            self.context.liveness_stats["proxy_search_rounds"] = round_index + 1
            self.context.liveness_stats["proxy_search"].append(
                {
                    "round": round_index + 1,
                    "max_candidates": max_candidates,
                    "max_candidates_per_source": max_candidates_per_source,
                    "working": len(pool_urls),
                },
            )
            if len(pool_urls) >= min_proxies:
                break
            if retry_delay > 0 and round_index + 1 < search_rounds:
                await asyncio.sleep(retry_delay)

        if len(pool_urls) < min_proxies:
            logger.warning(
                "Proxy pool search found only %d/%d working SOCKS5 proxies "
                "after %d round(s).",
                len(pool_urls),
                min_proxies,
                search_rounds,
            )
        return pool_urls

    def _extra_probe_targets(self, pool_cfg: dict[str, Any]) -> list[tuple[str, int]]:
        """Failover self-check targets from settings ([[host, port], ...])."""
        raw = pool_cfg.get("probe_extra_targets")
        targets: list[tuple[str, int]] = []
        if isinstance(raw, (list, tuple)):
            for item in raw:
                if isinstance(item, (list, tuple)) and len(item) >= 2:
                    host = str(item[0]).strip()
                    try:
                        port = int(item[1])
                    except (TypeError, ValueError):
                        continue
                    if host and 1 <= port <= 65535:
                        targets.append((host, port))
        return targets

    async def _validator_proxy_urls(self) -> list[str]:
        """Return configured validator proxies, including optional free pool."""
        if self._validator_proxy_urls_cache is not None:
            return list(self._validator_proxy_urls_cache)

        vcfg = self._section("validator")
        urls: list[str] = []
        explicit = str(
            vcfg.get("proxy_url")
            or __import__("os").environ.get("VALIDATOR_PROXY")
            or "",
        )
        explicit = explicit.strip()
        if explicit:
            urls.append(explicit)

        pool_cfg = self._proxy_pool_config()
        self.context.liveness_stats.update(
            {
                "explicit_proxy": bool(explicit),
                "proxy_pool_enabled": self._as_bool(pool_cfg.get("enabled"), False),
                "proxy_pool_required": self._as_bool(pool_cfg.get("required"), False),
                "proxy_pool_validate": self._as_bool(pool_cfg.get("validate"), True),
            },
        )
        if self._as_bool(pool_cfg.get("enabled"), False):
            try:
                from src.validators.proxy_pool import load_proxy_pool
            except ImportError as exc:
                logger.warning("Proxy pool unavailable: %s", exc)
            else:
                sources = self._source_list(pool_cfg.get("sources"))
                try:
                    pool_urls = await self._search_validator_proxy_pool(
                        load_proxy_pool,
                        sources,
                        pool_cfg,
                    )
                except Exception as exc:
                    logger.warning("Proxy pool load failed: %s", exc)
                else:
                    for proxy_url in pool_urls:
                        if proxy_url not in urls:
                            urls.append(proxy_url)

        self._validator_proxy_urls_cache = urls
        self.context.liveness_stats["proxy_count"] = len(urls)
        try:
            from src.validators.proxy_pool import count_proxy_networks

            networks = count_proxy_networks(urls)
        except Exception as exc:  # pragma: no cover - import-guard only
            logger.warning("Cannot count proxy networks: %s", exc)
            networks = 0
        self.context.liveness_stats["proxy_networks"] = networks
        if len(urls) > 1 and networks < 2:
            logger.warning(
                "Proxy pool: all %d working proxies sit in %d network(s) — "
                "one network event empties the subscription.",
                len(urls),
                networks,
            )
        if explicit:
            self.context.liveness_stats["proxy_urls"] = [
                "<explicit-proxy-hidden>",
                *[self._redact_proxy_url(url) for url in urls[1:]],
            ]
        else:
            self.context.liveness_stats["proxy_urls"] = [
                self._redact_proxy_url(url) for url in urls
            ]
        return list(urls)

    async def validate_by_list(
        self,
        configs_by_list: dict[str, list[Config]],
    ) -> dict[str, list[Config]]:
        # Verdicts from a previous run must not ride into this one: the cache
        # is keyed by host only, and a rebinding host could keep a stale
        # "public" verdict across run boundaries in --continuous mode.
        clear_verdict_cache()
        self._health_update_seen = set()
        vcfg = self._section("validator")
        tcp_enabled = self._as_bool(vcfg.get("tcp_enabled"), False)
        tls_enabled = self._as_bool(vcfg.get("tls_enabled"), False)
        xray_enabled = self._as_bool(vcfg.get("xray_enabled"), False)
        pool_cfg = self._proxy_pool_config()
        self.context.liveness_stats = {
            "tcp_enabled": tcp_enabled,
            "tls_enabled": tls_enabled,
            "xray_enabled": xray_enabled,
            "fail_open_on_low_alive": self._as_bool(
                vcfg.get("fail_open_on_low_alive"),
                True,
            ),
            "drop_unchecked_after_tls": self._as_bool(
                vcfg.get("drop_unchecked_after_tls"),
                False,
            ),
            # Defaults must mirror the ones used by the actual check calls below,
            # otherwise run-summary.json reports settings that were never used.
            "proxy_pool_enabled": self._as_bool(pool_cfg.get("enabled"), False),
            "proxy_pool_required": self._as_bool(pool_cfg.get("required"), False),
            "proxy_pool_validate": self._as_bool(pool_cfg.get("validate"), True),
            "proxy_attempts_per_config": self._as_int(
                vcfg.get("proxy_attempts_per_config"),
                5,
                minimum=0,
            ),
            "tls_proxy_attempts_per_config": self._as_int(
                vcfg.get("tls_proxy_attempts_per_config"),
                self._as_int(vcfg.get("proxy_attempts_per_config"), 5, minimum=0),
                minimum=0,
            ),
            "check_hostnames": self._as_bool(vcfg.get("check_hostnames"), True),
            "resolve_timeout": self._as_float(
                vcfg.get("resolve_timeout"), 5.0, minimum=0.1
            ),
            "proxy_count": 0,
            "lists": {},
        }
        if not tcp_enabled and not tls_enabled and not xray_enabled:
            self.context.liveness_stats["status"] = "disabled"
            return configs_by_list
        self.context.liveness_stats["status"] = "enabled"

        validated: dict[str, list[Config]] = {}
        for list_type, configs in configs_by_list.items():
            alive = await self.validate_configs(
                list(configs),
                label=list_type,
                tcp_enabled=tcp_enabled,
                tls_enabled=tls_enabled,
                xray_enabled=xray_enabled,
            )
            if alive:
                validated[list_type] = alive
        return validated

    async def validate_configs(
        self,
        configs: list[Config],
        *,
        label: str,
        tcp_enabled: bool,
        tls_enabled: bool,
        xray_enabled: bool = False,
    ) -> list[Config]:
        """Validate one list and keep the health history in sync.

        ``health.update()`` / ``update_sources()`` / ``is_banned()`` used to be
        called only inside the Xray branch, so with ``xray_enabled: false`` the
        history file was rewritten empty every run and
        ``ban_after_consecutive_failures``, ``ban_cooldown_hours`` and
        ``source_bad_runs_to_ban`` never did anything. Runs without Xray now
        record and enforce the TCP/TLS verdicts here; when Xray is enabled it
        stays the single source of truth, exactly as before.

        Args:
            configs: Configs of one list type.
            label: List label used for logging and per-list statistics.
            tcp_enabled: Run the TCP connect check.
            tls_enabled: Run the TLS handshake check.
            xray_enabled: Run the Xray probe.

        Returns:
            The configs that survived every enabled check.
        """
        probe_log = _ProbeLog()
        try:
            result = await self._validate_configs(
                configs,
                label=label,
                tcp_enabled=tcp_enabled,
                tls_enabled=tls_enabled,
                xray_enabled=xray_enabled,
                probe_log=probe_log,
            )
        finally:
            if not xray_enabled:
                self._record_probe_health(probe_log)
        if xray_enabled or not probe_log.configs:
            return result
        return self._drop_banned(result, label=label, stats=probe_log.stats)

    def _record_probe_health(self, probe_log: _ProbeLog) -> None:
        """Persist the health of everything the TCP/TLS checks judged.

        Args:
            probe_log: Configs carrying a verdict from this validation.
        """
        if not probe_log.configs:
            return
        if self._update_health_callback:
            self._update_health_callback(probe_log.configs)
        else:
            self.health.update(probe_log.configs)
        if self._update_source_health_callback:
            self._update_source_health_callback(probe_log.configs, probe_log.stats)
        else:
            self.health.update_sources(probe_log.configs, probe_log.stats)

    def _drop_banned(
        self,
        configs: list[Config],
        *,
        label: str,
        stats: dict[str, Any],
    ) -> list[Config]:
        """Apply health/source bans, mirroring the Xray branch's ban step.

        Args:
            configs: Configs that survived the enabled checks.
            label: List label, for logging.
            stats: Per-list statistics to annotate.

        Returns:
            The configs that are not currently banned, or all of them when too
            few survived to risk erasing them with stale history.
        """
        health_ban_min_alive = self._as_int(
            self.settings.section("quality").get("health_ban_min_alive"),
            3,
            minimum=0,
        )
        if len(configs) <= health_ban_min_alive:
            logger.info(
                "%s liveness kept %d config(s) (<= %d); skipping health history bans.",
                label,
                len(configs),
                health_ban_min_alive,
            )
            return configs
        kept = [cfg for cfg in configs if not self.health.is_banned(cfg)]
        stats["output_after_health"] = len(kept)
        if len(kept) < len(configs):
            logger.info(
                "%s health history bans dropped %d config(s).",
                label,
                len(configs) - len(kept),
            )
        return kept

    async def _validate_configs(
        self,
        configs: list[Config],
        *,
        label: str,
        tcp_enabled: bool,
        tls_enabled: bool,
        xray_enabled: bool = False,
        probe_log: _ProbeLog,
    ) -> list[Config]:
        if not configs:
            return []

        vcfg = self._section("validator")
        proxy_urls = (
            await self._proxy_url_getter()
            if self._proxy_url_getter
            else await self._validator_proxy_urls()
        )
        pool_cfg = self._proxy_pool_config()
        pool_required = self._as_bool(pool_cfg.get("required"), False)
        pool_enabled = self._as_bool(pool_cfg.get("enabled"), False)
        fail_open_on_low_alive = self._as_bool(vcfg.get("fail_open_on_low_alive"), True)
        drop_unchecked_after_tls = self._as_bool(
            vcfg.get("drop_unchecked_after_tls"),
            False,
        )
        check_hostnames = self._as_bool(vcfg.get("check_hostnames"), True)
        resolve_timeout = self._as_float(vcfg.get("resolve_timeout"), 5.0, minimum=0.1)
        list_key = normalize_list_type(label)
        list_stats = {
            "input": len(configs),
            "proxy_count": len(proxy_urls),
            "checked": False,
            "filtered": False,
            "fail_open": False,
            "reason": "",
        }
        self.context.liveness_stats.setdefault("lists", {})[list_key] = list_stats
        probe_log.stats = list_stats
        if pool_enabled and pool_required and not proxy_urls:
            if not xray_enabled:
                list_stats["reason"] = "no_proxies"
                logger.warning(
                    "Liveness validation for %s skipped: proxy_pool.required=true "
                    "but no proxies are available.",
                    label,
                )
                return configs
            # The list *is* validated below (directly, without the pool), so
            # ``reason`` must stay free for the real outcome: leaving
            # "no_proxies" there told every run-summary reader that nothing was
            # checked while TCP/TLS/Xray had run in full.
            list_stats["proxy_pool_empty"] = True
            logger.warning(
                "%s proxy pool is empty; continuing with required direct Xray "
                "validation and skipping proxy-network score.",
                label,
            )

        current = list(configs)
        # Set when a fail-open kept the unfiltered list: the remaining optional
        # filters are skipped, but mandatory Xray validation still runs.
        fail_open_active = False

        if tcp_enabled:
            checkable = [c for c in current if c.protocol not in _TCP_SKIP_PROTOCOLS]
            passthrough = [c for c in current if c.protocol in _TCP_SKIP_PROTOCOLS]
            list_stats["tcp_candidates"] = len(checkable)
            list_stats["tcp_skipped_protocol"] = len(passthrough)
            if checkable:
                from src.validators.tcp_check import validate_configs_tcp

                candidate_limit = self._as_int(
                    vcfg.get("tcp_candidate_limit"),
                    1000,
                    minimum=0,
                )
                tcp_max_alive = self._as_int(vcfg.get("tcp_max_alive"), 0, minimum=0)
                tcp_max_alive_by_list = vcfg.get("tcp_max_alive_by_list", {})
                if isinstance(tcp_max_alive_by_list, dict):
                    specific_max_alive = tcp_max_alive_by_list.get(
                        normalize_list_type(label),
                    )
                    if specific_max_alive is not None:
                        tcp_max_alive = self._as_int(
                            specific_max_alive,
                            tcp_max_alive,
                            minimum=0,
                        )
                list_stats["tcp_max_alive"] = tcp_max_alive

                tcp_search_rounds = self._as_int(
                    vcfg.get("tcp_search_rounds"),
                    3,
                    minimum=1,
                )
                if candidate_limit <= 0:
                    tcp_search_rounds = 1
                    candidate_limit = len(checkable)
                list_stats["tcp_search_round_limit"] = tcp_search_rounds

                alive_tcp: list[Config] = []
                alive_keys: set[Any] = set()
                checked_total = 0
                tcp_checked_actual = 0
                offset = 0
                round_count = 0
                while offset < len(checkable) and round_count < tcp_search_rounds:
                    batch = checkable[offset : offset + candidate_limit]
                    if not batch:  # pragma: no cover
                        break
                    round_count += 1
                    offset += len(batch)
                    checked_total += len(batch)
                    remaining_alive = (
                        max(0, tcp_max_alive - len(alive_tcp))
                        if tcp_max_alive > 0
                        else 0
                    )
                    if tcp_max_alive > 0 and remaining_alive <= 0:  # pragma: no cover
                        break
                    logger.info(
                        "%s TCP validation round %d: checking %d/%d candidates.",
                        label,
                        round_count,
                        checked_total,
                        len(checkable),
                    )
                    batch_alive = await validate_configs_tcp(
                        batch,
                        timeout=self._as_float(
                            vcfg.get("tcp_timeout_seconds"),
                            5.0,
                            minimum=0.1,
                        ),
                        concurrency=self._as_int(
                            vcfg.get("tcp_concurrency"),
                            300,
                            minimum=1,
                        ),
                        max_alive=remaining_alive,
                        proxy_urls=proxy_urls,
                        proxy_attempts_per_config=self._as_int(
                            vcfg.get("proxy_attempts_per_config"),
                            5,
                            minimum=0,
                        ),
                        check_hostnames=check_hostnames,
                        resolve_timeout=resolve_timeout,
                    )
                    probe_log.add(batch)
                    actually_checked = sum(1 for c in batch if c.is_alive is not None)
                    tcp_checked_actual += actually_checked
                    for cfg in batch_alive:
                        # Ensure configs returned alive also carry is_alive=True
                        # even when the validator mock leaves it unset in tests.
                        if cfg.is_alive is None:
                            cfg.is_alive = True
                        if cfg.dedup_key in alive_keys:
                            continue
                        alive_keys.add(cfg.dedup_key)
                        alive_tcp.append(cfg)
                    if tcp_max_alive > 0 and len(alive_tcp) >= tcp_max_alive:
                        break

                list_stats["tcp_checked"] = tcp_checked_actual
                list_stats["tcp_search_rounds"] = round_count
                list_stats["checked"] = True
                list_stats["tcp_alive"] = len(alive_tcp)
                # The threshold counts the configs a socket was actually opened
                # for. Measuring it against every candidate made it unreachable
                # whenever tcp_candidate_limit * tcp_search_rounds was smaller
                # than the candidate list: the untried remainder was reported as
                # dead and the fail-open branch fired on every run.
                min_alive = self._liveness_min_alive(checked_total)
                list_stats["min_alive_to_filter"] = min_alive
                if len(alive_tcp) < min_alive:
                    list_stats["reason"] = "below_min_alive"
                    if fail_open_on_low_alive:
                        logger.warning(
                            "%s TCP validation found %d/%d checked alive (<%d; "
                            "%d candidates were not tried). "
                            "Keeping unfiltered configs.",
                            label,
                            len(alive_tcp),
                            checked_total,
                            min_alive,
                            len(checkable) - checked_total,
                        )
                        list_stats["fail_open"] = True
                        # The stage output is the unfiltered input; record it so
                        # run-summary never leaves the TCP step blank.
                        list_stats["output_after_tcp"] = len(configs)
                        if not xray_enabled:
                            return configs
                        logger.warning(
                            "%s TCP fail-open keeps unfiltered configs, but "
                            "Xray validation still applies to them.",
                            label,
                        )
                        fail_open_active = True
                    else:
                        logger.warning(
                            "%s TCP validation found %d/%d checked alive (<%d; "
                            "%d candidates were not tried). "
                            "Strict mode keeps only alive configs.",
                            label,
                            len(alive_tcp),
                            checked_total,
                            min_alive,
                            len(checkable) - checked_total,
                        )
                if not fail_open_active:
                    current = alive_tcp + passthrough
                    list_stats["filtered"] = True
                    list_stats["output_after_tcp"] = len(current)
                    logger.info(
                        "%s after TCP validation: %d alive, %d TCP-skipped.",
                        label,
                        len(alive_tcp),
                        len(passthrough),
                    )

        if tls_enabled and fail_open_active:
            # Leave a trace: without it run-summary shows tls_enabled=true and
            # no tls_* key at all, which reads exactly like "TLS ran and found
            # nothing" instead of "TLS never started".
            list_stats["tls_skipped"] = "tcp_fail_open"
            logger.info(
                "%s TLS validation skipped: the TCP fail-open already kept the "
                "unfiltered list.",
                label,
            )
        if tls_enabled and not fail_open_active:
            tls_checkable = [c for c in current if _is_tls_checkable(c)]
            if tls_checkable:
                from src.validators.tls_check import validate_configs_tls

                before_tls = list(current)
                tls_passthrough = [c for c in current if not _is_tls_checkable(c)]
                list_stats["tls_unchecked_passthrough"] = len(tls_passthrough)
                list_stats["tls_drop_unchecked"] = drop_unchecked_after_tls
                if drop_unchecked_after_tls:
                    tls_passthrough = []
                tls_min_alive = self._liveness_min_alive(len(tls_checkable))
                list_stats["tls_candidates"] = len(tls_checkable)
                candidate_limit = self._as_int(
                    vcfg.get("tls_candidate_limit"),
                    1000,
                    minimum=0,
                )
                if candidate_limit > 0 and len(tls_checkable) > candidate_limit:
                    logger.info(
                        "%s TLS validation candidate cap: checking first %d/%d.",
                        label,
                        candidate_limit,
                        len(tls_checkable),
                    )
                    tls_checkable = tls_checkable[:candidate_limit]
                list_stats["min_alive_to_filter"] = tls_min_alive
                alive_tls = await validate_configs_tls(
                    tls_checkable,
                    timeout=self._as_float(
                        vcfg.get("tls_timeout_seconds"),
                        5.0,
                        minimum=0.1,
                    ),
                    concurrency=self._as_int(
                        vcfg.get("tls_concurrency"),
                        120,
                        minimum=1,
                    ),
                    proxy_urls=proxy_urls,
                    proxy_attempts_per_config=self._as_int(
                        vcfg.get("tls_proxy_attempts_per_config"),
                        self._as_int(
                            vcfg.get("proxy_attempts_per_config"),
                            5,
                            minimum=0,
                        ),
                        minimum=0,
                    ),
                    check_hostnames=check_hostnames,
                    resolve_timeout=resolve_timeout,
                    verify_tls=self._as_bool(
                        vcfg.get("tls_verify_certificates"),
                        False,
                    ),
                )
                probe_log.add(tls_checkable)
                # tls_checked counts only configs that were actually probed:
                # guard-filtered ones keep is_alive=None and are excluded.
                list_stats["tls_checked"] = sum(
                    1 for c in tls_checkable if c.is_alive is not None
                )
                list_stats["tls_alive"] = len(alive_tls)
                if len(alive_tls) < tls_min_alive:
                    list_stats["reason"] = "below_min_alive_tls"
                    if fail_open_on_low_alive:
                        logger.warning(
                            "%s TLS validation left %d/%d configs (<%d). "
                            "Keeping pre-TLS configs.",
                            label,
                            len(alive_tls),
                            len(tls_checkable),
                            tls_min_alive,
                        )
                        list_stats["fail_open"] = True
                        # Same as the TCP fail-open: the pre-TLS list is what
                        # leaves this step, so report its size.
                        list_stats["output_after_tls"] = len(before_tls)
                        if not xray_enabled:
                            return before_tls
                        logger.warning(
                            "%s TLS fail-open keeps pre-TLS configs, but "
                            "Xray validation still applies to them.",
                            label,
                        )
                        fail_open_active = True
                    else:
                        logger.warning(
                            "%s TLS validation left %d/%d configs (<%d). "
                            "Strict mode keeps only TLS-alive configs.",
                            label,
                            len(alive_tls),
                            len(tls_checkable),
                            tls_min_alive,
                        )
                if not fail_open_active:
                    current = alive_tls + tls_passthrough
                    list_stats["filtered"] = True
                    list_stats["output_after_tls"] = len(current)
                    logger.info(
                        "%s after TLS validation: %d configs.",
                        label,
                        len(current),
                    )
            elif drop_unchecked_after_tls:
                list_stats["checked"] = True
                list_stats["tls_candidates"] = 0
                list_stats["tls_checked"] = 0
                list_stats["tls_alive"] = 0
                list_stats["tls_unchecked_passthrough"] = len(current)
                list_stats["tls_drop_unchecked"] = True
                list_stats["filtered"] = True
                list_stats["output_after_tls"] = 0
                logger.warning(
                    "%s TLS validation has no TLS/REALITY candidates. "
                    "Strict mode drops %d TCP-only configs.",
                    label,
                    len(current),
                )
                current = []
        if xray_enabled and current:
            from src.validators.singbox_probe import (
                find_singbox_executable,
                is_singbox_supported,
                validate_configs_singbox,
            )
            from src.validators.xray_probe import (
                find_xray_executable,
                is_xray_supported,
                validate_configs_xray,
            )

            xray_path = find_xray_executable(str(vcfg.get("xray_executable") or ""))
            xray_required = self._as_bool(vcfg.get("xray_required"), False)
            list_stats["xray_required"] = xray_required
            list_stats["xray_available"] = bool(xray_path)
            if not xray_path:
                list_stats["xray_checked"] = 0
                list_stats["xray_alive"] = 0
                list_stats["reason"] = "xray_unavailable"
                if xray_required:
                    logger.warning(
                        "%s Xray validation required but xray executable "
                        "is unavailable. Dropping configs.",
                        label,
                    )
                    return []
                logger.warning(
                    "%s Xray validation skipped: xray executable unavailable.",
                    label,
                )
                return current

            before_xray = list(current)
            supported = [cfg for cfg in current if is_xray_supported(cfg)]
            unsupported_configs = [cfg for cfg in current if not is_xray_supported(cfg)]
            drop_unsupported = self._as_bool(vcfg.get("xray_drop_unsupported"), True)
            list_stats["xray_candidates"] = len(supported)
            list_stats["xray_unsupported"] = len(unsupported_configs)
            list_stats["xray_drop_unsupported"] = drop_unsupported

            # QUIC protocols (hysteria2/tuic) get their L3 probe from
            # sing-box instead of dying here as "unsupported".
            singbox_path = None
            if self._as_bool(vcfg.get("singbox_enabled"), False):
                singbox_path = find_singbox_executable(
                    str(vcfg.get("singbox_executable") or ""),
                )
            list_stats["singbox_available"] = bool(singbox_path)
            singbox_configs: list[Config] = []
            if singbox_path:
                singbox_configs = [
                    cfg for cfg in unsupported_configs if is_singbox_supported(cfg)
                ]
                unsupported_configs = [
                    cfg for cfg in unsupported_configs if not is_singbox_supported(cfg)
                ]
                list_stats["xray_unsupported"] = len(unsupported_configs)
                list_stats["singbox_candidates"] = len(singbox_configs)

            if not supported and not singbox_configs:
                list_stats["xray_checked"] = 0
                list_stats["xray_alive"] = 0
                list_stats["reason"] = "xray_no_supported_candidates"
                return [] if drop_unsupported else current

            candidate_limit = self._as_int(
                vcfg.get("xray_candidate_limit"),
                0,
                minimum=0,
            )
            xray_candidate_limit_by_list = vcfg.get("xray_candidate_limit_by_list", {})
            if isinstance(xray_candidate_limit_by_list, dict):
                specific_candidate_limit = xray_candidate_limit_by_list.get(list_key)
                if specific_candidate_limit is not None:
                    candidate_limit = self._as_int(
                        specific_candidate_limit,
                        candidate_limit,
                        minimum=0,
                    )
            if candidate_limit > 0:
                supported = self._xray_candidate_preselect(
                    supported,
                    candidate_limit,
                    list_key,
                )
            list_stats["xray_preselected"] = len(supported)

            xray_max_alive = self._as_int(vcfg.get("xray_max_alive"), 0, minimum=0)
            xray_max_alive_by_list = vcfg.get("xray_max_alive_by_list", {})
            if isinstance(xray_max_alive_by_list, dict):
                specific_max_alive = xray_max_alive_by_list.get(
                    normalize_list_type(label),
                )
                if specific_max_alive is not None:
                    xray_max_alive = self._as_int(
                        specific_max_alive,
                        xray_max_alive,
                        minimum=0,
                    )

            list_stats["xray_checked"] = len(supported)
            list_stats["xray_max_alive"] = xray_max_alive
            probe_urls_raw = vcfg.get("xray_probe_urls")
            if isinstance(probe_urls_raw, str):
                xray_probe_urls = [
                    part.strip()
                    for part in probe_urls_raw.replace(";", ",").split(",")
                    if part.strip()
                ]
            elif isinstance(probe_urls_raw, list):
                xray_probe_urls = [
                    str(part).strip() for part in probe_urls_raw if str(part).strip()
                ]
            else:
                xray_probe_urls = []
            if not xray_probe_urls:
                xray_probe_urls = [
                    str(
                        vcfg.get("xray_probe_url")
                        or "https://www.gstatic.com/generate_204",
                    ),
                ]
            xray_min_probe_successes = self._as_int(
                vcfg.get("xray_min_probe_successes"),
                1,
                minimum=1,
            )
            xray_min_probe_successes = min(
                xray_min_probe_successes,
                len(xray_probe_urls),
            )
            xray_attempts_per_config = self._as_int(
                vcfg.get("xray_attempts_per_config"),
                1,
                minimum=1,
            )
            xray_min_attempt_successes = self._as_int(
                vcfg.get("xray_min_attempt_successes"),
                xray_attempts_per_config,
                minimum=1,
            )
            xray_min_attempt_successes = min(
                xray_min_attempt_successes,
                xray_attempts_per_config,
            )
            list_stats["xray_probe_count"] = len(xray_probe_urls)
            list_stats["xray_min_probe_successes"] = xray_min_probe_successes
            list_stats["xray_attempts_per_config"] = xray_attempts_per_config
            list_stats["xray_min_attempt_successes"] = xray_min_attempt_successes
            proxy_probe_count = self._as_int(
                vcfg.get("xray_proxy_probe_count"),
                0,
                minimum=0,
            )
            xray_proxy_urls = (
                proxy_urls[:proxy_probe_count] if proxy_probe_count else []
            )
            xray_min_proxy_successes = self._as_int(
                vcfg.get("xray_min_proxy_successes"),
                0,
                minimum=0,
            )
            xray_min_proxy_successes = min(
                xray_min_proxy_successes,
                len(xray_proxy_urls),
            )
            xray_probe_via_proxies = self._as_bool(
                vcfg.get("xray_probe_via_proxies"),
                False,
            )
            list_stats["xray_proxy_checks"] = len(xray_proxy_urls)
            list_stats["xray_min_proxy_successes"] = xray_min_proxy_successes
            list_stats["xray_probe_via_proxies"] = xray_probe_via_proxies
            # Latency baselines of the probe proxies, so the recorded
            # config latency can shed the proxy's own dial hop (see
            # validate_configs_xray).
            xray_proxy_latency_ms: dict[str, float] = {}
            if xray_probe_via_proxies and xray_proxy_urls:
                try:
                    from src.validators.proxy_health import ProxyHealthHistory

                    pool_health_cfg = self._proxy_pool_config().get("health", {})
                    history_file = pool_health_cfg.get("health_history_file")
                    if history_file:
                        proxy_history = ProxyHealthHistory.load(
                            str(history_file),
                            window=self._as_int(
                                pool_health_cfg.get("latency_window"),
                                5,
                                minimum=1,
                            ),
                        )
                        for proxy_url in xray_proxy_urls:
                            avg = proxy_history.average_latency(str(proxy_url))
                            if avg is not None:
                                xray_proxy_latency_ms[str(proxy_url)] = float(avg)
                except Exception as exc:
                    logger.warning("Cannot load proxy latency baselines: %s", exc)
            xray_require_distinct_outbound_ip = self._as_bool(
                vcfg.get("xray_require_distinct_outbound_ip"),
                False,
            )
            list_stats["xray_require_distinct_outbound_ip"] = (
                xray_require_distinct_outbound_ip
            )
            logger.info(
                "%s Xray validation: checking %d candidates "
                "(concurrency %d, timeout %.0fs) — this stage is slow, "
                "progress is silent by design.",
                label,
                len(supported),
                self._as_int(vcfg.get("xray_concurrency"), 6, minimum=1),
                self._as_float(vcfg.get("xray_timeout_seconds"), 12.0, minimum=1.0),
            )

            # TTL cache: configs that passed recently get one fast re-probe
            # instead of the full attempt set, freeing probe budget for the
            # long tail of new candidates. 0 disables the split.
            verification_ttl = (
                self._as_float(
                    vcfg.get("verification_ttl_minutes"),
                    0.0,
                    minimum=0.0,
                )
                * 60.0
            )
            fresh: list[Config] = []
            stale: list[Config] = list(supported)
            if verification_ttl > 0 and self.health.is_enabled():
                now = time.time()
                fresh_ids: set[int] = set()
                for cfg in supported:
                    last_pass = self.health.last_pass_ts(cfg)
                    if last_pass and (now - last_pass) <= verification_ttl:
                        fresh.append(cfg)
                        fresh_ids.add(id(cfg))
                stale = [cfg for cfg in supported if id(cfg) not in fresh_ids]
                list_stats["xray_fresh_verified"] = len(fresh)
                if fresh:
                    logger.info(
                        "%s TTL cache: %d/%d candidates passed within %.0f min "
                        "— one fast re-probe each.",
                        label,
                        len(fresh),
                        len(supported),
                        verification_ttl / 60.0,
                    )

            alive_xray: list[Config] = []
            if fresh:
                alive_xray = await validate_configs_xray(
                    fresh,
                    xray_path=xray_path,
                    probe_urls=xray_probe_urls,
                    min_probe_successes=xray_min_probe_successes,
                    attempts_per_config=1,
                    min_attempt_successes=1,
                    probe_proxy_urls=xray_proxy_urls,
                    min_proxy_successes=xray_min_proxy_successes,
                    probe_via_proxies=xray_probe_via_proxies,
                    proxy_latency_ms=xray_proxy_latency_ms,
                    require_distinct_outbound_ip=xray_require_distinct_outbound_ip,
                    check_hostnames=check_hostnames,
                    resolve_timeout=resolve_timeout,
                    timeout=self._as_float(
                        vcfg.get("xray_timeout_seconds"),
                        12.0,
                        minimum=1.0,
                    ),
                    startup_timeout=self._as_float(
                        vcfg.get("xray_startup_timeout_seconds"),
                        4.0,
                        minimum=0.5,
                    ),
                    concurrency=self._as_int(
                        vcfg.get("xray_concurrency"),
                        6,
                        minimum=1,
                    ),
                    max_alive=xray_max_alive,
                )
            if stale:
                if xray_max_alive > 0 and len(alive_xray) >= xray_max_alive:
                    # 0 would mean "unlimited" — the budget is full.
                    list_stats["xray_stale_skipped"] = "budget_full"
                    logger.info(
                        "%s fresh re-probes filled the alive budget (%d); "
                        "skipping full validation of %d remaining candidate(s).",
                        label,
                        xray_max_alive,
                        len(stale),
                    )
                else:
                    stale_budget = (
                        max(0, xray_max_alive - len(alive_xray))
                        if xray_max_alive > 0
                        else 0
                    )
                    alive_xray = alive_xray + await validate_configs_xray(
                        stale,
                        xray_path=xray_path,
                        probe_urls=xray_probe_urls,
                        min_probe_successes=xray_min_probe_successes,
                        attempts_per_config=xray_attempts_per_config,
                        min_attempt_successes=xray_min_attempt_successes,
                        probe_proxy_urls=xray_proxy_urls,
                        min_proxy_successes=xray_min_proxy_successes,
                        probe_via_proxies=xray_probe_via_proxies,
                        proxy_latency_ms=xray_proxy_latency_ms,
                        require_distinct_outbound_ip=xray_require_distinct_outbound_ip,
                        check_hostnames=check_hostnames,
                        resolve_timeout=resolve_timeout,
                        timeout=self._as_float(
                            vcfg.get("xray_timeout_seconds"),
                            12.0,
                            minimum=1.0,
                        ),
                        startup_timeout=self._as_float(
                            vcfg.get("xray_startup_timeout_seconds"),
                            4.0,
                            minimum=0.5,
                        ),
                        concurrency=self._as_int(
                            vcfg.get("xray_concurrency"),
                            6,
                            minimum=1,
                        ),
                        max_alive=stale_budget,
                    )
            list_stats["checked"] = True
            list_stats["filtered"] = True
            list_stats["xray_alive"] = len(alive_xray)
            if singbox_path and singbox_configs:
                if xray_max_alive > 0 and len(alive_xray) >= xray_max_alive:
                    # 0 would mean "unlimited" for the validator, not "stop"
                    # — the budget is full, so the QUIC stage is skipped.
                    list_stats["singbox_skipped"] = "budget_full"
                    logger.info(
                        "%s Xray filled the alive budget (%d); skipping "
                        "sing-box validation.",
                        label,
                        xray_max_alive,
                    )
                    singbox_configs = []
                else:
                    # QUIC configs share the list's alive budget with Xray.
                    sb_max_alive = (
                        max(0, xray_max_alive - len(alive_xray))
                        if xray_max_alive > 0
                        else 0
                    )
                    alive_singbox = await validate_configs_singbox(
                        singbox_configs,
                        singbox_path=singbox_path,
                        probe_urls=xray_probe_urls,
                        min_probe_successes=xray_min_probe_successes,
                        attempts_per_config=xray_attempts_per_config,
                        min_attempt_successes=xray_min_attempt_successes,
                        probe_proxy_urls=xray_proxy_urls,
                        proxy_latency_ms=xray_proxy_latency_ms,
                        check_hostnames=check_hostnames,
                        resolve_timeout=resolve_timeout,
                        timeout=self._as_float(
                            vcfg.get("singbox_timeout_seconds"),
                            12.0,
                            minimum=1.0,
                        ),
                        startup_timeout=self._as_float(
                            vcfg.get("xray_startup_timeout_seconds"),
                            4.0,
                            minimum=0.5,
                        ),
                        concurrency=self._as_int(
                            vcfg.get("singbox_concurrency"),
                            6,
                            minimum=1,
                        ),
                        max_alive=sb_max_alive,
                    )
                    list_stats["singbox_checked"] = sum(
                        1
                        for cfg in singbox_configs
                        if getattr(cfg, "xray_was_checked", False)
                    )
                    list_stats["singbox_alive"] = len(alive_singbox)
                    logger.info(
                        "%s sing-box validation: %d/%d QUIC configs alive.",
                        label,
                        len(alive_singbox),
                        len(singbox_configs),
                    )
                    alive_xray = alive_xray + alive_singbox
                    list_stats["xray_alive"] = len(alive_xray)
            xray_attempted = [
                cfg for cfg in supported if getattr(cfg, "xray_was_checked", False)
            ] + [
                cfg
                for cfg in singbox_configs
                if getattr(cfg, "xray_was_checked", False)
            ]
            list_stats["xray_checked"] = len(xray_attempted)
            # One verdict per config per run: the same server can ride in
            # two lists, and update() would append two `recent` entries for
            # a single run — halving the streak the stability gate counts
            # (and halving the failures needed for a ban).
            seen_keys = self._health_update_seen
            unique_attempted: list[Config] = []
            for cfg in xray_attempted:
                key = HealthHistory.config_key(cfg)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                unique_attempted.append(cfg)
            if self._update_health_callback:
                self._update_health_callback(unique_attempted)
            else:
                self.health.update(unique_attempted)
            if self._update_source_health_callback:
                self._update_source_health_callback(unique_attempted, list_stats)
            else:
                self.health.update_sources(unique_attempted, list_stats)
            current = alive_xray
            if not drop_unsupported and unsupported_configs:
                current = self._merge_unsupported(
                    before_xray,
                    alive_xray,
                    unsupported_configs,
                )
                list_stats["xray_unsupported_kept"] = len(unsupported_configs)
            health_ban_min_alive = self._as_int(
                self.settings.section("quality").get("health_ban_min_alive"),
                3,
                minimum=0,
            )
            # Bans are applied to the merged list: an Xray-unsupported config
            # skips the probe, not the health/source ban, or a banned source
            # would keep publishing every protocol Xray cannot check.
            # A config that passed its probe right now carries fresh evidence
            # it works — stale history (above all a source-level ban from two
            # bad runs) must not erase it.
            fresh_alive_ids = {id(cfg) for cfg in alive_xray}
            if len(current) > health_ban_min_alive:
                current = [
                    cfg
                    for cfg in current
                    if id(cfg) in fresh_alive_ids or not self.health.is_banned(cfg)
                ]
            else:
                logger.info(
                    "%s Xray stage kept %d config(s) (<= %d); "
                    "skipping health history bans.",
                    label,
                    len(current),
                    health_ban_min_alive,
                )
            list_stats["output_after_health"] = len(current)
            list_stats["output_after_xray"] = len(current)
            logger.info("%s after Xray validation: %d configs.", label, len(current))

        return current

    @staticmethod
    def _merge_unsupported(
        before_xray: list[Config],
        alive: list[Config],
        unsupported: list[Config],
    ) -> list[Config]:
        """Add Xray-unsupported configs back to the Xray-alive ones.

        Used when ``xray_drop_unsupported`` is false: protocols Xray cannot
        probe (for example hysteria2) must survive the stage instead of being
        silently dropped together with the configs that failed the probe.

        Args:
            before_xray: Configs as they entered the Xray stage, in order.
            alive: Configs that passed Xray validation.
            unsupported: Configs Xray cannot validate at all.

        Returns:
            Alive plus unsupported configs, in the original input order and
            without duplicates.
        """
        keep = {id(cfg) for cfg in alive} | {id(cfg) for cfg in unsupported}
        merged = [cfg for cfg in before_xray if id(cfg) in keep]
        seen = {id(cfg) for cfg in merged}
        merged.extend(cfg for cfg in alive if id(cfg) not in seen)
        return merged

    def _xray_candidate_preselect(
        self,
        configs: list[Config],
        max_total: int,
        list_type: str,
    ) -> list[Config]:
        from src.scheduler.stages.aggregate import Aggregator

        if normalize_list_type(list_type) == "whitelist":
            # _whitelist_balance honors whitelist_ru_ratio strictly: with
            # ratio=1.0 a shortfall of RU servers stays a shortfall and fewer
            # candidates reach Xray. That is intentional — the operator asked
            # for RU-only; final balancing happens later in Aggregator anyway.
            return Aggregator(self.context)._whitelist_balance(configs, max_total)
        return Aggregator(self.context)._country_balanced_limit(configs, max_total)
