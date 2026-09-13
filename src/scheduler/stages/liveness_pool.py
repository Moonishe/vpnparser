"""Proxy-pool lifecycle for the liveness stage.

Sources, health config, cached proxy URLs and the "pool died mid-run"
recovery: one cohesive concern that the validator composes as a mixin so
``LivenessValidator`` keeps only the probe orchestration.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

from src.scheduler.health_history import HealthHistory
from src.scheduler.settings import Settings

logger = logging.getLogger(__name__)


class LivenessPoolMixin:
    """Validator proxy pool: config, cached URLs, health, refetch recovery.

    Attributes and host methods below are declared as annotations only: the
    composing :class:`LivenessValidator` owns their real initialisation, and
    the declarations give mypy the self-contract of the mixin.
    """

    #: Declared by the composing validator (see its ``__init__``).
    context: Any
    settings: Settings
    health: HealthHistory
    _proxy_url_getter: Any
    _validator_proxy_urls_cache: list[str] | None
    _proxy_health_history: Any
    _proxy_health_file: str | None
    _pool_refetch_count: int
    _pool_refetch_used: bool
    _POOL_REFETCH_LIMIT: int

    def _section(self, name: str) -> dict[str, Any]:
        """Provided by the composing validator."""
        raise NotImplementedError

    def _as_bool(self, value: Any, default: bool = False) -> bool:
        raise NotImplementedError

    def _as_int(self, value: Any, default: int, *, minimum: int | None = None) -> int:
        raise NotImplementedError

    def _as_float(
        self,
        value: Any,
        default: float,
        *,
        minimum: float | None = None,
    ) -> float:
        raise NotImplementedError

    def _source_list(self, value: Any) -> list[str] | None:
        raise NotImplementedError

    @staticmethod
    def _redact_proxy_url(proxy_url: str) -> str:
        raise NotImplementedError

    def _proxy_pool_config(self) -> dict[str, Any]:
        raw = self._section("validator").get("proxy_pool", {})
        return raw if isinstance(raw, dict) else {}

    def _proxy_health_config(self) -> dict[str, Any]:
        pool_cfg = self._proxy_pool_config()
        defaults = {
            "health_enabled": True,
            "health_history_file": "output/proxy-health-history.json",
            "ban_after_consecutive_failures": 3,
            "ban_seconds": 3600.0,
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
            ban_seconds=self._as_float(
                hcfg.get("ban_seconds"),
                3600.0,
                minimum=0.0,
            ),
        )

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

        # Append, never overwrite: the pool is searched once per run at fill
        # time and again on every mid-run refill — resetting proxy_search to
        # [] here wiped the earlier rounds from run-summary.json.
        _existing_search = self.context.liveness_stats.get("proxy_search")
        if not isinstance(_existing_search, list):
            _existing_search = []
        _round_offset = len(_existing_search)
        self.context.liveness_stats.update(
            {
                "proxy_min_proxies": min_proxies,
                "proxy_search_round_limit": search_rounds,
                "proxy_search_rounds": _round_offset,
                "proxy_search": _existing_search,
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
            round_urls = await load_proxy_pool(
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
            # Monotonic search: a later round with a wider candidate budget can
            # still validate FEWER proxies (the self-check races whatever
            # endpoints happen to answer), and plain overwriting used to throw
            # the earlier round's working set away — the widest search ending
            # with the poorest pool. Merge first-seen-first (earlier proxies
            # already proved themselves), still capped by the configured size.
            pool_urls = list(dict.fromkeys([*pool_urls, *round_urls]))[:max_proxies]
            self.context.liveness_stats["proxy_search_rounds"] = (
                _round_offset + round_index + 1
            )
            self.context.liveness_stats["proxy_search"].append(
                {
                    "round": _round_offset + round_index + 1,
                    "max_candidates": max_candidates,
                    "max_candidates_per_source": max_candidates_per_source,
                    "working": len(round_urls),
                    "pool": len(pool_urls),
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
            vcfg.get("proxy_url") or os.environ.get("VALIDATOR_PROXY") or "",
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

    def _pool_degraded(self, alive_count: int, checked_count: int) -> bool:
        """Whether the pool looks dead even though the list is not empty.

        An empty list is the obvious signal, but a pool that dies mid-run
        usually shows up first as a collapsed alive ratio: 1 survivor out of
        hundreds is a dead-proxy spiral, not 99% dead input. Triggers the
        same self-check/recovery as the empty-list path.
        """
        if checked_count <= 0:
            return False
        if checked_count > 10 and alive_count < 2:
            return True
        try:
            ratio = float(alive_count) / float(checked_count)
        except (TypeError, ValueError, ZeroDivisionError):
            return False
        return ratio < 0.2

    async def _pool_died_after_empty_list(
        self,
        label: str,
        *,
        alive_count: int = 0,
        checked_count: int = 0,
    ) -> None:
        """React to a list validating to zero alive under a free proxy pool.

        A pool that dies mid-run used to go unnoticed: every remaining config
        was then "validated" through dead proxies, recorded dead in the health
        history and banned for hours — an infrastructure failure poisoning
        config verdicts run over run. When a whole list comes back empty
        (or degraded per :meth:`_pool_degraded`), cheaply re-probe the cached
        pool proxies; dead ones are recorded and dropped, and (with
        ``refresh_if_below_min``, up to ``_POOL_REFETCH_LIMIT`` times per run)
        the cache is invalidated so the next list rebuilds the pool from
        fresh sources.
        """

        pool_cfg = self._proxy_pool_config()
        if not self._as_bool(pool_cfg.get("enabled"), False):
            return
        if not self._as_bool(
            self._proxy_health_config().get("refresh_if_below_min"),
            True,
        ):
            return
        urls = list(self._validator_proxy_urls_cache or [])
        explicit = str(
            self._section("validator").get("proxy_url")
            or os.environ.get("VALIDATOR_PROXY")
            or "",
        ).strip()
        pool_only = [u for u in urls if u != explicit]
        if not pool_only:
            return

        from src.validators.proxy_pool import proxy_connects

        # Use the CONFIGURED self-check target, not the hardcoded default:
        # the initial pool search probes probe_host/probe_port (+ extras), and
        # a recovery check against a different destination disagrees with it —
        # a network that filters the default but allows the configured target
        # (or vice versa) invalidates a pool the search just proved good.
        probe_host = str(pool_cfg.get("probe_host") or "api.github.com")
        probe_port = self._as_int(pool_cfg.get("probe_port"), 443, minimum=1)
        results = await asyncio.gather(
            *(
                proxy_connects(
                    proxy_url,
                    probe_host=probe_host,
                    probe_port=probe_port,
                    extra_probe_targets=self._extra_probe_targets(pool_cfg),
                )
                for proxy_url in pool_only
            ),
            return_exceptions=True,
        )
        alive: list[str] = []
        for proxy_url, ok in zip(pool_only, results, strict=False):
            # gather(return_exceptions=True) delivers exception objects here;
            # only a literal True counts as success.
            success = ok is True
            # The self-check is real evidence either way: record it so the
            # persisted history reflects what just happened.
            if self._proxy_health_history is not None:
                try:
                    self._proxy_health_history.record(proxy_url, success)
                except Exception as exc:  # pragma: no cover - defensive only
                    logger.warning("Proxy pool self-check bookkeeping failed: %s", exc)
            if success:
                alive.append(proxy_url)

        responding = len(alive)
        if alive_count == 0 and checked_count == 0:
            logger.warning(
                "%s validated to 0 alive — pool self-check: %d/%d respond.",
                label,
                responding,
                len(pool_only),
            )
        else:
            logger.warning(
                "%s validated to %d/%d alive — pool self-check: %d/%d respond.",
                label,
                alive_count,
                checked_count,
                responding,
                len(pool_only),
            )
        if responding == len(pool_only):
            return  # pool is fine; the lists themselves are dead

        if alive:
            kept = [u for u in urls if u == explicit or u in set(alive)]
            self._validator_proxy_urls_cache = kept
            self.context.liveness_stats["proxy_count"] = len(kept)
            logger.warning(
                "Proxy pool: keeping %d responsive proxie(s) for the next lists.",
                len(alive),
            )
            return
        limit = int(getattr(self, "_POOL_REFETCH_LIMIT", 3) or 3)
        if self._pool_refetch_count >= limit:
            logger.warning(
                "Proxy pool is fully dead and was already rebuilt once this "
                "run (%d time(s) total, limit %d) — keeping the cache rather "
                "than re-fetching again.",
                self._pool_refetch_count,
                limit,
            )
            return
        self._pool_refetch_count += 1
        self._validator_proxy_urls_cache = None
        logger.warning(
            "Proxy pool is fully dead mid-run: cache invalidated — the next "
            "list will rebuild the pool from fresh sources.",
        )
