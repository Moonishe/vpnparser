"""Liveness validation stage: TCP/TLS/Xray checks."""

from __future__ import annotations

import logging
import time
from typing import Any

from src.parsers.base import Config
from src.scheduler.context import PipelineContext
from src.scheduler.health_history import HealthHistory
from src.scheduler.stages.base import PipelineStage
from src.scheduler.stages.liveness_pool import LivenessPoolMixin
from src.scheduler.stages.liveness_stages import LivenessStagesMixin, _ProbeLog
from src.sources.list_types import normalize_list_type
from src.validators.address_guard import clear_verdict_cache

logger = logging.getLogger(__name__)


class LivenessValidator(LivenessPoolMixin, LivenessStagesMixin, PipelineStage):
    """Validate configs via TCP/TLS/Xray and update health history.

    The proxy-pool lifecycle (config, cached URLs, health, refetch recovery)
    lives in :class:`LivenessPoolMixin`; the per-stage probe bodies (TCP,
    TLS, Xray) live in :class:`LivenessStagesMixin`. This class owns the
    probe orchestration and the health-bookkeeping contract.
    """

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
        #: Pool rebuild budget per run (max 3): free SOCKS lists burn out
        #: within minutes, so one refill per run was not enough — the second
        #: degraded list rode on corpses again. Counter, not a bool flag.
        self._pool_refetch_count: int = 0
        self._validator_proxy_urls_cache: list[str] | None = None
        self._proxy_health_history: Any | None = None
        self._proxy_health_file: str | None = None
        self._init_proxy_health_history()

    #: Max pool rebuilds per run (refill + empty-list recovery share it).
    _POOL_REFETCH_LIMIT: int = 3

    @property
    def _pool_refetch_used(self) -> bool:
        """Backward-compat: True once any pool refetch happened this run."""
        return self._pool_refetch_count > 0

    @_pool_refetch_used.setter
    def _pool_refetch_used(self, value: bool) -> None:
        # Tests and legacy paths flip the flag directly: True means the
        # budget is exhausted (legacy once-per-run semantic), False resets.
        if value:
            self._pool_refetch_count = int(getattr(self, "_POOL_REFETCH_LIMIT", 3))
        else:
            self._pool_refetch_count = 0

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

    def reset_proxy_cache(self) -> None:
        """Clear cached proxy URLs so they are re-fetched on the next run."""
        self._validator_proxy_urls_cache = None

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

    async def validate_by_list(
        self,
        configs_by_list: dict[str, list[Config]],
    ) -> dict[str, list[Config]]:
        # Verdicts from a previous run must not ride into this one: the cache
        # is keyed by host only, and a rebinding host could keep a stale
        # "public" verdict across run boundaries in --continuous mode.
        clear_verdict_cache()
        self._health_update_seen = set()
        self._pool_refetch_count = 0
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
                False,
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
            logger.warning(
                "Liveness validation fully disabled (tcp/tls/xray all off): no "
                "config can be verified alive. Marking every config not-alive so "
                "it is excluded from the subscription rather than published "
                "unverified (fail-closed); the publish floor keeps the last good "
                "subscription intact."
            )
            for _list_configs in configs_by_list.values():
                for _cfg in _list_configs:
                    _cfg.is_alive = False
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
                # A collapsed-but-nonempty list is the same dead-pool signal
                # as an empty one: 1 survivor out of hundreds means the pool
                # died mid-run, not that the input is 99% dead. Recover now
                # so the next list does not ride on corpses.
                if self._pool_degraded(len(alive), len(configs)):
                    await self._call_pool_watchdog(
                        list_type,
                        alive_count=len(alive),
                        checked_count=len(configs),
                    )
            else:
                await self._call_pool_watchdog(
                    list_type,
                    alive_count=0,
                    checked_count=len(configs),
                )
        return validated

    async def _call_pool_watchdog(
        self,
        label: str,
        *,
        alive_count: int = 0,
        checked_count: int = 0,
    ) -> None:
        """Invoke the pool watchdog tolerating legacy single-arg overrides.

        Tests monkeypatch ``_pool_died_after_empty_list`` with a one-arg
        fake; passing the new keywords unconditionally broke them with
        TypeError. Try the rich call first, fall back to the legacy shape.
        """
        try:
            await self._pool_died_after_empty_list(
                label,
                alive_count=alive_count,
                checked_count=checked_count,
            )
        except TypeError:
            await self._pool_died_after_empty_list(label)

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
        stage_started = time.monotonic()
        # Set inside the Xray branch once its health update consumed the
        # configs. That update registers every attempted config in
        # _health_update_seen first, so the _record_probe_health below skips
        # exactly those verdicts instead of recording them twice.
        self._xray_stage_consumed_probe_log = False
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
            # Stage duration lands in run-summary.json (list_stats is the same
            # dict stored in liveness_stats), so runtime trends are visible
            # without scraping logs.
            if probe_log.stats:
                probe_log.stats["duration_s"] = round(
                    time.monotonic() - stage_started,
                    1,
                )
            # Always record the TCP/TLS verdicts here. The old gate ran this
            # only when the Xray branch had not consumed the probe log, but
            # that branch records health for its own attempted subset only:
            # configs killed at the TCP/TLS stage never reached
            # health.update(), their consecutive_failures never grew, bans
            # never fired for them and their sources never accumulated
            # stats. _record_probe_health is idempotent per (run, dedup key)
            # via _health_update_seen, so a verdict the Xray branch already
            # recorded is skipped here, no matter which stages ran.
            self._record_probe_health(probe_log)
        if self._xray_stage_consumed_probe_log or not probe_log.configs:
            # The Xray branch applied the health-ban filter itself; only a
            # run whose verdicts came from TCP/TLS alone drops here.
            return result
        # A config probed alive in this pass carries fresh evidence that
        # outranks stale history — above all a source-level ban from two bad
        # runs (mirrors the post-Xray filter): only configs the probes never
        # judged are still ban-filtered.
        fresh_alive_ids = {id(cfg) for cfg in probe_log.configs if cfg.is_alive}
        return self._drop_banned(
            result,
            label=label,
            stats=probe_log.stats,
            fresh_alive_ids=fresh_alive_ids,
        )

    def _record_probe_health(self, probe_log: _ProbeLog) -> None:
        """Persist the health of everything the TCP/TLS checks judged.

        Runs for every validation, also when the Xray branch already recorded
        its own attempted subset: the shared ``_health_update_seen`` keys make
        it idempotent per (run, dedup key), so only the verdicts that stage
        never judged are recorded here.

        Same one-verdict-per-config-per-run rule the Xray branch applies
        (``_health_update_seen``): without it a server riding in two lists
        produced two ``recent`` entries per run, halving the streak the
        stability gate counts and halving the failures needed for a ban.

        Args:
            probe_log: Configs carrying a verdict from this validation.
        """
        if not probe_log.configs:
            return
        seen_keys = self._health_update_seen
        unique_configs: list[Config] = []
        for cfg in probe_log.configs:
            # None = no verdict (budget-skip/cancel/infra/DNS-pin): the
            # Xray/sing-box stages reset is_alive to None for unprobed
            # candidates so a shared probe_log reference must not become
            # a false failure (or a false pass) in health history.
            if cfg.is_alive is None:
                continue
            key = HealthHistory.config_key(cfg)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            unique_configs.append(cfg)
        if not unique_configs:
            return
        if self._update_health_callback:
            self._update_health_callback(unique_configs)
        else:
            self.health.update(unique_configs)
        if self._update_source_health_callback:
            self._update_source_health_callback(unique_configs, probe_log.stats)
        else:
            self.health.update_sources(unique_configs, probe_log.stats)

    def _drop_banned(
        self,
        configs: list[Config],
        *,
        label: str,
        stats: dict[str, Any],
        fresh_alive_ids: set[int],
    ) -> list[Config]:
        """Apply health/source bans, mirroring the Xray branch's ban step.

        Args:
            configs: Configs that survived the enabled checks.
            label: List label, for logging.
            stats: Per-list statistics to annotate.
            fresh_alive_ids: Ids of the configs that were probed alive in
                this very pass (the verdict _record_probe_health just
                recorded). A source ban must not erase configs with fresh
                successful probes, so they are exempt exactly like in the
                Xray branch; only configs the probes skipped are still
                ban-filtered.

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
        kept = [
            cfg
            for cfg in configs
            if id(cfg) in fresh_alive_ids or not self.health.is_banned(cfg)
        ]
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
        """Run the enabled probe stages over one list.

        Pure orchestration: shared per-list setup and the TCP -> TLS -> Xray
        sequence, with the stage bodies themselves in
        :class:`LivenessStagesMixin`. A stage's fail-open exit arrives as an
        explicit early result (the original code returned it from the middle
        of ``_validate_configs``); otherwise the working list flows stage to
        stage unchanged.
        """
        if not configs:
            return []

        vcfg = self._section("validator")
        # Per-list pool snapshot: proxy latency baselines are NOT taken here.
        # Each stage snapshots them after its own recheck/refill (see
        # _run_tcp_stage / _run_xray_stage) so a mid-list pool rebuild does
        # not leave stale baselines describing dead proxies.
        proxy_urls = (
            await self._proxy_url_getter()
            if self._proxy_url_getter
            else await self._validator_proxy_urls()
        )
        pool_cfg = self._proxy_pool_config()
        pool_required = self._as_bool(pool_cfg.get("required"), False)
        pool_enabled = self._as_bool(pool_cfg.get("enabled"), False)
        fail_open_on_low_alive = self._as_bool(
            vcfg.get("fail_open_on_low_alive"), False
        )
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
                # Fail-closed: without the required proxy pool AND without Xray
                # there is no validator left, so returning the unfiltered input
                # would push unvalidated (likely dead) configs into the
                # subscription. Returning nothing leaves the previously published
                # file untouched (the empty-run path skips subscription publish).
                list_stats["reason"] = "no_proxies"
                logger.warning(
                    "Liveness validation for %s skipped: proxy_pool.required=true "
                    "but no proxies are available and Xray is disabled — dropping "
                    "the list instead of publishing unvalidated configs.",
                    label,
                )
                return []
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
        # Skip configs with an active health ban BEFORE any network probe: a
        # config-level ban (2 consecutive failures, 12h) means the config just
        # failed everything recently, and re-probing the known-dead tail burned
        # most of the 2026-08-30 run's Xray budget. Skipped configs record no
        # verdict, so their bans simply expire — time-boxed self-heal, not a
        # permanent drop. Source bans are NOT pre-filtered: a passing probe is
        # fresh evidence that outranks the stale source-level ban (mirrors the
        # post-Xray filter below). Small lists are exempt: stale history must
        # not erase the last survivors.
        prefilter_min_alive = self._as_int(
            self.settings.section("quality").get("health_ban_min_alive"),
            3,
            minimum=0,
        )
        if len(current) > prefilter_min_alive and self.health.is_enabled():
            banned_configs = [
                cfg for cfg in current if self.health.is_config_banned(cfg)
            ]
            if banned_configs:
                banned_ids = {id(cfg) for cfg in banned_configs}
                current = [cfg for cfg in current if id(cfg) not in banned_ids]
                list_stats["ban_prefiltered"] = len(banned_configs)
                logger.info(
                    "%s health bans pre-filtered %d config(s) before probing.",
                    label,
                    len(banned_configs),
                )
        # Set when a fail-open kept the unfiltered list: the remaining optional
        # filters are skipped, but mandatory Xray validation still runs.
        fail_open_active = False

        if tcp_enabled:
            current, fail_open_active, fail_open_result = await self._run_tcp_stage(
                configs,
                current,
                label=label,
                vcfg=vcfg,
                proxy_urls=proxy_urls,
                check_hostnames=check_hostnames,
                resolve_timeout=resolve_timeout,
                xray_enabled=xray_enabled,
                fail_open_on_low_alive=fail_open_on_low_alive,
                list_stats=list_stats,
                probe_log=probe_log,
            )
            # Fail-open with no Xray stage left: the unfiltered input IS the
            # final result (was: ``return configs`` / ``return before_tls``).
            if fail_open_result is not None:
                return fail_open_result

        if tls_enabled:
            current, fail_open_result = await self._run_tls_stage(
                current,
                label=label,
                vcfg=vcfg,
                proxy_urls=proxy_urls,
                check_hostnames=check_hostnames,
                resolve_timeout=resolve_timeout,
                xray_enabled=xray_enabled,
                fail_open_on_low_alive=fail_open_on_low_alive,
                drop_unchecked_after_tls=drop_unchecked_after_tls,
                fail_open_active=fail_open_active,
                list_stats=list_stats,
                probe_log=probe_log,
            )
            if fail_open_result is not None:
                return fail_open_result

        if xray_enabled and current:
            current = await self._run_xray_stage(
                current,
                label=label,
                list_key=list_key,
                vcfg=vcfg,
                proxy_urls=proxy_urls,
                check_hostnames=check_hostnames,
                resolve_timeout=resolve_timeout,
                list_stats=list_stats,
            )

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
