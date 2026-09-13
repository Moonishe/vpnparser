"""TCP/TLS/Xray probe stages for the liveness validator.

Each ``_run_*_stage`` method is one ``if *_enabled`` body extracted from
``LivenessValidator._validate_configs``: the composing validator keeps the
shared per-list setup, the fail-open control flow and the stage sequence,
while the per-stage bodies live here as a mixin (same pattern as
:class:`~src.scheduler.stages.liveness_pool.LivenessPoolMixin`).
"""

from __future__ import annotations

import logging
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from src.parsers.base import Config
from src.scheduler.health_history import HealthHistory
from src.scheduler.settings import Settings
from src.sources.list_types import normalize_list_type

logger = logging.getLogger(__name__)

_TCP_SKIP_PROTOCOLS = {"tuic", "hysteria2"}


def _by_list_setting(raw: Any) -> dict[str, Any]:
    """Return a per-list override mapping with lowercased keys.

    YAML keys are case-sensitive while the lookup key is the normalized
    lowercase list name: an operator writing ``WHITELIST: false`` in
    ``xray_probe_via_proxies_by_list`` (or any ``*_by_list`` block) silently
    configured nothing.
    """
    if not isinstance(raw, dict):
        return {}
    return {str(key).strip().lower(): value for key, value in raw.items()}


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


class LivenessStagesMixin:
    """Validator probe stages: TCP, TLS and Xray list validation.

    Attributes and host methods below are declared as annotations only: the
    composing :class:`LivenessValidator` owns their real initialisation, and
    the declarations give mypy the self-contract of the mixin.

    Stage contract: every method mutates ``list_stats`` in place (it is the
    same dict stored in ``liveness_stats["lists"]``), and ``current`` plus the
    fail-open flag flow back to the orchestrator through the return values so
    the stage sequence there stays a literal TCP → TLS → Xray chain.
    """

    #: Declared by the composing validator (see its ``__init__``).
    context: Any
    settings: Settings
    health: HealthHistory
    _proxy_url_getter: Any
    _validator_proxy_urls_cache: list[str] | None
    _proxy_health_history: Any
    _pool_refetch_count: int
    _pool_refetch_used: bool
    _POOL_REFETCH_LIMIT: int
    _update_health_callback: Any
    _update_source_health_callback: Any
    _health_update_seen: set[str]
    _xray_stage_consumed_probe_log: bool

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

    def _liveness_min_alive(self, total: int) -> int:
        raise NotImplementedError

    def _proxy_pool_config(self) -> dict[str, Any]:
        raise NotImplementedError

    def reset_proxy_cache(self) -> None:
        raise NotImplementedError

    def _xray_candidate_preselect(
        self,
        configs: list[Config],
        max_total: int,
        list_type: str,
    ) -> list[Config]:
        raise NotImplementedError

    @staticmethod
    def _merge_unsupported(
        before_xray: list[Config],
        alive: list[Config],
        unsupported: list[Config],
    ) -> list[Config]:
        raise NotImplementedError

    async def _run_tcp_stage(
        self,
        configs: list[Config],
        current: list[Config],
        *,
        label: str,
        vcfg: dict[str, Any],
        proxy_urls: list[str],
        check_hostnames: bool,
        resolve_timeout: float,
        xray_enabled: bool,
        fail_open_on_low_alive: bool,
        list_stats: dict[str, Any],
        probe_log: _ProbeLog,
    ) -> tuple[list[Config], bool, list[Config] | None]:
        """TCP connect check: batched search rounds, caps and fail-open.

        Args:
            configs: Original, unfiltered input list (the fail-open exit
                returns it and reports its length).
            current: Working list after the health-ban pre-filter.
            label: List label used for logging.
            vcfg: The ``validator`` settings section.
            proxy_urls: Validator proxy URLs for the TCP dial.
            check_hostnames: Hostname pre-check flag for the probe.
            resolve_timeout: DNS timeout for the probe.
            xray_enabled: Whether an Xray stage follows; a fail-open without
                Xray ends the whole validation here.
            fail_open_on_low_alive: Keep the unfiltered list instead of
                filtering when the alive floor is not reached.
            list_stats: Per-list statistics, mutated in place.
            probe_log: Verdict accumulator shared across stages.

        Returns:
            Tuple of ``(current, fail_open_active, early_result)``:
            the working list for the next stage, whether a fail-open kept the
            unfiltered list (the TLS stage consults it), and the fail-open
            result the orchestrator must return immediately (``None`` to
            continue with the stage sequence).
        """
        # Set when a fail-open kept the unfiltered list: the remaining optional
        # filters are skipped, but mandatory Xray validation still runs.
        fail_open_active = False

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
            tcp_max_alive_by_list = _by_list_setting(vcfg.get("tcp_max_alive_by_list"))
            if tcp_max_alive_by_list:
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
            # Latency baselines of the pool proxies, so the recorded
            # config latency can shed the proxy's own dial hop (mirrors
            # the Xray stage; without it a fast server behind a congested
            # free proxy is ranked — and bounced — as slow).
            tcp_proxy_latency_ms: dict[str, float] = {}
            if self._proxy_health_history is not None and proxy_urls:
                for pool_proxy in proxy_urls:
                    avg = self._proxy_health_history.average_latency(
                        str(pool_proxy),
                    )
                    if avg is not None:
                        tcp_proxy_latency_ms[str(pool_proxy)] = float(avg)
            while offset < len(checkable) and round_count < tcp_search_rounds:
                batch = checkable[offset : offset + candidate_limit]
                if not batch:  # pragma: no cover
                    break
                round_count += 1
                offset += len(batch)
                checked_total += len(batch)
                remaining_alive = (
                    max(0, tcp_max_alive - len(alive_tcp)) if tcp_max_alive > 0 else 0
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
                    proxy_latency_ms=tcp_proxy_latency_ms,
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
            # The threshold is measured against every candidate that
            # entered a batch (checked_total), including ones the
            # address guard refused before a socket was opened —
            # deliberately: measuring only real dials (tcp_checked_actual)
            # makes the floor unreachable when refusals dominate, which
            # silently disabled the fail-open path. The fail-open logs
            # below report both numbers so the skew stays visible.
            min_alive = self._liveness_min_alive(checked_total)
            # Stage-suffixed keys: a single shared key let the TLS value
            # overwrite the TCP one, making the TCP fail-open decision
            # unauditable from run-summary.json.
            list_stats["min_alive_to_filter_tcp"] = min_alive
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
                        # Fail-open kept the unfiltered input and no Xray
                        # stage follows: the orchestrator returns this marker
                        # as the final result (was: ``return configs``).
                        return current, True, configs
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

        return current, fail_open_active, None

    async def _run_tls_stage(
        self,
        current: list[Config],
        *,
        label: str,
        vcfg: dict[str, Any],
        proxy_urls: list[str],
        check_hostnames: bool,
        resolve_timeout: float,
        xray_enabled: bool,
        fail_open_on_low_alive: bool,
        drop_unchecked_after_tls: bool,
        fail_open_active: bool,
        list_stats: dict[str, Any],
        probe_log: _ProbeLog,
    ) -> tuple[list[Config], list[Config] | None]:
        """TLS handshake check, or the skip notice after a TCP fail-open.

        Args:
            current: Working list handed over by the TCP stage.
            label: List label used for logging.
            vcfg: The ``validator`` settings section.
            proxy_urls: Validator proxy URLs for the handshake.
            check_hostnames: Hostname pre-check flag for the probe.
            resolve_timeout: DNS timeout for the probe.
            xray_enabled: Whether an Xray stage follows; a fail-open without
                Xray ends the whole validation here.
            fail_open_on_low_alive: Keep the pre-TLS list instead of
                filtering when the alive floor is not reached.
            drop_unchecked_after_tls: Drop non-TLS (TCP-only) configs when
                no TLS candidate exists at all.
            fail_open_active: Set by a TCP fail-open; TLS is then skipped and
                only leaves a trace in the statistics.
            list_stats: Per-list statistics, mutated in place.
            probe_log: Verdict accumulator shared across stages.

        Returns:
            Tuple of ``(current, early_result)``: the working list for the
            next stage, and the fail-open result the orchestrator must return
            immediately (``None`` to continue with the stage sequence).
        """
        if fail_open_active:
            # Leave a trace: without it run-summary shows tls_enabled=true and
            # no tls_* key at all, which reads exactly like "TLS ran and found
            # nothing" instead of "TLS never started".
            list_stats["tls_skipped"] = "tcp_fail_open"
            logger.info(
                "%s TLS validation skipped: the TCP fail-open already kept the "
                "unfiltered list.",
                label,
            )
        if not fail_open_active:
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
                tls_capped_skipped: list[Config] = []
                if candidate_limit > 0 and len(tls_checkable) > candidate_limit:
                    logger.info(
                        "%s TLS validation candidate cap: checking first %d/%d.",
                        label,
                        candidate_limit,
                        len(tls_checkable),
                    )
                    tls_capped_skipped = tls_checkable[candidate_limit:]
                    tls_checkable = tls_checkable[:candidate_limit]
                    # Capped tail never reaches the TLS probe: no verdict, so
                    # it must not keep a stale TCP True as a health pass.
                    # None means "retry first next run" in _record_probe_health
                    # (mirrors the Xray preselect tail below).
                    for cfg in tls_capped_skipped:
                        cfg.is_alive = None
                        cfg.xray_was_checked = False
                    list_stats["tls_capped_skipped"] = len(tls_capped_skipped)
                list_stats["min_alive_to_filter_tls"] = tls_min_alive
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
                            # Fail-open kept the pre-TLS list and no Xray
                            # stage follows: the orchestrator returns this
                            # marker as the final result (was:
                            # ``return before_tls``).
                            return current, before_tls
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
                    current = alive_tls + tls_passthrough + tls_capped_skipped
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
        return current, None

    async def _run_xray_stage(
        self,
        current: list[Config],
        *,
        label: str,
        list_key: str,
        vcfg: dict[str, Any],
        proxy_urls: list[str],
        check_hostnames: bool,
        resolve_timeout: float,
        list_stats: dict[str, Any],
    ) -> list[Config]:
        """L3 Xray/sing-box probe: the last filter of the stage sequence.

        Args:
            current: Working list handed over by the TLS stage; the
                ``xray_enabled and current`` guard lives in the orchestrator.
            label: List label used for logging and per-list overrides.
            list_key: Normalized list key used for per-list candidate caps.
            vcfg: The ``validator`` settings section.
            proxy_urls: Validator proxy URLs for the probe-via-proxy path
                (recheck, refill and latency baselines included).
            check_hostnames: Hostname pre-check flag for the probe.
            resolve_timeout: DNS timeout for the probe.
            list_stats: Per-list statistics, mutated in place.

        Returns:
            The final list for the whole validation: every exit path of the
            original ``if xray_enabled and current:`` body (unavailable
            executable, no supported candidates, or the post-ban filter)
            returned its result directly, so this method returns it unchanged
            and the orchestrator forwards it as-is.
        """
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
        xray_candidate_limit_by_list = _by_list_setting(
            vcfg.get("xray_candidate_limit_by_list")
        )
        if xray_candidate_limit_by_list:
            specific_candidate_limit = xray_candidate_limit_by_list.get(list_key)
            if specific_candidate_limit is not None:
                candidate_limit = self._as_int(
                    specific_candidate_limit,
                    candidate_limit,
                    minimum=0,
                )
        if candidate_limit > 0:
            pre_ids = {id(cfg) for cfg in supported}
            supported = self._xray_candidate_preselect(
                supported,
                candidate_limit,
                list_key,
            )
            # Preselect tail never reaches Xray: no L3 verdict, so it must
            # not keep its TCP True as a health-history pass. None means
            # "retry first next run" in _record_probe_health.
            kept_ids = {id(cfg) for cfg in supported}
            for cfg in list(current):
                if id(cfg) in pre_ids and id(cfg) not in kept_ids:
                    cfg.is_alive = None
                    cfg.xray_was_checked = False
        list_stats["xray_preselected"] = len(supported)

        xray_max_alive = self._as_int(vcfg.get("xray_max_alive"), 0, minimum=0)
        xray_max_alive_by_list = _by_list_setting(vcfg.get("xray_max_alive_by_list"))
        if xray_max_alive_by_list:
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
        # Wall-clock safety net per list (0 = off): candidates arriving
        # after the deadline get no verdict and retry first next run.
        # ONE absolute deadline for the fresh, retry and stale passes —
        # passing the duration to each pass let each start its own clock
        # (up to 3x the budget), and the sing-box pass had none at all.
        xray_stage_budget_seconds = (
            self._as_float(
                vcfg.get("xray_stage_budget_minutes"),
                0.0,
                minimum=0.0,
            )
            * 60.0
        )
        xray_stage_deadline = (
            time.monotonic() + xray_stage_budget_seconds
            if xray_stage_budget_seconds > 0
            else None
        )
        list_stats["xray_stage_budget_minutes"] = (
            xray_stage_budget_seconds / 60.0 if xray_stage_budget_seconds > 0 else 0
        )
        # Hard ceiling per config (0 = off): bounds the semaphore-slot time
        # one slow URL chain can consume, see xray_probe_check.
        xray_per_config_timeout_raw = self._as_float(
            vcfg.get("xray_per_config_timeout_seconds"),
            0.0,
            minimum=0.0,
        )
        xray_per_config_timeout: float | None = xray_per_config_timeout_raw or None
        list_stats["xray_per_config_timeout_seconds"] = (
            xray_per_config_timeout if xray_per_config_timeout else 0
        )
        proxy_probe_count = self._as_int(
            vcfg.get("xray_proxy_probe_count"),
            0,
            minimum=0,
        )
        xray_proxy_urls = proxy_urls[:proxy_probe_count] if proxy_probe_count else []
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
        # Probing a "white list" config through a foreign SOCKS exit is a
        # false negative by construction. Those servers are published
        # precisely because they are reachable from the operator's own
        # country, and many refuse or misroute traffic arriving from abroad.
        # Measured on 2026-09-12: the whitelist probes through the pool only
        # (via-proxy mode makes no direct attempt at all, see the
        # ``not probe_via_proxies`` guard in xray_probe), and the live run
        # reported 685 whitelist configs checked with 0 alive — while the
        # same configs probed directly yield 9-21%. Allow a per-list
        # opt-out, mirroring xray_max_alive_by_list /
        # xray_candidate_limit_by_list.
        xray_probe_via_proxies_by_list = _by_list_setting(
            vcfg.get("xray_probe_via_proxies_by_list"),
        )
        if xray_probe_via_proxies_by_list:
            specific_probe_via_proxies = xray_probe_via_proxies_by_list.get(list_key)
            if specific_probe_via_proxies is not None:
                xray_probe_via_proxies = self._as_bool(
                    specific_probe_via_proxies,
                    xray_probe_via_proxies,
                )
        # Mid-run proxy recheck: the pool self-checked possibly an hour ago
        # (at fill time) and free SOCKS proxies die constantly. The
        # 2026-08-30 run rode on 3 proxies whose death poisoned a third of
        # every config's attempts (9/6252 TLS-alive survived). Re-dialing
        # the known probe target through each candidate now (a) drops the
        # proxies that died since the fill and (b) records their failure
        # into proxy health, so bans accumulate across runs. Unambiguous
        # signal by design: no VPN config involved, only the proxy.
        if xray_probe_via_proxies and xray_proxy_urls:
            try:
                from src.validators.proxy_pool import validate_proxy_candidates

                pool_cfg_recheck = self._proxy_pool_config()
                recheck_targets: list[tuple[str, int]] = []
                raw_extra = pool_cfg_recheck.get("probe_extra_targets") or []
                if isinstance(raw_extra, list):
                    recheck_targets = [
                        (str(item[0]), int(item[1]))
                        for item in raw_extra
                        if isinstance(item, (list, tuple)) and len(item) == 2
                    ]
                # Recheck the WHOLE pool, not just the probe slice: the
                # survival rate of the full pool is what decides a refill
                # (a slice capped at proxy_probe_count would always look
                # "full" while the pool around it bleeds out).
                rechecked = await validate_proxy_candidates(
                    list(proxy_urls),
                    max_proxies=len(proxy_urls),
                    timeout=self._as_float(
                        pool_cfg_recheck.get("validation_timeout_seconds"),
                        5.0,
                        minimum=0.5,
                    ),
                    concurrency=self._as_int(
                        pool_cfg_recheck.get("validation_concurrency"),
                        50,
                        minimum=1,
                    ),
                    probe_host=str(
                        pool_cfg_recheck.get("probe_host") or "api.github.com",
                    ),
                    probe_port=self._as_int(
                        pool_cfg_recheck.get("probe_port"),
                        443,
                        minimum=1,
                    ),
                    history=self._proxy_health_history,
                    extra_probe_targets=recheck_targets,
                )
                dropped = len(xray_proxy_urls) - len(
                    [u for u in xray_proxy_urls if u in rechecked],
                )
                if rechecked != list(xray_proxy_urls):
                    logger.info(
                        "%s Xray probe recheck: %d/%d pool proxies alive%s.",
                        label,
                        len(rechecked),
                        len(proxy_urls),
                        f" ({dropped} of the pre-selected died since fill)"
                        if dropped
                        else "",
                    )
                # Proactive refill: free SOCKS lists burn out within
                # minutes (2026-08-31 runs measured 7-8 of the whole
                # 40-proxy pool dead ~70s after the fill). When fewer
                # than half the pool survived, rebuilding it (up to
                # _POOL_REFETCH_LIMIT times per run, shared with the
                # empty-list recovery) from fresh sources beats probing
                # through corpses — a dead proxy marks living configs dead,
                # and that skew outlives the run through the health history.
                # The recheck itself already recorded the failures, so the
                # rebuilt pool prefers proxies that just proved themselves.
                refill_needed = (
                    len(proxy_urls) > 0
                    and len(rechecked) < len(proxy_urls) // 2
                    and self._pool_refetch_count
                    < int(getattr(self, "_POOL_REFETCH_LIMIT", 3) or 3)
                )
                refill_applied = False
                if refill_needed and self._proxy_url_getter is not None:
                    logger.warning(
                        "%s only %d/%d pool proxies alive — rebuilding "
                        "the pool from fresh sources before the Xray "
                        "stage.",
                        label,
                        len(rechecked),
                        len(proxy_urls),
                    )
                    # The getter serves the cached pool, so the cache must
                    # be invalidated first — otherwise the "refill"
                    # returned the very corpses this branch exists to
                    # replace, reported a refill that never happened, and
                    # burned the once-per-run refetch flag. The stale list
                    # is snapshotted so a failed rebuild can restore it:
                    # leaving the cache empty would make the next list
                    # re-run the full pool search for nothing.
                    stale_pool = list(self._validator_proxy_urls_cache or [])
                    self.reset_proxy_cache()
                    try:
                        fresh_urls = await self._proxy_url_getter()
                        if fresh_urls:
                            self._validator_proxy_urls_cache = list(fresh_urls)
                            self.context.liveness_stats["proxy_count"] = len(
                                fresh_urls,
                            )
                            self._pool_refetch_count += 1
                            list_stats["xray_pool_refill_count"] = (
                                self._pool_refetch_count
                            )
                            xray_proxy_urls = fresh_urls[:proxy_probe_count]
                            list_stats["xray_pool_refilled"] = len(fresh_urls)
                            refill_applied = True
                        else:
                            self._validator_proxy_urls_cache = stale_pool
                    except Exception as exc:
                        self._validator_proxy_urls_cache = stale_pool
                        logger.warning(
                            "%s pool refill failed (%s); continuing with "
                            "the rechecked proxies.",
                            label,
                            exc,
                        )
                if not refill_applied:
                    # Without an applied refill the recheck result stands:
                    # probing through the pre-selected slice would dial the
                    # proxies that just failed the recheck, and a dead
                    # proxy marks living configs dead. Only the configured
                    # probe-count slice is used — the pre-selection was
                    # clamped against the same count, so handing the whole
                    # surviving pool (up to max_proxies) would probe more
                    # proxies than min_proxy_successes was computed for.
                    # An empty recheck means every pre-selected proxy just
                    # failed: falling back to them (`or xray_proxy_urls`)
                    # probed through known-dead proxies. An empty pool
                    # probes directly instead (validate_configs_xray logs
                    # it) — strictly better than guaranteed false deaths.
                    xray_proxy_urls = rechecked[:proxy_probe_count]
            except Exception as exc:
                logger.warning(
                    "%s Xray probe recheck failed (%s); using the "
                    "pre-selected proxies as-is.",
                    label,
                    exc,
                )
        list_stats["xray_proxy_checks"] = len(xray_proxy_urls)
        list_stats["xray_min_proxy_successes"] = xray_min_proxy_successes
        list_stats["xray_probe_via_proxies"] = xray_probe_via_proxies
        # Latency baselines of the probe proxies, so the recorded
        # config latency can shed the proxy's own dial hop (see
        # validate_configs_xray). Snapshotted HERE, after the recheck/refill
        # above: baselines taken before the refill would describe the dead
        # pool (or miss the fresh proxies entirely), skewing every latency
        # the Xray stage records.
        xray_proxy_latency_ms: dict[str, float] = {}
        if xray_probe_via_proxies and xray_proxy_urls:
            try:
                from src.validators.proxy_health import ProxyHealthHistory

                pool_health_cfg = self._proxy_pool_config().get("health", {})
                # The in-memory history is authoritative: it already
                # carries everything the on-disk file had at startup PLUS
                # the verdicts the recheck a few lines above just
                # recorded. Re-reading the file per list ignored those
                # fresh failures and re-parsed the JSON once per list.
                proxy_history = self._proxy_health_history
                if proxy_history is None:
                    from src.validators.proxy_health import ProxyHealthHistory

                    proxy_history = ProxyHealthHistory(
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
            "(concurrency %d, timeout %.0fs) — heartbeat every 60s.",
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
            # The fresh pass deliberately runs a reduced 1-attempt/1-success
            # probe (a cheap liveness re-check, not the full verdict). Record
            # it explicitly: the generic xray_attempts_per_config /
            # xray_min_attempt_successes stats above describe the STALE pass
            # only, and an operator comparing them to the summary read the
            # fresh core as probed with the full budget.
            list_stats["xray_fresh_attempts_per_config"] = 1
            list_stats["xray_fresh_min_attempt_successes"] = 1
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
            # Fresh re-probes run first, so a stable core of ~max_alive
            # passing configs would fill the whole budget every run and
            # the "budget_full" skip below would permanently starve
            # first-time candidates. Reserve at least half of the budget
            # for them; whatever fresh leaves unused flows to stale via
            # stale_budget.
            fresh_budget = xray_max_alive
            if stale and xray_max_alive > 0:
                fresh_budget = max(1, xray_max_alive // 2)
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
                max_alive=fresh_budget,
                deadline=xray_stage_deadline,
                per_config_timeout=xray_per_config_timeout,
                progress_label=f"{label} Xray",
            )
            # A single fast re-probe is cheap evidence, not proof: hand
            # TTL-fresh configs that just failed it to a capped second
            # chance before the verdict counts toward the multi-hour
            # health ban. Without this, two unlucky single-probe runs in
            # a row banned exactly the servers that recently passed.
            # Capped at 2 attempts instead of merging into the full-set
            # stale pass: fresh (1) + full (3) spent 4 Xray startups on
            # one config — the same evidence bar (2 successes) at a
            # bounded cost.
            # id()-set, not Config equality: Config is a plain dataclass,
            # so `cfg not in alive_xray` compared every field pair-wise
            # (O(n*m) over six-figure lists) and could even misjudge two
            # equal-by-field configs as the same object.
            alive_xray_ids = {id(cfg) for cfg in alive_xray}
            failed_fresh = [cfg for cfg in fresh if id(cfg) not in alive_xray_ids]
            if failed_fresh:
                if xray_max_alive > 0 and len(alive_xray) >= xray_max_alive:
                    # 0 would mean "unlimited" inside the validator — the
                    # budget is already full, so the retry pass must not
                    # run at all (the stale branch below does the same).
                    # A single fast-probe failure is weak evidence: without
                    # the retry it must not count toward the health ban.
                    for cfg in failed_fresh:
                        cfg.xray_was_checked = False
                        cfg.is_alive = None
                    list_stats["xray_fresh_retried"] = 0
                    list_stats["xray_fresh_retried_alive"] = 0
                    list_stats["xray_fresh_retry_skipped"] = "budget_full"
                else:
                    # Cap the retry at the fresh half, NOT at the whole
                    # remaining budget: a large fresh backlog whose fast
                    # probes flaked would otherwise refill the budget here,
                    # the stale branch below would skip with "budget_full"
                    # and first-time candidates would never be probed at
                    # all (subscription stagnation). The stale half stays
                    # reserved exactly like the fresh pass reserves it.
                    retry_cap = (
                        fresh_budget if stale and xray_max_alive > 0 else xray_max_alive
                    )
                    retry_budget = (
                        max(0, retry_cap - len(alive_xray)) if xray_max_alive > 0 else 0
                    )
                    if xray_max_alive > 0 and retry_budget == 0:
                        # The fresh half is already full: skip the retry
                        # instead of handing the validator max_alive=0
                        # (unlimited). Skipped configs keep no verdict (no
                        # health-ban input), same as the whole-budget skip.
                        for cfg in failed_fresh:
                            cfg.xray_was_checked = False
                            cfg.is_alive = None
                        list_stats["xray_fresh_retried"] = 0
                        list_stats["xray_fresh_retried_alive"] = 0
                        list_stats["xray_fresh_retry_skipped"] = "budget_full"
                    else:
                        retried_alive = await validate_configs_xray(
                            failed_fresh,
                            xray_path=xray_path,
                            probe_urls=xray_probe_urls,
                            min_probe_successes=xray_min_probe_successes,
                            attempts_per_config=min(xray_attempts_per_config, 2),
                            min_attempt_successes=min(xray_min_attempt_successes, 2),
                            probe_proxy_urls=xray_proxy_urls,
                            min_proxy_successes=xray_min_proxy_successes,
                            probe_via_proxies=xray_probe_via_proxies,
                            proxy_latency_ms=xray_proxy_latency_ms,
                            require_distinct_outbound_ip=(
                                xray_require_distinct_outbound_ip
                            ),
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
                            max_alive=retry_budget,
                            deadline=xray_stage_deadline,
                            per_config_timeout=xray_per_config_timeout,
                            progress_label=f"{label} Xray",
                        )
                        list_stats["xray_fresh_retried"] = len(failed_fresh)
                        list_stats["xray_fresh_retried_alive"] = len(retried_alive)
                        alive_xray = alive_xray + retried_alive
        if stale:
            if xray_max_alive > 0 and len(alive_xray) >= xray_max_alive:
                # 0 would mean "unlimited" — the budget is full.
                # Skipped stale keeps no TCP True as a false health pass.
                for cfg in stale:
                    cfg.xray_was_checked = False
                    cfg.is_alive = None
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
                    deadline=xray_stage_deadline,
                    per_config_timeout=xray_per_config_timeout,
                    progress_label=f"{label} Xray",
                )
        list_stats["checked"] = True
        list_stats["filtered"] = True
        list_stats["xray_alive"] = len(alive_xray)
        if singbox_path and singbox_configs:
            if xray_max_alive > 0 and len(alive_xray) >= xray_max_alive:
                # 0 would mean "unlimited" for the validator, not "stop"
                # — the budget is full, so the QUIC stage is skipped.
                # Skipped QUIC keeps no TCP True as a false health pass.
                for cfg in singbox_configs:
                    cfg.xray_was_checked = False
                    cfg.is_alive = None
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
                    deadline=xray_stage_deadline,
                    per_config_timeout=xray_per_config_timeout,
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
        ] + [cfg for cfg in singbox_configs if getattr(cfg, "xray_was_checked", False)]
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
        # The Xray health update registered every attempted config in
        # _health_update_seen, so the _record_probe_health that
        # validate_configs always runs afterwards skips exactly these
        # verdicts (no double `recent` entries per run).
        self._xray_stage_consumed_probe_log = True
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
