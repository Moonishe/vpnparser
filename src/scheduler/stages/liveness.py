"""Liveness validation stage: TCP/TLS/Xray checks."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from src.parsers.base import Config
from src.scheduler.context import PipelineContext, PipelineState
from src.scheduler.health_history import HealthHistory
from src.scheduler.stages.base import PipelineStage
from src.sources.list_types import normalize_list_type

logger = logging.getLogger(__name__)

_TCP_SKIP_PROTOCOLS = {"tuic", "hysteria2"}


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
        self._validator_proxy_urls_cache: list[str] | None = None
        self._proxy_health_history: Any | None = None
        self._proxy_health_file: str | None = None
        self._init_proxy_health_history()

    async def run(
        self, state: PipelineState, context: PipelineContext | None = None
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
        self, value: Any, default: float, *, minimum: float | None = None
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
                hcfg.get("ban_after_consecutive_failures"), 3, minimum=1
            ),
            max_latency_ms=self._as_float(
                hcfg.get("max_latency_ms"), 8000.0, minimum=1.0
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
            pool_cfg.get("min_proxies"), min(10, max_proxies), minimum=1
        )
        max_proxies = max(max_proxies, min_proxies)

        search_rounds = self._as_int(pool_cfg.get("search_rounds"), 3, minimum=1)
        candidate_growth = self._as_float(
            pool_cfg.get("candidate_growth_factor"), 2.0, minimum=1.0
        )
        retry_delay = self._as_float(
            pool_cfg.get("retry_delay_seconds"), 0.0, minimum=0.0
        )
        base_max_candidates = self._as_int(
            pool_cfg.get("max_candidates"), 200, minimum=1
        )
        base_per_source = self._as_int(
            pool_cfg.get("max_candidates_per_source"), 80, minimum=1
        )

        self.context.liveness_stats.update(
            {
                "proxy_min_proxies": min_proxies,
                "proxy_search_round_limit": search_rounds,
                "proxy_search_rounds": 0,
                "proxy_search": [],
            }
        )

        pool_urls: list[str] = []
        for round_index in range(search_rounds):
            multiplier = candidate_growth**round_index
            max_candidates = max(
                base_max_candidates, int(base_max_candidates * multiplier)
            )
            max_candidates_per_source = max(
                base_per_source, int(base_per_source * multiplier)
            )
            pool_urls = await load_proxy_pool(
                sources,
                fetch_timeout=self._as_float(
                    pool_cfg.get("fetch_timeout_seconds"), 10.0, minimum=1.0
                ),
                max_candidates=max_candidates,
                max_candidates_per_source=max_candidates_per_source,
                max_proxies=max_proxies,
                validate=self._as_bool(pool_cfg.get("validate"), True),
                validation_timeout=self._as_float(
                    pool_cfg.get("validation_timeout_seconds"), 5.0, minimum=1.0
                ),
                validation_concurrency=self._as_int(
                    pool_cfg.get("validation_concurrency"), 50, minimum=1
                ),
                probe_host=str(pool_cfg.get("probe_host") or "api.github.com"),
                probe_port=self._as_int(pool_cfg.get("probe_port"), 443, minimum=1),
                history=self._proxy_health_history,
            )
            self.context.liveness_stats["proxy_search_rounds"] = round_index + 1
            self.context.liveness_stats["proxy_search"].append(
                {
                    "round": round_index + 1,
                    "max_candidates": max_candidates,
                    "max_candidates_per_source": max_candidates_per_source,
                    "working": len(pool_urls),
                }
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

    async def _validator_proxy_urls(self) -> list[str]:
        """Return configured validator proxies, including optional free pool."""
        if self._validator_proxy_urls_cache is not None:
            return list(self._validator_proxy_urls_cache)

        vcfg = self._section("validator")
        urls: list[str] = []
        explicit = str(
            vcfg.get("proxy_url")
            or __import__("os").environ.get("VALIDATOR_PROXY")
            or ""
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
            }
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
        self, configs_by_list: dict[str, list[Config]]
    ) -> dict[str, list[Config]]:
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
                vcfg.get("fail_open_on_low_alive"), False
            ),
            "drop_unchecked_after_tls": self._as_bool(
                vcfg.get("drop_unchecked_after_tls"), True
            ),
            "proxy_pool_enabled": self._as_bool(pool_cfg.get("enabled"), True),
            "proxy_pool_required": self._as_bool(pool_cfg.get("required"), True),
            "proxy_pool_validate": self._as_bool(pool_cfg.get("validate"), True),
            "proxy_attempts_per_config": self._as_int(
                vcfg.get("proxy_attempts_per_config"), 3, minimum=0
            ),
            "tls_proxy_attempts_per_config": self._as_int(
                vcfg.get("tls_proxy_attempts_per_config"),
                self._as_int(vcfg.get("proxy_attempts_per_config"), 3, minimum=0),
                minimum=0,
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
            vcfg.get("drop_unchecked_after_tls"), False
        )
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
        if pool_enabled and pool_required and not proxy_urls:
            list_stats["reason"] = "no_proxies"
            if not xray_enabled:
                logger.warning(
                    "Liveness validation for %s skipped: proxy_pool.required=true "
                    "but no proxies are available.",
                    label,
                )
                return configs
            logger.warning(
                "%s proxy pool is empty; continuing with required direct Xray "
                "validation and skipping proxy-network score.",
                label,
            )

        current = list(configs)

        if tcp_enabled:
            checkable = [c for c in current if c.protocol not in _TCP_SKIP_PROTOCOLS]
            passthrough = [c for c in current if c.protocol in _TCP_SKIP_PROTOCOLS]
            list_stats["tcp_candidates"] = len(checkable)
            list_stats["tcp_skipped_protocol"] = len(passthrough)
            if checkable:
                from src.validators.tcp_check import validate_configs_tcp

                candidate_limit = self._as_int(
                    vcfg.get("tcp_candidate_limit"), 1000, minimum=0
                )
                tcp_max_alive = self._as_int(vcfg.get("tcp_max_alive"), 0, minimum=0)
                tcp_max_alive_by_list = vcfg.get("tcp_max_alive_by_list", {})
                if isinstance(tcp_max_alive_by_list, dict):
                    specific_max_alive = tcp_max_alive_by_list.get(
                        normalize_list_type(label)
                    )
                    if specific_max_alive is not None:
                        tcp_max_alive = self._as_int(
                            specific_max_alive,
                            tcp_max_alive,
                            minimum=0,
                        )
                list_stats["tcp_max_alive"] = tcp_max_alive

                min_alive = self._liveness_min_alive(len(checkable))
                list_stats["min_alive_to_filter"] = min_alive
                tcp_search_rounds = self._as_int(
                    vcfg.get("tcp_search_rounds"), 3, minimum=1
                )
                if candidate_limit <= 0:
                    tcp_search_rounds = 1
                    candidate_limit = len(checkable)
                list_stats["tcp_search_round_limit"] = tcp_search_rounds

                alive_tcp: list[Config] = []
                alive_keys: set[Any] = set()
                checked_total = 0
                offset = 0
                round_count = 0
                while offset < len(checkable) and round_count < tcp_search_rounds:
                    batch = checkable[offset : offset + candidate_limit]
                    if not batch:
                        break
                    round_count += 1
                    offset += len(batch)
                    checked_total += len(batch)
                    remaining_alive = (
                        max(0, tcp_max_alive - len(alive_tcp))
                        if tcp_max_alive > 0
                        else 0
                    )
                    if tcp_max_alive > 0 and remaining_alive <= 0:
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
                            vcfg.get("tcp_timeout_seconds"), 5.0, minimum=0.1
                        ),
                        concurrency=self._as_int(
                            vcfg.get("tcp_concurrency"), 300, minimum=1
                        ),
                        max_alive=remaining_alive,
                        proxy_urls=proxy_urls,
                        proxy_attempts_per_config=self._as_int(
                            vcfg.get("proxy_attempts_per_config"), 5, minimum=0
                        ),
                    )
                    for cfg in batch_alive:
                        if cfg.dedup_key in alive_keys:
                            continue
                        alive_keys.add(cfg.dedup_key)
                        alive_tcp.append(cfg)
                    if tcp_max_alive > 0 and len(alive_tcp) >= tcp_max_alive:
                        break

                list_stats["tcp_checked"] = checked_total
                list_stats["tcp_search_rounds"] = round_count
                list_stats["checked"] = True
                list_stats["tcp_alive"] = len(alive_tcp)
                if len(alive_tcp) < min_alive:
                    list_stats["reason"] = "below_min_alive"
                    if fail_open_on_low_alive:
                        logger.warning(
                            "%s TCP validation found %d/%d alive (<%d). "
                            "Keeping unfiltered configs.",
                            label,
                            len(alive_tcp),
                            len(checkable),
                            min_alive,
                        )
                        list_stats["fail_open"] = True
                        return configs
                    logger.warning(
                        "%s TCP validation found %d/%d alive (<%d). "
                        "Strict mode keeps only alive configs.",
                        label,
                        len(alive_tcp),
                        len(checkable),
                        min_alive,
                    )
                current = alive_tcp + passthrough
                list_stats["filtered"] = True
                list_stats["output_after_tcp"] = len(current)
                logger.info(
                    "%s after TCP validation: %d alive, %d TCP-skipped.",
                    label,
                    len(alive_tcp),
                    len(passthrough),
                )

        if tls_enabled:
            tls_checkable = [
                c
                for c in current
                if str(c.security or "").lower() in ("tls", "reality")
            ]
            if tls_checkable:
                from src.validators.tls_check import validate_configs_tls

                before_tls = list(current)
                tls_passthrough = [
                    c
                    for c in current
                    if str(c.security or "").lower() not in ("tls", "reality")
                ]
                list_stats["tls_unchecked_passthrough"] = len(tls_passthrough)
                list_stats["tls_drop_unchecked"] = drop_unchecked_after_tls
                if drop_unchecked_after_tls:
                    tls_passthrough = []
                tls_min_alive = self._liveness_min_alive(len(tls_checkable))
                list_stats["tls_candidates"] = len(tls_checkable)
                candidate_limit = self._as_int(
                    vcfg.get("tls_candidate_limit"), 1000, minimum=0
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
                        vcfg.get("tls_timeout_seconds"), 5.0, minimum=0.1
                    ),
                    concurrency=self._as_int(
                        vcfg.get("tls_concurrency"), 120, minimum=1
                    ),
                    proxy_urls=proxy_urls,
                    proxy_attempts_per_config=self._as_int(
                        vcfg.get("tls_proxy_attempts_per_config"),
                        self._as_int(
                            vcfg.get("proxy_attempts_per_config"), 5, minimum=0
                        ),
                        minimum=0,
                    ),
                )
                list_stats["tls_checked"] = len(tls_checkable)
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
                        return before_tls
                    logger.warning(
                        "%s TLS validation left %d/%d configs (<%d). "
                        "Strict mode keeps only TLS-alive configs.",
                        label,
                        len(alive_tls),
                        len(tls_checkable),
                        tls_min_alive,
                    )
                current = alive_tls + tls_passthrough
                list_stats["filtered"] = True
                list_stats["output_after_tls"] = len(current)
                logger.info("%s after TLS validation: %d configs.", label, len(current))
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

            supported = [cfg for cfg in current if is_xray_supported(cfg)]
            unsupported = len(current) - len(supported)
            drop_unsupported = self._as_bool(vcfg.get("xray_drop_unsupported"), True)
            list_stats["xray_candidates"] = len(supported)
            list_stats["xray_unsupported"] = unsupported
            list_stats["xray_drop_unsupported"] = drop_unsupported
            if not supported:
                list_stats["xray_checked"] = 0
                list_stats["xray_alive"] = 0
                list_stats["reason"] = "xray_no_supported_candidates"
                return [] if drop_unsupported else current

            candidate_limit = self._as_int(
                vcfg.get("xray_candidate_limit"), 0, minimum=0
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
                    normalize_list_type(label)
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
                        or "https://www.gstatic.com/generate_204"
                    )
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
            list_stats["xray_proxy_checks"] = len(xray_proxy_urls)
            list_stats["xray_min_proxy_successes"] = xray_min_proxy_successes
            xray_require_distinct_outbound_ip = self._as_bool(
                vcfg.get("xray_require_distinct_outbound_ip"),
                False,
            )
            list_stats["xray_require_distinct_outbound_ip"] = (
                xray_require_distinct_outbound_ip
            )
            alive_xray = await validate_configs_xray(
                supported,
                xray_path=xray_path,
                probe_urls=xray_probe_urls,
                min_probe_successes=xray_min_probe_successes,
                attempts_per_config=xray_attempts_per_config,
                min_attempt_successes=xray_min_attempt_successes,
                probe_proxy_urls=xray_proxy_urls,
                min_proxy_successes=xray_min_proxy_successes,
                require_distinct_outbound_ip=xray_require_distinct_outbound_ip,
                timeout=self._as_float(
                    vcfg.get("xray_timeout_seconds"), 12.0, minimum=1.0
                ),
                startup_timeout=self._as_float(
                    vcfg.get("xray_startup_timeout_seconds"), 4.0, minimum=0.5
                ),
                concurrency=self._as_int(vcfg.get("xray_concurrency"), 6, minimum=1),
                max_alive=xray_max_alive,
            )
            list_stats["checked"] = True
            list_stats["filtered"] = True
            list_stats["xray_alive"] = len(alive_xray)
            xray_attempted = [
                cfg for cfg in supported if getattr(cfg, "xray_was_checked", False)
            ]
            list_stats["xray_checked"] = len(xray_attempted)
            if self._update_health_callback:
                self._update_health_callback(xray_attempted)
            else:
                self.health.update(xray_attempted)
            if self._update_source_health_callback:
                self._update_source_health_callback(xray_attempted, list_stats)
            else:
                self.health.update_sources(xray_attempted, list_stats)
            health_ban_min_alive = self._as_int(
                self.settings.section("quality").get("health_ban_min_alive"),
                3,
                minimum=0,
            )
            if len(alive_xray) > health_ban_min_alive:
                alive_xray = [
                    cfg for cfg in alive_xray if not self.health.is_banned(cfg)
                ]
            else:
                logger.info(
                    "%s Xray found %d alive configs (<= %d); "
                    "skipping health history bans.",
                    label,
                    len(alive_xray),
                    health_ban_min_alive,
                )
            list_stats["output_after_health"] = len(alive_xray)
            list_stats["output_after_xray"] = len(alive_xray)
            current = alive_xray
            logger.info("%s after Xray validation: %d configs.", label, len(current))

        return current

    def _xray_candidate_preselect(
        self, configs: list[Config], max_total: int, list_type: str
    ) -> list[Config]:
        from src.scheduler.stages.aggregate import Aggregator

        if normalize_list_type(list_type) == "whitelist":
            return Aggregator(self.context)._whitelist_balance(configs, max_total)
        return Aggregator(self.context)._country_balanced_limit(configs, max_total)
