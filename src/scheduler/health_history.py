"""Persistent health history for configs and sources."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import time
from typing import Any

from src.parsers.base import Config
from src.scheduler.settings import Settings
from src.utils.paths import (
    history_file_lock,
    resolve_safe_output_path,
    write_text_atomic,
)

logger = logging.getLogger(__name__)

#: Record fields that readers below pass to ``int()``.
_INT_RECORD_FIELDS = frozenset(
    {
        "bad_runs",
        "banned_until",
        "consecutive_failures",
        "fails",
        "last_alive",
        "last_checked",
        "last_seen",
        "passes",
        "runs",
        # Cumulative source sample: update_sources() reads both through int()
        # (see the ``cum_checked``/``cum_alive`` block), so a hand-edited value
        # here raised *inside the liveness stage*, before save() could repair
        # the file — every subsequent run then died the same way.
        "sample_alive",
        "sample_checked",
        "updated_at",
    },
)
#: Record fields that readers below pass to ``float()``.
_FLOAT_RECORD_FIELDS = frozenset({"last_alive_rate"})


def _sanitize_numeric_fields(record: dict[str, Any]) -> int:
    """Coerce a record's numeric fields in place, zeroing unusable values.

    Every reader (``is_banned``, ``score``, ``update``, ``update_sources``)
    calls ``int()``/``float()`` on these fields without a guard, so a single
    hand-edited value such as ``"banned_until": "2026-01-01"`` would raise and
    abort the whole run on every subsequent pass.

    Args:
        record: One health-history record, mutated in place.

    Returns:
        Number of fields that had to be replaced by a zero.
    """
    replaced = 0
    for field in _INT_RECORD_FIELDS & record.keys():
        value = record[field]
        if value is None:
            continue
        try:
            record[field] = int(value)
        except (TypeError, ValueError):
            record[field] = 0
            replaced += 1
    for field in _FLOAT_RECORD_FIELDS & record.keys():
        value = record[field]
        if value is None:
            continue
        try:
            record[field] = float(value)
        except (TypeError, ValueError):
            record[field] = 0.0
            replaced += 1
    recent = record.get("recent")
    if isinstance(recent, list):
        # Only strict booleans are verdicts; a hand-edited "false" string is
        # truthy and would count as a pass in consecutive_successes()/score().
        kept = [item for item in recent if isinstance(item, bool)]
        if len(kept) != len(recent):
            replaced += 1
        record["recent"] = kept[-64:]
    elif recent is not None:
        record["recent"] = []
        replaced += 1
    return replaced


class HealthHistory:
    """Loads, updates, and persists config/source health records."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._cache: dict[str, Any] | None = None
        # When the cache last reflected the file: load() stamps it, and each
        # save() re-stamps it on adoption. Drives the merge tie-break: a disk
        # file written AFTER our snapshot was taken is the later observation
        # of any record, so it wins recency ties over our (older-view) copy.
        self._cache_loaded_at: int = 0
        # Keys dropped by prune()/cap eviction during the CURRENT save cycle:
        # the disk merge must not resurrect them from a concurrently written
        # (or previous) file.
        self._pruned_keys: set[str] = set()

    def _cfg(self) -> dict[str, Any]:
        raw = self.settings.section("quality")
        return raw if isinstance(raw, dict) else {}

    def _file(self) -> str | None:
        raw = self._cfg().get("health_history_file", "output/health-history.json")
        return str(raw) if raw else None

    def is_enabled(self) -> bool:
        return self.settings.as_bool(self._cfg().get("health_history_enabled"), True)

    def source_health_enabled(self) -> bool:
        return self.settings.as_bool(self._cfg().get("source_health_enabled"), True)

    def load(self) -> dict[str, Any]:
        if self._cache is not None:
            return self._cache
        path = self._file()
        if not path:
            self._cache = {"configs": {}, "sources": {}}
            return self._cache
        raw: Any = {}
        try:
            safe_path = resolve_safe_output_path(path)
        except ValueError as exc:
            logger.warning("Unsafe health history path %r: %s", path, exc)
        else:
            # A missing file is the normal first run; anything else means the
            # accumulated bans are about to be silently overwritten by save(),
            # so it must be reported instead of failing into an empty history.
            if safe_path.exists():
                try:
                    raw = json.loads(safe_path.read_text(encoding="utf-8"))
                except Exception as exc:
                    logger.warning(
                        "Failed to load health history from %s: %s — starting "
                        "empty, the recorded history is lost on the next save.",
                        safe_path,
                        exc,
                    )
        data: dict[str, Any] = {}
        if isinstance(raw, dict):
            data = raw
        else:
            logger.warning(
                "Health history %s is %s, expected an object — starting empty.",
                path,
                type(raw).__name__,
            )
        # A hand-edited or partially written file can hold anything; every
        # caller below assumes dict-of-dicts, so coerce here once.
        data["configs"] = self._sanitized_records(data.get("configs"), "configs")
        data["sources"] = self._sanitized_records(data.get("sources"), "sources")
        self._cache = data
        self._cache_loaded_at = int(time.time())
        return data

    @staticmethod
    def _sanitized_records(raw: Any, section: str) -> dict[str, dict[str, Any]]:
        """Return only the well-formed records of a health-history section.

        Args:
            raw: Raw section value loaded from JSON.
            section: Section name, used for warning messages.

        Returns:
            Mapping of record key to record dict; malformed entries are dropped
            and unusable numeric fields inside a kept record are zeroed.
        """
        if raw is None:
            return {}
        if not isinstance(raw, dict):
            logger.warning(
                "Health history section %r is %s, expected object — ignoring it.",
                section,
                type(raw).__name__,
            )
            return {}
        records: dict[str, dict[str, Any]] = {}
        dropped = 0
        replaced = 0
        for key, value in raw.items():
            if isinstance(value, dict):
                replaced += _sanitize_numeric_fields(value)
                records[str(key)] = value
            else:
                dropped += 1
        if dropped:
            logger.warning(
                "Dropped %d malformed record(s) from health history section %r.",
                dropped,
                section,
            )
        if replaced:
            logger.warning(
                "Zeroed %d non-numeric field(s) in health history section %r.",
                replaced,
                section,
            )
        return records

    def _retention_seconds(self) -> int:
        """Age past which an untouched config record is dropped on save."""
        days = self.settings.as_int(
            self._cfg().get("health_history_retention_days"),
            30,
            minimum=1,
        )
        return days * 86400

    def _max_records(self) -> int:
        """Hard cap on stored config records (0 = unlimited)."""
        return self.settings.as_int(
            self._cfg().get("health_history_max_records"),
            20000,
            minimum=0,
        )

    def _prune_over_cap(self, *, now: int) -> int:
        """Drop the oldest config records beyond the hard cap.

        Age-based pruning alone could not bound the file: a source that keeps
        rotating configs (short-lived TLS endpoints behind one IP) streams in
        new records faster than 30-day retention removes them — the shipped
        history passed 69k records / 25 MB this way. The cap evicts the
        least-recently-seen records; still-banned ones are exempt, mirroring
        the age rule (the ban is the reason the config is skipped).
        """
        max_records = self._max_records()
        if max_records <= 0:
            return 0
        configs = self._cache.get("configs") if self._cache else None
        if not isinstance(configs, dict) or len(configs) <= max_records:
            return 0
        evictable = [
            (int(record.get("last_seen") or 0), key)
            for key, record in configs.items()
            if isinstance(record, dict) and int(record.get("banned_until") or 0) <= now
        ]
        overflow = len(configs) - max_records
        if not evictable:
            return 0
        evictable.sort()
        # Evict what we can: if bans exempt more than the overflow, drop all
        # evictable instead of nothing (the old <= check kept the file over
        # cap forever while many bans were active).
        drop = min(overflow, len(evictable))
        for _last_seen, key in evictable[:drop]:
            del configs[key]
            self._pruned_keys.add(key)
        logger.info(
            "Health history: dropped %d oldest config record(s) over the "
            "%d-record cap.",
            drop,
            max_records,
        )
        return drop

    def prune(self, *, now: int | None = None) -> int:
        """Drop config records not seen within the retention window.

        Nothing ever removed a record, so the file grew with every config the
        sources ever served — and it is published to the repository on each
        run. A record is kept while it is still banned (the ban is the reason
        the config is skipped) or while it was seen recently. A hard record
        cap (``health_history_max_records``) additionally bounds the file
        against sources that rotate configs faster than age prunes them.

        Args:
            now: Unix timestamp to measure ages against; defaults to the
                current time.

        Returns:
            Number of records dropped.
        """
        if self._cache is None:
            return 0
        configs = self._cache.get("configs")
        if not isinstance(configs, dict) or not configs:
            return 0
        now = now if now is not None else int(time.time())
        cutoff = now - self._retention_seconds()
        stale = [
            key
            for key, record in configs.items()
            if isinstance(record, dict)
            and int(record.get("last_seen") or 0) < cutoff
            and int(record.get("banned_until") or 0) <= now
        ]
        for key in stale:
            del configs[key]
            self._pruned_keys.add(key)
        over_cap = self._prune_over_cap(now=now)
        if stale or over_cap:
            logger.info(
                "Health history: dropped %d stale + %d over-cap config "
                "record(s) (retention %d day(s)).",
                len(stale),
                over_cap,
                self._retention_seconds() // 86400,
            )
        # Source records age out exactly like config records; nothing ever used
        # to remove them, so the `sources` section kept growing even after the
        # config pruning was added (the file is committed on every run). A
        # still-banned source is always kept, mirroring the config rule.
        sources = self._cache.get("sources")
        stale_sources: list[str] = []
        if isinstance(sources, dict) and sources:
            stale_sources = [
                key
                for key, record in sources.items()
                if isinstance(record, dict)
                and int(record.get("updated_at") or 0) < cutoff
                and int(record.get("banned_until") or 0) <= now
            ]
            for key in stale_sources:
                del sources[key]
                self._pruned_keys.add(key)
        if stale_sources:
            logger.info(
                "Health history: dropped %d source record(s) unseen for %d day(s).",
                len(stale_sources),
                self._retention_seconds() // 86400,
            )
        # Return counts only age-based prunes (cap eviction is observable
        # through the cache); over_cap is already logged above.
        _ = over_cap
        return len(stale) + len(stale_sources)

    def save(self) -> str | None:
        """Persist the history (blocking file IO).

        Async callers must run this via ``await asyncio.to_thread(...)`` —
        it serializes tens of thousands of records and fsyncs the file.
        """
        path = self._file()
        if not path or self._cache is None:
            return None
        # Fresh per-save cycle: keys pruned in an EARLIER save of this process
        # may legitimately exist on disk again (a concurrent run refreshed
        # them); only THIS prune's removals must win over the disk merge.
        self._pruned_keys = set()
        self.prune()
        payload = dict(self._cache)
        payload["updated_at"] = int(time.time())
        try:
            target = resolve_safe_output_path(path)
            # A full run and an hourly fast-track overlap and both hold their
            # own cache: two plain writes made the last writer the winner and
            # silently discarded the other run's verdicts and bans. Under the
            # history lock the on-disk state is re-read and per-record winners
            # are merged in before the atomic write, so no run's evidence is
            # lost.
            with history_file_lock(target):
                merged = self._merged_with_disk(target, payload)
                # The file timestamp belongs to THIS write, not to the disk
                # state that was merged in — it drives the recency tie-break
                # of the next concurrent save.
                merged["updated_at"] = payload["updated_at"]
                # Atomic write - write to temp file then rename. An in-place
                # write can leave a truncated history on a crash mid-write,
                # wiping the whole accumulated state. Compact (no indent):
                # with tens of thousands of records indenting doubled the
                # file size on every save, and the file is parsed back on
                # every run.
                write_text_atomic(
                    target,
                    json.dumps(merged, ensure_ascii=False, sort_keys=True),
                )
            # The cache adopts the merged state so later in-run reads (and
            # the next save) see what the file actually holds.
            self._cache = merged
            self._cache_loaded_at = payload["updated_at"]
        except Exception as exc:
            logger.warning("Could not write health history %s: %s", path, exc)
            return None
        return path

    def _merged_with_disk(self, target: Any, payload: dict[str, Any]) -> dict[str, Any]:
        """Re-read the on-disk history and merge it with *payload*.

        Per-record winners are picked by the record's own recency field —
        ``last_seen`` for configs, ``updated_at`` for sources — so a stale
        cache never overwrites fresher records written by a concurrent run.
        A recency tie goes to whichever side observed the record LATER: a
        disk file written after this cache was loaded (or last adopted) was
        written by a later observer, so the disk copy wins the tie; a file
        our snapshot already reflects loses to the in-memory record, which
        is the only state newer than it. Keys this instance just pruned are
        not resurrected from disk — unless the disk copy is fresher than the
        retention cutoff, i.e. a concurrent run refreshed what our stale
        cache had judged stale.
        """
        try:
            disk = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return payload
        if not isinstance(disk, dict):
            return payload
        merged = dict(disk)
        # > (not >=): a file our snapshot already reflects must not outrank
        # our own in-memory records on ties.
        ties_go_to_disk = int(disk.get("updated_at") or 0) > self._cache_loaded_at
        for section, recency_field in (
            ("configs", "last_seen"),
            ("sources", "updated_at"),
        ):
            memory_section = payload.get(section)
            disk_section = merged.get(section)
            if not isinstance(memory_section, dict) or not isinstance(
                disk_section, dict
            ):
                merged[section] = (
                    memory_section if isinstance(memory_section, dict) else disk_section
                )
                continue
            combined = dict(disk_section)
            for key, memory_record in memory_section.items():
                if key in self._pruned_keys:
                    # This save cycle deliberately dropped the record; a disk
                    # copy must not resurrect it.
                    continue
                disk_record = combined.get(key)
                if not isinstance(disk_record, dict) or not isinstance(
                    memory_record, dict
                ):
                    combined[key] = memory_record
                    continue
                memory_recency = int(memory_record.get(recency_field) or 0)
                disk_recency = int(disk_record.get(recency_field) or 0)
                memory_wins = memory_recency > disk_recency or (
                    memory_recency == disk_recency and not ties_go_to_disk
                )
                if memory_wins:
                    combined[key] = memory_record
            # Pruned keys are dropped — unless the disk copy was concurrently
            # refreshed within the retention window (our prune judged a stale
            # snapshot; the concurrent writer saw a live record).
            retention_cutoff = int(time.time()) - self._retention_seconds()
            for key in self._pruned_keys:
                disk_record = combined.get(key)
                if isinstance(disk_record, dict):
                    recency_field = (
                        "last_seen" if section == "configs" else "updated_at"
                    )
                    if int(disk_record.get(recency_field) or 0) >= retention_cutoff:
                        continue
                combined.pop(key, None)
            merged[section] = combined
        return merged

    @staticmethod
    def config_key(cfg: Config) -> str:
        """Remark-independent identity of a config.

        The key used to be ``sha256(raw_link)`` — the full link *including*
        the remark.  Free-list sources rotate remarks every run ("US-01" one
        run, "5777" the next), which rotated the key with them: dead servers
        were never banned (each failure landed on a fresh record) and the
        stability streak could never build for exactly the sources this
        pipeline exists for.

        The structural identity below covers everything that changes how the
        server is reached — protocol, endpoint, credential, transport,
        security and the parameters that select among configs sharing one
        address:port (ws path/host, SNI, ALPN, REALITY keys, flow, cipher).
        vmess remarks ride inside the base64 JSON body, so stripping the URL
        fragment alone would not be enough; no link text is hashed at all.
        """
        address = str(cfg.address or "")
        try:
            address = str(ipaddress.ip_address(address.strip().strip("[]")))
        except ValueError:
            address = address.strip().lower()

        # Length-prefixed fields instead of a plain separator join: a "\x00"
        # cannot occur inside a field value, but a raw credential containing
        # "%7C" ("|") made "a|b"+"c" and "a"+"b|c" collide into one record.
        def _part(value: Any) -> str:
            part = str(value or "")
            return f"{len(part)}\x00{part}" if part else ""

        # Same granularity as Config.dedup_key: bare vs obfs / different aid
        # or TUIC cc/urm are different servers and must not share one ban
        # record. UUID hex is case-insensitive (passwords are not).
        # NOTE: adding fields resets existing bans once (old keys miss).
        protocol_lc = str(cfg.protocol or "").lower()
        uuid_part = str(cfg.uuid_or_password or "")
        if protocol_lc in ("vless", "vmess"):
            uuid_part = uuid_part.strip().lower()
        parts = [
            protocol_lc,
            address,
            str(cfg.port),
            _part(uuid_part),
            _part(str(cfg.network or "").strip().lower()),
            _part(str(cfg.security or "").strip().lower()),
            _part(cfg.path),
            _part(str(cfg.host or "").strip().lower()),
            _part(str(cfg.sni or "").strip().lower()),
            _part(cfg.alpn),
            _part(cfg.fp),
            _part(cfg.pbk),
            _part(str(cfg.sid or "").strip().lower()),
            _part(cfg.flow),
            _part(str(cfg.ss_method or "").strip().lower()),
            _part(cfg.alter_id),
            _part(cfg.obfs),
            _part(cfg.obfs_password),
            _part(str(cfg.congestion_control or "").strip().lower()),
            _part(str(cfg.udp_relay_mode or "").strip().lower()),
        ]
        return hashlib.sha256(
            "".join(parts).encode("utf-8", errors="ignore"),
        ).hexdigest()

    def is_config_banned(self, cfg: Config, *, now: int | None = None) -> bool:
        """Config-level health ban only — source bans are deliberately excluded.

        Used by the probe pre-filter: a time-boxed config ban means the config
        itself recently failed everything, so re-probing it is wasted budget.
        A source ban must NOT pre-filter, because a passing probe is fresh
        evidence that outranks the stale source-level verdict (mirrors the
        post-Xray filter, which keeps fresh-alive configs from banned sources).
        """
        if not self.is_enabled():
            return False
        now = now if now is not None else int(time.time())
        record = self.load().get("configs", {}).get(self.config_key(cfg), {})
        if int(record.get("banned_until") or 0) > now:
            cfg.quality_block_reason = "health_ban"
            return True
        return False

    def is_banned(self, cfg: Config, *, now: int | None = None) -> bool:
        if not self.is_enabled():
            return False
        now = now if now is not None else int(time.time())
        history = self.load()
        record = history.get("configs", {}).get(self.config_key(cfg), {})
        if int(record.get("banned_until") or 0) > now:
            cfg.quality_block_reason = "health_ban"
            return True
        source = str(getattr(cfg, "source_name", "?") or "?")
        source_record = history.get("sources", {}).get(source, {})
        if int(source_record.get("banned_until") or 0) > now:
            cfg.quality_block_reason = "source_ban"
            return True
        return False

    def _config_record(self, cfg: Config) -> dict[str, Any]:
        record = self.load().get("configs", {}).get(self.config_key(cfg), {})
        return record if isinstance(record, dict) else {}

    def consecutive_successes(self, cfg: Config) -> int:
        """Trailing run of passes in the recent-verdict window.

        ``update()`` has already recorded the current run by the time the
        quality stage asks, so this counts the passes ending with *this*
        run в?" 1 for a config that just passed for the first time.
        """
        recent = list(self._config_record(cfg).get("recent") or [])
        streak = 0
        for verdict in reversed(recent):
            if not verdict:
                break
            streak += 1
        return streak

    def is_first_pass(self, cfg: Config) -> bool:
        """True when the config carries at most one recorded verdict.

        After ``update()`` a first-ever pass has ``recent == [True]``; a
        config with two or more verdicts has run-to-run history the stability
        gate can meaningfully judge. A config with no record at all counts as
        a first pass too (defensive: callers update before asking).
        """
        recent = self._config_record(cfg).get("recent")
        if not isinstance(recent, list):
            return True
        return len(recent) <= 1

    def last_pass_ts(self, cfg: Config) -> int:
        """Unix time of the config's last success (0 when it never passed)."""
        return int(self._config_record(cfg).get("last_alive") or 0)

    def update(self, checked_configs: list[Config]) -> None:
        if not self.is_enabled():
            return
        history = self.load()
        records = history.setdefault("configs", {})
        now = int(time.time())
        max_recent = self.settings.as_int(
            self._cfg().get("health_recent_window"),
            5,
            minimum=1,
        )
        fail_threshold = self.settings.as_int(
            self._cfg().get("ban_after_consecutive_failures"),
            2,
            minimum=1,
        )
        cooldown_seconds = int(
            self.settings.as_float(
                self._cfg().get("ban_cooldown_hours"),
                12.0,
                minimum=0.1,
            )
            * 3600,
        )
        for cfg in checked_configs:
            # No-verdict configs (budget skip, guard drop, infra failure) are
            # not a verdict: bool(None) is False, so feeding one here used to
            # record a failure and, after two such runs, a 12-hour ban — a
            # healthy config punished for never being probed. Callers already
            # filter these out; the guard keeps the invariant local. Nothing
            # is recorded at all: the record ages out via retention and the
            # config is re-probed from scratch, rather than a stale streak
            # being frozen forever.
            if getattr(cfg, "is_alive", False) is None:
                continue
            key = self.config_key(cfg)
            record = records.setdefault(
                key,
                {
                    "passes": 0,
                    "fails": 0,
                    "consecutive_failures": 0,
                    "recent": [],
                    "banned_until": 0,
                },
            )
            alive = bool(getattr(cfg, "is_alive", False))
            recent = list(record.get("recent") or [])
            recent.append(alive)
            record["recent"] = recent[-max_recent:]
            record["last_seen"] = now
            record["last_alive"] = now if alive else int(record.get("last_alive") or 0)
            source_name = str(getattr(cfg, "source_name", "") or "")
            # The fast-track revalidation rides under the synthetic names
            # "published-blacklist"/"published-whitelist" (not real sources):
            # overwriting the record would detach the config from the healthy
            # source that found it and forfeit the source-health bonus.
            # Empty names keep the previous source for the same reason.
            if source_name and not source_name.startswith("published-"):
                record["source"] = source_name
            record["country"] = getattr(cfg, "country", "")
            if alive:
                record["passes"] = int(record.get("passes") or 0) + 1
                record["consecutive_failures"] = 0
                record["banned_until"] = 0
            else:
                failures = int(record.get("consecutive_failures") or 0) + 1
                record["fails"] = int(record.get("fails") or 0) + 1
                record["consecutive_failures"] = failures
                if failures >= fail_threshold:
                    record["banned_until"] = now + cooldown_seconds
            cfg.health_record = record

    def source_run_stats(
        self,
        checked_configs: list[Config],
    ) -> dict[str, dict[str, int]]:
        stats: dict[str, dict[str, int]] = {}
        for cfg in checked_configs:
            source = str(getattr(cfg, "source_name", "?") or "?")
            # The fast-track revalidation rides under the synthetic names
            # "published-blacklist"/"published-whitelist" (runner's
            # _published_source_results). They are not real sources, so they
            # must not register stats: accumulated bad runs source-banned
            # them, and every fast-track run then wiped the whole list.
            if source.startswith("published-"):
                continue
            item = stats.setdefault(source, {"checked": 0, "alive": 0})
            item["checked"] += 1
            if getattr(cfg, "is_alive", False):
                item["alive"] += 1
        return stats

    def update_sources(
        self,
        checked_configs: list[Config],
        list_stats: dict[str, Any],
    ) -> None:
        qcfg = self._cfg()
        source_stats = self.source_run_stats(checked_configs)
        list_stats["sources"] = source_stats
        if not self.source_health_enabled():
            return
        min_checked = self.settings.as_int(
            qcfg.get("source_min_checked"),
            50,
            minimum=1,
        )
        bad_rate = self.settings.as_float(
            qcfg.get("source_bad_alive_rate"),
            0.02,
            minimum=0.0,
        )
        bad_runs = self.settings.as_int(
            qcfg.get("source_bad_runs_to_ban"),
            2,
            minimum=1,
        )
        disable_runs = self.settings.as_int(
            qcfg.get("source_bad_runs_to_disable"),
            0,
            minimum=0,
        )
        cooldown_seconds = int(
            self.settings.as_float(
                qcfg.get("source_ban_cooldown_hours"),
                12.0,
                minimum=0.1,
            )
            * 3600,
        )
        now = int(time.time())
        history = self.load().setdefault("sources", {})
        for source, stats in source_stats.items():
            checked = int(stats["checked"])
            alive = int(stats["alive"])
            rate = alive / checked if checked else 0.0
            record = history.setdefault(
                source,
                {"runs": 0, "bad_runs": 0, "banned_until": 0},
            )
            record["runs"] = int(record.get("runs") or 0) + 1
            record["last_checked"] = checked
            record["last_alive"] = alive
            record["last_alive_rate"] = rate
            record["updated_at"] = now
            # ``source_min_checked`` is judged over a *cumulative* sample,
            # not a single run: a source publishing 48 configs never reached
            # the floor within one run and was therefore never judged — nor
            # re-banned after its old ban expired, so it lived forever.
            # Accumulate until the floor is met, judge once, start fresh.
            cum_checked = int(record.get("sample_checked") or 0) + checked
            cum_alive = int(record.get("sample_alive") or 0) + alive
            if cum_checked < min_checked:
                record["sample_checked"] = cum_checked
                record["sample_alive"] = cum_alive
                continue
            record["sample_checked"] = 0
            record["sample_alive"] = 0
            if cum_alive / cum_checked <= bad_rate:
                record["bad_runs"] = int(record.get("bad_runs") or 0) + 1
                # Permanent disable: a source that keeps failing long after
                # repeated 12h bans (bad_runs keeps accumulating across
                # banned periods) is archived with a far-future banned_until
                # instead of re-entering the pool every cooldown. Only a
                # genuinely good cumulative sample clears bad_runs below.
                if disable_runs > 0 and int(record["bad_runs"]) >= disable_runs:
                    # ~10 years out: effectively permanent, but still a plain
                    # integer so the file format stays unchanged.
                    record["banned_until"] = now + 10 * 365 * 24 * 3600
                    logger.warning(
                        "Source %s disabled permanently after %d bad runs "
                        "(alive %d/%d). Re-enable it manually in "
                        "config/sources.json if this is wrong.",
                        source,
                        record["bad_runs"],
                        cum_alive,
                        cum_checked,
                    )
                elif int(record["bad_runs"]) >= bad_runs:
                    record["banned_until"] = now + cooldown_seconds
            else:
                # A genuinely good cumulative sample forgives the source: the
                # ban ladder (bad_runs -> cooldown -> permanent disable) must
                # reflect consecutive bad judgement windows, not a lifetime
                # failure count — otherwise one recovered source stays banned
                # forever on stale history.
                record["bad_runs"] = 0
                record["banned_until"] = 0

    def score(self, cfg: Config) -> float:
        qcfg = self._cfg()
        score = 60.0 if getattr(cfg, "is_alive", False) else 0.0
        record = self.load().get("configs", {}).get(self.config_key(cfg), {})
        recent = list(record.get("recent") or [])
        if sum(1 for item in recent[-3:] if item) >= 2:
            score += 20.0
        if cfg.latency_ms is not None:
            max_latency = self.settings.as_float(
                qcfg.get("max_latency_ms"),
                10000.0,
                minimum=1.0,
            )
            if cfg.latency_ms <= max_latency:
                score += max(0.0, 10.0 * (1.0 - (float(cfg.latency_ms) / max_latency)))
        if getattr(cfg, "country", None):
            score += 5.0
        source = str(getattr(cfg, "source_name", "?") or "?")
        source_record = self.load().get("sources", {}).get(source, {})
        source_rate = float(source_record.get("last_alive_rate") or 0.0)
        if source_rate >= self.settings.as_float(
            qcfg.get("source_good_alive_rate"),
            0.2,
            minimum=0.0,
        ):
            score += 5.0
        proxy_checks = int(getattr(cfg, "xray_proxy_checks", 0) or 0)
        proxy_successes = int(getattr(cfg, "xray_proxy_successes", 0) or 0)
        if proxy_checks:
            score += min(5.0, 5.0 * (proxy_successes / proxy_checks))
        return score
