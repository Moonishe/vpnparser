"""Render pipeline state into Telegram report text.

Pure formatting: every function here takes its data in and returns text.
The collaborators that tests patch (fact history, file readers, repo
identity) stay in telegram.py, which calls into this module — that keeps a
single patching surface and avoids a circular import.
"""

from __future__ import annotations

import contextlib
import html
import json
import logging
import time
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import quote

logger = logging.getLogger(__name__)


def _h(value: Any) -> str:
    """Escape dynamic values for Telegram HTML parse mode."""
    return html.escape(str(value), quote=True)


def _b(value: Any) -> str:
    """Bold-wrap an escaped value."""
    return f"<b>{_h(value)}</b>"


def _link(label: Any, url: Any) -> str:
    return f'<a href="{_h(url)}">{_h(label)}</a>'


def _safe_int(value: Any, default: int = 0) -> int:
    """Best-effort int for untrusted summary JSON (never raises)."""
    try:
        if value is None or value == "":
            return default
        if isinstance(value, bool):
            return int(value)
        return int(value)
    except (TypeError, ValueError, OverflowError):
        try:
            return int(float(value))
        except (TypeError, ValueError, OverflowError):
            return default


# Country flag emojis + Russian names for output.
COUNTRY_INFO = {
    "DE": ("🇩🇪", "Германия"),
    "FI": ("🇫🇮", "Финляндия"),
    "NL": ("🇳🇱", "Нидерланды"),
    "US": ("🇺🇸", "США"),
    "GB": ("🇬🇧", "Великобритания"),
    "FR": ("🇫🇷", "Франция"),
    "JP": ("🇯🇵", "Япония"),
    "SG": ("🇸🇬", "Сингапур"),
    "CA": ("🇨🇦", "Канада"),
    "AE": ("🇦🇪", "ОАЭ"),
    "TR": ("🇹🇷", "Турция"),
    "ID": ("🇮🇩", "Индонезия"),
    "RU": ("🇷🇺", "Россия"),
    "PL": ("🇵🇱", "Польша"),
    "SE": ("🇸🇪", "Швеция"),
    "CH": ("🇨🇭", "Швейцария"),
    "AT": ("🇦🇹", "Австрия"),
    "ES": ("🇪🇸", "Испания"),
    "IT": ("🇮🇹", "Италия"),
    "AU": ("🇦🇺", "Австралия"),
    "KR": ("🇰🇷", "Корея"),
    "HK": ("🇭🇰", "Гонконг"),
    "TW": ("🇹🇼", "Тайвань"),
    "IN": ("🇮🇳", "Индия"),
    "TH": ("🇹🇭", "Таиланд"),
    "VN": ("🇻🇳", "Вьетнам"),
    "BR": ("🇧🇷", "Бразилия"),
    "MX": ("🇲🇽", "Мексика"),
    "IR": ("🇮🇷", "Иран"),
    "BE": ("🇧🇪", "Бельгия"),
    "CZ": ("🇨🇿", "Чехия"),
    "UA": ("🇺🇦", "Украина"),
    "PH": ("🇵🇭", "Филиппины"),
    "MY": ("🇲🇾", "Малайзия"),
    "ZA": ("🇿🇦", "ЮАР"),
    "AR": ("🇦🇷", "Аргентина"),
}

#: Repo-relative paths used when the run summary does not name the outputs.
DEFAULT_OUTPUT_PATHS = {
    "combined": "output/subscription.txt",
    "blacklist": "output/subscription-blacklist.txt",
    "whitelist": "output/subscription-whitelist.txt",
    "mix": "output/subscription-mix.txt",
}

SUBSCRIPTION_LABELS = {
    "combined": "Общая",
    "blacklist": "Blacklist",
    "whitelist": "Whitelist",
    # Fallback when the run summary carries no per-list counts; the dynamic
    # variant comes from _mix_label().
    "mix": "Mix",
}


def _repo_relative_output(summary: dict[str, Any], key: str) -> str | None:
    """Return the repo path of output *key*, as recorded by the pipeline.

    The publisher commits every output file under the same (relative) path it
    was written to, so ``run-summary.json`` already knows where the links must
    point — including after ``publisher.output_file`` or ``split_output_files``
    were repointed in settings.yaml.

    Args:
        summary: Parsed run-summary.json (may be empty).
        key: Output name (``combined``, ``blacklist``, ...).

    Returns:
        The forward-slash repo path, or ``None`` when the summary does not
        carry a usable one. Absolute paths and ``..`` segments yield ``None``:
        they exist outside the repository, so no raw URL can address them.
    """
    outputs = summary.get("outputs")
    item = outputs.get(key) if isinstance(outputs, dict) else None
    raw = item.get("file") if isinstance(item, dict) else None
    if not raw or not isinstance(raw, str):
        return None
    native = Path(raw)
    if (
        native.is_absolute()
        or native.drive
        # On Linux, PurePosixPath does not recognise drive letters, so
        # C:/secrets/out.txt is neither absolute nor has .drive set.
        or (len(raw) > 1 and raw[1:2] == ":")
    ):
        return None
    path = PurePosixPath(raw.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts:
        return None
    return str(path)


def _subscription_urls(
    summary: dict[str, Any] | None = None,
    *,
    repo_slug: str = "",
    repo_branch: str = "main",
) -> dict[str, str]:
    """Return raw GitHub URLs for all published subscription outputs.

    Args:
        summary: Parsed run-summary.json. When it names the files this run
            wrote, the links follow them; otherwise the default layout is used.
        repo_slug: "owner/repo" of the published repository (injected by
            telegram.py, which owns the repo-identity helpers and is what the
            tests patch).
        repo_branch: Published branch name.

    The percent-encoding of each path segment keeps a run-summary path
    containing a space, "#", "?" or non-ASCII clickable instead of silently
    truncating at the fragment/query; the separator stays literal
    (safe="/") because slugs carry "owner/repo" and paths carry "/".
    """
    summary = summary if isinstance(summary, dict) else {}
    slug = quote(repo_slug, safe="/")
    branch = quote(repo_branch, safe="/")
    return {
        key: (
            f"https://raw.githubusercontent.com/{slug}/{branch}/"
            f"{quote(_repo_relative_output(summary, key) or default, safe='/')}"
        )
        for key, default in DEFAULT_OUTPUT_PATHS.items()
    }


def _mix_label(summary: dict[str, Any]) -> str:
    """Build a dynamic "Mix <blacklist>/<whitelist>" label from real counts.

    The old static "Mix 100/100" kept advertising round numbers while both
    lists were capped by xray_max_alive (200 each) or filtered down to far
    less; the numbers next to the label must match the per-list lines above.
    """
    outputs = summary.get("outputs")
    if not isinstance(outputs, dict):
        return SUBSCRIPTION_LABELS["mix"]

    def _count(key: str) -> int | None:
        item = outputs.get(key)
        if not isinstance(item, dict):
            return None
        raw = item.get("count")
        # bool is an int subclass (True == 1): a boolean count is garbage,
        # not "Mix 1/80" — fall back to the static label like for "abc".
        if isinstance(raw, bool):
            return None
        try:
            # Plain int() here: a garbage count ("abc") must fall back to
            # the static label, not render as 0 (which _safe_int would do).
            return int(raw or 0)
        except (TypeError, ValueError, OverflowError):
            return None

    blacklist_count = _count("blacklist")
    whitelist_count = _count("whitelist")
    if blacklist_count is None or whitelist_count is None:
        return SUBSCRIPTION_LABELS["mix"]
    return f"Mix {blacklist_count}/{whitelist_count}"


def _country_name(code: str) -> str:
    flag, name = COUNTRY_INFO.get(code, ("🌍", code))
    return f"{flag} {_h(name)}"


def _format_country_counts(countries: dict[str, Any], *, max_items: int = 6) -> str:
    """Format country counts as a compact Telegram line."""
    parsed: list[tuple[str, int]] = []
    for code, count in countries.items():
        try:
            parsed.append((str(code).upper(), _safe_int(count, default=-1)))
            if parsed[-1][1] < 0:
                parsed.pop()
        except (TypeError, ValueError, OverflowError):
            continue
    if not parsed:
        return "страны не определены"

    parsed.sort(key=lambda item: item[1], reverse=True)
    shown = parsed[:max_items]
    parts = [f"{_country_name(code)} {count}" for code, count in shown]
    remaining = len(parsed) - len(shown)
    if remaining > 0:
        parts.append(f"+{remaining} стран")
    return ", ".join(parts)


def _format_country_codes(countries: str, *, max_items: int = 9) -> str:
    """Format a caller-supplied country-code list for Telegram.

    Args:
        countries: Whitespace- or comma-separated ISO codes ("DE FI NL").
        max_items: How many countries are rendered before "+N стран".

    Returns:
        A compact ``flag name, flag name`` line, or ``""`` when nothing parsed.
    """
    codes: list[str] = []
    for chunk in (countries or "").replace(",", " ").split():
        code = chunk.strip().upper()
        if code and code not in codes:
            codes.append(code)
    if not codes:
        return ""
    shown = codes[:max_items]
    text = ", ".join(_country_name(code) for code in shown)
    remaining = len(codes) - len(shown)
    if remaining > 0:
        text += f", +{remaining} стран"
    return text


def _sibling_path(status_file: str, name: str) -> Path:
    """Resolve a file living next to the run summary, like the runner writes it.

    The runner writes through ``resolve_safe_output_path`` (project root, not
    CWD), so a relative ``status_file`` must resolve the same way — otherwise
    a different CWD silently reads an unrelated history file (or none).
    Absolute paths are used as-is.
    """
    from src.utils.paths import resolve_safe_output_path

    if status_file:
        candidate = Path(status_file)
        if candidate.is_absolute():
            return candidate.parent / name
        try:
            return resolve_safe_output_path(status_file).parent / name
        except ValueError:
            return candidate.parent / name
    try:
        return resolve_safe_output_path("output/run-summary.json").parent / name
    except ValueError:
        return Path("output") / name


def _stats_history_path(status_file: str) -> Path:
    """The stats-history file lives next to the run summary it belongs to."""
    return _sibling_path(status_file, "stats-history.json")


def _format_trend_alert(status_file: str = "") -> str:
    """Warn when a run collapsed relative to the previous one.

    Reads the last two entries of the published stats history: a list (or the
    proxy pool) losing 40%+ of its alive count is the earliest visible signal
    of a dying source or a network event, well before the absolute floor
    fires.
    """
    try:
        path = _stats_history_path(status_file)
        if not path.exists():
            return ""
        entries = [
            item
            for item in json.loads(path.read_text(encoding="utf-8"))
            if isinstance(item, dict) and item.get("status") == "ok"
        ]
    except Exception:
        return ""
    if len(entries) < 2:
        return ""
    # Only "ok" runs carry complete liveness stats: diffing against a
    # partially-written entry (mid-run failure, publish failure) would
    # report a collapse that never happened.
    prev, current = entries[-2], entries[-1]
    lines: list[str] = []

    def _alive(entry: dict[str, Any], key: str) -> int:
        lists = entry.get("lists")
        if not isinstance(lists, dict):
            return 0
        item = lists.get(key)
        if not isinstance(item, dict):
            return 0
        # Prefer the canonical xray count, but TCP/TLS-only runs never set
        # it — fall back to the richest available stage so the alert does
        # not cry collapse on healthy non-Xray runs (see run_stats_entry).
        for field in ("alive", "tcp_alive", "tls_alive"):
            value = _safe_int(item.get(field))
            if value:
                return value
        return 0

    for key in ("blacklist", "whitelist"):
        prev_alive = _alive(prev, key)
        cur_alive = _alive(current, key)
        # Small numbers wobble run to run; only meaningful drops alert.
        if prev_alive >= 5 and cur_alive < prev_alive * 0.6:
            drop = round(100 * (1 - cur_alive / prev_alive))
            lines.append(
                f"📉 {_b(key)}: {_b(cur_alive)} против {_b(prev_alive)} "
                f"в прошлом прогоне (−{_b(drop)}%)"
            )
    prev_pool = _safe_int(prev.get("proxy_count"))
    cur_pool = _safe_int(current.get("proxy_count"))
    if prev_pool >= 6 and cur_pool * 2 < prev_pool:
        lines.append(f"🧦 Прокси-пул просел: {_b(cur_pool)} против {_b(prev_pool)}")
    return "\n".join(lines)


def _format_validation_section(summary: dict[str, Any]) -> str:
    validation = summary.get("validation")
    if not isinstance(validation, dict) or not validation:
        return f"{_b('🧪 Проверка')}: нет данных по этому прогону"

    tcp_enabled = bool(validation.get("tcp_enabled"))
    tls_enabled = bool(validation.get("tls_enabled"))
    xray_enabled = bool(validation.get("xray_enabled"))
    proxy_pool_enabled = bool(validation.get("proxy_pool_enabled"))
    proxy_pool_required = bool(validation.get("proxy_pool_required"))
    proxy_count = _safe_int(validation.get("proxy_count") or 0)
    proxy_min = _safe_int(validation.get("proxy_min_proxies") or 0)
    proxy_rounds = _safe_int(validation.get("proxy_search_rounds") or 0)
    proxy_round_limit = _safe_int(validation.get("proxy_search_round_limit") or 0)
    strict_liveness = not validation.get("fail_open_on_low_alive")
    drop_unchecked = validation.get("drop_unchecked_after_tls") is True
    proxy_search_text = ""
    if proxy_rounds > 0 and proxy_round_limit > 0:
        proxy_search_text = f", поиск {proxy_rounds}/{proxy_round_limit}"
    strict_text = ", strict" if strict_liveness else ""
    unchecked_text = ", без TCP-only" if drop_unchecked else ""
    lists = validation.get("lists")
    xray_ran_without_proxies = (
        xray_enabled
        and isinstance(lists, dict)
        and any(
            isinstance(item, dict) and _safe_int(item.get("xray_checked") or 0) > 0
            for item in lists.values()
        )
    )

    if not tcp_enabled and not tls_enabled and not xray_enabled:
        first = f"{_b('🧪 Проверка')}: выключена"
    elif (
        proxy_pool_enabled
        and proxy_pool_required
        and proxy_count <= 0
        and xray_ran_without_proxies
    ):
        first = (
            f"{_b('🧪 Проверка')}: включена, без рабочих SOCKS5 прокси, "
            f"Xray напрямую{strict_text}{unchecked_text}"
        )
        if proxy_round_limit > 0:
            first += f", поиск прокси {proxy_round_limit} раундов"
    elif proxy_pool_enabled and proxy_pool_required and proxy_count <= 0:
        first = f"{_b('🧪 Проверка')}: пропущена, рабочих SOCKS5 прокси не найдено"
        if proxy_round_limit > 0:
            first += f" после {proxy_round_limit} раундов поиска"
    elif proxy_count > 0:
        min_text = f", минимум {proxy_min}" if proxy_min > 0 else ""
        first = (
            f"{_b('🧪 Проверка')}: включена, через {proxy_count} SOCKS5 прокси"
            f"{min_text}{proxy_search_text}{strict_text}{unchecked_text}"
        )
    else:
        first = (
            f"{_b('🧪 Проверка')}: включена, без прокси{strict_text}{unchecked_text}"
        )

    lines = [first]
    if isinstance(lists, dict):
        for key in ("blacklist", "whitelist"):
            item = lists.get(key)
            if not isinstance(item, dict):
                continue
            label = SUBSCRIPTION_LABELS.get(key, key)

            tcp_checked = _safe_int(item.get("tcp_checked") or 0)
            tcp_alive = _safe_int(item.get("tcp_alive") or 0)
            tls_checked = _safe_int(item.get("tls_checked") or 0)
            tls_alive = _safe_int(item.get("tls_alive") or 0)
            tls_unchecked = _safe_int(item.get("tls_unchecked_passthrough") or 0)
            xray_checked = _safe_int(item.get("xray_checked") or 0)
            xray_alive = _safe_int(item.get("xray_alive") or 0)
            xray_unsupported = _safe_int(item.get("xray_unsupported") or 0)
            xray_probe_count = _safe_int(item.get("xray_probe_count") or 0)
            xray_min_probe_successes = _safe_int(
                item.get("xray_min_probe_successes") or 0
            )
            xray_attempts_per_config = _safe_int(
                item.get("xray_attempts_per_config") or 0
            )
            xray_min_attempt_successes = _safe_int(
                item.get("xray_min_attempt_successes") or 0
            )
            xray_proxy_checks = _safe_int(item.get("xray_proxy_checks") or 0)
            xray_min_proxy_successes = _safe_int(
                item.get("xray_min_proxy_successes") or 0
            )
            xray_ip_check = bool(item.get("xray_require_distinct_outbound_ip"))
            skipped = _safe_int(item.get("tcp_skipped_protocol") or 0)
            rounds = _safe_int(item.get("tcp_search_rounds") or 0)
            round_limit = _safe_int(item.get("tcp_search_round_limit") or 0)
            if (
                item.get("reason") == "no_proxies"
                and tcp_checked <= 0
                and tls_checked <= 0
                and xray_checked <= 0
            ):
                lines.append(f"  {_b(label)}: не проверялся, нет рабочих прокси")
                continue
            if (
                tcp_checked <= 0
                and tls_checked <= 0
                and xray_checked <= 0
                and not item.get("checked")
            ):
                lines.append(f"  {_b(label)}: нет кандидатов для TCP/TLS проверки")
                continue

            suffix = " fail-open" if item.get("fail_open") else ""
            round_text = (
                f", раунды {rounds}/{round_limit}"
                if rounds > 0 and round_limit > 1
                else ""
            )
            if tcp_checked > 0:
                tcp_label = "TCP" if tls_checked > 0 else ""
                tcp_label = f" {tcp_label}" if tcp_label else ""
                lines.append(
                    f"  {_b(f'{label}{tcp_label}')}: проверено {tcp_checked}, "
                    f"порт открыт {tcp_alive}, пропущено {skipped}"
                    f"{round_text}{suffix}",
                )
            if tls_checked > 0:
                dropped_text = (
                    f", TCP-only отброшено {tls_unchecked}"
                    if item.get("tls_drop_unchecked") and tls_unchecked > 0
                    else ""
                )
                lines.append(
                    f"  {_b(f'{label} TLS/REALITY')}: проверено {tls_checked}, "
                    f"живых {tls_alive}{dropped_text}{suffix}",
                )
            if item.get("reason") == "xray_unavailable":
                lines.append(f"  {_b(f'{label} Xray')}: пропущен, xray не установлен")
            elif xray_checked > 0:
                unsupported_text = (
                    f", неподдержано {xray_unsupported}" if xray_unsupported > 0 else ""
                )
                probe_text = (
                    f", HTTPS-пробы {xray_min_probe_successes}/{xray_probe_count}"
                    if xray_probe_count > 1 and xray_min_probe_successes > 0
                    else ""
                )
                attempt_text = (
                    f", повторы {xray_min_attempt_successes}/{xray_attempts_per_config}"
                    if xray_attempts_per_config > 1 and xray_min_attempt_successes > 0
                    else ""
                )
                proxy_text = (
                    f", proxy-сети {xray_min_proxy_successes}/{xray_proxy_checks}"
                    if xray_proxy_checks > 0 and xray_min_proxy_successes > 0
                    else ""
                )
                ip_text = ", IP-check" if xray_ip_check else ""
                lines.append(
                    f"  {_b(f'{label} Xray')}: проверено {xray_checked}, "
                    f"реально рабочих {xray_alive}{unsupported_text}{probe_text}"
                    f"{attempt_text}{proxy_text}{ip_text}",
                )
    quality = validation.get("quality")
    if isinstance(quality, dict):
        for key in ("blacklist", "whitelist"):
            item = quality.get(key)
            if not isinstance(item, dict):
                continue
            label = SUBSCRIPTION_LABELS.get(key, key)
            kept = _safe_int(item.get("kept") or 0)
            slow_dropped = _safe_int(item.get("slow_dropped") or 0)
            try:
                avg_score = float(item.get("avg_score") or 0)
            except (TypeError, ValueError):
                avg_score = 0.0
            lines.append(
                f"  {_b(f'{label} quality')}: прошло {kept}, "
                f"медленных удалено {slow_dropped}, score {avg_score:.1f}",
            )
    return "\n".join(lines)


def _format_source_alerts(summary: dict[str, Any]) -> str:
    """Render one line per source that returned nothing or failed to fetch.

    ``sources.errors`` in run-summary.json is the only place these failures
    live otherwise — an operator watching the chat never sees a quietly empty
    source until its configs vanish from the subscription entirely.
    """
    lines: list[str] = []
    permanently_disabled = _format_permanently_disabled_sources(summary)
    if permanently_disabled:
        lines.append(permanently_disabled)
    sources = summary.get("sources")
    if not isinstance(sources, dict):
        return "\n".join(lines)
    errors = sources.get("errors")
    if isinstance(errors, list) and errors:
        lines.append(f"⚠️ {_b('Проблемные источники')}:")
        for item in errors[:5]:
            if not isinstance(item, dict):
                continue
            name = _h(item.get("source") or "?")
            reason = str(item.get("error") or "нет данных")
            if len(reason) > 100:
                reason = reason[:97] + "…"
            lines.append(f"  ⚠️ {name} — {_h(reason)}")
        remaining = len(errors) - 5
        if remaining > 0:
            lines.append(f"  … и ещё {remaining}")
    return "\n".join(lines)


def _format_permanently_disabled_sources(summary: dict[str, Any]) -> str:
    """Name the sources the health gate archived permanently this run.

    Permanent disable means ``banned_until`` more than a year out (the code
    writes ``now + 10 years``) in health-history.json. Unlike the routine 12h
    bans this is a cull decision, so the operator must see it in the chat
    instead of discovering an empty subscription weeks later.
    """
    status_file = str(summary.get("_status_file") or "")
    health_file = _sibling_path(status_file, "health-history.json")
    try:
        data = json.loads(health_file.read_text(encoding="utf-8"))
    except Exception:
        return ""
    sources = data.get("sources")
    if not isinstance(sources, dict):
        return ""
    cutoff = time.time() + 365 * 24 * 3600
    disabled = sorted(
        name
        for name, record in sources.items()
        if isinstance(record, dict)
        and _safe_int(record.get("banned_until") or 0) > cutoff
    )
    if not disabled:
        return ""
    shown = disabled[:5]
    # Names arrive from health-history keys (i.e. sources.json) and go into a
    # parse_mode=HTML message: an unescaped "<" rejected the WHOLE run report
    # with 400 "can't parse entities", not just this line.
    lines = [
        f"🚫 {_b('Источники отключены навсегда')}: " + ", ".join(_h(n) for n in shown)
    ]
    remaining = len(disabled) - len(shown)
    if remaining > 0:
        lines.append(f"  … и ещё {remaining}")
    lines.append("  Верните вручную в config/sources.json, если это ошибка.")
    return "\n".join(lines)


def _is_watermark_line(line: str) -> bool:
    """Detect the display-only vmess watermark (``add`` is 0.0.0.0)."""
    from src.aggregator.output import is_watermark_vmess

    return is_watermark_vmess(line)


def _decode_subscription_lines(raw: str) -> set[str]:
    """Decode a base64 (or plain) subscription body into its config links."""
    import base64

    text = raw.strip()
    # Same contract as telegram's _count_countries_from_file: the default
    # decoder silently drops non-alphabet characters, so a plain-format body
    # that merely *resembled* base64 decoded into garbage and the new/removed
    # delta was lost. Link-bearing text skips the decode; a failed decode
    # falls back to the raw body.
    if "://" not in text:
        with contextlib.suppress(Exception):
            text = base64.b64decode(text, validate=True).decode("utf-8")
    # Skip the watermark vmess line: it is regenerated every run and would
    # otherwise show up as a fake "+1/-1" delta.
    return {
        line.strip()
        for line in text.splitlines()
        if "://" in line and not _is_watermark_line(line.strip())
    }


def _format_delta_section(current: set[str], previous: set[str]) -> str:
    """Render "new vs removed" counts against the previous publication.

    "Убрано" covers both dead configs and pool rotation past the cap — the
    wording stays neutral because the pipeline cannot always tell them apart.
    """
    if not previous:
        return ""
    added = len(current - previous)
    removed = len(previous - current)
    if not added and not removed:
        return ""
    parts = []
    if added:
        parts.append(f"➕ новых {_h(added)}")
    if removed:
        parts.append(f"⚰️ убрано {_h(removed)}")
    return f"🔄 {' · '.join(parts)}"
