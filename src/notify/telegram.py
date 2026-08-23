"""Telegram notifier with rotating fun VPN facts.

Sends a message to a Telegram chat after each pipeline run with:
- Config count and countries, freshness timestamp, publish delta
- Subscription URLs (combined, blacklist, whitelist, 100/100 mix)

Usage (standalone, from CLI):
    python -m src.notify.telegram --configs 50 --countries "DE FI NL US"

Usage (imported):
    from src.notify.telegram import send_notification
    send_notification(configs_count=50, countries="DE FI NL US")
"""

from __future__ import annotations

import argparse
import contextlib
import html
import json
import logging
import os
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import quote

from src.repo_info import github_branch, github_repo_slug
from src.utils.paths import resolve_safe_output_path

logger = logging.getLogger(__name__)

# Telegram bot tokens have format: <digits>:<alphanumeric_hash>
# e.g. "123456789:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"
_TOKEN_MIN_LEN = 20

# Characters http.client rejects inside a URL path (C0 controls, space, DEL).
# The token is interpolated into the sendMessage URL, and the rejection message
# quotes that whole path — so a token pasted into .env with an embedded newline
# would end up in the log verbatim.  Refuse it before it reaches urllib.
_URL_FORBIDDEN_CHARS = frozenset(chr(code) for code in (*range(0x21), 0x7F))

_REDACTED = "<redacted>"

# HTML tags used in the notification template that need closing when truncated.
_SELF_CLOSING_TAGS = {"br", "hr"}
_PAIRED_TAGS = ("b", "i", "u", "s", "a", "code", "pre", "blockquote")

# Telegram sendMessage rejects text longer than this with a 400.
_TELEGRAM_MAX_TEXT = 4096

# Longest entity html.escape() can emit ("&quot;" / "&#x27;") plus slack.
_MAX_ENTITY_LEN = 8

_ELLIPSIS = "..."

# One retry is enough for the flood limit: two runs colliding (a manual
# workflow_dispatch on top of the hourly schedule) is the realistic case, and
# without it the "subscription updated" message is simply lost.
_SEND_ATTEMPTS = 2

# Used when a 429 body carries no usable ``retry_after``.
_DEFAULT_FLOOD_WAIT = 3.0

# Upper bound on an honoured ``retry_after`` — a bogus value must not park the
# pipeline for hours.
_MAX_FLOOD_WAIT = 30.0


def _flood_wait_seconds(body: str) -> float:
    """Return the delay to honour before retrying a flood-limited send.

    Telegram answers a flood limit with HTTP 429 and
    ``{"parameters": {"retry_after": N}}``.

    Args:
        body: Decoded response body of the 429 answer.

    Returns:
        Seconds to wait, clamped to ``_MAX_FLOOD_WAIT``.
    """
    try:
        parameters = json.loads(body).get("parameters")
        raw = parameters.get("retry_after")
    except (AttributeError, TypeError, ValueError):
        return _DEFAULT_FLOOD_WAIT
    try:
        seconds = float(raw)
    except (TypeError, ValueError):
        return _DEFAULT_FLOOD_WAIT
    return min(max(seconds, 0.0), _MAX_FLOOD_WAIT)


def _safe_cut_offset(text: str, limit: int) -> int:
    """Return an offset ``<= limit`` at which ``text`` can be split safely.

    ``text[:offset]`` never ends inside an HTML tag or a half-written
    ``&entity;`` — both would make Telegram reject the message with
    "can't parse entities".
    """
    cut = min(limit, len(text))
    # Avoid cutting inside an HTML entity (&...;) — back up to '&'.  The ';'
    # must land *inside* text[:cut], so the search bound is exclusive: a ';'
    # at index cut is not part of the slice.
    last_amp = text.rfind("&", max(0, cut - _MAX_ENTITY_LEN), cut)
    if last_amp != -1 and text.find(";", last_amp, cut) == -1:
        cut = last_amp
    # Avoid cutting between '<' and '>' (inside a tag).  Backing up once is not
    # enough: with runs like "a<<b" the new boundary lands right after another
    # '<', so the prefix would again end on an unclosed tag opener.  ``cut``
    # strictly decreases every round, so the loop always terminates.
    while True:
        last_open = text.rfind("<", 0, cut)
        if last_open == -1 or text.find(">", last_open, cut) != -1:
            break
        cut = last_open
    return max(0, cut)


def _open_tags(text: str) -> list[str]:
    """Return the paired tags left open in ``text``, outermost first."""
    open_stack: list[str] = []
    pos = 0
    while pos < len(text):
        lt = text.find("<", pos)
        if lt == -1:
            break
        gt = text.find(">", lt)
        if gt == -1:
            break
        tag_text = text[lt + 1 : gt].strip()
        pos = gt + 1
        if not tag_text:
            continue
        if tag_text.startswith("/"):
            # A nameless closing tag ("</>", "</ >") has nothing to pop, and
            # split() on the empty remainder yields no element to index.
            closing = tag_text[1:].split()
            if not closing:
                continue
            name = closing[0].lower()
            for i in range(len(open_stack) - 1, -1, -1):
                if open_stack[i] == name:
                    open_stack.pop(i)
                    break
            continue
        name = tag_text.split()[0].lower()
        if name in _SELF_CLOSING_TAGS or name not in _PAIRED_TAGS:
            continue
        open_stack.append(name)
    return open_stack


def _truncate_html_safe(text: str, limit: int) -> str:
    """Truncate Telegram HTML text so the *result* is at most limit characters.

    Cuts at a safe offset (never inside a <tag> or an entity), appends an
    ellipsis, and closes any tags left open by the cut. The ellipsis and the
    closing tags count against ``limit`` — a "</blockquote>" tail adds 13
    characters, and without reserving room for it the message would come back
    from Telegram as 400 "message is too long".
    """
    if len(text) <= limit:
        return text
    cut = limit
    while cut > 0:
        prefix = text[: _safe_cut_offset(text, cut)].rstrip()
        closing = "".join(f"</{name}>" for name in reversed(_open_tags(prefix)))
        result = f"{prefix}{_ELLIPSIS}{closing}"
        if len(result) <= limit:
            return result
        # Shrink by exactly the overflow: the next attempt keeps as much text
        # as the reserved ellipsis/closing tags allow.
        cut -= max(1, len(result) - limit)
    return ""


def _repo_slug() -> str:
    """Return owner/repo for Telegram URLs."""
    return github_repo_slug()


def _repo_branch() -> str:
    """Return branch for raw GitHub subscription URLs."""
    return github_branch()


def _h(value: Any) -> str:
    """Escape dynamic values for Telegram HTML parse mode."""
    return html.escape(str(value), quote=True)


def _b(value: Any) -> str:
    return f"<b>{_h(value)}</b>"


def _link(label: Any, url: Any) -> str:
    return f'<a href="{_h(url)}">{_h(label)}</a>'


def _bot_intro() -> str:
    repo_slug = _repo_slug()
    repo_url = f"https://github.com/{repo_slug}"
    return (
        f"🤖 {_b('Я — vpnparser бот')} от @dutysissy\n"
        "📡 Парсю публичные VPN конфиги каждый час\n"
        f"🔗 {_link(repo_slug, repo_url)}"
    )


_FACT_HISTORY_FILE = "facts_history.json"
_FACT_HISTORY_MAX = 50  # keep last 50 facts

_FACT_FALLBACK_NO_KEY = (
    "VPN расшифровывается как Very Private Network "
    "(шутка, на самом деле Virtual Private Network)."
)

# Multiple fallback facts — rotate so consecutive messages don't repeat.
_FACT_FALLBACKS = [
    "Первый VPN был создан в 1996 году компанией Microsoft. С тех пор мы прячемся от провайдеров уже 30 лет.",  # noqa: E501
    "Слово VPN на латыни звучит бы как 'privatus iter', что примерно переводится как 'тайный путь'. Римляне бы оценили.",  # noqa: E501
    "Если бы VPN был человеком, он бы носил плащ, шляпу и говорил бы 'я не был здесь' каждому встречному.",  # noqa: E501
    "В некоторых странах за использование VPN можно получить штраф. В других — просто нормальный интернет.",  # noqa: E501
    "VPN не делает вас анонимным. Он делает вас 'труднодоступным'. Это как прятаться за ширмой — видно ноги, но не лицо.",  # noqa: E501
    "Самый популярный пароль для WiFi в 2024 году — '12345678'. VPN хотя бы пытается вас защитить.",  # noqa: E501
    "Без VPN ваш провайдер знает каждый сайт, который вы посещаете. С VPN — он знает только что вы зашли в туннель.",  # noqa: E501
    "VPN-протокол WireGuard состоит всего из 4000 строк кода. OpenVPN — из 70 000. Иногда меньше — значит лучше.",  # noqa: E501
    "Первый протокол VPN (PPTP) был создан Microsoft в 1996 году. Сейчас его не рекомендуют даже сами разработчики.",  # noqa: E501
    "Tor и VPN — это не одно и то же. Tor — это лук, VPN — это труба. Оба прячут, но по-разному.",  # noqa: E501
    "В Китае более 700 миллионов пользователей VPN. Это больше, чем население всей Европы.",  # noqa: E501
    "VPN-серверы в Швейцарии и Исландии популярны из-за строгих законов о приватности. Банки данных — не банки денег.",  # noqa: E501
    "Самый дорогой VPN стоит около $15 в месяц. Самый дешёвый — ваш сосед с OpenVPN на Raspberry Pi.",  # noqa: E501
    "Слово 'туннелирование' в VPN — это не метафора. Ваш трафик реально упаковывается в другой пакет, как матрёшка.",  # noqa: E501
    "Если вы используете бесплатный VPN, вы — товар. Ваш данные могут продаваться. К счастью, наш парсер находит бесплатные серверы, а не бесплатный VPN-сервис.",  # noqa: E501
]

# Country flag emojis + Russian names for output.
_COUNTRY_INFO = {
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
_DEFAULT_OUTPUT_PATHS = {
    "combined": "output/subscription.txt",
    "blacklist": "output/subscription-blacklist.txt",
    "whitelist": "output/subscription-whitelist.txt",
    "mix": "output/subscription-mix.txt",
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


def _subscription_urls(summary: dict[str, Any] | None = None) -> dict[str, str]:
    """Return raw GitHub URLs for all published subscription outputs.

    Args:
        summary: Parsed run-summary.json. When it names the files this run
            wrote, the links follow them; otherwise the default layout is used.
    """
    # Percent-encode each path segment so a run-summary path containing a
    # space, "#", "?" or non-ASCII still yields a clickable raw link instead of
    # silently truncating at the fragment/query or breaking the URL. Slugs carry
    # "owner/repo" and paths carry "/" separators, so keep the separator literal
    # (safe="/") while encoding the dangerous characters.
    summary = summary if isinstance(summary, dict) else {}
    slug = quote(_repo_slug(), safe="/")
    branch = quote(_repo_branch(), safe="/")
    return {
        key: (
            f"https://raw.githubusercontent.com/{slug}/{branch}/"
            f"{quote(_repo_relative_output(summary, key) or default, safe='/')}"
        )
        for key, default in _DEFAULT_OUTPUT_PATHS.items()
    }


_SUBSCRIPTION_LABELS = {
    "combined": "Общая",
    "blacklist": "Blacklist",
    "whitelist": "Whitelist",
    # Fallback when the run summary carries no per-list counts; the dynamic
    # variant comes from _mix_label().
    "mix": "Mix",
}


def _mix_label(summary: dict[str, Any]) -> str:
    """Build a dynamic "Mix <blacklist>/<whitelist>" label from real counts.

    The old static "Mix 100/100" kept advertising round numbers while both
    lists were capped by xray_max_alive (200 each) or filtered down to far
    less; the numbers next to the label must match the per-list lines above.
    """
    outputs = summary.get("outputs")
    if not isinstance(outputs, dict):
        return _SUBSCRIPTION_LABELS["mix"]

    def _count(key: str) -> int | None:
        item = outputs.get(key)
        if not isinstance(item, dict):
            return None
        try:
            return int(item.get("count") or 0)
        except (TypeError, ValueError):
            return None

    blacklist_count = _count("blacklist")
    whitelist_count = _count("whitelist")
    if blacklist_count is None or whitelist_count is None:
        return _SUBSCRIPTION_LABELS["mix"]
    return f"Mix {blacklist_count}/{whitelist_count}"


def _load_run_summary(filepath: str) -> dict[str, Any]:
    """Load output/run-summary.json written by the pipeline."""
    if not filepath:
        return {}
    try:
        with resolve_safe_output_path(filepath).open("r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _subscription_file_paths(subscription_file: str) -> dict[str, str]:
    """Return expected local output files using the combined path as anchor."""
    combined = Path(subscription_file or "output/subscription.txt")
    output_dir = combined.parent
    return {
        "combined": str(combined),
        "blacklist": str(output_dir / "subscription-blacklist.txt"),
        "whitelist": str(output_dir / "subscription-whitelist.txt"),
        "mix": str(output_dir / "subscription-mix.txt"),
    }


def _country_name(code: str) -> str:
    flag, name = _COUNTRY_INFO.get(code, ("🌍", code))
    return f"{flag} {_h(name)}"


def _format_country_counts(countries: dict[str, Any], *, max_items: int = 6) -> str:
    """Format country counts as a compact Telegram line."""
    parsed: list[tuple[str, int]] = []
    for code, count in countries.items():
        try:
            parsed.append((str(code).upper(), int(count)))
        except (TypeError, ValueError):
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


def _fallback_subscription_line(configs_count: int, countries: str) -> str:
    """Render the caller-supplied totals when no per-output data was found.

    ``send_notification`` receives the count the pipeline reported (the
    ``--configs`` CLI flag is required for exactly this case), so a missing
    run-summary.json plus unreadable output files must not leave the operator
    with a notification that contains no numbers at all.
    """
    if configs_count <= 0:
        return "  данных по файлам нет"
    country_text = _format_country_codes(countries)
    # The country list is the caller's allow-list, not a measurement — label it
    # so it never reads like the per-country counts of the lines above.
    suffix = f" — ожидались {country_text}" if country_text else ""
    return f"  {_b(_SUBSCRIPTION_LABELS['combined'])}: {configs_count}{suffix}"


def _alert_min_alive() -> int:
    """Per-list Xray-alive floor from settings; 10 when unreadable."""
    try:
        import yaml

        settings_path = (
            resolve_safe_output_path(".", strict=True) / "config" / "settings.yaml"
        )
        with settings_path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        section = data.get("telegram")
        if isinstance(section, dict):
            value = section.get("alert_min_alive")
            if value is not None:
                return max(0, int(value))
    except Exception:
        logger.debug("settings.yaml unreadable; using default alert floor")
    return 10


def _stats_history_path(status_file: str) -> Path:
    """The stats-history file lives next to the run summary it belongs to."""
    if status_file:
        return Path(status_file).parent / "stats-history.json"
    return Path("output") / "stats-history.json"


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
        return int(item.get("alive") or 0) if isinstance(item, dict) else 0

    for key in ("blacklist", "whitelist"):
        prev_alive = _alive(prev, key)
        cur_alive = _alive(current, key)
        # Small numbers wobble run to run; only meaningful drops alert.
        if prev_alive >= 5 and cur_alive < prev_alive * 0.6:
            drop = round(100 * (1 - cur_alive / prev_alive))
            lines.append(
                f"📉 {_b(_h(key))}: {_b(cur_alive)} против {_b(prev_alive)} "
                f"в прошлом прогоне (−{_b(drop)}%)"
            )
    prev_pool = int(prev.get("proxy_count") or 0)
    cur_pool = int(current.get("proxy_count") or 0)
    if prev_pool >= 6 and cur_pool * 2 < prev_pool:
        lines.append(f"🧦 Прокси-пул просел: {_b(cur_pool)} против {_b(prev_pool)}")
    return "\n".join(lines)


def _format_low_alive_alert(summary: dict[str, Any]) -> str:
    """One warning line per list whose verified-alive count collapsed."""
    lists = (summary.get("validation") or {}).get("lists")
    if not isinstance(lists, dict):
        return ""
    min_alive = _alert_min_alive()
    if min_alive <= 0:
        return ""
    alerts: list[str] = []
    for key in ("blacklist", "whitelist"):
        item = lists.get(key)
        if not isinstance(item, dict):
            continue
        checked = int(item.get("xray_checked") or 0)
        alive = int(item.get("xray_alive") or 0)
        if checked > 0 and alive < min_alive:
            alerts.append(
                f"⚠️ {_b(_h(key))}: живых {_b(alive)}/{_h(checked)} "
                f"(порог {_h(min_alive)}) — проверьте пул прокси и источники"
            )
    return "\n".join(alerts)


def _format_validation_section(summary: dict[str, Any]) -> str:
    validation = summary.get("validation")
    if not isinstance(validation, dict) or not validation:
        return f"{_b('🧪 Проверка')}: нет данных по этому прогону"

    tcp_enabled = bool(validation.get("tcp_enabled"))
    tls_enabled = bool(validation.get("tls_enabled"))
    xray_enabled = bool(validation.get("xray_enabled"))
    proxy_pool_enabled = bool(validation.get("proxy_pool_enabled"))
    proxy_pool_required = bool(validation.get("proxy_pool_required"))
    proxy_count = int(validation.get("proxy_count") or 0)
    proxy_min = int(validation.get("proxy_min_proxies") or 0)
    proxy_rounds = int(validation.get("proxy_search_rounds") or 0)
    proxy_round_limit = int(validation.get("proxy_search_round_limit") or 0)
    strict_liveness = validation.get("fail_open_on_low_alive") is False
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
            isinstance(item, dict) and int(item.get("xray_checked") or 0) > 0
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
            label = _SUBSCRIPTION_LABELS.get(key, key)

            tcp_checked = int(item.get("tcp_checked") or 0)
            tcp_alive = int(item.get("tcp_alive") or 0)
            tls_checked = int(item.get("tls_checked") or 0)
            tls_alive = int(item.get("tls_alive") or 0)
            tls_unchecked = int(item.get("tls_unchecked_passthrough") or 0)
            xray_checked = int(item.get("xray_checked") or 0)
            xray_alive = int(item.get("xray_alive") or 0)
            xray_unsupported = int(item.get("xray_unsupported") or 0)
            xray_probe_count = int(item.get("xray_probe_count") or 0)
            xray_min_probe_successes = int(item.get("xray_min_probe_successes") or 0)
            xray_attempts_per_config = int(item.get("xray_attempts_per_config") or 0)
            xray_min_attempt_successes = int(
                item.get("xray_min_attempt_successes") or 0,
            )
            xray_proxy_checks = int(item.get("xray_proxy_checks") or 0)
            xray_min_proxy_successes = int(item.get("xray_min_proxy_successes") or 0)
            xray_ip_check = bool(item.get("xray_require_distinct_outbound_ip"))
            skipped = int(item.get("tcp_skipped_protocol") or 0)
            rounds = int(item.get("tcp_search_rounds") or 0)
            round_limit = int(item.get("tcp_search_round_limit") or 0)
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
            label = _SUBSCRIPTION_LABELS.get(key, key)
            kept = int(item.get("kept") or 0)
            slow_dropped = int(item.get("slow_dropped") or 0)
            avg_score = float(item.get("avg_score") or 0)
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
    sources = summary.get("sources")
    if not isinstance(sources, dict):
        return ""
    errors = sources.get("errors")
    if not isinstance(errors, list) or not errors:
        return ""
    lines = [f"⚠️ {_b('Проблемные источники')}:"]
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


def _format_subscriptions_section(
    summary: dict[str, Any],
    subscription_file: str,
    *,
    fallback_count: int = 0,
    fallback_countries: str = "",
) -> str:
    """Render the per-output subscription lines.

    Args:
        summary: Parsed run-summary.json (may be empty).
        subscription_file: Combined output path, used to locate sibling files.
        fallback_count: Config count reported by the caller, used only when
            neither the summary nor the local files yielded any number.
        fallback_countries: Country codes reported by the caller, same fallback.
    """
    outputs = summary.get("outputs")
    lines = [f"{_b('📍 Подписки и страны')}:"]

    if isinstance(outputs, dict) and outputs:
        for key in ("combined", "blacklist", "whitelist", "mix"):
            item = outputs.get(key)
            if not isinstance(item, dict):
                continue
            label = (
                _mix_label(summary)
                if key == "mix"
                else _SUBSCRIPTION_LABELS.get(key, key)
            )
            try:
                count = int(item.get("count") or 0)
            except (TypeError, ValueError):
                count = 0
            countries = item.get("countries")
            country_text = _format_country_counts(
                countries if isinstance(countries, dict) else {},
            )
            lines.append(f"  {_b(label)}: {count} — {country_text}")
        location_outputs = [
            item
            for key, item in outputs.items()
            if str(key).startswith("location_") and isinstance(item, dict)
        ]
        if location_outputs:
            total_locations = len(location_outputs)
            try:
                max_count = max(
                    int(item.get("count") or 0) for item in location_outputs
                )
            except (TypeError, ValueError):
                max_count = 0
            lines.append(
                f"  {_b('Локации')}: {total_locations} файлов, до {max_count} серверов",
            )
        if len(lines) > 1:
            return "\n".join(lines)

    for key, filepath in _subscription_file_paths(subscription_file).items():
        counts = _count_countries_from_file(filepath)
        if not counts:
            continue
        label = _SUBSCRIPTION_LABELS.get(key, key)
        lines.append(
            f"  {_b(label)}: {sum(counts.values())} — {_format_country_counts(counts)}",
        )

    if len(lines) == 1:
        lines.append(_fallback_subscription_line(fallback_count, fallback_countries))
    return "\n".join(lines)


def _count_countries_from_file(filepath: str) -> dict[str, int]:
    """Decode subscription.txt and count configs per country.

    Returns a dict {country_code: count}, sorted by count descending.
    Returns empty dict if file can't be read or decoded.
    """
    from collections import Counter

    from src.validators.country_filter import detect_country

    try:
        with resolve_safe_output_path(filepath).open("r", encoding="utf-8") as f:
            raw = f.read().strip()
    except Exception:
        return {}

    try:
        import base64

        text = base64.b64decode(raw).decode("utf-8")
    except Exception:
        text = raw

    lines = [line.strip() for line in text.strip().split("\n") if "://" in line]

    countries: Counter[str] = Counter()
    for line in lines:
        # Skip watermark
        if "0.0.0.0" in line and "vmess://" in line:
            continue
        # Extract remark from fragment
        remark = ""
        if "#" in line:
            from urllib.parse import unquote

            remark = unquote(line.split("#", 1)[1].strip())
        # Extract host from link body
        host = ""
        body = line.split("://", 1)[1] if "://" in line else ""
        if "@" in body:
            host = body.split("@", 1)[1].split(":")[0].split("?")[0].strip("[]")
        # Use detect_country from country_filter (same logic as pipeline)
        code = detect_country(remark, host)
        if code:
            countries[code] += 1

    return dict(countries.most_common())


def _load_facts_history() -> list[str]:
    """Load previously generated facts from cache file."""
    try:
        with resolve_safe_output_path(_FACT_HISTORY_FILE).open(
            "r",
            encoding="utf-8",
        ) as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except (FileNotFoundError, json.JSONDecodeError):
        return []
    except Exception:
        return []


def _save_fact(fact: str) -> None:
    """Append fact to history file, keeping last _FACT_HISTORY_MAX entries."""
    history = _load_facts_history()
    history.append(fact)
    history = history[-_FACT_HISTORY_MAX:]
    try:
        with resolve_safe_output_path(_FACT_HISTORY_FILE).open(
            "w",
            encoding="utf-8",
        ) as f:
            json.dump(history, f, ensure_ascii=False, indent=2)
    except Exception as exc:
        logger.warning("Could not save fact history: %s", exc)


def _generate_fun_fact() -> str:
    """Pick a fun VPN fact, rotating so consecutive messages don't repeat.

    The LLM-generated facts were removed: the only configured key was a
    Yandex one that every supported provider rejects with 401, so every call
    wasted seconds before falling back anyway. History-based rotation of the
    static fallbacks keeps the same variety for free.
    """
    import random

    history = _load_facts_history()
    all_facts = [_FACT_FALLBACK_NO_KEY, *_FACT_FALLBACKS]
    seen = {h.lower().strip() for h in history}
    available = [f for f in all_facts if f.lower().strip() not in seen]
    if not available:
        # Everything has been shown once — restart the rotation.
        available = all_facts
    fact = random.choice(available)
    _save_fact(fact)
    return fact


def _is_watermark_line(line: str) -> bool:
    """Detect the display-only vmess watermark (``add`` is 0.0.0.0).

    The payload is itself base64, so a substring check on the link text never
    matches; the JSON body needs one lenient decode first.
    """
    import base64

    if not line.startswith("vmess://"):
        return False
    body = line[len("vmess://") :].split("#", 1)[0].split("?", 1)[0]
    padded = body + "=" * (-len(body) % 4)
    with contextlib.suppress(Exception):
        return "0.0.0.0" in base64.b64decode(padded).decode("utf-8", errors="ignore")
    return False


def _decode_subscription_lines(raw: str) -> set[str]:
    """Decode a base64 (or plain) subscription body into its config links."""
    import base64

    text = raw.strip()
    with contextlib.suppress(Exception):
        text = base64.b64decode(text).decode("utf-8")
    # Skip the watermark vmess line: it is regenerated every run and would
    # otherwise show up as a fake "+1/-1" delta.
    return {
        line.strip()
        for line in text.splitlines()
        if "://" in line and not _is_watermark_line(line.strip())
    }


def _current_subscription_lines(subscription_file: str) -> set[str]:
    try:
        with resolve_safe_output_path(subscription_file).open(
            "r",
            encoding="utf-8",
        ) as f:
            return _decode_subscription_lines(f.read())
    except Exception:
        return set()


def _previous_published_lines(subscription_file: str) -> set[str]:
    """Decode the previously published combined subscription.

    Baseline is the pre-run commit checked out by CI (``GITHUB_SHA``):
    publishing rewrites the working copy and pushes new commits *before* the
    notify step runs, so only git history still holds what subscribers see
    right now. Empty set when the baseline is unavailable — the delta line
    is then simply omitted instead of lying about "everything is new".
    """
    sha = (os.environ.get("GITHUB_SHA") or "").strip()
    if not re.fullmatch(r"[0-9a-fA-F]{6,40}", sha or ""):
        return set()
    path = (
        PurePosixPath(subscription_file or "output/subscription.txt")
        .as_posix()
        .lstrip("/")
    )
    try:
        result = subprocess.run(
            ["git", "show", f"{sha}:{path}"],
            capture_output=True,
            text=True,
            timeout=15,
            check=True,
        )
    except Exception:
        return set()
    return _decode_subscription_lines(result.stdout)


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


def _send_telegram(token: str, chat_id: str, text: str) -> bool:
    """Send a message to Telegram via Bot API.

    A flood limit (HTTP 429) is retried once after the ``retry_after`` delay
    Telegram sends with it; every other failure gives up immediately.

    Returns True on success, False on failure.
    """
    # Fail fast on empty credentials — otherwise we make a guaranteed-to-fail
    # network request that blocks for the full timeout (10s) before returning
    # False.  A negative ``chat_id`` is legitimate (Telegram groups/supergroups),
    # so only emptiness is rejected here.
    if not token or not str(token).strip() or not chat_id or not str(chat_id).strip():
        logger.warning("Telegram send skipped — empty token or chat_id")
        return False

    token = str(token).strip()
    chat_id = str(chat_id).strip()
    text = text or ""

    # Telegram sendMessage rejects text longer than 4096 chars with a 400.
    # Truncate defensively; avoid cutting inside an HTML tag which would break
    # parse_mode="HTML" and produce a 400.  The ellipsis and the closing tags
    # are counted inside the limit, so the result always fits.
    if len(text) > _TELEGRAM_MAX_TEXT:
        text = _truncate_html_safe(text, _TELEGRAM_MAX_TEXT)
        logger.warning("Telegram message truncated to 4096 chars")

    # Validate token format — fail fast instead of a 10s network timeout.
    # Telegram bot tokens: 123456789:ABC-DEF1234ghIkl-zyx57W2v1u123ew11
    if (
        ":" not in token
        or len(token) < _TOKEN_MIN_LEN
        or not token.split(":", 1)[0].isdigit()
        or not _URL_FORBIDDEN_CHARS.isdisjoint(token)
    ):
        logger.warning("Telegram token has invalid format — expected '<digits>:<hash>'")
        return False

    data = json.dumps(
        {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
        },
    ).encode("utf-8")

    for attempt in range(1, _SEND_ATTEMPTS + 1):
        try:
            req = urllib.request.Request(
                f"https://api.telegram.org/bot{quote(token, safe='')}/sendMessage",
                data=data,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "vpnparser/1.0",
                },
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                return bool(result.get("ok", False))
        except urllib.error.HTTPError as exc:
            # HTTPError is file-like — read Telegram's error description.
            try:
                body = exc.read().decode("utf-8", errors="replace")
            except Exception:
                body = ""
            logger.warning("Telegram API returned HTTP %d: %s", exc.code, body[:200])
            if exc.code != 429 or attempt >= _SEND_ATTEMPTS:
                return False
            wait = _flood_wait_seconds(body)
            logger.warning(
                "Telegram flood limit — retrying once in %.0fs.",
                wait,
            )
            time.sleep(wait)
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, (socket.timeout, TimeoutError)):
                logger.warning("Telegram send timed out after 10s — API unreachable")
            else:
                logger.warning("Telegram send network error: %s", exc.reason)
            return False
        except Exception as exc:
            # Unexpected errors from urllib quote the request URL, which carries
            # the bot token in BOTH raw and percent-encoded form — mask both.
            message = str(exc).replace(token, "<redacted>")
            encoded = quote(token, safe="")
            if encoded != token:
                message = message.replace(encoded, "<redacted>")
            logger.warning("Telegram send failed unexpectedly: %s", message)
            return False
    return False  # pragma: no cover - the last attempt always returns above


def send_notification(
    configs_count: int,
    countries: str = "DE FI NL US GB FR JP SG CA",
    subscription_file: str = "",
    status_file: str = "",
) -> bool:
    """Send a Telegram notification with config count + fun fact.

    Reads TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID from env.
    If status_file is provided, uses exact per-output pipeline metadata.
    Returns True if sent, False if skipped or failed.
    """
    token = (os.environ.get("TELEGRAM_BOT_TOKEN") or "").strip()
    chat_id = (os.environ.get("TELEGRAM_CHAT_ID") or "").strip()

    if not token or not chat_id:
        logger.info("Telegram credentials not set — skipping notification")
        return False

    # Normalise inputs.
    if not isinstance(configs_count, int):
        try:
            configs_count = int(configs_count)
        except (TypeError, ValueError):
            configs_count = 0
    configs_count = max(configs_count, 0)

    summary = _load_run_summary(status_file)

    # Generate fun fact (rotating static pool — see _generate_fun_fact).
    fact = _generate_fun_fact()
    urls = _subscription_urls(summary)

    validation_section = _format_validation_section(summary)
    low_alive_alert = _format_low_alive_alert(summary)
    if low_alive_alert:
        validation_section = f"{validation_section}\n{low_alive_alert}"
    trend_alert = _format_trend_alert(status_file)
    if trend_alert:
        validation_section = f"{validation_section}\n{trend_alert}"
    source_alerts = _format_source_alerts(summary)
    if source_alerts:
        validation_section = f"{validation_section}\n{source_alerts}"
    subscriptions_section = _format_subscriptions_section(
        summary,
        subscription_file,
        fallback_count=configs_count,
        fallback_countries=countries,
    )

    # Build message.
    repo_slug = _repo_slug()
    repo_url = f"https://github.com/{repo_slug}"
    # The message is sent seconds after publish, so send time == data
    # freshness; subscribers decide by the clock whether to re-import.
    updated_at = datetime.now(UTC).strftime("%d.%m %H:%M UTC")
    mix_label = _mix_label(summary)
    delta_section = _format_delta_section(
        _current_subscription_lines(subscription_file),
        _previous_published_lines(subscription_file),
    )
    delta_line = f"{delta_section}\n" if delta_section else ""
    message = (
        f"{_bot_intro()}\n"
        f"\n"
        f"{_b('Конфиг обновился')}, обновите конфигурацию.\n"
        f"🕒 {_b('Обновлено')}: {_h(updated_at)}\n"
        f"{delta_line}"
        f"{validation_section}\n"
        f"\n"
        f"{subscriptions_section}\n"
        f"\n"
        f"{_b('🔮 Факт')}: {_h(fact)}\n"
        f"\n"
        f"{_b('📋 Подписки')} ({_link(repo_slug, repo_url)}):\n"
        f"  🔗 {_link('Общая', urls['combined'])}\n"
        f"  ⚫ {_link('Рабочий blacklist', urls['blacklist'])}\n"
        f"  ⚪ {_link('Рабочий whitelist', urls['whitelist'])}\n"
        f"  🧩 {_link(mix_label, urls['mix'])}"
    )

    return _send_telegram(token, chat_id, message)


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Send Telegram notification")
    parser.add_argument("--configs", type=int, required=True, help="Number of configs")
    parser.add_argument("--countries", type=str, default="DE FI NL US GB FR JP SG CA")
    parser.add_argument(
        "--file",
        type=str,
        default="output/subscription.txt",
        help="Path to subscription.txt for per-country breakdown",
    )
    parser.add_argument(
        "--status-file",
        type=str,
        default="output/run-summary.json",
        help="Path to run-summary.json for validation and per-output stats",
    )
    args = parser.parse_args()

    if args.configs < 0:
        parser.error(f"--configs must be >= 0 (got {args.configs})")

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    ok = send_notification(
        configs_count=args.configs,
        countries=args.countries,
        subscription_file=args.file,
        status_file=args.status_file,
    )
    if ok:
        logger.info("Notification sent")
        return 0
    logger.info("Notification skipped or failed (non-fatal)")
    return 0  # Non-fatal — don't fail the workflow.


if __name__ == "__main__":
    sys.exit(main())
