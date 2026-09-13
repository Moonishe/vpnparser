"""Telegram notifier with rotating fun VPN facts.

Sends a message to a Telegram chat after each pipeline run with:
- Config count and countries, freshness timestamp, publish delta
- Subscription URLs (combined, blacklist, whitelist, dynamic mix)

Usage (standalone, from CLI):
    python -m src.notify.telegram --configs 50 --countries "DE FI NL US"

Usage (imported):
    from src.notify.telegram import send_notification
    send_notification(configs_count=50, countries="DE FI NL US")
"""

from __future__ import annotations

import argparse
import contextlib
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

from src.notify import report as _report
from src.notify.html_limits import (  # noqa: F401  (re-exports: tests reach these via telegram_module)
    _ELLIPSIS,
    _MAX_ENTITY_LEN,
    _PAIRED_TAGS,
    _SELF_CLOSING_TAGS,
    _SEND_ATTEMPTS,
    _TELEGRAM_MAX_TEXT,
    _TOKEN_MIN_LEN,
    _URL_FORBIDDEN_CHARS,
    _flood_wait_seconds,
    _open_tags,
    _safe_cut_offset,
    _truncate_html_safe,
    _utf16_len,
)
from src.notify.report import (
    _format_country_codes,
    _format_country_counts,
    _format_delta_section,
    _format_source_alerts,
    _format_trend_alert,
    _format_validation_section,
    _mix_label,
    _subscription_urls,
)
from src.parsers.base import split_host_port
from src.repo_info import github_branch, github_repo_slug
from src.utils.paths import resolve_safe_output_path, write_text_atomic

# Re-exports: tests reach these privates via `telegram_module.<name>`, and
# the patch surface (monkeypatch.setattr(telegram_module, ...)) must keep
# resolving here. Module-qualified binds keep ruff from pruning them as
# "unused imports" without self-assignment tricks.
_SUBSCRIPTION_LABELS = _report.SUBSCRIPTION_LABELS
_country_name = _report._country_name
_decode_subscription_lines = _report._decode_subscription_lines
_format_permanently_disabled_sources = _report._format_permanently_disabled_sources
_is_watermark_line = _report._is_watermark_line
_repo_relative_output = _report._repo_relative_output
_stats_history_path = _report._stats_history_path

logger = logging.getLogger(__name__)

# --- limits & truncation: src/notify/html_limits.py (re-exported below) ---


def _repo_slug() -> str:
    """Return owner/repo for Telegram URLs."""
    return github_repo_slug()


def _repo_branch() -> str:
    """Return branch for raw GitHub subscription URLs."""
    return github_branch()


# _h/_b/_link: single definitions live in report.py (imported below);
# this module and its tests use the same functions.
_h = _report._h


_b = _report._b


_link = _report._link


#: Handle credited in the bot intro. Overridable so a fork does not advertise
#: this deployment's author; the default keeps the current behaviour.
_DEFAULT_BOT_AUTHOR = "@dutysissy"


def _bot_author() -> str:
    """Return the handle credited in the intro line (env-overridable)."""
    return (os.environ.get("TELEGRAM_BOT_AUTHOR") or "").strip() or _DEFAULT_BOT_AUTHOR


def _bot_intro() -> str:
    repo_slug = _repo_slug()
    repo_url = f"https://github.com/{repo_slug}"
    return (
        f"🤖 {_b('Я — vpnparser бот')} от {_h(_bot_author())}\n"
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


#: Repo-relative paths used when the run summary does not name the outputs.


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
    """Return expected local output files using the combined path as anchor.

    Resolved like the runner writes them (project root for relative paths),
    so a different CWD does not point the fallback counts at stray files.
    """
    raw = subscription_file or "output/subscription.txt"
    candidate = Path(raw)
    if not candidate.is_absolute():
        with contextlib.suppress(ValueError):
            candidate = resolve_safe_output_path(raw)
    combined = candidate
    output_dir = combined.parent
    return {
        "combined": str(combined),
        "blacklist": str(output_dir / "subscription-blacklist.txt"),
        "whitelist": str(output_dir / "subscription-whitelist.txt"),
        "mix": str(output_dir / "subscription-mix.txt"),
    }


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

        # validate=True: the default decoder silently drops non-alphabet
        # characters, so a plain-format file decoded into garbage instead of
        # failing and keeping its raw lines. A link-bearing text skips decode.
        # Whitespace is stripped first: files may arrive MIME-wrapped
        # (soft line breaks every 76 chars), which validate=True rejects.
        if "://" not in raw:
            text = base64.b64decode("".join(raw.split()), validate=True).decode("utf-8")
        else:
            text = raw
    except Exception:
        text = raw

    lines = [line.strip() for line in text.strip().split("\n") if "://" in line]

    countries: Counter[str] = Counter()
    for line in lines:
        # Skip watermark — structural detection (decoded ``add``), same as
        # everywhere else; the old substring check could never match because
        # base64 cannot contain dots.
        from src.aggregator.output import is_watermark_vmess

        if is_watermark_vmess(line):
            continue
        # Extract remark from fragment
        remark = ""
        if "#" in line:
            from urllib.parse import unquote

            remark = unquote(line.split("#", 1)[1].strip())
        # Extract host from link body. split_host_port handles bracketed
        # IPv6 (a plain .split(":") turned "2001:db8::1" into "2001").
        host = ""
        body = line.split("://", 1)[1] if "://" in line else ""
        if "@" in body:
            after_at = body.rsplit("@", 1)[1].split("?")[0].split("/", 1)[0]
            parsed_hp = split_host_port(after_at)
            if parsed_hp is not None:
                host = parsed_hp[0]
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
    """Append fact to history file, keeping last _FACT_HISTORY_MAX entries.

    No FileLock: the notifier is a single-writer step and the write itself
    is atomic (tmp file + os.replace), so a crash cannot tear the file —
    only a lost-update race between two concurrent notifiers remains. Retry
    once on failure to ride out that race.
    """
    for _ in range(2):
        try:
            history = _load_facts_history()
            history.append(fact)
            history = history[-_FACT_HISTORY_MAX:]
            # Atomic like every other state file: a crash mid-write used to be
            # able to truncate the only non-atomic state artifact, silently
            # resetting the rotation.
            write_text_atomic(
                resolve_safe_output_path(_FACT_HISTORY_FILE),
                json.dumps(history, ensure_ascii=False, indent=2),
            )
            return
        except Exception as exc:
            logger.warning("Could not save fact history: %s", exc)
    return


def _generate_fun_fact(*, save: bool = True) -> str:
    """Pick a fun VPN fact, rotating so consecutive messages don't repeat.

    The LLM-generated facts were removed: the only configured key was a
    Yandex one that every supported provider rejects with 401, so every call
    wasted seconds before falling back anyway. History-based rotation of the
    static fallbacks keeps the same variety for free.

    Args:
        save: Record the pick immediately (legacy default, keeps existing
            callers/tests green). The pipeline passes ``save=False`` and
            records only after a successful send, so a failed send does not
            burn a fact the subscribers never saw.
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
    if save:
        _save_fact(fact)
    return fact


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


def _format_low_alive_alert(summary: dict[str, Any]) -> str:
    """One warning line per list whose verified-alive count collapsed."""
    lists = (summary.get("validation") or {}).get("lists")
    if not isinstance(lists, dict):
        return ""
    alerts: list[str] = []
    # Infra-collapse banner: the runner computed explicit degradation reasons
    # (a full Xray sweep with zero survivors is a dead-proxy spiral, not 100%
    # dead input) — say so loudly before the per-list thresholds below.
    reasons = summary.get("degraded_reasons")
    if isinstance(reasons, list) and reasons:
        alerts.append(
            "🚨 Деградация пробы: "
            + "; ".join(_h(str(reason)) for reason in reasons)
            + " — похоже, умер пул прокси, а не все конфиги разом"
        )
    min_alive = _alert_min_alive()
    if min_alive <= 0:
        return "\n".join(alerts)
    for key in ("blacklist", "whitelist"):
        item = lists.get(key)
        if not isinstance(item, dict):
            continue
        checked = _report._safe_int(item.get("xray_checked"))
        alive = _report._safe_int(item.get("xray_alive"))
        if checked > 0 and alive < min_alive:
            alerts.append(
                f"⚠️ {_b(key)}: живых {_b(alive)}/{_h(checked)} "
                f"(порог {_h(min_alive)}) — проверьте пул прокси и источники"
            )
    return "\n".join(alerts)


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

    Runs ``git show`` via blocking subprocess: the caller (send_notification
    via main._notify) is fully synchronous, so no ``to_thread`` offload is
    needed here — do not call this from the async pipeline without one.
    """
    sha = (os.environ.get("GITHUB_SHA") or "").strip()
    if not re.fullmatch(r"[0-9a-fA-F]{6,40}", sha or ""):
        logger.warning(
            "No GITHUB_SHA for the publish delta — omitting the delta line "
            "instead of reporting every config as new."
        )
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
            # git show emits raw subscription bytes; text=True alone decodes
            # with the ANSI code page (cp1251 on Windows), mangling non-ASCII
            # remarks so the diff-vs-published set never matched.
            encoding="utf-8",
            timeout=15,
            check=True,
        )
    except Exception:
        return set()
    return _decode_subscription_lines(result.stdout)


def _send_telegram(token: str, chat_id: str, text: str) -> bool:
    """Send a message to Telegram via Bot API.

    A flood limit (HTTP 429) is retried once after the ``retry_after`` delay
    Telegram sends with it; 5xx and transport errors (URLError) get 2 retries
    with backoff — Telegram flakes with 502s often enough that giving up
    immediately lost notifications. Other 4xx give up immediately.

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

    # Telegram sendMessage rejects text longer than 4096 UTF-16 units with a
    # 400.  Truncate defensively; avoid cutting inside an HTML tag which would
    # break parse_mode="HTML" and produce a 400.  The ellipsis and the closing
    # tags are counted inside the limit, so the result always fits.
    if _utf16_len(text) > _TELEGRAM_MAX_TEXT:
        text = _truncate_html_safe(text, _TELEGRAM_MAX_TEXT)
        logger.warning(
            "Telegram message truncated to %d UTF-16 units",
            _TELEGRAM_MAX_TEXT,
        )

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
            if exc.code == 429 and attempt < _SEND_ATTEMPTS:
                wait = _flood_wait_seconds(body)
                logger.warning(
                    "Telegram flood limit — retrying once in %.0fs.",
                    wait,
                )
                time.sleep(wait)
                continue
            if 500 <= exc.code < 600 and attempt < _SEND_ATTEMPTS:
                wait = 2.0 * attempt
                logger.warning(
                    "Telegram 5xx — retrying in %.0fs (attempt %d/%d).",
                    wait,
                    attempt + 1,
                    _SEND_ATTEMPTS,
                )
                time.sleep(wait)
                continue
            return False
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, (socket.timeout, TimeoutError)):
                logger.warning("Telegram send timed out after 10s — API unreachable")
            else:
                logger.warning("Telegram send network error: %s", exc.reason)
            if attempt < _SEND_ATTEMPTS:
                wait = 2.0 * attempt
                logger.warning(
                    "Retrying Telegram send in %.0fs (attempt %d/%d).",
                    wait,
                    attempt + 1,
                    _SEND_ATTEMPTS,
                )
                time.sleep(wait)
                continue
            return False
        except TimeoutError as exc:
            # A READ-phase timeout (connect succeeded, response never came):
            # the request may still have been delivered, so retrying could
            # double-send — fail the attempt without a retry.
            logger.warning(
                "Telegram send read-timed out — not retrying (the message "
                "may have been delivered): %s",
                exc,
            )
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
    # The runner does not know its own summary path inside the payload; the
    # helper needs it only to locate sibling artifacts (health history).
    if isinstance(summary, dict) and status_file:
        summary["_status_file"] = status_file

    # Generate fun fact without recording yet — saved only after a
    # successful send (see below), so failures don't burn the rotation.
    # Tolerate legacy zero-arg test doubles.
    try:
        fact = _generate_fun_fact(save=False)
    except TypeError:
        fact = _generate_fun_fact()
    urls = _subscription_urls(
        summary,
        repo_slug=_repo_slug(),
        repo_branch=_repo_branch(),
    )

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
    # The subscription links are the single actionable block of this message
    # and truncation cuts from the tail — so the fun fact goes LAST, after
    # the links. The previous order (fact then links) made an over-limit
    # message lose exactly the links while keeping the trivia.
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
        f"{_b('📋 Подписки')} ({_link(repo_slug, repo_url)}):\n"
        f"  🔗 {_link('Общая', urls['combined'])}\n"
        f"  ⚫ {_link('Рабочий blacklist', urls['blacklist'])}\n"
        f"  ⚪ {_link('Рабочий whitelist', urls['whitelist'])}\n"
        f"  🧩 {_link(mix_label, urls['mix'])}\n"
        f"\n"
        f"{_b('🔮 Факт')}: {_h(fact)}\n"
    )

    ok = _send_telegram(token, chat_id, message)
    if ok:
        # Record the fact only when subscribers actually saw it — saving
        # before the send burned one rotation entry per failed send.
        _save_fact(fact)
    return ok


def send_crash_notification(error_message: str = "") -> bool:
    """Send a compact pipeline-crash alert.

    :func:`send_notification` reports a *finished* run; a crashed pipeline
    produces no summary to report, and in ``--continuous`` mode that made
    every crash invisible in the chat — the loop just logged and retried.
    Returns True if sent, False if skipped or failed.
    """
    token = (os.environ.get("TELEGRAM_BOT_TOKEN") or "").strip()
    chat_id = (os.environ.get("TELEGRAM_CHAT_ID") or "").strip()
    if not token or not chat_id:
        logger.info("Telegram credentials not set — skipping crash notification")
        return False

    repo_slug = _repo_slug()
    updated_at = datetime.now(UTC).strftime("%d.%m %H:%M UTC")
    message = f"💥 {_b('Пайплайн упал')} ({_h(repo_slug)})\n🕒 {_h(updated_at)}\n"
    detail = (error_message or "").strip()
    if detail:
        message += f"\n{_h(detail[:300])}\n"
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
    logger.warning("Notification failed")
    return 1


if __name__ == "__main__":
    sys.exit(main())
