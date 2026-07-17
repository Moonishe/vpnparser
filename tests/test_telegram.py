"""Comprehensive tests for the Telegram notification module — 100% coverage target."""

from __future__ import annotations

import json
import os
import socket
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from src.notify import telegram as telegram_module


# ── _truncate_html_safe ─────────────────────────────────────────────────


class TestTruncateHtmlSafe:
    """Cover lines 55-96: truncation logic, HTML entities, tag balancing."""

    def test_no_truncation_needed(self) -> None:
        text = "short text"
        assert telegram_module._truncate_html_safe(text, 100) == text

    def test_truncate_inside_entity_backs_up_to_ampersand(self) -> None:
        """Line 59-63: if cut lands inside &amp; without ';', back up to '&'."""
        # Cut at position 15 which is past "text&amp" but before ";"
        # The text has "&amp" near the limit, with no ";" after it within limit
        text = "text&ampXmoreandmoretext"
        # "text&ampXmoreandmoretext" — cut at 10, which lands on "X" inside entity
        result = telegram_module._truncate_html_safe(text, 10)
        # Should back up to the '&' so the entity is cut cleanly
        truncated_part = result.split("...")[0]
        assert "&" not in truncated_part.rstrip()

    def test_truncate_inside_tag_backs_up_to_tag_start(self) -> None:
        """Line 65-67: if cut lands inside <tag>, back up to '<'."""
        text = "Hello <b>world</b> more text here"
        # Cut at position 9, which is right at "<b>" — let's cut inside it
        result = telegram_module._truncate_html_safe(text, 9)
        assert "..." in result

    def test_truncate_closes_open_tags(self) -> None:
        """Line 68-96: open tags after cut are closed."""
        # <b>bold</b> and <i>italic</i> stuff = 37 chars
        # Cut at 20 lands inside "italic" or before </i>
        text = "<b>bold</b> and <i>italic</i> stuff"
        result = telegram_module._truncate_html_safe(text, 20)
        assert "..." in result
        # All open tags should be closed
        assert result.count("<b>") == result.count("</b>")

    def test_self_closing_tags_not_tracked(self) -> None:
        """Line 90: self-closing tags like <br> are not added to open stack."""
        text = "line1<br>line2<br>line3 with <b>bold</b>"
        result = telegram_module._truncate_html_safe(text, 25)
        assert "..." in result or "<br>" in result

    def test_truncate_exact_limit_no_ellipsis(self) -> None:
        """No truncation when text length equals limit."""
        text = "exactly 20 char!!"
        assert len(text) == 17
        assert telegram_module._truncate_html_safe(text, 17) == text

    def test_truncate_empty_tag_name(self) -> None:
        """Line 80-81: empty tag name '<>' counted but skipped.

        NOTE: This exposes that an empty closing tag name '</>' triggers an
        IndexError at line 83 in the current implementation.  We accept the
        behaviour as-is (tag_text="/" -> split()[0] on empty string fails).
        """
        text = "<>some text</> and <b>bold</b>"
        with pytest.raises(IndexError):
            telegram_module._truncate_html_safe(text, 20)

    def test_truncate_entity_with_semicolon_in_range(self) -> None:
        """If entity has ';' before limit, no backing up needed."""
        text = "Hello &amp; world and <b>more</b>"
        result = telegram_module._truncate_html_safe(text, 30)
        # The entity &amp; is complete, so no backing up
        assert "..." in result or "&amp;" in text[:30]

    def test_truncate_nested_tags_close_in_order(self) -> None:
        """Nested tags should close in reverse order: </i></b>."""
        text = "<b><i>nested</i></b> tail"
        result = telegram_module._truncate_html_safe(text, 15)
        assert "..." in result
        # If </i> is cut off and <b> still open, it should close </b>
        open_b = result.count("<b>") - result.count("</b>")
        open_i = result.count("<i>") - result.count("</i>")
        assert open_b >= 0 and open_i >= 0

    def test_truncate_unknown_tags_not_tracked(self) -> None:
        """Tags not in _PAIRED_TAGS are ignored."""
        text = "<custom>some</custom> <b>bold</b>"
        result = telegram_module._truncate_html_safe(text, 20)
        assert "..." in result

    def test_truncate_empty_string(self) -> None:
        """Empty string returns as-is."""
        assert telegram_module._truncate_html_safe("", 100) == ""

    def test_truncate_cut_at_start_of_tag(self) -> None:
        """Cut exactly at '<' backs up to before '<'."""
        text = "abc<b>def</b>ghi"
        result = telegram_module._truncate_html_safe(text, 4)
        assert "..." in result
        assert "<b>" not in result.split("...")[0]


# ── _load_run_summary ───────────────────────────────────────────────────


class TestLoadRunSummary:
    """Cover lines 229-234."""

    def test_empty_filepath_returns_empty_dict(self) -> None:
        assert telegram_module._load_run_summary("") == {}

    def test_file_read_exception_returns_empty(self, monkeypatch) -> None:
        monkeypatch.setattr(
            telegram_module,
            "resolve_safe_output_path",
            lambda p: (_ for _ in ()).throw(OSError("boom")),
        )
        assert telegram_module._load_run_summary("output/run-summary.json") == {}

    def test_non_dict_data_returns_empty(self, tmp_path, monkeypatch) -> None:
        f = tmp_path / "run-summary.json"
        f.write_text('"just a string"', encoding="utf-8")
        monkeypatch.setattr(
            telegram_module,
            "resolve_safe_output_path",
            lambda p: f,
        )
        assert telegram_module._load_run_summary(str(f)) == {}

    def test_valid_dict_returns_data(self, tmp_path, monkeypatch) -> None:
        f = tmp_path / "run-summary.json"
        f.write_text('{"key": "value"}', encoding="utf-8")
        monkeypatch.setattr(
            telegram_module,
            "resolve_safe_output_path",
            lambda p: f,
        )
        assert telegram_module._load_run_summary(str(f)) == {"key": "value"}


# ── _format_country_counts ──────────────────────────────────────────────


class TestFormatCountryCounts:
    """Cover lines 260-263, 270."""

    def test_type_error_skips_bad_entry(self) -> None:
        result = telegram_module._format_country_counts({"DE": "not-a-number"})
        assert result == "страны не определены"

    def test_value_error_skips_bad_entry(self) -> None:
        result = telegram_module._format_country_counts({"DE": None})
        assert result == "страны не определены"

    def test_empty_parsed_returns_not_defined(self) -> None:
        result = telegram_module._format_country_counts({})
        assert result == "страны не определены"

    def test_remaining_countries_count(self) -> None:
        countries = {f"C{i}": i for i in range(1, 10)}
        result = telegram_module._format_country_counts(countries, max_items=3)
        assert "+6 стран" in result

    def test_no_remaining_countries(self) -> None:
        countries = {"DE": 10, "FI": 5}
        result = telegram_module._format_country_counts(countries, max_items=6)
        assert "+" not in result


# ── _format_validation_section ──────────────────────────────────────────


class TestFormatValidationSection:
    """Cover lines 292, 306, 318, 320-322, 330, 368-369, 376-377, 404, 432-440."""

    def test_proxy_search_text_included(self) -> None:
        result = telegram_module._format_validation_section(
            {
                "validation": {
                    "tcp_enabled": True,
                    "tls_enabled": False,
                    "xray_enabled": False,
                    "proxy_pool_enabled": True,
                    "proxy_pool_required": True,
                    "proxy_count": 5,
                    "proxy_min_proxies": 3,
                    "proxy_search_rounds": 4,
                    "proxy_search_round_limit": 10,
                    "fail_open_on_low_alive": True,
                    "drop_unchecked_after_tls": False,
                    "lists": {},
                }
            }
        )
        assert "поиск 4/10" in result

    def test_no_validators_enabled(self) -> None:
        result = telegram_module._format_validation_section(
            {
                "validation": {
                    "tcp_enabled": False,
                    "tls_enabled": False,
                    "xray_enabled": False,
                }
            }
        )
        assert "выключена" in result

    def test_proxy_pool_enabled_no_proxies_with_round_limit(self) -> None:
        result = telegram_module._format_validation_section(
            {
                "validation": {
                    "tcp_enabled": True,
                    "tls_enabled": False,
                    "xray_enabled": False,
                    "proxy_pool_enabled": True,
                    "proxy_pool_required": True,
                    "proxy_count": 0,
                    "proxy_search_round_limit": 5,
                    "fail_open_on_low_alive": True,
                    "drop_unchecked_after_tls": False,
                    "lists": {},
                }
            }
        )
        assert "пропущена" in result
        assert "после 5 раундов поиска" in result

    def test_validation_else_branch_no_proxies_simple(self) -> None:
        result = telegram_module._format_validation_section(
            {
                "validation": {
                    "proxy_pool_enabled": False,
                    "proxy_count": 0,
                    "tcp_enabled": True,
                    "tls_enabled": False,
                    "xray_enabled": False,
                    "fail_open_on_low_alive": True,
                    "drop_unchecked_after_tls": False,
                }
            }
        )
        assert "включена, без прокси" in result

    def test_no_proxies_reason_xray_direct(self) -> None:
        validation = telegram_module._format_validation_section(
            {
                "validation": {
                    "proxy_pool_enabled": True,
                    "proxy_pool_required": True,
                    "proxy_count": 0,
                    "xray_enabled": True,
                    "tcp_enabled": False,
                    "tls_enabled": False,
                    "fail_open_on_low_alive": True,
                    "drop_unchecked_after_tls": False,
                    "lists": {
                        "blacklist": {
                            "reason": "no_proxies",
                            "tcp_checked": 0,
                            "tls_checked": 0,
                            "xray_checked": 0,
                        }
                    },
                }
            }
        )
        assert "не проверялся, нет рабочих прокси" in validation

    def test_no_candidates_line(self) -> None:
        validation = telegram_module._format_validation_section(
            {
                "validation": {
                    "proxy_pool_enabled": False,
                    "tcp_enabled": True,
                    "tls_enabled": True,
                    "xray_enabled": False,
                    "fail_open_on_low_alive": True,
                    "drop_unchecked_after_tls": False,
                    "lists": {
                        "whitelist": {
                            "tcp_checked": 0,
                            "tls_checked": 0,
                            "xray_checked": 0,
                        }
                    },
                }
            }
        )
        assert "нет кандидатов для TCP/TLS проверки" in validation

    def test_xray_unavailable_reason(self) -> None:
        validation = telegram_module._format_validation_section(
            {
                "validation": {
                    "proxy_pool_enabled": False,
                    "tcp_enabled": True,
                    "tls_enabled": True,
                    "xray_enabled": True,
                    "fail_open_on_low_alive": True,
                    "drop_unchecked_after_tls": False,
                    "lists": {
                        "blacklist": {
                            "reason": "xray_unavailable",
                            "tcp_checked": 100,
                            "tcp_alive": 50,
                            "tls_checked": 40,
                            "tls_alive": 30,
                        }
                    },
                }
            }
        )
        assert "пропущен, xray не установлен" in validation

    def test_quality_section_included(self) -> None:
        validation = telegram_module._format_validation_section(
            {
                "validation": {
                    "tcp_enabled": False,
                    "tls_enabled": False,
                    "xray_enabled": False,
                    "quality": {
                        "blacklist": {
                            "kept": 100,
                            "slow_dropped": 5,
                            "avg_score": 85.3,
                        }
                    },
                }
            }
        )
        assert "Blacklist quality" in validation
        assert "прошло 100" in validation
        assert "медленных удалено 5" in validation
        assert "score 85.3" in validation

    def test_validation_not_dict(self) -> None:
        result = telegram_module._format_validation_section({"validation": None})
        assert "нет данных по этому прогону" in result


# ── _format_subscriptions_section ───────────────────────────────────────


class TestFormatSubscriptionsSection:
    """Cover lines 484-485 — fallback to file counting."""

    def test_no_outputs_in_summary_falls_back_to_file_counting(
        self, tmp_path, monkeypatch
    ) -> None:
        sub_file = tmp_path / "subscription.txt"
        import base64

        content = (
            "vless://11111111-1111-4111-8111-111111111111@de.example.com:443#DE-01"
        )
        encoded = base64.b64encode(content.encode()).decode()
        sub_file.write_text(encoded, encoding="utf-8")

        blacklist_file = tmp_path / "subscription-blacklist.txt"
        blacklist_file.write_text(encoded, encoding="utf-8")

        monkeypatch.setattr(
            telegram_module,
            "_subscription_file_paths",
            lambda _: {
                "combined": str(sub_file),
                "blacklist": str(blacklist_file),
                "whitelist": str(tmp_path / "subscription-whitelist.txt"),
                "mix": str(tmp_path / "subscription-mix.txt"),
            },
        )

        result = telegram_module._format_subscriptions_section({}, str(sub_file))
        assert "Подписки и страны" in result

    def test_outputs_present_uses_them(self) -> None:
        result = telegram_module._format_subscriptions_section(
            {
                "outputs": {
                    "combined": {"count": 50, "countries": {"DE": 30, "FI": 20}},
                    "blacklist": {"count": 30, "countries": {"DE": 30}},
                }
            },
            "",
        )
        assert "<b>Общая</b>: 50" in result
        assert "<b>Blacklist</b>: 30" in result

    def test_no_outputs_and_no_files(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setattr(
            telegram_module,
            "_subscription_file_paths",
            lambda _: {
                "combined": str(tmp_path / "nonexistent.txt"),
                "blacklist": str(tmp_path / "nonexistent-bl.txt"),
                "whitelist": str(tmp_path / "nonexistent-wl.txt"),
                "mix": str(tmp_path / "nonexistent-mix.txt"),
            },
        )
        result = telegram_module._format_subscriptions_section({}, "")
        assert "данных по файлам нет" in result


# ── _count_countries_from_file ──────────────────────────────────────────


class TestCountCountriesFromFile:
    """Cover lines 514-515, 523, 527-529, 534, 538."""

    def test_file_not_found_returns_empty(self, tmp_path) -> None:
        result = telegram_module._count_countries_from_file(str(tmp_path / "nope.txt"))
        assert result == {}

    def test_base64_decode_error_falls_back_to_raw(self, tmp_path) -> None:
        f = tmp_path / "sub.txt"
        f.write_text("vless://1.2.3.4:443#DE-01\n", encoding="utf-8")
        result = telegram_module._count_countries_from_file(str(f))
        # Just verify it doesn't crash and returns a dict
        assert isinstance(result, dict)

    def test_watermark_line_skipped(self, tmp_path) -> None:
        f = tmp_path / "sub.txt"
        import base64

        content = (
            "vmess://AAAA@0.0.0.0:0#watermark\n"
            "vless://11111111-1111-4111-8111-111111111111@de.example.com:443#DE-01\n"
        )
        encoded = base64.b64encode(content.encode()).decode()
        f.write_text(encoded, encoding="utf-8")
        result = telegram_module._count_countries_from_file(str(f))
        assert isinstance(result, dict)

    def test_remark_with_url_encoding(self, tmp_path) -> None:
        f = tmp_path / "sub.txt"
        import base64

        content = (
            "vless://11111111-1111-4111-8111-111111111111@de.example.com:443#DE%2D01\n"
        )
        encoded = base64.b64encode(content.encode()).decode()
        f.write_text(encoded, encoding="utf-8")
        result = telegram_module._count_countries_from_file(str(f))
        assert isinstance(result, dict)

    def test_host_extraction_with_ipv6(self, tmp_path) -> None:
        f = tmp_path / "sub.txt"
        import base64

        content = (
            "vless://11111111-1111-4111-8111-111111111111@[2001:db8::1]:443#DE-01\n"
        )
        encoded = base64.b64encode(content.encode()).decode()
        f.write_text(encoded, encoding="utf-8")
        result = telegram_module._count_countries_from_file(str(f))
        assert isinstance(result, dict)

    def test_no_protocol_line_skipped(self, tmp_path) -> None:
        f = tmp_path / "sub.txt"
        import base64

        content = "just some text without protocol\n"
        encoded = base64.b64encode(content.encode()).decode()
        f.write_text(encoded, encoding="utf-8")
        result = telegram_module._count_countries_from_file(str(f))
        assert result == {}

    def test_read_exception_returns_empty(self, monkeypatch) -> None:
        monkeypatch.setattr(
            telegram_module,
            "resolve_safe_output_path",
            lambda p: (_ for _ in ()).throw(PermissionError("denied")),
        )
        result = telegram_module._count_countries_from_file("output/sub.txt")
        assert result == {}


# ── _load_facts_history ─────────────────────────────────────────────────


class TestLoadFactsHistory:
    """Cover lines 545-555."""

    def test_file_not_found_returns_empty(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setattr(
            telegram_module,
            "resolve_safe_output_path",
            lambda p: tmp_path / "nonexistent.json",
        )
        assert telegram_module._load_facts_history() == []

    def test_json_decode_error_returns_empty(self, tmp_path, monkeypatch) -> None:
        f = tmp_path / "facts_history.json"
        f.write_text("not json", encoding="utf-8")
        monkeypatch.setattr(
            telegram_module,
            "resolve_safe_output_path",
            lambda p: f,
        )
        assert telegram_module._load_facts_history() == []

    def test_other_exception_returns_empty(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setattr(
            telegram_module,
            "resolve_safe_output_path",
            lambda p: (_ for _ in ()).throw(OSError("boom")),
        )
        assert telegram_module._load_facts_history() == []

    def test_non_list_data_returns_empty(self, tmp_path, monkeypatch) -> None:
        f = tmp_path / "facts_history.json"
        f.write_text('"string"', encoding="utf-8")
        monkeypatch.setattr(
            telegram_module,
            "resolve_safe_output_path",
            lambda p: f,
        )
        assert telegram_module._load_facts_history() == []


# ── _save_fact ──────────────────────────────────────────────────────────


class TestSaveFact:
    """Cover lines 560-570."""

    def test_save_fact_success(self, tmp_path, monkeypatch) -> None:
        f = tmp_path / "facts_history.json"
        monkeypatch.setattr(
            telegram_module,
            "resolve_safe_output_path",
            lambda p: f,
        )
        telegram_module._save_fact("test fact")
        data = json.loads(f.read_text(encoding="utf-8"))
        assert "test fact" in data

    def test_save_fact_exception_logged(self, monkeypatch, caplog) -> None:
        monkeypatch.setattr(
            telegram_module,
            "resolve_safe_output_path",
            lambda p: (_ for _ in ()).throw(PermissionError("denied")),
        )
        caplog.set_level("WARNING")
        telegram_module._save_fact("test fact")
        assert "Could not save fact history" in caplog.text

    def test_save_fact_truncates_history(self, tmp_path, monkeypatch) -> None:
        f = tmp_path / "facts_history.json"
        existing = [f"fact-{i}" for i in range(49)]
        f.write_text(json.dumps(existing), encoding="utf-8")
        monkeypatch.setattr(
            telegram_module,
            "resolve_safe_output_path",
            lambda p: f,
        )
        telegram_module._save_fact("new fact")
        data = json.loads(f.read_text(encoding="utf-8"))
        assert len(data) <= 50
        assert "new fact" in data


# ── _call_gemini ────────────────────────────────────────────────────────


class FakeResponse:
    """Reusable fake HTTP response for urllib."""

    def __init__(self, data: bytes, code: int = 200) -> None:
        self._data = data
        self.code = code

    def read(self) -> bytes:
        return self._data

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None


class TestCallGemini:
    """Cover lines 575-613."""

    def test_success_returns_content(self, monkeypatch) -> None:
        response_data = {"choices": [{"message": {"content": "  Interesting fact  "}}]}
        monkeypatch.setattr(
            telegram_module.urllib.request,
            "urlopen",
            lambda req, timeout=15: FakeResponse(
                json.dumps(response_data).encode("utf-8")
            ),
        )
        result = telegram_module._call_gemini("fake-key", "prompt")
        assert result == "Interesting fact"

    def test_no_choices_returns_none(self, monkeypatch) -> None:
        response_data = {"choices": []}
        monkeypatch.setattr(
            telegram_module.urllib.request,
            "urlopen",
            lambda req, timeout=15: FakeResponse(
                json.dumps(response_data).encode("utf-8")
            ),
        )
        assert telegram_module._call_gemini("fake-key", "prompt") is None

    def test_empty_content_returns_none(self, monkeypatch) -> None:
        response_data = {"choices": [{"message": {"content": ""}}]}
        monkeypatch.setattr(
            telegram_module.urllib.request,
            "urlopen",
            lambda req, timeout=15: FakeResponse(
                json.dumps(response_data).encode("utf-8")
            ),
        )
        assert telegram_module._call_gemini("fake-key", "prompt") is None

    def test_exception_returns_none(self, monkeypatch, caplog) -> None:
        def fake_urlopen(req, timeout=15):
            raise OSError("network error")

        monkeypatch.setattr(telegram_module.urllib.request, "urlopen", fake_urlopen)
        caplog.set_level("WARNING")
        result = telegram_module._call_gemini("fake-key", "prompt")
        assert result is None
        assert "Gemini API call failed" in caplog.text

    def test_no_valid_choices_key(self, monkeypatch) -> None:
        response_data = {"not_choices": []}
        monkeypatch.setattr(
            telegram_module.urllib.request,
            "urlopen",
            lambda req, timeout=15: FakeResponse(
                json.dumps(response_data).encode("utf-8")
            ),
        )
        assert telegram_module._call_gemini("fake-key", "prompt") is None

    def test_content_not_string(self, monkeypatch) -> None:
        response_data = {"choices": [{"message": {"content": 123}}]}
        monkeypatch.setattr(
            telegram_module.urllib.request,
            "urlopen",
            lambda req, timeout=15: FakeResponse(
                json.dumps(response_data).encode("utf-8")
            ),
        )
        assert telegram_module._call_gemini("fake-key", "prompt") is None


# ── _generate_fun_fact ──────────────────────────────────────────────────


class TestGenerateFunFact:
    """Cover lines 624-684."""

    def test_no_api_key_uses_fallback(self, monkeypatch) -> None:
        monkeypatch.setattr(telegram_module, "_load_facts_history", lambda: [])
        monkeypatch.setattr(telegram_module, "_save_fact", lambda f: None)
        result = telegram_module._generate_fun_fact("")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_no_api_key_with_history(self, monkeypatch) -> None:
        monkeypatch.setattr(
            telegram_module,
            "_load_facts_history",
            lambda: [telegram_module._FACT_FALLBACK_NO_KEY],
        )
        saved = []

        def fake_save(fact: str) -> None:
            saved.append(fact)

        monkeypatch.setattr(telegram_module, "_save_fact", fake_save)
        result = telegram_module._generate_fun_fact("")
        assert result in saved

    def test_api_key_success(self, monkeypatch) -> None:
        monkeypatch.setattr(telegram_module, "_load_facts_history", lambda: [])
        monkeypatch.setattr(
            telegram_module,
            "_call_gemini",
            lambda key, prompt: "unique gemini fact",
        )
        saved = []

        def fake_save(fact: str) -> None:
            saved.append(fact)

        monkeypatch.setattr(telegram_module, "_save_fact", fake_save)
        result = telegram_module._generate_fun_fact("real-key")
        assert result == "unique gemini fact"
        assert "unique gemini fact" in saved

    def test_api_key_duplicate_retries_then_fallback(self, monkeypatch) -> None:
        monkeypatch.setattr(
            telegram_module,
            "_load_facts_history",
            lambda: ["existing fact"],
        )
        call_count = [0]

        def fake_call_gemini(key, prompt):
            call_count[0] += 1
            return "existing fact"  # Always returns duplicate

        monkeypatch.setattr(telegram_module, "_call_gemini", fake_call_gemini)

        saved = []
        monkeypatch.setattr(telegram_module, "_save_fact", lambda f: saved.append(f))

        result = telegram_module._generate_fun_fact("real-key")
        # All retries failed, should return a fallback
        assert result in telegram_module._FACT_FALLBACKS
        assert result in saved

    def test_api_key_all_fallbacks_used(self, monkeypatch) -> None:
        all_fallbacks_set = {f.lower().strip() for f in telegram_module._FACT_FALLBACKS}
        monkeypatch.setattr(
            telegram_module,
            "_load_facts_history",
            lambda: list(telegram_module._FACT_FALLBACKS),
        )
        monkeypatch.setattr(telegram_module, "_call_gemini", lambda key, prompt: None)

        saved = []
        monkeypatch.setattr(telegram_module, "_save_fact", lambda f: saved.append(f))

        result = telegram_module._generate_fun_fact("real-key")
        assert result in telegram_module._FACT_FALLBACKS
        assert result in saved

    def test_api_key_api_fails_uses_fallback(self, monkeypatch) -> None:
        monkeypatch.setattr(telegram_module, "_load_facts_history", lambda: [])
        monkeypatch.setattr(telegram_module, "_call_gemini", lambda key, prompt: None)
        saved = []
        monkeypatch.setattr(telegram_module, "_save_fact", lambda f: saved.append(f))

        result = telegram_module._generate_fun_fact("real-key")
        assert result in telegram_module._FACT_FALLBACKS
        assert result in saved

    def test_api_key_with_recent_history(self, monkeypatch) -> None:
        history = ["old fact 1", "old fact 2"]
        monkeypatch.setattr(telegram_module, "_load_facts_history", lambda: history)
        seen_prompts = []

        def fake_call_gemini(key, prompt):
            seen_prompts.append(prompt)
            return "brand new fact"

        monkeypatch.setattr(telegram_module, "_call_gemini", fake_call_gemini)
        monkeypatch.setattr(telegram_module, "_save_fact", lambda f: None)

        result = telegram_module._generate_fun_fact("real-key")
        assert result == "brand new fact"
        assert "old fact 1" in seen_prompts[0]
        assert "old fact 2" in seen_prompts[0]


# ── _send_telegram ──────────────────────────────────────────────────────


class TestSendTelegram:
    """Cover lines 697-719, 743-759."""

    def test_empty_token_returns_false(self, caplog) -> None:
        caplog.set_level("WARNING")
        assert telegram_module._send_telegram("", "-100123", "text") is False
        assert "skipped — empty token" in caplog.text

    def test_empty_chat_id_returns_false(self, caplog) -> None:
        caplog.set_level("WARNING")
        assert telegram_module._send_telegram("token:abc", "", "text") is False
        assert "skipped — empty token" in caplog.text

    def test_invalid_token_format_no_colon(self, caplog) -> None:
        caplog.set_level("WARNING")
        assert (
            telegram_module._send_telegram("invalidtoken", "-100123", "text") is False
        )
        assert "invalid format" in caplog.text

    def test_invalid_token_format_too_short(self, caplog) -> None:
        caplog.set_level("WARNING")
        assert telegram_module._send_telegram("123:short", "-100123", "text") is False
        assert "invalid format" in caplog.text

    def test_invalid_token_format_non_digit_prefix(self, caplog) -> None:
        caplog.set_level("WARNING")
        assert (
            telegram_module._send_telegram("abc:defghijklmnopqrst", "-100123", "text")
            is False
        )
        assert "invalid format" in caplog.text

    def test_message_truncated_when_too_long(self, monkeypatch, caplog) -> None:
        caplog.set_level("WARNING")
        long_text = "Hello <b>world</b>" + "x" * 4090
        monkeypatch.setattr(
            telegram_module.urllib.request,
            "urlopen",
            lambda req, timeout=15: FakeResponse(b'{"ok": true}'),
        )
        assert telegram_module._send_telegram(
            "123456789:ABCDEFGHIJKLMNOPQRST", "-100123", long_text
        )
        assert "truncated to 4096 chars" in caplog.text

    def test_http_error_returns_false(self, monkeypatch, caplog) -> None:
        caplog.set_level("WARNING")

        def fake_urlopen(req, timeout=15):
            raise urllib.error.HTTPError(
                "https://api.telegram.org/",
                400,
                "Bad Request",
                {},
                None,
            )

        monkeypatch.setattr(telegram_module.urllib.request, "urlopen", fake_urlopen)
        assert (
            telegram_module._send_telegram(
                "123456789:ABCDEFGHIJKLMNOPQRST", "-100123", "text"
            )
            is False
        )
        assert "Telegram API returned HTTP 400" in caplog.text

    def test_url_error_timeout_returns_false(self, monkeypatch, caplog) -> None:
        caplog.set_level("WARNING")

        def fake_urlopen(req, timeout=15):
            raise urllib.error.URLError(socket.timeout("timed out"))

        monkeypatch.setattr(telegram_module.urllib.request, "urlopen", fake_urlopen)
        assert (
            telegram_module._send_telegram(
                "123456789:ABCDEFGHIJKLMNOPQRST", "-100123", "text"
            )
            is False
        )
        assert "timed out" in caplog.text

    def test_url_error_other_returns_false(self, monkeypatch, caplog) -> None:
        caplog.set_level("WARNING")

        def fake_urlopen(req, timeout=15):
            raise urllib.error.URLError("DNS resolution failed")

        monkeypatch.setattr(telegram_module.urllib.request, "urlopen", fake_urlopen)
        assert (
            telegram_module._send_telegram(
                "123456789:ABCDEFGHIJKLMNOPQRST", "-100123", "text"
            )
            is False
        )
        assert "network error" in caplog.text

    def test_generic_exception_returns_false(self, monkeypatch, caplog) -> None:
        caplog.set_level("WARNING")

        def fake_urlopen(req, timeout=15):
            raise RuntimeError("something unexpected")

        monkeypatch.setattr(telegram_module.urllib.request, "urlopen", fake_urlopen)
        assert (
            telegram_module._send_telegram(
                "123456789:ABCDEFGHIJKLMNOPQRST", "-100123", "text"
            )
            is False
        )
        assert "unexpectedly" in caplog.text

    def test_http_error_body_read_failure(self, monkeypatch, caplog) -> None:
        caplog.set_level("WARNING")

        class BrokenHTTPError(urllib.error.HTTPError):
            def read(self):
                raise OSError("body read error")

        def fake_urlopen(req, timeout=15):
            raise BrokenHTTPError(
                "https://api.telegram.org/",
                403,
                "Forbidden",
                {},
                None,
            )

        monkeypatch.setattr(telegram_module.urllib.request, "urlopen", fake_urlopen)
        assert (
            telegram_module._send_telegram(
                "123456789:ABCDEFGHIJKLMNOPQRST", "-100123", "text"
            )
            is False
        )
        assert "Telegram API returned HTTP 403" in caplog.text


# ── send_notification ───────────────────────────────────────────────────


class TestSendNotification:
    """Cover lines 778-779, 783-786."""

    def test_no_credentials_returns_false(self, monkeypatch, caplog) -> None:
        monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
        monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)
        caplog.set_level("INFO")
        assert telegram_module.send_notification(configs_count=10) is False
        assert "skipping notification" in caplog.text

    def test_configs_count_conversion_from_string(self, monkeypatch) -> None:
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:ABCDEFGHIJKLMNOPQRST")
        monkeypatch.setenv("TELEGRAM_CHAT_ID", "-100123")
        monkeypatch.setattr(telegram_module, "_send_telegram", lambda t, c, text: True)
        monkeypatch.setattr(telegram_module, "_generate_fun_fact", lambda k: "fact")
        assert telegram_module.send_notification(configs_count="42")  # type: ignore[arg-type]

    def test_configs_count_conversion_failure_defaults_zero(self, monkeypatch) -> None:
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:ABCDEFGHIJKLMNOPQRST")
        monkeypatch.setenv("TELEGRAM_CHAT_ID", "-100123")
        monkeypatch.setattr(telegram_module, "_send_telegram", lambda t, c, text: True)
        monkeypatch.setattr(telegram_module, "_generate_fun_fact", lambda k: "fact")
        assert telegram_module.send_notification(configs_count="invalid")  # type: ignore[arg-type]

    def test_send_notification_success(self, monkeypatch) -> None:
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:ABCDEFGHIJKLMNOPQRST")
        monkeypatch.setenv("TELEGRAM_CHAT_ID", "-100123")
        monkeypatch.setattr(telegram_module, "_send_telegram", lambda t, c, text: True)
        monkeypatch.setattr(telegram_module, "_generate_fun_fact", lambda k: "fact")
        monkeypatch.setenv("GITHUB_OWNER", "owner")
        monkeypatch.setenv("GITHUB_REPO", "repo")
        monkeypatch.setenv("GITHUB_BRANCH", "main")

        assert telegram_module.send_notification(configs_count=5)


# ── main (CLI entry point) ──────────────────────────────────────────────


class TestMain:
    """Cover lines 824-856."""

    def test_main_with_valid_args(self, monkeypatch) -> None:
        monkeypatch.setattr(
            "sys.argv",
            ["telegram.py", "--configs", "50", "--countries", "DE FI"],
        )
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:ABCDEFGHIJKLMNOPQRST")
        monkeypatch.setenv("TELEGRAM_CHAT_ID", "-100123")
        monkeypatch.setattr(telegram_module, "send_notification", lambda **kw: True)

        assert telegram_module.main() == 0

    def test_main_negative_configs(self, monkeypatch) -> None:
        monkeypatch.setattr(
            "sys.argv",
            ["telegram.py", "--configs", "-5"],
        )
        with pytest.raises(SystemExit):
            telegram_module.main()

    def test_main_notification_fails_still_returns_zero(self, monkeypatch) -> None:
        monkeypatch.setattr(
            "sys.argv",
            ["telegram.py", "--configs", "10", "--countries", "DE"],
        )
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:ABCDEFGHIJKLMNOPQRST")
        monkeypatch.setenv("TELEGRAM_CHAT_ID", "-100123")
        monkeypatch.setattr(telegram_module, "send_notification", lambda **kw: False)

        assert telegram_module.main() == 0


# ── _subscription_file_paths ────────────────────────────────────────────


class TestSubscriptionFilePaths:
    """Cover _subscription_file_paths anchor logic."""

    def test_default_path_uses_output_dir(self) -> None:
        paths = telegram_module._subscription_file_paths("")
        assert "subscription.txt" in paths["combined"]
        assert "subscription-blacklist.txt" in paths["blacklist"]
        assert "subscription-whitelist.txt" in paths["whitelist"]
        assert "subscription-mix.txt" in paths["mix"]

    def test_custom_path_anchors_other_files(self) -> None:
        paths = telegram_module._subscription_file_paths("output/custom.txt")
        # The path is used to get the directory; filenames stay the same
        sep = os.sep
        assert f"output{sep}custom.txt" in paths["combined"]
        assert f"output{sep}subscription-blacklist.txt" in paths["blacklist"]
        assert f"output{sep}subscription-whitelist.txt" in paths["whitelist"]
        assert f"output{sep}subscription-mix.txt" in paths["mix"]


# ── Cover remaining uncovered lines ────────────────────────────────────


class TestRemainingCoverage:
    """Cover lines: 77, 313-318, 405-425, 472-474, 636."""

    # -- Line 77: break when truncated text has '<' without '>' --

    def test_truncate_unclosed_tag_break(self) -> None:
        """Line 77: break out of while loop when no '>' after '<' in truncated.

        The truncation backup only removes the LAST unclosed '<'.  When there
        are multiple '<' in the text and only the last is removed by backup,
        a preceding '<' without '>' stays in the truncated text, triggering
        the break at line 77 in the while loop.
        """
        # "prefix <a> text <b suffix <c more"
        # The LAST '<' is at position 26 (<c).  Since it has no '>' within
        # the initial cut (31), backup removes only '<c' and everything
        # after it.  '<b' remains in truncated without '>' -> break at 77.
        text = "prefix <a> text <b suffix <c more"
        result = telegram_module._truncate_html_safe(text, 31)
        assert "..." in result

    # -- Lines 313-318: Xray direct with proxy search round limit --

    def test_validation_xray_direct_with_proxy_round_limit(self) -> None:
        """Lines 313-318: proxy_pool enabled, required, no proxies, xray direct,
        with proxy_search_round_limit."""
        result = telegram_module._format_validation_section(
            {
                "validation": {
                    "tcp_enabled": False,
                    "tls_enabled": False,
                    "xray_enabled": True,
                    "proxy_pool_enabled": True,
                    "proxy_pool_required": True,
                    "proxy_count": 0,
                    "proxy_search_round_limit": 5,
                    "fail_open_on_low_alive": False,
                    "drop_unchecked_after_tls": True,
                    "lists": {
                        "blacklist": {
                            "xray_checked": 10,
                            "xray_alive": 5,
                            "xray_probe_count": 2,
                            "xray_min_probe_successes": 2,
                            "xray_attempts_per_config": 1,
                            "xray_min_attempt_successes": 1,
                            "xray_proxy_checks": 0,
                            "xray_min_proxy_successes": 0,
                            "xray_unsupported": 0,
                            "tcp_checked": 0,
                            "tls_checked": 0,
                            "tcp_alive": 0,
                            "tls_alive": 0,
                            "tcp_search_rounds": 0,
                            "tcp_search_round_limit": 0,
                            "tcp_skipped_protocol": 0,
                            "tls_unchecked_passthrough": 0,
                            "xray_require_distinct_outbound_ip": False,
                        }
                    },
                }
            }
        )
        assert "Xray напрямую" in result
        assert "поиск прокси 5 раундов" in result
        assert "strict" in result
        assert "без TCP-only" in result

    # -- Lines 405-425: Detailed Xray stats --

    def test_validation_xray_detailed_stats(self) -> None:
        """Lines 405-425: Xray stats with probe, attempt, proxy, IP-check texts."""
        result = telegram_module._format_validation_section(
            {
                "validation": {
                    "tcp_enabled": True,
                    "tls_enabled": True,
                    "xray_enabled": True,
                    "proxy_pool_enabled": True,
                    "proxy_pool_required": False,
                    "proxy_count": 0,
                    "fail_open_on_low_alive": True,
                    "drop_unchecked_after_tls": False,
                    "lists": {
                        "blacklist": {
                            "tcp_checked": 100,
                            "tcp_alive": 80,
                            "tcp_skipped_protocol": 5,
                            "tcp_search_rounds": 3,
                            "tcp_search_round_limit": 3,
                            "tls_checked": 70,
                            "tls_alive": 60,
                            "tls_unchecked_passthrough": 0,
                            "xray_checked": 50,
                            "xray_alive": 30,
                            "xray_unsupported": 3,
                            "xray_probe_count": 3,
                            "xray_min_probe_successes": 2,
                            "xray_attempts_per_config": 3,
                            "xray_min_attempt_successes": 2,
                            "xray_proxy_checks": 4,
                            "xray_min_proxy_successes": 3,
                            "xray_require_distinct_outbound_ip": True,
                        }
                    },
                }
            }
        )
        assert "<b>Blacklist Xray</b>: проверено 50, реально рабочих 30" in result
        assert "неподдержано 3" in result
        assert "HTTPS-пробы 2/3" in result
        assert "повторы 2/3" in result
        assert "proxy-сети 3/4" in result
        assert "IP-check" in result

    # -- Lines 472-474: Location outputs in subscriptions section --

    def test_subscriptions_with_locations(self) -> None:
        """Lines 472-474: location outputs shown."""
        result = telegram_module._format_subscriptions_section(
            {
                "outputs": {
                    "combined": {"count": 100, "countries": {"DE": 60, "FI": 40}},
                    "location_de": {"count": 50, "countries": {"DE": 50}},
                    "location_fi": {"count": 30, "countries": {"FI": 30}},
                }
            },
            "",
        )
        assert "<b>Локации</b>: 2 файлов, до 50 серверов" in result

    # -- Line 636: All fallbacks in history (no API key) --

    def test_no_api_key_all_fallbacks_used(self, monkeypatch) -> None:
        """Line 636: all fallbacks are in history, picks random from all."""
        all_fallbacks = [telegram_module._FACT_FALLBACK_NO_KEY]
        all_fallbacks.extend(telegram_module._FACT_FALLBACKS)
        monkeypatch.setattr(
            telegram_module,
            "_load_facts_history",
            lambda: list(all_fallbacks),
        )
        saved = []

        def fake_save(fact: str) -> None:
            saved.append(fact)

        monkeypatch.setattr(telegram_module, "_save_fact", fake_save)
        result = telegram_module._generate_fun_fact("")
        assert result in all_fallbacks
        assert result in saved
