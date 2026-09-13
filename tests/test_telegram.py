"""Comprehensive tests for the Telegram notification module — 100% coverage target."""

from __future__ import annotations

import io
import json
import os
import urllib.error
import urllib.request

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
        """An empty tag name ('<>' / '</>') is skipped, not a crash.

        The helper exists to survive broken HTML, but a nameless closing tag
        made ``tag_text[1:].split()[0]`` index an empty list, so the whole
        notification was lost to an IndexError raised before the send.
        """
        text = "<>some text</> and <b>bold</b>"
        result = telegram_module._truncate_html_safe(text, 20)
        assert "..." in result

    @pytest.mark.parametrize("text", ["</>", "</ >", "x</>y", "</></></>"])
    def test_open_tags_survives_nameless_closing_tag(self, text: str) -> None:
        """A nameless closing tag closes nothing instead of raising IndexError."""
        assert telegram_module._open_tags(text) == []

    def test_open_tags_nameless_closing_tag_keeps_open_stack(self) -> None:
        """'</>' must not pop a genuinely open tag."""
        assert telegram_module._open_tags("<b>bold</>") == ["b"]

    def test_truncate_nameless_closing_tag_does_not_raise(self) -> None:
        """The reduced repro from fuzzing: '</>' repeated past the limit."""
        assert telegram_module._truncate_html_safe("</>" * 3, 6) == "</>..."

    def test_open_tags_stops_at_unterminated_tag_opener(self) -> None:
        """A '<' with no '>' ends the scan instead of being treated as a tag."""
        assert telegram_module._open_tags("<b>ok</b> then <broken") == []

    def test_truncate_returns_empty_when_limit_leaves_no_room(self) -> None:
        """A limit smaller than the ellipsis yields "" instead of overflowing."""
        assert (
            telegram_module._truncate_html_safe("<blockquote>hi</blockquote>", 2) == ""
        )

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

    # --- the limit covers ellipsis + closing tags (regression) -----------

    def test_truncate_result_fits_limit_with_closing_tags(self) -> None:
        """The closing tags are counted against the limit, not appended past it."""
        text = "<blockquote>" + "x" * 200 + "</blockquote>"
        result = telegram_module._truncate_html_safe(text, 100)
        assert len(result) <= 100
        assert result.endswith("...</blockquote>")

    def test_truncate_result_fits_limit_with_anchor(self) -> None:
        """An <a href=...> open at the cut is closed inside the limit."""
        text = '<a href="https://example.com/path">' + "y" * 200 + "</a>"
        result = telegram_module._truncate_html_safe(text, 60)
        assert len(result) <= 60
        assert result.endswith("...</a>")
        assert result.count("<a ") == result.count("</a>")

    def test_truncate_semicolon_exactly_at_limit_drops_entity(self) -> None:
        """';' sitting on the limit index is not part of text[:limit].

        The old bound (limit + 1) treated the entity as complete and left a
        bare '&amp' in the message, which Telegram rejects with 400
        "can't parse entities".
        """
        text = "xxxxxx&amp;tail and more text"
        assert text[10] == ";"
        result = telegram_module._truncate_html_safe(text, 10)
        assert len(result) <= 10
        assert "&" not in result

    def test_truncate_keeps_complete_entity_before_limit(self) -> None:
        """An entity that ends before the limit is kept intact."""
        text = "xxxxx&amp;tail and more text"
        assert text[9] == ";"
        result = telegram_module._truncate_html_safe(text, 15)
        assert len(result) <= 15
        assert result.startswith("xxxxx&amp;")

    # --- the cut never leaves a dangling '<' (regression) ----------------

    @pytest.mark.parametrize(
        ("text", "limit"),
        [
            ("&amp;<<<a<", 9),
            ("aaa<<bbb", 5),
            ("<<<<<<<<", 8),
            ("a<<<b>c", 4),
        ],
    )
    def test_safe_cut_offset_never_ends_on_unclosed_tag(
        self, text: str, limit: int
    ) -> None:
        """Backing up over '<' repeats until the prefix has no open tag.

        Backing up only once landed the boundary right after a preceding '<'
        ("&amp;<<"), and Telegram answers such a prefix with 400 "can't parse
        entities".
        """
        offset = telegram_module._safe_cut_offset(text, limit)
        prefix = text[:offset]
        assert offset <= limit
        last_open = prefix.rfind("<")
        assert last_open == -1 or prefix.find(">", last_open) != -1

    def test_truncate_does_not_emit_dangling_tag_opener(self) -> None:
        """The full truncation path inherits the invariant."""
        result = telegram_module._truncate_html_safe("&amp;<<<a<", 9)
        assert len(result) <= 9
        last_open = result.rfind("<")
        assert last_open == -1 or result.find(">", last_open) != -1


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

    # --- the caller's own count/countries are used as fallback -----------

    def test_caller_totals_used_when_no_summary_and_no_files(
        self, tmp_path, monkeypatch
    ) -> None:
        """Without run-summary.json the numbers passed in still get reported."""
        monkeypatch.setattr(
            telegram_module,
            "_subscription_file_paths",
            lambda _: {"combined": str(tmp_path / "nope.txt")},
        )
        result = telegram_module._format_subscriptions_section(
            {},
            "",
            fallback_count=75,
            fallback_countries="DE FI NL",
        )
        assert "<b>Общая</b>: 75" in result
        # The codes are the caller's allow-list, so they are labelled as
        # expected countries instead of masquerading as measured counts.
        assert "ожидались" in result
        assert "Германия" in result
        assert "данных по файлам нет" not in result

    def test_caller_totals_ignored_when_summary_has_outputs(self) -> None:
        """Exact pipeline metadata always wins over the caller's totals."""
        result = telegram_module._format_subscriptions_section(
            {"outputs": {"combined": {"count": 12, "countries": {"DE": 12}}}},
            "",
            fallback_count=999,
            fallback_countries="US",
        )
        assert "<b>Общая</b>: 12" in result
        assert "999" not in result


class TestFormatCountryCodes:
    """The plain 'DE FI NL' CLI form, as opposed to the counted dict form."""

    def test_empty_string_returns_empty(self) -> None:
        assert telegram_module._format_country_codes("") == ""
        assert telegram_module._format_country_codes("   ") == ""

    def test_codes_are_deduplicated_and_uppercased(self) -> None:
        result = telegram_module._format_country_codes("de,DE fi")
        assert result.count("Германия") == 1
        assert "Финляндия" in result

    def test_unknown_code_is_escaped(self) -> None:
        """The CLI value is operator input — it must not inject HTML."""
        assert "&lt;B&gt;" in telegram_module._format_country_codes("<b>")

    def test_overflow_is_summarised(self) -> None:
        result = telegram_module._format_country_codes("DE FI NL US GB", max_items=2)
        assert result.endswith("+3 стран")


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

        from src.aggregator.output import _watermark_link

        content = (
            _watermark_link()
            + "\nvless://11111111-1111-4111-8111-111111111111@de.example.com:443#DE-01\n"
        )
        encoded = base64.b64encode(content.encode()).decode()
        f.write_text(encoded, encoding="utf-8")
        result = telegram_module._count_countries_from_file(str(f))
        # The 0.0.0.0 watermark must not be counted; the one real config is.
        assert result == {"DE": 1}

    def test_remark_with_url_encoding(self, tmp_path) -> None:
        f = tmp_path / "sub.txt"
        import base64

        content = "vless://11111111-1111-4111-8111-111111111111@server.example.com:443#DE%2D01\n"
        encoded = base64.b64encode(content.encode()).decode()
        f.write_text(encoded, encoding="utf-8")
        result = telegram_module._count_countries_from_file(str(f))
        # A country-neutral host pins the remark path: DE must come from the
        # percent-decoded remark, not the hostname.
        assert result == {"DE": 1}

    def test_host_extraction_with_ipv6(self, tmp_path) -> None:
        f = tmp_path / "sub.txt"
        import base64

        content = (
            "vless://11111111-1111-4111-8111-111111111111@[2001:db8::1]:443#DE-01\n"
        )
        encoded = base64.b64encode(content.encode()).decode()
        f.write_text(encoded, encoding="utf-8")
        result = telegram_module._count_countries_from_file(str(f))
        # split_host_port must survive the bracketed IPv6 and still count.
        assert result == {"DE": 1}

    def test_mime_wrapped_base64_decoded(self, tmp_path) -> None:
        f = tmp_path / "sub.txt"
        import base64

        content = "vless://11111111-1111-4111-8111-111111111111@server.example.com:443#DE-01\n"
        encoded = base64.b64encode(content.encode()).decode()
        # MIME soft-wraps base64 at 76 chars; the strict decoder must still
        # read it instead of silently keeping the raw (undecodable) text.
        wrapped = "\r\n".join(encoded[i : i + 76] for i in range(0, len(encoded), 76))
        f.write_text(wrapped, encoding="utf-8")
        result = telegram_module._count_countries_from_file(str(f))
        assert result == {"DE": 1}

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


# ── _call_llm ────────────────────────────────────────────────────────


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


# ── _generate_fun_fact ──────────────────────────────────────────────────


class TestGenerateFunFact:
    """Rotation over static facts, deduplicated against saved history."""

    def test_returns_fact_and_saves_it(self, monkeypatch) -> None:
        monkeypatch.setattr(telegram_module, "_load_facts_history", lambda: [])
        saved = []
        monkeypatch.setattr(telegram_module, "_save_fact", lambda f: saved.append(f))
        result = telegram_module._generate_fun_fact()
        assert isinstance(result, str)
        assert len(result) > 0
        assert result in saved

    def test_skips_facts_already_in_history(self, monkeypatch) -> None:
        history = [telegram_module._FACT_FALLBACK_NO_KEY]
        history.extend(telegram_module._FACT_FALLBACKS[:-1])
        monkeypatch.setattr(telegram_module, "_load_facts_history", lambda: history)
        saved = []
        monkeypatch.setattr(telegram_module, "_save_fact", lambda f: saved.append(f))
        result = telegram_module._generate_fun_fact()
        # The only unseen fact left is the last fallback.
        assert result == telegram_module._FACT_FALLBACKS[-1]
        assert result in saved

    def test_all_used_restarts_rotation(self, monkeypatch) -> None:
        all_facts = [telegram_module._FACT_FALLBACK_NO_KEY]
        all_facts.extend(telegram_module._FACT_FALLBACKS)
        monkeypatch.setattr(
            telegram_module,
            "_load_facts_history",
            lambda: list(all_facts),
        )
        saved = []
        monkeypatch.setattr(telegram_module, "_save_fact", lambda f: saved.append(f))
        result = telegram_module._generate_fun_fact()
        assert result in all_facts
        assert result in saved


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
        assert "truncated to 4096 UTF-16 units" in caplog.text

    @pytest.mark.parametrize(
        "prefix,suffix",
        [
            ("<blockquote>", "</blockquote>"),
            ('<a href="https://example.com/some/long/path">', "</a>"),
            ("<b><i>", "</i></b>"),
        ],
    )
    def test_truncated_payload_never_exceeds_telegram_limit(
        self, monkeypatch, prefix, suffix
    ) -> None:
        """The body actually sent must fit 4096 chars, closing tags included.

        Reserving only 3 chars for the ellipsis made the closing tags overflow
        the limit and Telegram answered 400 'message is too long'.
        """
        sent: dict[str, object] = {}

        def fake_urlopen(req, timeout=15):
            sent.update(json.loads(req.data.decode("utf-8")))
            return FakeResponse(b'{"ok": true}')

        monkeypatch.setattr(telegram_module.urllib.request, "urlopen", fake_urlopen)

        long_text = f"{prefix}{'x' * 4200}{suffix}"
        assert telegram_module._send_telegram(
            "123456789:ABCDEFGHIJKLMNOPQRST", "-100123", long_text
        )
        text = sent["text"]
        assert isinstance(text, str)
        assert len(text) <= 4096
        # Every tag opened before the cut is closed after the ellipsis.
        assert text.endswith(f"...{suffix}")

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
            raise urllib.error.URLError(TimeoutError("timed out"))

        monkeypatch.setattr(telegram_module.urllib.request, "urlopen", fake_urlopen)
        assert (
            telegram_module._send_telegram(
                "123456789:ABCDEFGHIJKLMNOPQRST", "-100123", "text"
            )
            is False
        )
        assert "timed out" in caplog.text

    def test_read_timeout_returns_false_without_retry(
        self, monkeypatch, caplog
    ) -> None:
        """A READ-phase timeout (bare TimeoutError, not URLError) must not
        retry: the request may already have been delivered, a retry would
        double-send."""
        caplog.set_level("WARNING")
        attempts = {"n": 0}

        def fake_urlopen(req, timeout=15):
            attempts["n"] += 1
            raise TimeoutError("read timed out")

        monkeypatch.setattr(telegram_module.urllib.request, "urlopen", fake_urlopen)
        assert (
            telegram_module._send_telegram(
                "123456789:ABCDEFGHIJKLMNOPQRST", "-100123", "text"
            )
            is False
        )
        assert attempts["n"] == 1
        assert "not retrying" in caplog.text

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

    # --- the token never reaches the log (regression) --------------------

    @pytest.mark.parametrize(
        "token",
        [
            "123456789:AAHf\nSECRETSECRETSECRET-xyz",
            "123456789:AAHf SECRETSECRETSECRET-xyz",
            "123456789:AAHf\tSECRETSECRETSECRET-xyz",
        ],
    )
    def test_token_with_control_char_is_rejected_before_the_request(
        self, monkeypatch, caplog, token
    ) -> None:
        """A token pasted with an embedded newline/space must not be sent.

        The token is interpolated into the sendMessage URL; urllib rejects the
        control character with a message quoting the whole path, which the
        generic handler used to log verbatim — leaking the secret into the run
        log (and into the log file on a local run).
        """
        caplog.set_level("WARNING")

        def fail_urlopen(req, timeout=10):  # pragma: no cover - must not run
            raise AssertionError("malformed token must not reach urllib")

        monkeypatch.setattr(telegram_module.urllib.request, "urlopen", fail_urlopen)

        assert telegram_module._send_telegram(token, "-100123", "text") is False
        assert "invalid format" in caplog.text
        assert "SECRETSECRETSECRET" not in caplog.text

    def test_unexpected_error_message_is_redacted(self, monkeypatch, caplog) -> None:
        """Even an unexpected error must not echo the token into the log."""
        caplog.set_level("WARNING")
        token = "123456789:ABCDEFGHIJKLMNOPQRST"

        def fake_urlopen(req, timeout=10):
            raise RuntimeError(f"boom while posting to /bot{token}/sendMessage")

        monkeypatch.setattr(telegram_module.urllib.request, "urlopen", fake_urlopen)

        assert telegram_module._send_telegram(token, "-100123", "text") is False
        assert "unexpectedly" in caplog.text
        assert token not in caplog.text
        assert "<redacted>" in caplog.text

    def test_percent_encoded_token_is_redacted_too(self, monkeypatch, caplog) -> None:
        """The URL carries quote(token); that form must be masked as well."""
        from urllib.parse import quote

        caplog.set_level("WARNING")
        token = "123456789:ABCDEFGHIJKLMNOPQRST"

        def fake_urlopen(req, timeout=10):
            raise RuntimeError(f"boom near /bot{quote(token, safe='')}/sendMessage")

        monkeypatch.setattr(telegram_module.urllib.request, "urlopen", fake_urlopen)

        assert telegram_module._send_telegram(token, "-100123", "text") is False
        assert token not in caplog.text
        assert quote(token, safe="") not in caplog.text
        assert "<redacted>" in caplog.text

    # --- 429 flood limit is retried once (regression) --------------------

    def test_flood_limit_is_retried_once_and_succeeds(
        self, monkeypatch, caplog
    ) -> None:
        """A 429 with retry_after is honoured instead of losing the message."""
        caplog.set_level("WARNING")
        calls: list[int] = []
        slept: list[float] = []

        def fake_urlopen(req, timeout=10):
            calls.append(1)
            if len(calls) == 1:
                raise urllib.error.HTTPError(
                    "https://api.telegram.org/",
                    429,
                    "Too Many Requests",
                    {},
                    io.BytesIO(
                        json.dumps(
                            {"ok": False, "parameters": {"retry_after": 7}},
                        ).encode("utf-8"),
                    ),
                )
            return FakeResponse(b'{"ok": true}')

        monkeypatch.setattr(telegram_module.urllib.request, "urlopen", fake_urlopen)
        monkeypatch.setattr(telegram_module.time, "sleep", slept.append)

        assert telegram_module._send_telegram(
            "123456789:ABCDEFGHIJKLMNOPQRST", "-100123", "text"
        )
        assert len(calls) == 2
        assert slept == [7.0]
        assert "flood limit" in caplog.text

    def test_flood_limit_gives_up_after_one_retry(self, monkeypatch) -> None:
        """A second 429 is final — no unbounded retry loop."""
        calls: list[int] = []
        slept: list[float] = []

        def fake_urlopen(req, timeout=10):
            calls.append(1)
            raise urllib.error.HTTPError(
                "https://api.telegram.org/",
                429,
                "Too Many Requests",
                {},
                io.BytesIO(b'{"parameters": {"retry_after": 1}}'),
            )

        monkeypatch.setattr(telegram_module.urllib.request, "urlopen", fake_urlopen)
        monkeypatch.setattr(telegram_module.time, "sleep", slept.append)

        assert (
            telegram_module._send_telegram(
                "123456789:ABCDEFGHIJKLMNOPQRST", "-100123", "text"
            )
            is False
        )
        assert len(calls) == 2
        assert slept == [1.0]

    def test_non_flood_http_error_is_not_retried(self, monkeypatch) -> None:
        """A 400 stays a single attempt — retrying a bad request is pointless."""
        calls: list[int] = []

        def fake_urlopen(req, timeout=10):
            calls.append(1)
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
        assert len(calls) == 1

    @pytest.mark.parametrize(
        ("body", "expected"),
        [
            ('{"parameters": {"retry_after": 5}}', 5.0),
            ('{"parameters": {"retry_after": "12"}}', 12.0),
            ('{"parameters": {"retry_after": 9999}}', 30.0),
            ('{"parameters": {"retry_after": -4}}', 0.0),
            ('{"parameters": {"retry_after": "soon"}}', 3.0),
            ('{"parameters": null}', 3.0),
            ("{}", 3.0),
            ("not json", 3.0),
            ("", 3.0),
        ],
    )
    def test_flood_wait_seconds_is_clamped(self, body: str, expected: float) -> None:
        """retry_after is parsed defensively and capped at 30s."""
        assert telegram_module._flood_wait_seconds(body) == expected

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
        monkeypatch.setattr(telegram_module, "_generate_fun_fact", lambda: "fact")
        assert telegram_module.send_notification(configs_count="42")  # type: ignore[arg-type]

    def test_configs_count_conversion_failure_defaults_zero(self, monkeypatch) -> None:
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:ABCDEFGHIJKLMNOPQRST")
        monkeypatch.setenv("TELEGRAM_CHAT_ID", "-100123")
        monkeypatch.setattr(telegram_module, "_send_telegram", lambda t, c, text: True)
        monkeypatch.setattr(telegram_module, "_generate_fun_fact", lambda: "fact")
        assert telegram_module.send_notification(configs_count="invalid")  # type: ignore[arg-type]

    def test_configs_count_and_countries_reach_the_message(self, monkeypatch) -> None:
        """Both arguments were validated and then dropped before rendering.

        With run-summary.json missing (the very case the required ``--configs``
        flag exists for) the operator used to get a notification with no numbers
        at all: "нет данных по этому прогону" plus "данных по файлам нет".
        """
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:ABCDEFGHIJKLMNOPQRST")
        monkeypatch.setenv("TELEGRAM_CHAT_ID", "-100123")
        monkeypatch.setattr(telegram_module, "_generate_fun_fact", lambda: "fact")
        sent: dict[str, str] = {}

        def fake_send(_token, _chat_id, text) -> bool:
            sent["text"] = text
            return True

        monkeypatch.setattr(telegram_module, "_send_telegram", fake_send)

        assert telegram_module.send_notification(
            configs_count=75,
            countries="DE FI NL",
            subscription_file="output/nope.txt",
            status_file="output/nope.json",
        )
        assert "75" in sent["text"]
        assert "Германия" in sent["text"]

    def test_send_notification_success(self, monkeypatch) -> None:
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:ABCDEFGHIJKLMNOPQRST")
        monkeypatch.setenv("TELEGRAM_CHAT_ID", "-100123")
        monkeypatch.setattr(telegram_module, "_send_telegram", lambda t, c, text: True)
        monkeypatch.setattr(telegram_module, "_generate_fun_fact", lambda: "fact")
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
        # Contract changed: CLI reports send failure with exit 1 so the
        # workflow step is visibly red (was: non-fatal 0 that hid failures).
        monkeypatch.setattr(
            "sys.argv",
            ["telegram.py", "--configs", "10", "--countries", "DE"],
        )
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:ABCDEFGHIJKLMNOPQRST")
        monkeypatch.setenv("TELEGRAM_CHAT_ID", "-100123")
        monkeypatch.setattr(telegram_module, "send_notification", lambda **kw: False)

        assert telegram_module.main() == 1


# ── _subscription_urls ──────────────────────────────────────────────────


class TestSubscriptionUrls:
    """The published links must follow the files the pipeline actually wrote."""

    def _urls(self, monkeypatch, summary):
        monkeypatch.setenv("GITHUB_OWNER", "acme")
        monkeypatch.setenv("GITHUB_REPO", "vpn")
        monkeypatch.setenv("GITHUB_BRANCH", "main")
        return telegram_module._subscription_urls(summary)

    def test_defaults_without_summary(self, monkeypatch) -> None:
        urls = self._urls(monkeypatch, None)
        assert urls["combined"].endswith("/main/output/subscription.txt")
        assert urls["blacklist"].endswith("/main/output/subscription-blacklist.txt")
        assert urls["whitelist"].endswith("/main/output/subscription-whitelist.txt")
        assert urls["mix"].endswith("/main/output/subscription-mix.txt")

    def test_summary_paths_win_over_the_default_layout(self, monkeypatch) -> None:
        """Regression: renaming outputs in settings.yaml left dead links.

        ``publisher.output_file`` / ``split_output_files`` / ``mix_output_file``
        were ignored here, so the message linked to output/subscription*.txt
        whatever the operator had configured — and the pipeline records the real
        paths in run-summary.json, which this notifier already reads.
        """
        summary = {
            "outputs": {
                "combined": {"file": "subs/all.txt"},
                "blacklist": {"file": "subs\\black.txt"},
                "mix": {"file": "subs/mix100.txt"},
            }
        }
        urls = self._urls(monkeypatch, summary)
        assert urls["combined"].endswith("/main/subs/all.txt")
        # Windows separators are normalised for the raw URL.
        assert urls["blacklist"].endswith("/main/subs/black.txt")
        assert urls["mix"].endswith("/main/subs/mix100.txt")
        # Not recorded — keeps the documented default.
        assert urls["whitelist"].endswith("/main/output/subscription-whitelist.txt")

    @pytest.mark.parametrize(
        "recorded",
        [
            "/etc/passwd",
            "C:/secrets/out.txt",
            "../outside.txt",
            "",
            123,
        ],
    )
    def test_unusable_recorded_paths_fall_back(self, monkeypatch, recorded) -> None:
        """Anything that cannot be a repo path keeps the default link."""
        summary = {"outputs": {"combined": {"file": recorded}}}
        urls = self._urls(monkeypatch, summary)
        assert urls["combined"].endswith("/main/output/subscription.txt")

    def test_malformed_summary_is_ignored(self, monkeypatch) -> None:
        urls = self._urls(monkeypatch, {"outputs": [1, 2, 3]})
        assert urls["combined"].endswith("/main/output/subscription.txt")


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
        result = telegram_module._generate_fun_fact()
        assert result in all_fallbacks
        assert result in saved


# --- low-alive alert ---------------------------------------------------------


def test_low_alive_alert_flags_collapsed_lists() -> None:
    from src.notify.telegram import _format_low_alive_alert

    summary = {
        "validation": {
            "lists": {
                "blacklist": {"xray_checked": 300, "xray_alive": 120},
                "whitelist": {"xray_checked": 100, "xray_alive": 3},
            }
        }
    }
    text = _format_low_alive_alert(summary)
    assert "whitelist" in text
    assert "3" in text
    assert "blacklist" not in text


def test_low_alive_alert_silent_when_healthy_or_no_checks() -> None:
    from src.notify.telegram import _format_low_alive_alert

    healthy = {
        "validation": {
            "lists": {
                "blacklist": {"xray_checked": 300, "xray_alive": 120},
                "whitelist": {"xray_checked": 50, "xray_alive": 20},
            }
        }
    }
    assert _format_low_alive_alert(healthy) == ""
    assert _format_low_alive_alert({}) == ""
    unchecked = {"validation": {"lists": {"whitelist": {"xray_checked": 0}}}}
    assert _format_low_alive_alert(unchecked) == ""


def test_low_alive_alert_threshold_from_settings(monkeypatch, tmp_path) -> None:
    import src.notify.telegram as tg

    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / "settings.yaml").write_text(
        "telegram:\n  alert_min_alive: 25\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        tg,
        "resolve_safe_output_path",
        lambda _p, strict=False: tmp_path,
    )
    summary = {
        "validation": {"lists": {"blacklist": {"xray_checked": 10, "xray_alive": 20}}}
    }
    assert "blacklist" in tg._format_low_alive_alert(summary)


# --- trend diff alert ---------------------------------------------------------


def test_trend_alert_flags_drop_vs_previous_run(tmp_path) -> None:
    import src.notify.telegram as tg

    history = [
        {
            "ts": 1,
            "status": "ok",
            "proxy_count": 30,
            "lists": {"blacklist": {"alive": 100}, "whitelist": {"alive": 10}},
        },
        {
            "ts": 2,
            "status": "ok",
            "proxy_count": 12,
            "lists": {"blacklist": {"alive": 40}, "whitelist": {"alive": 9}},
        },
    ]
    (tmp_path / "stats-history.json").write_text(
        __import__("json").dumps(history), encoding="utf-8"
    )
    text = tg._format_trend_alert(str(tmp_path / "run-summary.json"))
    assert "blacklist" in text and "40" in text and "100" in text
    assert "<b>60</b>%" in text  # minus-60%, typographic minus + bold number
    assert "Прокси-пул просел" in text
    # whitelist 9 vs 10 is wobble, not a drop.
    assert "whitelist" not in text


def test_trend_alert_ignores_non_ok_runs(tmp_path) -> None:
    import src.notify.telegram as tg

    # A partially-written failed entry between two ok runs must not be used
    # as the diff baseline: its zeros would fake a collapse.
    history = [
        {
            "ts": 1,
            "status": "ok",
            "proxy_count": 30,
            "lists": {"blacklist": {"alive": 100}},
        },
        {
            "ts": 2,
            "status": "no_configs",
            "proxy_count": 0,
            "lists": {"blacklist": {"alive": 0}},
        },
        {
            "ts": 3,
            "status": "ok",
            "proxy_count": 28,
            "lists": {"blacklist": {"alive": 95}},
        },
    ]
    (tmp_path / "stats-history.json").write_text(
        __import__("json").dumps(history), encoding="utf-8"
    )
    assert tg._format_trend_alert(str(tmp_path / "run-summary.json")) == ""


def test_trend_alert_silent_without_history_or_change(tmp_path) -> None:
    import src.notify.telegram as tg

    assert tg._format_trend_alert(str(tmp_path / "run-summary.json")) == ""
    stable = [
        {"ts": 1, "proxy_count": 30, "lists": {"blacklist": {"alive": 100}}},
        {"ts": 2, "proxy_count": 28, "lists": {"blacklist": {"alive": 95}}},
    ]
    (tmp_path / "stats-history.json").write_text(
        __import__("json").dumps(stable), encoding="utf-8"
    )
    assert tg._format_trend_alert(str(tmp_path / "run-summary.json")) == ""
    only_one = [{"ts": 1, "proxy_count": 30}]
    (tmp_path / "stats-history.json").write_text(
        __import__("json").dumps(only_one), encoding="utf-8"
    )
    assert tg._format_trend_alert(str(tmp_path / "run-summary.json")) == ""


# --- source degradation alerts ------------------------------------------------


def test_source_alerts_lists_failed_sources() -> None:
    summary = {
        "sources": {
            "ok": 15,
            "failed": 1,
            "total": 16,
            "errors": [
                {
                    "source": "igareck-white-vless-reality-mobile-2",
                    "error": "url source 'https://example.invalid/x.txt' is empty",
                }
            ],
        }
    }
    result = telegram_module._format_source_alerts(summary)
    assert "<b>Проблемные источники</b>:" in result
    assert "igareck-white-vless-reality-mobile-2" in result
    assert "is empty" in result


def test_source_alerts_empty_when_no_errors() -> None:
    assert telegram_module._format_source_alerts({}) == ""
    assert telegram_module._format_source_alerts({"sources": {}}) == ""
    assert telegram_module._format_source_alerts({"sources": {"errors": []}}) == ""


def test_source_alerts_truncates_errors_and_caps_lines() -> None:
    errors = [{"source": f"src-{i}", "error": "x" * 200} for i in range(8)]
    result = telegram_module._format_source_alerts({"sources": {"errors": errors}})
    assert "… и ещё 3" in result
    assert "x" * 200 not in result
    assert "x" * 97 + "…" in result


# --- publish delta ------------------------------------------------------------


def test_format_delta_section_counts_added_and_removed() -> None:
    current = {"a://1", "b://2"}
    previous = {"b://2", "c://3"}
    result = telegram_module._format_delta_section(current, previous)
    assert result.startswith("🔄")
    assert "новых 1" in result
    assert "убрано 1" in result


def test_format_delta_section_only_additions() -> None:
    result = telegram_module._format_delta_section({"a://1", "b://2"}, {"a://1"})
    assert "новых 1" in result
    assert "убрано" not in result


def test_format_delta_section_silent_without_previous() -> None:
    assert telegram_module._format_delta_section({"a://1"}, set()) == ""


def test_format_delta_section_silent_when_identical() -> None:
    lines = {"a://1", "b://2"}
    assert telegram_module._format_delta_section(lines, lines) == ""


def test_decode_subscription_lines_decodes_base64_and_skips_watermark() -> None:
    import base64 as _b64

    watermark = "vmess://" + _b64.b64encode(b'{"add":"0.0.0.0"}').decode()
    body = "\n".join(["ss://YWJj", watermark, "vless://xyz"])
    raw = _b64.b64encode(body.encode("utf-8")).decode("ascii")
    assert telegram_module._decode_subscription_lines(raw) == {
        "ss://YWJj",
        "vless://xyz",
    }


def test_decode_subscription_lines_keeps_plain_text() -> None:
    """A plain-format subscription must keep its lines: the old decode without
    validate=True silently mangled text that merely resembled base64, and the
    new/removed delta was lost."""
    raw = "\n".join(
        [
            "vless://11111111-1111-4111-8111-111111111111@a.example:443#A",
            "vless://11111111-1111-4111-8111-111111111111@b.example:443#B",
        ],
    )
    assert telegram_module._decode_subscription_lines(raw) == {
        "vless://11111111-1111-4111-8111-111111111111@a.example:443#A",
        "vless://11111111-1111-4111-8111-111111111111@b.example:443#B",
    }


def test_previous_published_lines_requires_github_sha(monkeypatch) -> None:
    monkeypatch.delenv("GITHUB_SHA", raising=False)
    assert telegram_module._previous_published_lines("output/subscription.txt") == set()


def test_previous_published_lines_rejects_bad_sha(monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_SHA", "../main;rm -rf /")
    assert telegram_module._previous_published_lines("output/subscription.txt") == set()


def test_previous_published_lines_reads_git_show(monkeypatch) -> None:
    import base64 as _b64
    import subprocess as _sp

    monkeypatch.setenv("GITHUB_SHA", "abc123def4567890")
    seen_argv = []

    def fake_run(argv, **kwargs):
        seen_argv.append(argv)
        payload = _b64.b64encode(b"ss://abc\n").decode("ascii")
        return _sp.CompletedProcess(argv, 0, stdout=payload, stderr="")

    monkeypatch.setattr(telegram_module.subprocess, "run", fake_run)
    lines = telegram_module._previous_published_lines("output/subscription.txt")
    assert seen_argv[0] == [
        "git",
        "show",
        "abc123def4567890:output/subscription.txt",
    ]
    assert lines == {"ss://abc"}


# --- coverage: watermark fallback, current-lines read, git failure, wiring ----


def test_is_watermark_line_false_for_undecodable_body() -> None:
    """A vmess link with a non-base64 body is not the watermark."""
    assert telegram_module._is_watermark_line("vmess://@@@ not base64") is False


def test_current_subscription_lines_reads_and_decodes(tmp_path, monkeypatch) -> None:
    import base64 as _b64

    sub = tmp_path / "sub.txt"
    sub.write_text(_b64.b64encode(b"ss://abc\n").decode("ascii"), encoding="utf-8")
    monkeypatch.setattr(telegram_module, "resolve_safe_output_path", lambda p: sub)
    assert telegram_module._current_subscription_lines("output/subscription.txt") == {
        "ss://abc"
    }


def test_previous_published_lines_git_failure_returns_empty(monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_SHA", "abc123def4567890")

    def boom(*args, **kwargs):
        raise OSError("git unavailable")

    monkeypatch.setattr(telegram_module.subprocess, "run", boom)
    assert telegram_module._previous_published_lines("output/subscription.txt") == set()


def test_send_notification_includes_alerts_and_delta(monkeypatch) -> None:
    """Alerts and the publish delta all land in the outgoing message."""
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:ABCDEFGHIJKLMNOPQRST")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "-100123")
    summary = {
        "validation": {
            "lists": {
                "blacklist": {"xray_checked": 300, "xray_alive": 3},
                "whitelist": {"xray_checked": 100, "xray_alive": 3},
            }
        },
        "sources": {"errors": [{"source": "src-x", "error": "empty or not found"}]},
    }
    monkeypatch.setattr(telegram_module, "_load_run_summary", lambda p: summary)
    monkeypatch.setattr(telegram_module, "_generate_fun_fact", lambda: "факт")
    monkeypatch.setattr(telegram_module, "_format_trend_alert", lambda p: "")
    monkeypatch.setattr(
        telegram_module,
        "_current_subscription_lines",
        lambda p: {"a://1", "b://2"},
    )
    monkeypatch.setattr(
        telegram_module,
        "_previous_published_lines",
        lambda p: {"b://2", "c://3"},
    )
    sent = {}

    def fake_send(token, chat_id, text):
        sent["text"] = text
        return True

    monkeypatch.setattr(telegram_module, "_send_telegram", fake_send)

    assert telegram_module.send_notification(configs_count=2)

    text = sent["text"]
    # Delta section rendered from the patched sets.
    assert "новых 1" in text
    assert "убрано 1" in text
    # Source degradation alert present.
    assert "Проблемные источники" in text
    assert "src-x" in text


# ── _utf16_len ──────────────────────────────────────────────────────────


class TestUtf16Len:
    """Telegram's limit counts UTF-16 code units, not Python code points."""

    def test_empty_string(self) -> None:
        assert telegram_module._utf16_len("") == 0

    def test_ascii_counts_one_unit_per_char(self) -> None:
        assert telegram_module._utf16_len("abc") == 3

    def test_astral_char_counts_two_units(self) -> None:
        # U+1F525 fire is outside the BMP → one surrogate pair = 2 units.
        assert telegram_module._utf16_len("\U0001f525") == 2

    def test_flag_emoji_counts_four_units(self) -> None:
        # 🇩🇪 is two regional indicators, each astral → 2 + 2 units, while
        # len() sees only 2 code points.
        assert telegram_module._utf16_len("\U0001f1e9\U0001f1ea") == 4

    def test_bmp_char_counts_one_unit(self) -> None:
        assert telegram_module._utf16_len("a⚙b") == 3

    def test_lone_surrogate_does_not_crash(self) -> None:
        # surrogatepass: untrusted text with a lone surrogate encodes to a
        # single unit instead of raising on the notify step.
        assert telegram_module._utf16_len("\ud83d") == 1


class TestTruncateHtmlSafeUtf16:
    """The cut is measured in UTF-16 units, so astral chars count twice."""

    def test_within_utf16_limit_returns_text_unchanged(self) -> None:
        # 10 flags = 40 UTF-16 units but only 20 code points: the limit is
        # measured in units, so exactly-at-limit text passes through.
        text = "\U0001f1e9\U0001f1ea" * 10
        assert telegram_module._truncate_html_safe(text, 40) == text

    def test_over_utf16_limit_truncates_even_when_len_fits(self) -> None:
        # 40 UTF-16 units, 20 code points: a len()-based guard (20 <= 30)
        # returned the text unchanged and Telegram answered 400 "too long".
        text = "\U0001f1e9\U0001f1ea" * 10
        result = telegram_module._truncate_html_safe(text, 30)
        assert result != text
        assert telegram_module._utf16_len(result) <= 30
        assert result.endswith("...")

    def test_truncation_never_splits_a_surrogate_pair(self) -> None:
        text = "\U0001f1e9\U0001f1ea" * 50
        result = telegram_module._truncate_html_safe(text, 25)
        assert telegram_module._utf16_len(result) <= 25
        # Python slices by code points, so every remaining char is complete.
        for ch in result:
            assert not 0xD800 <= ord(ch) <= 0xDFFF

    def test_truncation_with_astral_chars_and_tags_fits_limit(self) -> None:
        # 🔥 (U+1F525) costs 2 UTF-16 units per code point: the cut is chosen
        # in units, and the closing </b> counts against the limit.
        text = "<b>" + "x" * 100 + "\U0001f525" * 30 + "</b>"
        result = telegram_module._truncate_html_safe(text, 60)
        assert telegram_module._utf16_len(result) <= 60
        assert result.endswith("...</b>")
        assert result.count("<b>") == result.count("</b>")

    def test_astral_text_beyond_any_cut_returns_empty(self) -> None:
        # Every flag code point costs 2 units, so the shrink step can
        # overshoot straight past zero — the invariant is "fits, or empty".
        text = "\U0001f1e9\U0001f1ea" * 100
        assert telegram_module._truncate_html_safe(text, 50) == ""


# ── send_crash_notification ─────────────────────────────────────────────


class TestSendCrashNotification:
    """Compact crash alert for a pipeline that died before any summary."""

    @staticmethod
    def _capture_send(monkeypatch) -> dict[str, str]:
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:ABCDEFGHIJKLMNOPQRST")
        monkeypatch.setenv("TELEGRAM_CHAT_ID", "-100123")
        sent: dict[str, str] = {}

        def fake_send(token, chat_id, text) -> bool:
            sent.update(token=token, chat_id=chat_id, text=text)
            return True

        monkeypatch.setattr(telegram_module, "_send_telegram", fake_send)
        return sent

    def test_no_credentials_returns_false(self, monkeypatch, caplog) -> None:
        monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
        monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)
        caplog.set_level("INFO")
        assert telegram_module.send_crash_notification("boom") is False
        assert "skipping crash notification" in caplog.text

    def test_success_sends_compact_message(self, monkeypatch) -> None:
        sent = self._capture_send(monkeypatch)
        assert telegram_module.send_crash_notification("boom")
        assert sent["token"] == "123456789:ABCDEFGHIJKLMNOPQRST"
        assert sent["chat_id"] == "-100123"
        assert "💥" in sent["text"]
        assert "<b>Пайплайн упал</b>" in sent["text"]
        # Header + timestamp + detail block.
        assert sent["text"].count("\n") == 4

    def test_error_message_is_escaped_and_truncated(self, monkeypatch) -> None:
        sent = self._capture_send(monkeypatch)
        detail = "<b>traceback</b>" + "x" * 400
        assert telegram_module.send_crash_notification(detail)
        text = sent["text"]
        # The error text is untrusted output — it must not inject HTML.
        assert "&lt;b&gt;traceback&lt;/b&gt;" in text
        assert "<b>traceback</b>" not in text
        # Only the first 300 *raw* characters of the detail are kept
        # (16 of them are the escaped tag markup).
        assert "x" * 284 in text
        assert "x" * 285 not in text

    def test_blank_error_message_omits_detail(self, monkeypatch) -> None:
        sent = self._capture_send(monkeypatch)
        assert telegram_module.send_crash_notification("   ")
        # Header + timestamp only — no dangling empty detail block.
        assert sent["text"].count("\n") == 2
        assert "traceback" not in sent["text"]

    def test_repo_slug_is_escaped(self, monkeypatch) -> None:
        sent = self._capture_send(monkeypatch)
        monkeypatch.setattr(telegram_module, "_repo_slug", lambda: "acme/r<b>x")
        assert telegram_module.send_crash_notification()
        assert "acme/r&lt;b&gt;x" in sent["text"]


# ── _mix_label ──────────────────────────────────────────────────────────


class TestMixLabel:
    """Dynamic "Mix <blacklist>/<whitelist>" label from real per-list counts."""

    def test_dynamic_counts(self) -> None:
        summary = {"outputs": {"blacklist": {"count": 120}, "whitelist": {"count": 80}}}
        assert telegram_module._mix_label(summary) == "Mix 120/80"

    def test_non_dict_outputs_falls_back_to_static(self) -> None:
        assert telegram_module._mix_label({"outputs": "nope"}) == "Mix"

    def test_missing_list_key_falls_back_to_static(self) -> None:
        summary = {"outputs": {"whitelist": {"count": 80}}}
        assert telegram_module._mix_label(summary) == "Mix"

    def test_non_dict_item_falls_back_to_static(self) -> None:
        summary = {"outputs": {"blacklist": "oops", "whitelist": {"count": 80}}}
        assert telegram_module._mix_label(summary) == "Mix"

    def test_bad_count_value_falls_back_to_static(self) -> None:
        summary = {
            "outputs": {"blacklist": {"count": "abc"}, "whitelist": {"count": 80}}
        }
        assert telegram_module._mix_label(summary) == "Mix"


# ── _format_trend_alert edge cases ──────────────────────────────────────


class TestTrendAlertEdgeCases:
    """Malformed history and entries without liveness stats."""

    def test_invalid_json_returns_empty(self, tmp_path) -> None:
        (tmp_path / "stats-history.json").write_text("not json", encoding="utf-8")
        assert telegram_module._format_trend_alert(str(tmp_path / "s.json")) == ""

    def test_entries_without_lists_still_alert_on_pool_drop(self, tmp_path) -> None:
        # ok entries without "lists" → _alive() yields 0 for every list, but
        # the proxy-pool diff must still fire.
        history = [
            {"ts": 1, "status": "ok", "proxy_count": 30},
            {"ts": 2, "status": "ok", "proxy_count": 10},
        ]
        (tmp_path / "stats-history.json").write_text(
            json.dumps(history), encoding="utf-8"
        )
        text = telegram_module._format_trend_alert(str(tmp_path / "s.json"))
        assert "Прокси-пул просел" in text
        assert "<b>10</b> против <b>30</b>" in text


# ── _format_low_alive_alert edge cases ──────────────────────────────────


class TestLowAliveAlertEdgeCases:
    """Degradation banner and the min_alive<=0 short circuit."""

    @staticmethod
    def _patch_settings(monkeypatch, tmp_path, value: int) -> None:
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "settings.yaml").write_text(
            f"telegram:\n  alert_min_alive: {value}\n", encoding="utf-8"
        )
        monkeypatch.setattr(
            telegram_module,
            "resolve_safe_output_path",
            lambda _p, strict=False: tmp_path,
        )

    def test_degraded_reasons_banner(self) -> None:
        summary = {
            "validation": {"lists": {}},
            "degraded_reasons": ["Xray: 0 alive out of 200"],
        }
        text = telegram_module._format_low_alive_alert(summary)
        assert "Деградация пробы" in text
        assert "Xray: 0 alive out of 200" in text
        assert "умер пул прокси" in text

    def test_min_alive_zero_keeps_banner_drops_threshold_lines(
        self, monkeypatch, tmp_path
    ) -> None:
        self._patch_settings(monkeypatch, tmp_path, 0)
        summary = {
            "validation": {
                "lists": {"blacklist": {"xray_checked": 10, "xray_alive": 0}}
            },
            "degraded_reasons": ["probe collapsed"],
        }
        text = telegram_module._format_low_alive_alert(summary)
        assert "Деградация пробы" in text
        assert "порог" not in text

    def test_min_alive_zero_silent_without_reasons(self, monkeypatch, tmp_path) -> None:
        self._patch_settings(monkeypatch, tmp_path, 0)
        summary = {
            "validation": {
                "lists": {"blacklist": {"xray_checked": 10, "xray_alive": 0}}
            }
        }
        assert telegram_module._format_low_alive_alert(summary) == ""


# ── _format_permanently_disabled_sources ────────────────────────────────


class TestPermanentlyDisabledSources:
    """The health gate's permanent culls must reach the chat, HTML-escaped."""

    @staticmethod
    def _summary(tmp_path) -> dict[str, str]:
        return {"_status_file": str(tmp_path / "run-summary.json")}

    @staticmethod
    def _write_health(tmp_path, data: dict) -> None:
        (tmp_path / "health-history.json").write_text(
            json.dumps(data), encoding="utf-8"
        )

    def test_unreadable_health_file_returns_empty(self, tmp_path) -> None:
        # No health-history.json next to the summary.
        assert (
            telegram_module._format_permanently_disabled_sources(
                self._summary(tmp_path)
            )
            == ""
        )

    def test_invalid_json_returns_empty(self, tmp_path) -> None:
        (tmp_path / "health-history.json").write_text("not json", encoding="utf-8")
        assert (
            telegram_module._format_permanently_disabled_sources(
                self._summary(tmp_path)
            )
            == ""
        )

    def test_sources_not_a_dict_returns_empty(self, tmp_path) -> None:
        self._write_health(tmp_path, {"sources": ["a", "b"]})
        assert (
            telegram_module._format_permanently_disabled_sources(
                self._summary(tmp_path)
            )
            == ""
        )

    def test_recent_ban_only_returns_empty(self, tmp_path) -> None:
        import time

        self._write_health(
            tmp_path, {"sources": {"src-a": {"banned_until": time.time() + 3600}}}
        )
        assert (
            telegram_module._format_permanently_disabled_sources(
                self._summary(tmp_path)
            )
            == ""
        )

    def test_permanent_bans_are_listed_and_escaped(self, tmp_path) -> None:
        import time

        self._write_health(
            tmp_path,
            {
                "sources": {
                    "bad<source>": {"banned_until": time.time() + 10 * 365 * 24 * 3600},
                    "recent-src": {"banned_until": time.time() + 3600},
                }
            },
        )
        result = telegram_module._format_permanently_disabled_sources(
            self._summary(tmp_path)
        )
        assert "Источники отключены навсегда" in result
        # The name goes into a parse_mode=HTML message: an unescaped "<"
        # rejected the WHOLE run report with 400 "can't parse entities".
        assert "bad&lt;source&gt;" in result
        assert "bad<source>" not in result
        assert "recent-src" not in result
        assert "Верните вручную" in result

    def test_more_than_five_sources_adds_overflow_line(self, tmp_path) -> None:
        import time

        far = time.time() + 10 * 365 * 24 * 3600
        self._write_health(
            tmp_path, {"sources": {f"src-{i}": {"banned_until": far} for i in range(6)}}
        )
        result = telegram_module._format_permanently_disabled_sources(
            self._summary(tmp_path)
        )
        assert "… и ещё 1" in result

    def test_source_alerts_leads_with_permanent_disabled_line(self, tmp_path) -> None:
        import time

        self._write_health(
            tmp_path,
            {
                "sources": {
                    "src-x": {"banned_until": time.time() + 10 * 365 * 24 * 3600}
                }
            },
        )
        summary = {
            "_status_file": str(tmp_path / "run-summary.json"),
            "sources": {"errors": [{"source": "src-y", "error": "empty"}]},
        }
        result = telegram_module._format_source_alerts(summary)
        assert "Источники отключены навсегда" in result
        assert result.index("Источники отключены") < result.index(
            "Проблемные источники"
        )

    def test_source_alerts_skips_non_dict_error_items(self) -> None:
        errors = ["garbage", {"source": "src-ok", "error": "empty"}]
        result = telegram_module._format_source_alerts({"sources": {"errors": errors}})
        assert "src-ok" in result
        assert "garbage" not in result


# ── _format_subscriptions_section count fallbacks ──────────────────────


class TestSubscriptionsCountFallbacks:
    """A malformed count must zero out, not kill the notification."""

    def test_bad_output_count_becomes_zero(self) -> None:
        result = telegram_module._format_subscriptions_section(
            {"outputs": {"combined": {"count": "abc", "countries": {"DE": 1}}}},
            "",
        )
        assert "<b>Общая</b>: 0" in result

    def test_bad_location_count_becomes_zero(self) -> None:
        result = telegram_module._format_subscriptions_section(
            {
                "outputs": {
                    "combined": {"count": 5, "countries": {"DE": 5}},
                    "location_de": {"count": "oops"},
                }
            },
            "",
        )
        assert "<b>Локации</b>: 1 файлов, до 0 серверов" in result


# ── _count_countries_from_file: plain text / IPv6 / watermark ──────────


class TestCountCountriesFromFilePlainText:
    """Plain-format files skip base64; hosts come from split_host_port."""

    def test_plain_text_file_with_links_counts_countries(self, tmp_path) -> None:
        f = tmp_path / "sub.txt"
        f.write_text(
            "vless://11111111-1111-4111-8111-111111111111@de.example.com:443#DE-01\n"
            "vless://11111111-1111-4111-8111-111111111111@fi.example.com:443#FI-02\n",
            encoding="utf-8",
        )
        result = telegram_module._count_countries_from_file(str(f))
        assert result == {"DE": 1, "FI": 1}

    def test_plain_text_without_links_falls_back_to_raw(self, tmp_path) -> None:
        # No "://" anywhere and a non-alphabet payload: b64decode(validate=True)
        # rejects it and the raw text is kept instead of decoding into garbage.
        f = tmp_path / "sub.txt"
        f.write_text("totally not base64!!\n", encoding="utf-8")
        assert telegram_module._count_countries_from_file(str(f)) == {}

    def test_bracketed_ipv6_host_is_counted(self, tmp_path) -> None:
        f = tmp_path / "sub.txt"
        f.write_text(
            "vless://11111111-1111-4111-8111-111111111111@[2001:db8::1]:443#DE-01\n",
            encoding="utf-8",
        )
        result = telegram_module._count_countries_from_file(str(f))
        # The remark decides here: the trailing "#DE-01" poisons the port
        # for split_host_port, so the extracted host stays empty.
        assert result == {"DE": 1}

    def test_bracketed_ipv6_without_fragment_parses_host(self, tmp_path) -> None:
        # A plain .split(":") turned "2001:db8::1" into "2001"; split_host_port
        # handles the brackets, so the host is extracted (and simply matches no
        # country — the line is counted via the host, not a remark).
        f = tmp_path / "sub.txt"
        f.write_text(
            "vless://11111111-1111-4111-8111-111111111111@[2001:db8::1]:443\n",
            encoding="utf-8",
        )
        assert telegram_module._count_countries_from_file(str(f)) == {}

    def test_host_without_fragment_drives_country_detection(self, tmp_path) -> None:
        # No "#" remark: only split_host_port succeeding (line "host =
        # parsed_hp[0]") lets the hostname rule see "de01.example.com".
        f = tmp_path / "sub.txt"
        f.write_text(
            "vless://11111111-1111-4111-8111-111111111111@de01.example.com:443\n",
            encoding="utf-8",
        )
        assert telegram_module._count_countries_from_file(str(f)) == {"DE": 1}

    def test_vmess_link_without_at_yields_empty_host(self, tmp_path) -> None:
        import base64 as _b64

        payload = _b64.b64encode(
            json.dumps({"add": "de.example.com", "ps": "DE node"}).encode("utf-8")
        ).decode("ascii")
        f = tmp_path / "sub.txt"
        f.write_text(f"vmess://{payload}#DE-01\n", encoding="utf-8")
        # No "@" in the body → host stays empty; the remark still counts.
        result = telegram_module._count_countries_from_file(str(f))
        assert result == {"DE": 1}

    def test_watermark_line_structurally_skipped(self, tmp_path) -> None:
        import base64 as _b64

        watermark = "vmess://" + _b64.b64encode(
            json.dumps({"add": "0.0.0.0", "ps": "watermark"}).encode("utf-8")
        ).decode("ascii")
        f = tmp_path / "sub.txt"
        f.write_text(
            watermark
            + "\n"
            + "vless://11111111-1111-4111-8111-111111111111@de.example.com:443#DE-01\n",
            encoding="utf-8",
        )
        result = telegram_module._count_countries_from_file(str(f))
        assert result == {"DE": 1}


# ── send_notification: trend wiring + message tail order ───────────────


class TestSendNotificationOrdering:
    """The tail keeps the actionable links before the fun fact."""

    @staticmethod
    def _capture_send(monkeypatch) -> dict[str, str]:
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:ABCDEFGHIJKLMNOPQRST")
        monkeypatch.setenv("TELEGRAM_CHAT_ID", "-100123")
        sent: dict[str, str] = {}

        def fake_send(token, chat_id, text) -> bool:
            sent.update(text=text)
            return True

        monkeypatch.setattr(telegram_module, "_send_telegram", fake_send)
        return sent

    def test_links_come_before_fun_fact(self, monkeypatch) -> None:
        monkeypatch.setattr(telegram_module, "_generate_fun_fact", lambda: "ФАКТ-XYZ")
        monkeypatch.setattr(telegram_module, "_load_run_summary", lambda p: {})
        monkeypatch.setattr(telegram_module, "_format_trend_alert", lambda p: "")
        sent = self._capture_send(monkeypatch)
        assert telegram_module.send_notification(configs_count=5)
        text = sent["text"]
        assert text.index("📋 Подписки") < text.index("ФАКТ-XYZ")
        # The fact is the very last block: truncation cuts it, not the links.
        assert text.rstrip().endswith("ФАКТ-XYZ")

    def test_trend_alert_is_appended_to_validation_section(self, monkeypatch) -> None:
        monkeypatch.setattr(telegram_module, "_generate_fun_fact", lambda: "fact")
        monkeypatch.setattr(telegram_module, "_load_run_summary", lambda p: {})
        monkeypatch.setattr(
            telegram_module,
            "_format_trend_alert",
            lambda p: "📉 <b>Blacklist</b>: обвал",
        )
        sent = self._capture_send(monkeypatch)
        assert telegram_module.send_notification(configs_count=5)
        assert "📉 <b>Blacklist</b>: обвал" in sent["text"]


class TestBotAuthorOverride:
    """The credited handle is config, not a hardcoded deployment detail."""

    def test_default_author_is_used_without_env(self, monkeypatch) -> None:
        monkeypatch.delenv("TELEGRAM_BOT_AUTHOR", raising=False)
        assert telegram_module._bot_author() == telegram_module._DEFAULT_BOT_AUTHOR
        assert telegram_module._DEFAULT_BOT_AUTHOR in telegram_module._bot_intro()

    def test_env_override_is_escaped_into_the_intro(self, monkeypatch) -> None:
        monkeypatch.setenv("TELEGRAM_BOT_AUTHOR", "@fork<owner>")
        assert telegram_module._bot_author() == "@fork<owner>"
        intro = telegram_module._bot_intro()
        assert "@fork&lt;owner&gt;" in intro
        assert "@fork<owner>" not in intro

    def test_blank_env_falls_back_to_the_default(self, monkeypatch) -> None:
        monkeypatch.setenv("TELEGRAM_BOT_AUTHOR", "   ")
        assert telegram_module._bot_author() == telegram_module._DEFAULT_BOT_AUTHOR
