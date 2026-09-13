# Отчёт по исправлениям vpnparser

- **Проект:** `vpnparser` (repo root)
- **Дата основной сессии правок:** 2026-08-28
- **Среда:** Windows, Python 3.12.10, Xray `bin\xray.exe`, `geoip.dat`/`geosite.dat` на месте
- **Статус на момент завершения:** тесты `1873 passed / 1 skipped`, `ruff` чисто, `mypy` чисто (`58 source files`), `bandit` 0 issues

---

## 1. Начальное состояние (проблема)

Пользователь запустил vpnparser локально и обнаружил, что в **итоговой подписке оказывались мёртвые / N/A конфиги**, а также ряд мест, где пайплайн вёл себя небезопасно (fail-open, утечки, потеря данных).

Перед циклом правок полный прогон был зелёным, но содержал скрытые дефекты:
- `liveness.py` — пул required+пустой+xray выкл → возврат неотфильтрованного списка (fail-open).
- `fail_open_on_low_alive` по умолчанию `True`.
- Xray/Sing-box принимали HTTP-коды `200–400` (ошибки 3xx/4xx считались успехом).
- Подписки в формате gzip/zlib не распаковывались → 0 конфигов.
- SSRF-пути в пуле прокси и `api_base` GitHub не проверялись.
- `dedup_key` хэшировал credential только для REALITY (разные uuid сливались).
- Парсер shadowsocks искажал пароли (`errors="replace"`), публикация выдавала мёртвые (`is_alive=False`) конфиги.

---

## 2. Что исправлено (хронология)

### Предыдущие сессии (до 2026-08-28) — блок HIGH

| # | Файл | Суть исправления |
|---|------|------------------|
| H1 | `liveness.py`, `telegram.py` | `fail_open_on_low_alive` дефолт `True→False`; исправлена логика `not validation.get("fail_open_on_low_alive")` |
| H2 | `xray_probe.py`, `singbox_probe.py` | Коды ответа `200-400 → 200-299` (`_DEFAULT_ACCEPTED_STATUS_CODES`) |
| H3 | `subscription.py` | Декомпрессия zlib (wbits 15/-15/31) + gzip чанками, лимит `32 MiB` (`_MAX_DECOMPRESSED_BYTES`) |
| H4 | `proxy_pool.py` | SSRF-проверка редиректов по хосту + резолв публичности (`_resolve_host_public`, `_is_safe_redirect_url`) |
| H5 | `address_guard.py` | Канонизация IP-литералов (`inet_aton`, восьмеричн./hex/тай/точка-в-конце) |
| H6 | `country_filter.py` | `allowed=None → TypeError` (пустой список по-прежнему возвращает все) |
| H7 | `base.py` | `dedup_key` хэширует credential (`security|pbk|uuid|ss_method`) для ВСЕХ протоколов |
| H8 | `net.py` + xray/singbox/proxy_health/proxy_pool | `redact_proxy_url` — credential режутся в логах |

### 2026-08-28 — блок MEDIUM (M1–M7)

| # | Файл | Суть исправления |
|---|------|------------------|
| M1 | `aggregator/output.py` | Публикация пропускает `is_alive is False`; `None` сохраняется (passthrough для выключенной валидации) |
| M2 | `singbox_probe.py` | `verify_probe_tls` теперь пробрасывается в `singbox_probe_check` |
| M3 | `shadowsocks.py` | Строгий utf-8 декод (без `errors="replace`, портящего пароль); плагин сохраняется в `raw_link` |
| M4 | `sources/manager.py` | Gate вынесен за бюджет таймаута (очередь не списывается со здоровых источников) |
| M5 | `publisher/github.py`, `sources/github.py` | `api_base` валидируется (https + публичный хост) до отправки токена |
| M6 | `scheduler/runner.py` | Пол публикации `min_publish_configs` (дефолт 10) — пустая/около-пустая подписка не затирает рабочую |
| M7 | `scheduler/stages/liveness.py` | Все валидаторы выкл → конфиги помечаются `is_alive=False` (fail-closed, не публикуются непроверенные) |

Каждое исправление проверено **5 независимыми агентами** (чтение/функциональный тест/регрессия/линт-типы/безопасность) → все **PASS**.

---

## 3. Что добавлено (тесты)

- `test_xray_probe.py`, `test_singbox_probe.py`, `test_subscription*.py`, `test_proxy_pool.py`, `test_address_guard.py`, `test_country_filter.py`, `test_parsers.py`, `test_merger.py` — новые тесты на каждую правку.
- `test_aggregator_output.py::test_generate_plain_skips_dead_configs`
- `test_singbox_probe.py::test_validate_configs_singbox_forwards_verify_probe_tls`
- `test_parsers_regressions.py::test_strict_b64decode_rejects_non_utf8_payload`
- `test_sources_manager.py::test_fetch_direct_url_gate_time_excluded_from_budget`
- `test_publisher_github.py` / `test_sources_github.py` — проверки отказа на небезопасный `api_base`
- `test_runner_coverage.py` — `test_run_publish_floor_skips_subscription_below_min`, `test_run_publish_floor_disabled_when_min_zero`
- `test_liveness.py::test_all_disabled_marks_configs_not_alive` (заменил старый passthrough-тест)
- Исправлены регрессии: `test_used_keys_skipped` (из-за нового `dedup_key`), `test_bonus_interleave_default_matches_sort_cap` (из-за fail-closed «все выкл»).

Итог: с `1848 passed` (до цикла) до **`1873 passed, 1 skipped`**.

---

## 4. Что осталось (опционально, вне scope, не блокирует)

- **M4:** добавить внешний таймаут на захват gate (защита от редкого зависания пула).
- **M6:** per-split защита от пустого файла при `combined ≥ min`; статус `degraded` вместо `ok`, когда пол удержал публикацию.
- **M5:** DNS-pinning для `api_base` (защита от DNS-rebinding между проверкой и запросом — известное ограничение DNS-верификации SSRF).
- **M7 (замечание):** документация в `output.py` — `is_alive is None` описан как «validation disabled passthrough»; после M7 all-off даёт `False`, но частично-выкл режимы всё ещё дают `None`, так что описание корректно.

---

## 5. Что нужно проверить / сделать дальше

1. **Реальный прогон пайплайна** (с сетью и Xray):
   ```
   python -m src.main --run
   ```
   Подтвердить: подписка содержит только живые конфиги, нет N/A, файл публикуется только при `count >= min_publish_configs`.

2. **Коммит изменений.** Git в среде не установлен — нужно поставить git, затем:
   - закоммитить по логическим группам (HIGH / MEDIUM) с сообщениями на русском (`fix: ...`);
   - не коммитить `.env`, секреты, токены.

3. **Проверка настроек** `config/settings.local.yaml` — убедиться, что `validator.fail_open_on_low_alive: false` и включён хотя бы один валидатор (`tcp_enabled`/`tls_enabled`/`xray_enabled`), иначе по M7 все конфиги будут отброшены ( fail-closed ).

4. **Покрытие / линты по регламенту** (уже пройдены локально):
   ```
   python -m ruff check --no-cache src tests
   python -m mypy --no-incremental src
   python -m bandit -c pyproject.toml -r src
   python -m pytest -q -p no:cacheprovider
   ```

5. **Опциональные улучшения** из раздела 4 — по желанию пользователя.

---

## 6. Резюме

- Закрыта корневая причина «мёртвых/N-A» конфигов: пайплайн стал fail-closed там, где раньше был fail-open.
- Устранены реальные уязвимости: SSRF через редиректы пула, утечка GitHub-токена на непубличный `api_base`, публикация пустой подписки поверх рабочей, искажение паролей в shadowsocks.
- Все 8 HIGH + 7 MEDIUM исправлений верифицированы 5 агентами каждое → PASS.


## 7. Верификация внешнего security-ревью (агентский обзор)

Проверены и исправлены находки агентского ревью. Каждый блок верифицирован 5 агентами (PASS).

### P1 — proxy_pool: DNS-rebinding TOCTOU (высший приоритет)
- src/validators/proxy_pool.py: убраны per-hop name-проверки; добавлены _PinnedTarget, _host_literal, _safe_source_url, _pin_public_target. _fetch_source резолвит хост ровно один раз через resolve_global_ips (AF_UNSPEC, fail-closed) и коннектится к ЗАПИНЕННОМУ IP-литералу, сохраняя Host-заголовок и sni_hostname для https. Блокируется https->http downgrade. Закрыт TOCTOU-окно, поддержан IPv6, hop-0 теперь тоже резолвится.
- Тесты: test_proxy_pool.py (52 passed), добавлены refuses_internal_hostname_redirect, refuses_https_downgrade.

### P2 — runner: per-file wipeout (пустой split затирал рабочий файл)
- src/scheduler/runner.py: _filter_empty_subscription_slices + _is_empty_output_file. Пустой split/mix-слайс не публикуется поверх ранее рабочего файла, когда combined floor пройден.
- Тест: test_filter_empty_subscription_slices_skips_empty.

### P3 — пакет мелких правок
- subscription.py: убран невалидный max_length у zlib.decompress (убивал zlib/raw-deflate кандидаты); _b64_to_bytes теперь validate=True. + tests/test_subscription_parser.py (7 passed).
- address_guard.py: inet_aton не коерцит bare-десятичные < 0x1000000 в IP (идут в DNS), но 2130706433 (loopback) по-прежнему блокируется.
- shadowsocks.py: utf-8 decode errors=replace (конфиг не теряется).
- base.py: dedup_key — полный sha256 без [:8] (нет коллизий).
- net.py: regex redact non-greedy (хост не перезатирается при @ в пути).
- manager.py: _safe_error_message редактирует ВСЕ строки ошибки.
- github.py (publisher+sources): aclose сбрасывает _api_base_checked.

### Итог
- Полный прогон: 1882 passed, 1 skipped. ruff / mypy / bandit — чисто.
- Все 15 верификационных агентов: PASS.
