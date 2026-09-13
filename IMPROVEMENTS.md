# IMPROVEMENTS — что можно улучшить (по всем аспектам)

> СТАТУС: исторический план. Перечисленное ниже — исходные находки аудитов,
> актуальные статусы см. в CHANGELOG.md и разделе «Статус» в конце файла.

Сводка 8 аудитов (performance, architecture, security, observability, testing,
CI/packaging, robustness, config/docs). Приоритет: **P0** — влияет на корректность
публикации/безопасность; **P1** — заметно улучшает надёжность/качество; **P2** —
эргономика/документация/CI. Буква усилия: **S** (часы), **M** (дни), **L** (недели).

> Текущее состояние проверок: `ruff` clean, `mypy` success, `bandit` 0 issues,
> `pytest` 2094 passed / 1 skipped. Ниже — возможности для роста, не блокирующие.

---

## P0 — Корректность публикации и безопасность (сделать в первую очередь)

### R1. Torn-write основной подписки (риск «мёртвого» конфига)
`src/aggregator/output.py:236-244` (`write_subscription`) пишет temp + `os.replace`,
но **без `flush()`/`os.fsync()`** (в отличие от `utils/paths.write_text_atomic:198`).
При power-loss/kill-9 публикуется обрезанный base64 → конфиг не парсится.
**Фикс:** добавить `fh.flush(); os.fsync(fh.fileno())` перед `os.replace`. **S**

### R2. НЕ-атомарные записи Clash и plaintext-fallback
`src/aggregator/clash.py:216` и `src/scheduler/stages/write.py:476-487` пишут
через `open("w")` без temp/rename/fsync. Падение посреди записи → битый YAML/text
в репозитории. **Фикс:** пускать обе через `write_text_atomic`. **S**

### R3. Один запинённый адрес «убивает» multi-homed живой конфиг
`src/validators/address_guard.py:210-213` возвращает только `public[0]`;
`tcp_check.py:87` / `tls_check.py:195` коннектятся к нему одному (путь fetch
итерирует до `_MAX_PINNED_ADDRESSES`). Хост, у которого первый A/AAAA недоступен,
помечается мёртвым, хотя другой работает → ложноотрицательная живость (потеря
покрытия). **Фикс:** при `OSError` пробовать следующий запинённый адрес до
фейла. **M**

### R4. Non-UTF8 источник ломает round-trip `raw_link`
`src/utils/http.py:44` / `src/parsers/base.py:171` декодируют `errors="replace"`;
non-UTF8 пароль/remark превращается в U+FFFD, и опубликованная ссылка репарсится
в мёртвый конфиг. **Фикс:** хранить сырые байты или `surrogateescape`. **L**

### S1. LLM `api_base` не проходит SSRF-валидацию
`src/parsers/llm_fallback.py:132-142` — операторский `api_base` получает
`Bearer`-ключ, но не проверяется `is_safe_public_url` (в отличие от GitHub
publisher). Риск exfil-а при опечатке/компрометации. **Фикс:** валидировать
host через `is_safe_public_url` + https. **S**

### S2. Probe-URL пропускают public-host проверку
`src/validators/xray_probe.py:587-628` — операторские `probe_urls` могут
указывать на `https://169.254.169.254/...` (config-driven SSRF). **Фикс:**
требовать публичный host в `_is_https_probe_url`. **S**

### O1. Метрики/алерты игнорируют TCP/TLS (неправильные цифры)
`stats_history.py:62-64`, `runner.py:1096`, `telegram.py:538-582` —
`run_stats_entry` и алерты читают только `xray_*`. Когда Xray выключен
(частый случай), badge/stats показывают alive=0 навсегда, алерты не срабатывают.
**Фикс:** считать alive/checked по реально запущенному чеку (xray→tls→tcp). **M**

### O2. Exit 3 ложно маркирует empty-run
`main.py:342-343` — при пустом run публикация намеренно НЕ трогает прошлый
хороший файл, но неудача публикации там поднимает exit 3 («stale subscription»),
что в `OPERATIONS.md` трактуется как тревога. **Фикс:** возвращать 3 только
когда `count>0`. **S**

---

## P1 — Надёжность, производительность, архитектура

### PERF1. Per-config spawn Xray/sing-box subprocess
`xray_probe.py:847`, `singbox_probe.py:210` — каждый конфиг (и каждая попытка)
стартует целый процесс (~100–400мс). При `xray_concurrency=6` это доминирует в
прогоне (~2ч). **Фикс:** пул долгоживущих процессов с реконфигурацией outbound,
либо один multi-outbound инстанс. **L**

### PERF2. Избыточная TCP→TLS→Xray ревалидация
`liveness.py:748,930,1050` — один и тот же сервер TCP-коннектится, TLS-хендшейк,
затем Xray (который сам делает TLS+HTTP). TLS для `is_xray_supported` протоколов
полностью покрывается Xray. **Фикс:** при `xray_enabled` пропускать standalone
TCP/TLS для поддерживаемых; TCP/TLS оставить как дёшевый префильтр для
proxy-only run-ов. **M**

### PERF3. Повторное DNS-резолвление по стадиям
`tcp_check.py:87`, `tls_check.py:195`, `xray_probe.py:967` резолвят каждый
конфиг 3–4×. **Фикс:** кешировать запинённый IP на `Config` (раз в run). **S**

### PERF4. `dedup_key` считается (sha256) при каждом доступе
`base.py:69` вызывается в `deduplicate`, `merger`, `liveness` для тысяч конфигов.
**Фикс:** считать один раз, кешировать в атрибут/cached_property. **S**

### PERF5. `discover_public_ip` на каждый пул-прокси каждый run
`xray_probe.py:1039` — `gather` прощупывает identity-endpoint раз на прокси.
**Фикс:** кешировать direct/proxy public IP на run. **S**

### PERF6. `tcp_search_rounds` (def 3) × candidate_limit (1000)
`liveness.py:775-783` — до ~3000 TCP-проверок до Xray. **Фикс:** при последующей
Xray-ревалидации `tcp_search_rounds=1` + ранняя остановка по `tcp_max_alive`. **S**

### ARCH1. Runner — God-object (1426 строк, ~40 методов)
`src/scheduler/runner.py:56` + лезет во внутренности Aggregator
(`_whitelist_balance:677`, `_build_mixed_output:685`, `_take_unique_configs:694`).
**Фикс:** вынести `output_writer.py`, `publisher.py`, `run_summary.py`,
`health_state.py`; дать Aggregator публичный API. **L**

### ARCH2. Две реализации SSRF-pinned fetch
`sources/manager.py:133,522,586` vs `validators/proxy_pool.py:99,165,217` —
дублирующая критичная логика (guard + redirect). Риск расхождения.
**Фикс:** вынести в `src/utils/ssrf_fetch.py`. **L**

### ARCH3. Stringly-typed settings
`settings.py:79` — dict; вызовы `section("x").get("y")` строками по 9 файлам
(runner:153, aggregate:39, liveness:653…). **Фикс:** типизированные датаклассы
(`AggregatorSettings`, `ValidatorSettings`). **M**

### ARCH4. Две агрегационные тропы
`runner.py:666 _preprocess_configs` vs `:696 _process_configs` (sort/limit ещё
в `aggregate.py`) — риск расхождения. **Фикс:** вести обе через Aggregator. **M**

### ARCH5. Liveness stage bloat (1571 строк)
`stages/liveness.py:60` — бан/скоринг-хелперы (`health_ban_min_alive:653,1499`)
вынессти в `quality_policy.py`. **M**

### O3. Нет структурированного (JSON) логирования
`main.py:94-117` — plaintext мешает CI/dashboard парсингу. **Фикс:** env-gated
JSON-форматтер. **L**

### O4. run-summary без CI-friendly alive%
`runner.py:1068-1075` — добавить `validation.alive_total/checked_total/alive_pct`. **M**

### O5. Лог-шум per-list TCP round
`liveness.py:817-823` — INFO на раунд/лист. **Фикс:** DEMOTE в DEBUG. **S**

---

## P1 — Тестирование (закрыть реальные дыры)

### T1. Hypothesis не используется
`pyproject.toml:41` объявлен, но ни один тест не импортирует. Парсеры не имеют
fuzz-тестов на malformed input. **Фикс:** `@given` round-trip для vmess/vless/
trojan/ss. **L**

### T2. Нет E2E со ВСЕМИ валидаторами вместе
Все `run()`-тесты мокают валидаторы по отдельности. **Фикс:** один интеграционный
run, связывающий tcp/tls/xray/proxy_pool/address_guard на фейках. **L**

### T3. Per-file floor только unit-уровень
`test_runner_coverage.py:935` тестит `_filter_empty_subscription_slices`
изолированно; нет регрессии через реальный `_publish_files`. **Фикс:** добавить
publish-stage регрессию. **M**

### T4. GitHub publisher flow gaps
`test_publisher_github.py` мокает одиночные PUT, но не `publish_files`/commit/
branch и не взаимодействие с per-file floor при сбое. **M**

### T5. Дедупликация фикстур
`_make_config/_mk/make_config/_make_runner` переопределены в ≥8 файлах.
**Фикс:** вынести в `conftest.py`. **M**

### T6. proxy_pool pin cap не покрыт
`_MAX_PINNED_ADDRESSES=4` + `_pin_public_target` не тестированы с >4 адресами.
**Фикс:** тест на усечение капа. **S**

### T7. Медленные/flaky без разметки
`test_liveness.py` (3198), `test_pipeline_helpers.py` (2687), `test_xray_probe.py`
(2453) — нет `@pytest.mark.slow`; 52с рискуют CI-таймаут. **M**

---

## P2 — CI/CD, упаковка, безопасность сборки

### C1. Нет console entry point
`pyproject.toml` нет `[project.scripts]` — `vpnparser` недоступен после установки,
только `python -m src.main`. **Фикс:** `scripts = {"vpnparser" = "src.main:main"}`. **S**

### C2. `src.` layout ломает установленный wheel
`setuptools.packages.find` (pyproject.toml:57) «сплющивает» `src`, `import src.main`
падает из wheel. **Фикс:** `package-dir`/mapping или плоский layout. **M/L**

### C3. Unpinned зависимости
pyproject.toml:27-34 — только lower bounds; невоспроизводимый CI. **Фикс:**
upper caps или lockfile (`uv.lock`). **M**

### C4. Binary discovery ломается после установки
`xray_probe.py:84` `_PROJECT_ROOT = parents[2]` резолвится в site-packages;
закоммиченный `bin/xray.exe` не находится. **Фикс:** resource/data-dir lookup. **L**

### C5. Нет build/verify в CI
ни `ci.yml`, ни `update.yml` не гонят `python -m build`/`twine check`. **S**

### C6. Lint/type/security только на 3.12
`ci.yml:30,55,111` игнорируют 3.11/3.13 при наличии их в matrix. **S**

### C7. Крупный бинарь в git
`bin/xray.exe` закоммичен; лучше fetch (как `update.yml`) или Git LFS. **M**

### C8. sha256 только для linux
`.github/xray.sha256`/`singbox.sha256` пинят linux; Windows/macOS не проверяются. **S**

### SEC3. Supply-chain: нет hash-pinned deps
`pyproject.toml` — риск компрометации зависимости. **Фикс:** hash-pinning/lockfile. **M**

---

## P2 — Config/UX и документация

### D1. Тихие опечатки ключей settings
`settings.py:90` — неизвестный ключ молча игнорируется и падает на дефолт
(может выключить валидацию fail-open). **Фикс:** warning на неизвестный ключ. **M**

### D2. README config table неполная
`README.md:179-199` — нет `xray_probe_via_proxies`, `xray_proxy_probe_count`,
`xray_min_proxy_successes`, `verification_ttl_minutes`, `singbox_*`, `tcp_search_rounds`,
`xray_startup_timeout_seconds`, `proxy_pool.*`. Документировать. **M**

### D3. Расхождение дефолтов doc/code
`README.md:187` пишет `proxy_attempts_per_config` = 3, код = 5 (`liveness.py:440`).
Поправить. **S**

### D4. Недокументированные ключи
`xray_executable` (liveness.py:1062), `singbox_executable` (1095),
`xray_probe_url` (1169) читаются, но нет в settings.yaml/README. **S**

### D5. CLI фичи вне README
`main.py --help`: `--revalidate-published`, `--continuous`, `--notify` не в
`README.md:154-171`. Добавить строки. **S**

### D6. Нет walkthrough для proxy pool
`README.md:41-55` / `docs/OPERATIONS.md:54-75` описывают поведение, но не
настройку/ротацию источников пула. Добавить раздел. **M**

### D7. Нет примера минимального settings
`config/settings.local.yaml` существует, но не задокументирован. Добавить
аннотированный пример. **S**

### D8. Тонкий docs по GitHub token scope
`.env.example:8` — добавить fine-grained альтернативу и кросс-репо publish. **S**

---

## Быстрые выигрыши (S), рекомендованные первыми
R1, R2, S1, S2, O2, O5, PERF3, PERF4, PERF5, PERF6, C1, C5, C6, C8, D3, D4, D5, D7, D8, T6.
Эти правки малы, не меняют архитектуру и закрывают большинство рисков публикации
«мёртвого» конфига и оставшихся SSRF-дыр.

ВНИМАНИЕ: список выше исторический — **все перечисленные пункты уже выполнены**
(R1 fsync в output.py, R2 write_text_atomic в clash.py, S1 SSRF-проверки в
llm_fallback, R3 multi-homed fallback через resolve_pinned_addresses в
tcp/tls_check, C1/C2 пакетинг+entry point, PERF3-6 кеши/пины, D3-D5/ D7-D8
доки и CLI). См. актуальный статус ниже и CHANGELOG.md.

---

## Статус (обновлено 2026-09)

Снимок выше — исторический план. Уже выполнено (не ищите их в списке как открытые):

- **R1** (torn-write) — `utils/paths.write_text_atomic` + fsync в `aggregator/output.py`.
- **R2** (не-атомарная запись Clash) — `aggregator/clash.py` идёт через `write_text_atomic`.
- **S1** (SSRF `api_base` LLM) — sync-валидация в конструкторе + runtime
  `is_safe_public_url` в `_call_api` (`parsers/llm_fallback.py`).
- **D7** — `config/settings.local.yaml` удалён: это был мёртвый fail-open форк
  `settings.yaml`, покрыт `.gitignore`.
- **C1/C2** частично — консольная точка входа добавлена (см. pyproject), пакет
  собирается как `src*`.
- **T6** (proxy pool pin cap), **PERF3/PERF4/PERF5/PERF6**, **R3** (multi-homed configs через resolve_pinned_addresses), **S2**, **O2/O5** — выполнены.
- Все P0-баги аудита 2026-09 (CI exit-code, publish 25 МБ health-history,
  refill прокси-пула, дедуп, L3 DNS-pinning, 429, `%3D`, UTF-16 в Telegram и
  ~40 остальных) закрыты; покрытие 99% при гейте 97%.
