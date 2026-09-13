# AGENTS.md — правила работы агента в этом репозитории

## Проект
vpnparser — Python ≥3.11 пайплайн: сбор VPN-конфигов (vmess/vless/trojan/ss/hysteria2/tuic и др.) из GitHub-источников, валидация живости (TCP/TLS/Xray L3 через SOCKS5-пул) и публикация подписок через GitHub Contents API. Операционный регламент: `docs/OPERATIONS.md` (коды выхода 0/1/2/3/130, exit 3 = «пайплайн OK, публикация упала»).

## Автономность
Работай без вопросов к пользователю: принимай технические решения сам, опираясь на этот файл, существующий код и тесты. К пользователю обращайся только если задача невыполнима без его данных.

## Команды (Windows: `python`, не `python3`)
- Тесты: `python -m pytest -q -p no:cacheprovider` (addopts уже в pyproject.toml; порог покрытия 97% — `--cov-fail-under`)
- Линт: `python -m ruff check --no-cache src tests tools` + `python -m ruff format --check --no-cache src tests tools` (как CI lint-job); автофикс: `--fix`; формат: `python -m ruff format src tests tools`
- Типы: `python -m mypy --no-incremental src` (strict, без ignore без причины)
- Безопасность: `python -m bandit -c pyproject.toml -r src`
- Пайплайн: `python -m src.main --run` (полный прогон — только при необходимости; использует сеть и Xray)
- Альтернатива: `make test`, `make lint`, `make typecheck` (Makefile есть, но на Windows прямые вызовы python надёжнее)

## Обязательный цикл правок
1. Правка → 2. ruff check+format → 3. mypy → 4. pytest. Коммитить только когда всё зелёное. Падающий тест чини по существу, а не ослаблением ассертов/порога покрытия.

## Стиль
- Python: ruff (black-совместимый формат), type hints везде, без `# type: ignore` без комментария-причины.
- Комментарии — только на «почему» (нетривиальные ограничения, обходные пути); на английском, как в кодовой базе.
- Коммит-сообщения — на русском, в стиле истории: `fix:`, `style:`, `docs:`, `fix(ci):` + краткое описание.

## Git
- Коммиты делай сам по завершении логической правки. Не используй `git add -A`/`git add .` — только конкретные файлы.
- Пуш в текущую рабочую ветку допустим после зелёных проверок. В `main` не пушить без явной просьбы. Никаких `--force`, `--no-verify`, `reset --hard` по чужим изменениям.
- Никогда не коммитить `.env`, секреты, токены; `.env.example` — только шаблоны.

## Безопасность кода
Проект прошёл аудит: при правках сохраняй существующие защиты (SSRF-guard, лимиты размеров/редиректов, fail-closed валидация, экранирование в publisher). Новая обработка внешних данных — с таймаутами и лимитами.

## Тесты
pytest + pytest-asyncio (auto mode) + hypothesis; conftest.py общий. Новый функционал — с тестами; сетевые вызовы только через моки/фикстуры, без реального интернета в тестах.

## Layout 0.2.0 (module map)

- `src/scheduler/stages/fetch.py` — source fetching (`SourceFetcher`); `parse.py` — link parsing + country detection; `filter.py` — garbage/country/dedup preprocessing; `quality.py` — slow-drop + health/source bans (`QualityFilter`); `aggregate.py` — sort/country-balance/whitelist-mix/limit (`Aggregator`); `write.py` — subscription/split/location writers; `base.py` — `PipelineStage` marker interface.
- `src/scheduler/stages/liveness_pool.py` — proxy-pool lifecycle mixin; `liveness_stages.py` — TCP/TLS/Xray stage bodies (mixin); `liveness.py` — orchestrator + health bookkeeping.
- `src/notify/html_limits.py` (truncation/UTF-16), `src/notify/report.py` (summary→text formatters), `telegram.py` — transport + CLI + patch surface.
- `src/sources/source_options.py` — per-source option parsing; `manager.py` — fetch layer + dispatch.
- Releases: bump `pyproject.toml` version AND add a CHANGELOG.md entry in the same change.
