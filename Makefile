.PHONY: install install-dev lint format typecheck test test-cov audit security clean run run-publish

PYTHON := python3

install:
	$(PYTHON) -m pip install -e .

install-dev:
	$(PYTHON) -m pip install -e ".[dev]"
	$(PYTHON) -m pre_commit install

lint:
	ruff check --no-cache src tests

lint-fix:
	ruff check --fix --no-cache src tests

format:
	ruff format --no-cache src tests

format-check:
	ruff format --check --no-cache src tests

typecheck:
	mypy --cache-dir=/dev/null src

test:
	$(PYTHON) -m pytest -q -p no:cacheprovider

test-cov:
	$(PYTHON) -m pytest -q -p no:cacheprovider --cov=src --cov-report=term-missing

audit:
	bandit -c pyproject.toml -r src
	pip-audit --desc

security: audit
	$(PYTHON) -m trufflehog git file://.

run:
	$(PYTHON) -m src.main --run

run-publish:
	$(PYTHON) -m src.main --run --publish

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .pytest_cache .ruff_cache .mypy_cache *.egg-info build dist
