.PHONY: install install-dev lint lint-fix format format-check typecheck test test-cov audit security clean run run-publish

# Override on the command line when needed, e.g. `make test PYTHON=py`.
# Windows ships `python` only (`python3` there is a MS Store stub), POSIX ships both.
# Tools are invoked as `$(PYTHON) -m <tool>` so no Scripts/bin dir has to be on PATH.
ifeq ($(OS),Windows_NT)
PYTHON ?= python
else
PYTHON ?= python3
endif

install:
	$(PYTHON) -m pip install -e .

install-dev:
	$(PYTHON) -m pip install -e ".[dev]"
	$(PYTHON) -m pre_commit install

lint:
	$(PYTHON) -m ruff check --no-cache src tests tools
	$(PYTHON) -m ruff format --check --no-cache src tests tools

lint-fix:
	$(PYTHON) -m ruff check --fix --no-cache src tests tools

format:
	$(PYTHON) -m ruff format --no-cache src tests tools

format-check:
	$(PYTHON) -m ruff format --check --no-cache src tests tools

typecheck:
	$(PYTHON) -m mypy --no-incremental src

test:
	$(PYTHON) -m pytest -q -p no:cacheprovider

test-cov:
	# Coverage flags live in pyproject addopts (--cov=src, --cov-report,
	# --cov-fail-under); no per-target --cov needed here.
	$(PYTHON) -m pytest -q -p no:cacheprovider

audit:
	$(PYTHON) -m bandit -c pyproject.toml -r src
	$(PYTHON) -m pip_audit --desc

# `make security` (== `make audit`: bandit + pip-audit) is NOT the CI security
# job: secret scanning (trufflehog v3, a Go binary, not a Python module and
# not a dev dependency) runs only in CI via the trufflesecurity/trufflehog
# action. Alias kept for muscle memory.
security: audit

run:
	$(PYTHON) -m src.main --run

run-publish:
	$(PYTHON) -m src.main --run --publish

# Portable cleanup: cmd.exe ships neither `find -type` nor `rm`, and /dev/null is
# not a redirect target there, so this goes through $(PYTHON) like every other
# target. glob's `**` skips dot-directories, so .venv/.git are left alone.
# output/ is intentionally NOT cleaned: it holds generated subscriptions that
# a local run may still need; only tool/test byproducts go here.
clean:
	$(PYTHON) -c "import glob, shutil; [shutil.rmtree(p, ignore_errors=True) for p in glob.glob('**/__pycache__', recursive=True) + glob.glob('**/*.egg-info', recursive=True)]"
	$(PYTHON) -c "import glob, os; [os.remove(f) for f in glob.glob('**/*.py[co]', recursive=True) if os.path.isfile(f)]"
	$(PYTHON) -c "import shutil; [shutil.rmtree(d, ignore_errors=True) for d in ('.pytest_cache', '.ruff_cache', '.mypy_cache', 'build', 'dist', 'htmlcov')]"
	$(PYTHON) -c "import glob, os; [os.remove(f) for f in glob.glob('.coverage*') + ['facts_history.json'] if os.path.isfile(f)]"
