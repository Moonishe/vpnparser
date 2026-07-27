.PHONY: install install-dev lint format typecheck test test-cov audit security clean run run-publish

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
	$(PYTHON) -m ruff check --no-cache src tests

lint-fix:
	$(PYTHON) -m ruff check --fix --no-cache src tests

format:
	$(PYTHON) -m ruff format --no-cache src tests

format-check:
	$(PYTHON) -m ruff format --check --no-cache src tests

typecheck:
	$(PYTHON) -m mypy --no-incremental src

test:
	$(PYTHON) -m pytest -q -p no:cacheprovider

test-cov:
	$(PYTHON) -m pytest -q -p no:cacheprovider --cov=src --cov-report=term-missing

audit:
	$(PYTHON) -m bandit -c pyproject.toml -r src
	$(PYTHON) -m pip_audit --desc

# Alias kept for muscle memory. Secret scanning is not part of this target:
# trufflehog v3 is a Go binary, not a Python module, and is not a dev dependency —
# it runs in CI via the trufflesecurity/trufflehog action.
security: audit

run:
	$(PYTHON) -m src.main --run

run-publish:
	$(PYTHON) -m src.main --run --publish

# Portable cleanup: cmd.exe ships neither `find -type` nor `rm`, and /dev/null is
# not a redirect target there, so this goes through $(PYTHON) like every other
# target. glob's `**` skips dot-directories, so .venv/.git are left alone.
clean:
	$(PYTHON) -c "import glob, shutil; [shutil.rmtree(p, ignore_errors=True) for p in glob.glob('**/__pycache__', recursive=True) + glob.glob('**/*.egg-info', recursive=True)]"
	$(PYTHON) -c "import glob, os; [os.remove(f) for f in glob.glob('**/*.py[co]', recursive=True) if os.path.isfile(f)]"
	$(PYTHON) -c "import shutil; [shutil.rmtree(d, ignore_errors=True) for d in ('.pytest_cache', '.ruff_cache', '.mypy_cache', 'build', 'dist')]"
