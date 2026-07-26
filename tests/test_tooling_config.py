"""Guards for the repository tooling configuration.

These invariants are easy to break silently: a stale pre-commit ``rev`` still
"succeeds" as a green commit hook that never actually ran, and a CI matrix that
drops the target platform still reports a green build.  Each assertion below
encodes a rule that was violated at least once in this repository.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tomllib
from pathlib import Path
from typing import Any

import pytest
import yaml

_ROOT = Path(__file__).resolve().parent.parent

# The ruff/mypy versions the hooks must not fall behind.  The lint config in
# pyproject ignores selectors that only exist in modern ruff (RUF043, RUF059,
# ASYNC240, PLC0415); an older ruff aborts with "Unknown rule selector" and the
# hook protects nothing.  mypy 2.x reports a different error set than 1.x, so a
# 1.x hook disagrees with CI.
_MIN_RUFF = (0, 15, 13)
_MIN_MYPY = (2, 0)


def _version_tuple(raw: str) -> tuple[int, ...]:
    """Parse a dotted version, ignoring a leading ``v`` and any suffix."""
    cleaned = raw.lstrip("v").split("+")[0]
    parts: list[int] = []
    for chunk in cleaned.split("."):
        digits = ""
        for ch in chunk:
            if not ch.isdigit():
                break
            digits += ch
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts)


@pytest.fixture(scope="module")
def pyproject() -> dict[str, Any]:
    """Parsed pyproject.toml."""
    return tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def precommit() -> dict[str, Any]:
    """Parsed .pre-commit-config.yaml."""
    data = yaml.safe_load(
        (_ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    )
    assert isinstance(data, dict)
    return data


@pytest.fixture(scope="module")
def ci_workflow() -> dict[str, Any]:
    """Parsed .github/workflows/ci.yml."""
    data = yaml.safe_load(
        (_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    )
    assert isinstance(data, dict)
    return data


@pytest.fixture(scope="module")
def update_workflow() -> dict[str, Any]:
    """Parsed .github/workflows/update.yml."""
    data = yaml.safe_load(
        (_ROOT / ".github/workflows/update.yml").read_text(encoding="utf-8")
    )
    assert isinstance(data, dict)
    return data


@pytest.fixture(scope="module")
def settings() -> dict[str, Any]:
    """Parsed config/settings.yaml."""
    data = yaml.safe_load((_ROOT / "config/settings.yaml").read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


@pytest.fixture(scope="module")
def readme() -> str:
    """Raw README.md text."""
    return (_ROOT / "README.md").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def operations() -> str:
    """Raw docs/OPERATIONS.md text."""
    return (_ROOT / "docs/OPERATIONS.md").read_text(encoding="utf-8")


def _repo(precommit: dict[str, Any], name: str) -> dict[str, Any]:
    """Return the pre-commit repo entry whose URL ends with ``name``."""
    for entry in precommit["repos"]:
        if str(entry["repo"]).rstrip("/").endswith(name):
            return dict(entry)
    raise AssertionError(f"pre-commit repo {name} not configured")


def _dev_floor(pyproject: dict[str, Any], package: str) -> tuple[int, ...]:
    """Return the lower bound declared for ``package`` in the dev extra."""
    for spec in pyproject["project"]["optional-dependencies"]["dev"]:
        name, _, bound = str(spec).partition(">=")
        if name.strip().lower() == package:
            return _version_tuple(bound)
    raise AssertionError(f"{package} is not a dev dependency")


def _dev_specs(pyproject: dict[str, Any]) -> list[str]:
    return [str(s) for s in pyproject["project"]["optional-dependencies"]["dev"]]


def _steps(workflow: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the steps of the workflow's single job, in order."""
    jobs = list(workflow["jobs"].values())
    assert len(jobs) == 1, "helper assumes a one-job workflow"
    return [dict(step) for step in jobs[0]["steps"]]


def _make_target(name: str) -> list[str]:
    """Return the recipe lines of Makefile target ``name`` (tabs stripped)."""
    lines = (_ROOT / "Makefile").read_text(encoding="utf-8").splitlines()
    recipe: list[str] = []
    collecting = False
    for line in lines:
        if line.startswith(f"{name}:"):
            collecting = True
            continue
        if collecting:
            if line.startswith("\t"):
                recipe.append(line.lstrip("\t"))
            elif line.strip():
                break
    return recipe


def _md_table_row(text: str, key: str) -> tuple[list[str], list[str]] | None:
    """Return (key spans, default spans) of the markdown row documenting ``key``.

    Args:
        text: Markdown document to scan.
        key: Setting name expected inside a code span of the Key column.

    Returns:
        Two lists of code-span contents (key column, default column), or
        ``None`` when no row documents the key.
    """
    for line in text.splitlines():
        if not line.startswith("|") or f"`{key}`" not in line:
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 4:
            continue
        keys = re.findall(r"`([^`]+)`", cells[1])
        if key not in keys:
            continue
        return keys, re.findall(r"`([^`]+)`", cells[2])
    return None


# ---------------------------------------------------------------------------
# .pre-commit-config.yaml
# ---------------------------------------------------------------------------


def test_ruff_hook_is_new_enough_for_the_lint_config(
    precommit: dict[str, Any], pyproject: dict[str, Any]
) -> None:
    """The pinned ruff must understand every selector pyproject ignores."""
    rev = _version_tuple(_repo(precommit, "ruff-pre-commit")["rev"])
    assert rev >= _MIN_RUFF, f"ruff hook rev {rev} predates the configured selectors"
    assert _dev_floor(pyproject, "ruff") >= _MIN_RUFF


def test_mypy_hook_is_new_enough(
    precommit: dict[str, Any], pyproject: dict[str, Any]
) -> None:
    """The pinned mypy must match the major series CI installs."""
    rev = _version_tuple(_repo(precommit, "mirrors-mypy")["rev"])
    assert rev >= _MIN_MYPY, f"mypy hook rev {rev} disagrees with CI"
    assert _dev_floor(pyproject, "mypy") >= _MIN_MYPY


def test_hook_revs_match_dev_dependency_floors(
    precommit: dict[str, Any], pyproject: dict[str, Any]
) -> None:
    """Hook revs must not lag the versions declared for CI/local installs."""
    assert _version_tuple(_repo(precommit, "ruff-pre-commit")["rev"]) >= _dev_floor(
        pyproject, "ruff"
    )
    assert _version_tuple(_repo(precommit, "mirrors-mypy")["rev"]) >= _dev_floor(
        pyproject, "mypy"
    )


def test_mypy_hook_skips_tests(precommit: dict[str, Any]) -> None:
    """mypy gets explicit filenames, so tests/ must be filtered by the hook.

    ``[tool.mypy] exclude`` is ignored for files named on the command line, so
    without this the hook rejects any commit that touches tests/ under strict.
    """
    hook = next(
        h for h in _repo(precommit, "mirrors-mypy")["hooks"] if h["id"] == "mypy"
    )
    files = str(hook.get("files", ""))
    exclude = str(hook.get("exclude", ""))
    assert files.startswith("^src/") or "tests" in exclude


def test_mypy_hook_has_runtime_stub_dependencies(precommit: dict[str, Any]) -> None:
    """Every third-party import in src must resolve inside the hook venv."""
    hook = next(
        h for h in _repo(precommit, "mirrors-mypy")["hooks"] if h["id"] == "mypy"
    )
    deps = " ".join(str(d) for d in hook["additional_dependencies"]).lower()
    for package in ("httpx", "pyyaml", "python-socks", "python-dotenv"):
        assert package in deps, f"mypy hook is missing {package}"


# ---------------------------------------------------------------------------
# .github/workflows/ci.yml
# ---------------------------------------------------------------------------


def test_ci_tests_run_on_windows(ci_workflow: dict[str, Any]) -> None:
    """Windows is a target platform, so the test matrix must cover it."""
    matrix = ci_workflow["jobs"]["test"]["strategy"]["matrix"]
    images = {str(o) for o in matrix["os"]}
    images.update(str(entry["os"]) for entry in matrix.get("include", []))
    assert "windows-latest" in images
    assert "ubuntu-latest" in images


def test_ci_test_job_uses_matrix_os(ci_workflow: dict[str, Any]) -> None:
    """A multi-OS matrix is useless unless runs-on reads it."""
    assert ci_workflow["jobs"]["test"]["runs-on"] == "${{ matrix.os }}"


def test_secret_scan_does_not_use_event_before(ci_workflow: dict[str, Any]) -> None:
    """github.event.before is unresolvable on branch creation and force-push."""
    steps = ci_workflow["jobs"]["security"]["steps"]
    scan = next(s for s in steps if "trufflehog" in str(s.get("uses", "")))
    rendered = yaml.safe_dump(scan)
    assert "github.event.before" not in rendered
    assert "github.event.after" not in rendered


# ---------------------------------------------------------------------------
# pyproject.toml
# ---------------------------------------------------------------------------


def test_coverage_gate_guards_against_regression(pyproject: dict[str, Any]) -> None:
    """The gate must sit near actual coverage, not far below it.

    Measured coverage is ~99%; a gate in the low nineties leaves room to delete
    a whole module's tests (``xray_probe.py`` alone is ~480 statements) without
    turning the build red.
    """
    addopts = [str(o) for o in pyproject["tool"]["pytest"]["ini_options"]["addopts"]]
    gates = [o for o in addopts if o.startswith("--cov-fail-under=")]
    assert len(gates) == 1
    assert float(gates[0].split("=", 1)[1]) >= 97.0


# ---------------------------------------------------------------------------
# Makefile
# ---------------------------------------------------------------------------


def test_makefile_typecheck_and_python_are_portable() -> None:
    """The main dev targets must work on Windows, the project's own platform."""
    text = (_ROOT / "Makefile").read_text(encoding="utf-8")
    assert "--cache-dir=/dev/null" not in text, "no /dev/null on Windows"
    assert "PYTHON := python3" not in text, "python3 is a MS Store stub on Windows"
    assert "PYTHON ?=" in text, "PYTHON must be overridable from the command line"


def test_makefile_has_no_trufflehog_module_call() -> None:
    """trufflehog v3 is a Go binary and is not a dev dependency."""
    text = (_ROOT / "Makefile").read_text(encoding="utf-8")
    assert "-m trufflehog" not in text
    assert "trufflehog" not in " ".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )


def test_trufflehog_is_not_a_declared_dev_dependency(pyproject: dict[str, Any]) -> None:
    """Guard against re-adding it as if it were installable from PyPI."""
    assert not [s for s in _dev_specs(pyproject) if "trufflehog" in s.lower()]


def test_makefile_clean_is_portable() -> None:
    """``make clean`` must also clean on Windows, where find/rm do not exist."""
    recipe = _make_target("clean")
    assert recipe, "Makefile has no clean target"
    body = "\n".join(recipe)
    assert "find " not in body, "Windows find.exe knows neither -type nor -exec"
    assert "rm -rf" not in body, "cmd.exe/PowerShell ship no rm"
    assert "/dev/null" not in body, "not a valid redirect target on Windows"
    assert "$(PYTHON) -c" in body, "cleanup must run through the interpreter"


# ---------------------------------------------------------------------------
# .github/workflows/update.yml
# ---------------------------------------------------------------------------


def test_stale_publish_check_runs_before_telegram_notify(
    update_workflow: dict[str, Any],
) -> None:
    """A failed publish must not be announced as a successful run.

    run-summary.json carries no publish flag, so the notification built from it
    reports the local counts as if subscribers had received them.  The exit-code
    gate therefore has to fail the job before the notify step runs.
    """
    names = [str(step.get("name", "")) for step in _steps(update_workflow)]
    assert "Fail on stale publish" in names
    assert "Telegram notify" in names
    assert names.index("Fail on stale publish") < names.index("Telegram notify")
    notify = next(
        s for s in _steps(update_workflow) if s.get("name") == "Telegram notify"
    )
    # `always()`/`failure()` would run the step despite the failed gate above.
    assert "always()" not in str(notify.get("if", ""))


def test_publishing_workflow_queues_instead_of_cancelling(
    update_workflow: dict[str, Any],
) -> None:
    """Cancelling mid-publish leaves a half-updated set of subscriptions."""
    concurrency = update_workflow["concurrency"]
    assert concurrency["cancel-in-progress"] is False


# ---------------------------------------------------------------------------
# .github/workflows/ci.yml
# ---------------------------------------------------------------------------


def test_ci_jobs_have_explicit_timeouts(ci_workflow: dict[str, Any]) -> None:
    """Without a timeout a hung test holds a runner for GitHub's 6h default."""
    for name, job in ci_workflow["jobs"].items():
        timeout = job.get("timeout-minutes")
        assert isinstance(timeout, int), f"job {name} has no timeout-minutes"
        assert 0 < timeout <= 60, f"job {name} timeout {timeout} is not a guard rail"


def test_ci_setup_python_steps_cache_pip(ci_workflow: dict[str, Any]) -> None:
    """Seven jobs re-installing httpx/mypy/ruff from PyPI on every run is waste."""
    setups = [
        step
        for job in ci_workflow["jobs"].values()
        for step in job["steps"]
        if "setup-python" in str(step.get("uses", ""))
    ]
    assert setups
    for step in setups:
        assert step["with"].get("cache") == "pip"
        assert step["with"].get("cache-dependency-path") == "pyproject.toml"


# ---------------------------------------------------------------------------
# mypy configuration (pyproject + hook must agree)
# ---------------------------------------------------------------------------


def test_mypy_hook_does_not_relax_missing_imports(precommit: dict[str, Any]) -> None:
    """The hook must not be weaker than the ``mypy src`` CI step.

    mirrors-mypy defaults to ``--ignore-missing-imports --scripts-are-modules``,
    so without an explicit ``args`` an import with no stubs passes the commit
    hook and fails CI.
    """
    hook = next(
        h for h in _repo(precommit, "mirrors-mypy")["hooks"] if h["id"] == "mypy"
    )
    assert "args" in hook, "mirror default args apply unless overridden"
    assert "--ignore-missing-imports" not in [str(a) for a in hook["args"]]


def test_mypy_has_no_ignore_missing_imports_overrides(
    pyproject: dict[str, Any],
) -> None:
    """Overrides for typed packages are dead weight and hide missing stubs.

    httpx, python-socks and python-dotenv ship ``py.typed``; PyYAML is covered
    by types-PyYAML.  mypy prints ``unused section(s)`` for the leftovers on
    every partial run, which is exactly how the pre-commit hook invokes it.
    """
    overrides = pyproject["tool"]["mypy"].get("overrides", [])
    relaxed = [
        o["module"]
        for o in overrides
        if o.get("ignore_missing_imports") and not str(o["module"]).startswith("src")
    ]
    assert not relaxed, f"unnecessary ignore_missing_imports for {relaxed}"


def test_yaml_stubs_are_a_dev_dependency(pyproject: dict[str, Any]) -> None:
    """CI installs only the dev extra, so the stubs must live there.

    With the stubs missing locally-only, ``mypy src`` in CI types every
    ``yaml.*`` result as ``Any`` while the pre-commit hook (which installs them)
    sees the real signatures — two different verdicts from one config.
    """
    specs = [s.lower() for s in _dev_specs(pyproject)]
    assert any(s.startswith("types-pyyaml") for s in specs)


# ---------------------------------------------------------------------------
# ruff configuration
# ---------------------------------------------------------------------------

#: Per-file ignores that matched nothing when they were last measured with
#: ``ruff check --isolated --select <rule> <path>``.  A dead ignore silences the
#: first real violation someone adds, so they stay out of the table.
_DEAD_RUFF_IGNORES = {
    "src/notify/telegram.py": ["TRY003"],
    "src/scheduler/stages/liveness.py": ["RUF001"],
    "src/validators/geoip.py": ["TRY003"],
    "tests/*": ["S306", "UP041"],
}


def test_ruff_per_file_ignores_have_no_dead_entries(pyproject: dict[str, Any]) -> None:
    """Known-dead ignores must not come back."""
    table = pyproject["tool"]["ruff"]["lint"]["per-file-ignores"]
    for path, rules in _DEAD_RUFF_IGNORES.items():
        configured = [str(r) for r in table.get(path, [])]
        for rule in rules:
            assert rule not in configured, f"{path}: {rule} matches nothing"


# ---------------------------------------------------------------------------
# runtime dependencies
# ---------------------------------------------------------------------------

#: Distribution name -> module name actually imported by src/.
_RUNTIME_IMPORT_NAMES = {
    "httpx": "httpx",
    "pyyaml": "yaml",
    "python-socks": "python_socks",
    "python-dotenv": "dotenv",
}


def test_runtime_dependencies_are_imported_by_src(pyproject: dict[str, Any]) -> None:
    """Every runtime dependency must be used.

    An unused dependency is installed in each CI job and by every operator;
    ``aiodns`` also dragged in the compiled ``pycares``, which needs a toolchain
    wherever no wheel exists.
    """
    sources = "\n".join(
        path.read_text(encoding="utf-8") for path in (_ROOT / "src").rglob("*.py")
    )
    for spec in pyproject["project"]["dependencies"]:
        dist = re.split(r"[<>=!\[;]", str(spec), maxsplit=1)[0].strip().lower()
        module = _RUNTIME_IMPORT_NAMES.get(dist)
        assert module, f"undocumented runtime dependency {dist!r}"
        assert re.search(rf"^\s*(import|from) {module}\b", sources, re.MULTILINE), (
            f"{dist} is declared but never imported by src/"
        )


# ---------------------------------------------------------------------------
# .gitignore
# ---------------------------------------------------------------------------


def test_gitignore_covers_secret_files_and_not_docs() -> None:
    """``cp .env .env.bak`` before a rotation must not become a commit."""
    git = shutil.which("git")
    if git is None or not (_ROOT / ".git").exists():
        pytest.skip("needs a git checkout")

    def ignored(relative: str) -> bool:
        result = subprocess.run(
            [git, "check-ignore", "-q", "--no-index", relative],
            cwd=_ROOT,
            capture_output=True,
            check=False,
        )
        assert result.returncode in (0, 1), result.stderr.decode(errors="replace")
        return result.returncode == 0

    assert ignored(".env")
    assert ignored(".env.local")
    assert ignored(".env.bak")
    assert not ignored(".env.example"), "the template is tracked on purpose"
    # An unanchored `index.html` pattern would also swallow GitHub Pages docs.
    assert not ignored("docs/index.html")


# ---------------------------------------------------------------------------
# documentation vs. configuration
# ---------------------------------------------------------------------------

#: (settings section, key) pairs whose default the README quotes verbatim.
_DOCUMENTED_SETTINGS = [
    ("sources", "max_concurrent_fetches"),
    ("validator", "max_configs_to_validate"),
    ("validator", "xray_concurrency"),
    ("validator", "xray_required"),
    ("validator", "geoip_enabled"),
    ("validator", "geoip_requests_per_minute"),
    ("validator", "geoip_max_lookups"),
    ("validator", "xray_require_distinct_outbound_ip"),
    ("aggregator", "max_configs_in_output"),
    ("aggregator", "max_per_country"),
    ("publisher", "location_output_limit"),
]


@pytest.mark.parametrize(("section", "key"), _DOCUMENTED_SETTINGS)
def test_readme_settings_table_matches_settings_yaml(
    readme: str,
    settings: dict[str, Any],
    section: str,
    key: str,
) -> None:
    """A documented default that no longer matches the file is a support trap.

    Operators size their expectations from this table (how many configs land in
    a subscription, how many per country), so a stale value reads as a bug in
    the pipeline.
    """
    row = _md_table_row(readme, key)
    assert row is not None, f"README does not document {section}.{key}"
    _keys, defaults = row
    actual = settings[section][key]
    expected = str(actual).lower() if isinstance(actual, bool) else str(actual)
    assert expected in defaults, (
        f"README documents {defaults} for {section}.{key}, settings.yaml has {expected}"
    )


def test_readme_documents_every_configured_source_type(readme: str) -> None:
    """``url-list`` fetches third-party URLs; it must not be an undocumented mode."""
    sources = json.loads((_ROOT / "config/sources.json").read_text(encoding="utf-8"))
    types = {str(entry["type"]) for entry in sources["sources"]}
    assert types, "no sources configured"
    for stype in types:
        assert f"`{stype}`" in readme, f"README does not describe source type {stype}"


def test_readme_documents_xray_executable(readme: str) -> None:
    """Without the binary a fail-closed run silently publishes nothing."""
    env_example = (_ROOT / ".env.example").read_text(encoding="utf-8")
    assert "XRAY_EXECUTABLE" in env_example
    assert "XRAY_EXECUTABLE" in readme


def test_llm_provider_is_documented_consistently(
    readme: str,
    settings: dict[str, Any],
) -> None:
    """One key, one provider: a mismatched vendor 401s on every source."""
    provider = str(settings["llm"]["provider"]).lower()
    env_example = (_ROOT / ".env.example").read_text(encoding="utf-8").lower()
    assert provider in env_example, f".env.example does not name {provider}"
    assert provider in readme.lower()
    rivals = {"gemini", "groq", "openrouter", "yandex", "openai"} - {provider}
    named = sorted(rival for rival in rivals if rival in env_example)
    assert not named, f".env.example also names {named} for the same key"


def test_readme_workflow_triggers_match_the_workflow(
    readme: str,
    update_workflow: dict[str, Any],
) -> None:
    """update.yml has no push trigger, and ci.yml must not be invisible."""
    # yaml parses a bare `on:` key as True, hence the lookup by either name.
    triggers = update_workflow.get("on") or update_workflow[True]
    assert "push" not in triggers
    assert set(triggers) == {"schedule", "workflow_dispatch"}
    assert "ci.yml" in readme, "the workflow that gates pull requests is undocumented"
    assert "windows-latest" in readme, "the matrix platform is worth knowing"


def test_operations_runbook_documents_exit_codes(operations: str) -> None:
    """The CI error message points here; exit 3 must be actionable."""
    assert "## Exit codes" in operations
    for code in ("0", "1", "2", "3", "130"):
        assert f"| `{code}` |" in operations, f"exit code {code} is undocumented"
    assert "stale" in operations.lower()


def test_operations_runbook_uses_real_run_summary_fields(operations: str) -> None:
    """``configs_count`` never existed in run-summary.json."""
    assert "configs_count" not in operations
    assert ".outputs.combined.count" in operations


def test_operations_runbook_rollback_covers_every_commit(operations: str) -> None:
    """Publishing commits one file at a time, so a single revert is not a rollback."""
    assert "single commit per run" not in operations
    assert "one commit per file" in operations


def test_security_policy_does_not_plan_finished_work(
    ci_workflow: dict[str, Any],
) -> None:
    """Shipped mitigations must move out of "Planned Hardening".

    An auditor reading the policy would otherwise treat checksum verification
    and secret scanning as future work.
    """
    text = (_ROOT / "SECURITY.md").read_text(encoding="utf-8")
    mitigations, _, planned = text.partition("## Planned Hardening")
    rendered = yaml.safe_dump(ci_workflow)
    assert "trufflehog" in rendered
    assert (_ROOT / ".github/xray.sha256").is_file()
    assert "secret scanning" not in planned.lower()
    assert "checksum" not in planned.lower()
    assert "xray.sha256" in mitigations
    assert "trufflehog" in mitigations.lower()
    # Round-1 hardening that is live in src/ but was missing from the policy.
    assert "redirect" in mitigations.lower()
    assert "check_hostnames" in mitigations
