"""Tests for the CLI entry point in src/main.py.

Covers argparse parsing, the --run/--publish/--notify flags, and every exit
code path (2 no-action, 0 success/zero, 1 crash/import-error, 130 interrupt).
PipelineRunner is replaced with an inline fake so no real pipeline runs.
"""

from __future__ import annotations

import sys

import src.main as main_module
from src.main import _build_parser, main


def _parse(argv: list[str]):
    return _build_parser().parse_args(argv)


# --- argparse parsing ------------------------------------------------------


def test_build_parser_defaults() -> None:
    args = _parse(["--run"])
    assert args.run is True
    assert args.publish is False
    assert args.notify is False
    assert args.verbose is False
    assert args.settings == "config/settings.yaml"
    assert args.sources == "config/sources.json"
    assert args.output == "output/subscription.txt"


def test_build_parser_all_flags() -> None:
    args = _parse(["--run", "--publish", "--notify", "-v", "--output", "out.txt"])
    assert args.run is True
    assert args.publish is True
    assert args.notify is True
    assert args.verbose is True
    assert args.output == "out.txt"


def test_build_parser_no_run_flag() -> None:
    args = _parse([])
    assert args.run is False
    assert args.publish is False


# --- main() exit-code paths ------------------------------------------------


class _FakeRunner:
    """Stand-in for PipelineRunner that records calls and returns a set count."""

    def __init__(self, settings_path="", sources_path="", github_token=None) -> None:
        self.settings_path = settings_path
        self.sources_path = sources_path
        self.github_token = github_token
        self.settings = {"publisher": {"status_output_file": "output/run-summary.json"}}
        self.run_calls: list[tuple[str, bool]] = []
        self.run_return: int = 5
        self.run_exc: BaseException | None = None

    async def run(self, output_file, publish) -> int:
        self.run_calls.append((output_file, publish))
        if self.run_exc is not None:
            raise self.run_exc
        return self.run_return


def _stub_main(monkeypatch, argv: list[str], runner: _FakeRunner) -> _FakeRunner:
    """Wire up argv + a factory returning the fake runner + no-op logging/dotenv."""
    monkeypatch.setattr(sys, "argv", ["main.py", *argv])
    monkeypatch.setattr(main_module, "load_dotenv_if_available", lambda: True)
    monkeypatch.setattr(main_module, "_setup_logging", lambda verbose: None)

    # PipelineRunner is replaced with a callable that stores args on the
    # pre-configured fake instance, so main() gets the same object we set up.
    def _fake_runner(*a, **kw):
        runner.settings_path = kw.get("settings_path", "")
        runner.sources_path = kw.get("sources_path", "")
        runner.github_token = kw.get("github_token")
        return runner

    monkeypatch.setattr("src.scheduler.runner.PipelineRunner", _fake_runner)
    return runner


def test_main_no_action_returns_2(monkeypatch) -> None:
    monkeypatch.setattr(sys, "argv", ["main.py"])
    monkeypatch.setattr(main_module, "load_dotenv_if_available", lambda: True)
    monkeypatch.setattr(main_module, "_setup_logging", lambda verbose: None)
    assert main() == 2


def test_main_publish_without_run_returns_2(monkeypatch) -> None:
    monkeypatch.setattr(sys, "argv", ["main.py", "--publish"])
    monkeypatch.setattr(main_module, "load_dotenv_if_available", lambda: True)
    monkeypatch.setattr(main_module, "_setup_logging", lambda verbose: None)
    assert main() == 2


def test_main_run_success_returns_0(monkeypatch) -> None:
    runner = _stub_main(monkeypatch, ["--run"], _FakeRunner())
    runner.run_return = 7
    assert main() == 0
    assert runner.run_calls == [("output/subscription.txt", False)]


def test_main_run_zero_configs_returns_0(monkeypatch) -> None:
    runner = _stub_main(monkeypatch, ["--run"], _FakeRunner())
    runner.run_return = 0
    assert main() == 0


def test_main_run_crash_returns_1(monkeypatch) -> None:
    runner = _stub_main(monkeypatch, ["--run"], _FakeRunner())
    runner.run_exc = RuntimeError("boom")
    assert main() == 1


def test_main_run_keyboard_interrupt_returns_130(monkeypatch) -> None:
    runner = _stub_main(monkeypatch, ["--run"], _FakeRunner())
    runner.run_exc = KeyboardInterrupt()
    assert main() == 130


def test_main_publish_without_token_warns_but_runs(monkeypatch) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    runner = _stub_main(monkeypatch, ["--run", "--publish"], _FakeRunner())
    runner.run_return = 3
    assert main() == 0
    assert runner.run_calls == [("output/subscription.txt", True)]
    assert runner.github_token is None


def test_main_publish_with_token_passes_token(monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_secret")
    runner = _stub_main(monkeypatch, ["--run", "--publish"], _FakeRunner())
    runner.run_return = 3
    assert main() == 0
    assert runner.github_token == "ghp_secret"


def test_main_notify_calls_send_notification(monkeypatch) -> None:
    runner = _stub_main(monkeypatch, ["--run", "--notify"], _FakeRunner())
    runner.run_return = 9
    captured: dict[str, object] = {}

    def fake_send(*, configs_count, subscription_file, status_file) -> bool:
        captured["count"] = configs_count
        captured["sub"] = subscription_file
        captured["status"] = status_file
        return True

    monkeypatch.setattr("src.notify.telegram.send_notification", fake_send)
    assert main() == 0
    assert captured == {
        "count": 9,
        "sub": "output/subscription.txt",
        "status": "output/run-summary.json",
    }


def test_main_notify_failure_is_logged_not_fatal(monkeypatch) -> None:
    runner = _stub_main(monkeypatch, ["--run", "--notify"], _FakeRunner())
    runner.run_return = 9

    def fake_send(**_kwargs) -> bool:
        raise RuntimeError("telegram down")

    monkeypatch.setattr("src.notify.telegram.send_notification", fake_send)
    assert main() == 0


def test_main_runner_import_error_returns_1(monkeypatch) -> None:
    monkeypatch.setattr(sys, "argv", ["main.py", "--run"])
    monkeypatch.setattr(main_module, "load_dotenv_if_available", lambda: True)
    monkeypatch.setattr(main_module, "_setup_logging", lambda verbose: None)
    # Removing the attribute makes `from src.scheduler.runner import
    # PipelineRunner` raise ImportError, which main() must turn into exit 1.
    monkeypatch.delattr("src.scheduler.runner.PipelineRunner", raising=False)
    assert main() == 1
