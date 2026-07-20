"""Tests for src/scheduler/stages/publish.py — GitHubPublisherStage."""

from __future__ import annotations

import asyncio
import builtins
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.scheduler.context import PipelineContext, PipelineState
from src.scheduler.settings import Settings
from src.scheduler.stages.publish import Publisher


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def settings() -> Settings:
    return Settings(
        {
            "publisher": {
                "owner": "test-owner",
                "repo": "test-repo",
                "branch": "main",
                "commit_message": "auto-update [{timestamp}]",
                "output_file": "output/sub.txt",
            },
        }
    )


@pytest.fixture
def context(settings: Settings) -> PipelineContext:
    return PipelineContext(
        settings=settings,
        github_token="ghp_token",
        sources_path="/tmp/sources",
    )


@pytest.fixture
def state() -> PipelineState:
    return PipelineState(output_files=["output/sub.txt"])


# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------


def test_init_stores_context(context: PipelineContext) -> None:
    """__init__ stores the context argument."""
    stage = Publisher(context)
    assert stage.context is context


# ---------------------------------------------------------------------------
# run: early exits
# ---------------------------------------------------------------------------


async def test_run_asserts_context_not_none(context: PipelineContext) -> None:
    """run() raises AssertionError when context is None."""
    stage = Publisher(context)
    with pytest.raises(AssertionError):
        await stage.run(PipelineState(), context=None)


async def test_run_skips_when_no_token(context: PipelineContext) -> None:
    """run() returns early when github_token is falsy."""
    context.github_token = None
    stage = Publisher(context)
    state = PipelineState()
    result = await stage.run(state, context=context)
    assert result is state
    assert result.published is False


async def test_run_skips_when_no_owner(
    context: PipelineContext,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """run() returns early when owner/repo not configured."""
    context.settings = Settings({"publisher": {}})
    # Ensure env vars are absent
    monkeypatch.delenv("GITHUB_OWNER", raising=False)
    monkeypatch.delenv("GITHUB_REPO", raising=False)
    monkeypatch.delenv("GITHUB_BRANCH", raising=False)
    stage = Publisher(context)
    state = PipelineState()
    result = await stage.run(state, context=context)
    assert result is state
    assert result.published is False


async def test_run_skips_on_import_error(
    context: PipelineContext,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """run() returns early when GitHubPublisher cannot be imported."""
    import src.publisher.github as gh_mod

    monkeypatch.delattr(gh_mod, "GitHubPublisher", raising=False)

    stage = Publisher(context)
    state = PipelineState(output_files=["output/sub.txt"])
    result = await stage.run(state, context=context)
    assert result.published is False


# ---------------------------------------------------------------------------
# run: happy path with mocked dependencies
# ---------------------------------------------------------------------------


async def test_run_success(
    context: PipelineContext,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Full run with mocked GitHubPublisher and _publish_file."""
    state = PipelineState(output_files=["output/sub.txt"])

    # Mock the publisher instance used inside the async with block
    mock_publisher = AsyncMock()

    class FakeGitHubPublisher:
        def __init__(self, token, owner, repo, branch):
            self.token = token
            self.owner = owner
            self.repo = repo
            self.branch = branch

        async def __aenter__(self) -> AsyncMock:
            return mock_publisher

        async def __aexit__(self, *args: object) -> None:
            pass

    import src.publisher.github as gh_mod

    monkeypatch.setattr(gh_mod, "GitHubPublisher", FakeGitHubPublisher)
    # Isolate _publish_file from disk I/O (wrap in staticmethod to match original)
    monkeypatch.setattr(Publisher, "_publish_file", staticmethod(AsyncMock()))

    stage = Publisher(context)
    result = await stage.run(state, context=context)

    assert result.published is True
    assert result is state
    Publisher._publish_file.assert_awaited_once()  # type: ignore[attr-defined]
    # staticmethod wrapper: args[0] is publisher, args[1] is output_file
    call_args = Publisher._publish_file.call_args[0]  # type: ignore[attr-defined]
    assert call_args[0] is mock_publisher
    assert call_args[1] == "output/sub.txt"


async def test_run_with_env_owner_repo(
    context: PipelineContext,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """run() falls back to env vars GITHUB_OWNER / GITHUB_REPO."""
    context.settings = Settings({"publisher": {}})
    monkeypatch.setenv("GITHUB_OWNER", "env-owner")
    monkeypatch.setenv("GITHUB_REPO", "env-repo")
    monkeypatch.setenv("GITHUB_BRANCH", "env-branch")

    mock_publisher = AsyncMock()

    class FakeGitHubPublisher:
        def __init__(self, token, owner, repo, branch):
            assert owner == "env-owner"
            assert repo == "env-repo"
            assert branch == "env-branch"
            self.token = token
            self.owner = owner
            self.repo = repo
            self.branch = branch

        async def __aenter__(self) -> AsyncMock:
            return mock_publisher

        async def __aexit__(self, *args: object) -> None:
            pass

    import src.publisher.github as gh_mod

    monkeypatch.setattr(gh_mod, "GitHubPublisher", FakeGitHubPublisher)
    monkeypatch.setattr(Publisher, "_publish_file", staticmethod(AsyncMock()))

    stage = Publisher(context)
    state = PipelineState(output_files=["output/sub.txt"])
    result = await stage.run(state, context=context)

    assert result.published is True


async def test_run_multiple_output_files(
    context: PipelineContext,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """run() publishes each output file."""
    state = PipelineState(output_files=["output/a.txt", "output/b.txt"])

    mock_publisher = AsyncMock()

    class FakeGitHubPublisher:
        def __init__(self, token, owner, repo, branch):
            pass

        async def __aenter__(self) -> AsyncMock:
            return mock_publisher

        async def __aexit__(self, *args: object) -> None:
            pass

    import src.publisher.github as gh_mod

    monkeypatch.setattr(gh_mod, "GitHubPublisher", FakeGitHubPublisher)
    monkeypatch.setattr(Publisher, "_publish_file", staticmethod(AsyncMock()))

    stage = Publisher(context)
    result = await stage.run(state, context=context)

    assert result.published is True
    assert Publisher._publish_file.call_count == 2  # type: ignore[attr-defined]


async def test_run_output_file_equals_configured_path(
    context: PipelineContext,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Run where output_file matches configured_combined_path (repo_path override)."""
    state = PipelineState(output_files=["output/sub.txt"])

    mock_publisher = AsyncMock()

    class FakeGitHubPublisher:
        def __init__(self, token, owner, repo, branch):
            pass

        async def __aenter__(self) -> AsyncMock:
            return mock_publisher

        async def __aexit__(self, *args: object) -> None:
            pass

    import src.publisher.github as gh_mod

    monkeypatch.setattr(gh_mod, "GitHubPublisher", FakeGitHubPublisher)

    # Track the repo_path passed to _publish_file
    captured: list[str] = []

    async def fake_publish_file(
        publisher: object, output_file: str, repo_path: str, commit_message: str
    ) -> bool:
        captured.append(repo_path)
        return True

    monkeypatch.setattr(Publisher, "_publish_file", staticmethod(fake_publish_file))

    stage = Publisher(context)
    result = await stage.run(state, context=context)

    assert result.published is True
    # repo_path should be the configured_combined_path (str version)
    assert captured == ["output/sub.txt"]


# ---------------------------------------------------------------------------
# _publish_file
# ---------------------------------------------------------------------------


async def test_publish_file_unsafe_path() -> None:
    """_publish_file with a path containing '..' raises ValueError -> returns."""
    publisher_mock = MagicMock()
    await Publisher._publish_file(
        publisher_mock, "../../../etc/passwd", "repo/path", "msg"
    )
    publisher_mock.publish_file.assert_not_called()


async def test_publish_file_file_not_found(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """_publish_file when the file does not exist on disk."""
    missing = tmp_path / "nonexistent.txt"
    monkeypatch.setattr(
        "src.utils.paths.resolve_safe_output_path",
        lambda p, base_dir=None, must_exist=False: missing,
    )

    publisher_mock = MagicMock()
    await Publisher._publish_file(publisher_mock, str(missing), "repo/path", "msg")
    publisher_mock.publish_file.assert_not_called()


async def test_publish_file_read_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """_publish_file when reading raises an unexpected exception."""
    existing = tmp_path / "existing.txt"
    existing.write_text("content", encoding="utf-8")
    monkeypatch.setattr(
        "src.utils.paths.resolve_safe_output_path",
        lambda p, base_dir=None, must_exist=False: existing,
    )

    # Make asyncio.to_thread raise PermissionError
    async def fake_to_thread(fn, *args, **kwargs):
        raise PermissionError("access denied")

    monkeypatch.setattr(asyncio, "to_thread", fake_to_thread)

    publisher_mock = MagicMock()
    await Publisher._publish_file(publisher_mock, str(existing), "repo/path", "msg")
    publisher_mock.publish_file.assert_not_called()


async def test_publish_file_publish_returns_false(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """_publish_file when publish_file returns False (logged, not raised)."""
    existing = tmp_path / "existing.txt"
    existing.write_text("content", encoding="utf-8")
    monkeypatch.setattr(
        "src.utils.paths.resolve_safe_output_path",
        lambda p, base_dir=None, must_exist=False: existing,
    )

    async def fake_to_thread(fn, *args, **kwargs):
        return fn(*args, **kwargs)

    monkeypatch.setattr(asyncio, "to_thread", fake_to_thread)

    publisher_mock = MagicMock()
    publisher_mock.publish_file = AsyncMock(return_value=False)
    await Publisher._publish_file(publisher_mock, str(existing), "repo/path", "msg")
    publisher_mock.publish_file.assert_awaited_once_with("repo/path", "content", "msg")


async def test_publish_file_publish_raises(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """_publish_file when publish_file raises an exception (logged, not propagated)."""
    existing = tmp_path / "existing.txt"
    existing.write_text("content", encoding="utf-8")
    monkeypatch.setattr(
        "src.utils.paths.resolve_safe_output_path",
        lambda p, base_dir=None, must_exist=False: existing,
    )

    async def fake_to_thread(fn, *args, **kwargs):
        return fn(*args, **kwargs)

    monkeypatch.setattr(asyncio, "to_thread", fake_to_thread)

    publisher_mock = MagicMock()
    publisher_mock.publish_file = AsyncMock(side_effect=RuntimeError("publish error"))
    await Publisher._publish_file(publisher_mock, str(existing), "repo/path", "msg")
    publisher_mock.publish_file.assert_awaited_once()


async def test_publish_file_success(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """_publish_file happy path."""
    existing = tmp_path / "existing.txt"
    existing.write_text("content", encoding="utf-8")
    monkeypatch.setattr(
        "src.utils.paths.resolve_safe_output_path",
        lambda p, base_dir=None, must_exist=False: existing,
    )

    async def fake_to_thread(fn, *args, **kwargs):
        return fn(*args, **kwargs)

    monkeypatch.setattr(asyncio, "to_thread", fake_to_thread)

    publisher_mock = MagicMock()
    publisher_mock.publish_file = AsyncMock(return_value=True)
    await Publisher._publish_file(publisher_mock, str(existing), "repo/path", "msg")
    publisher_mock.publish_file.assert_awaited_once_with("repo/path", "content", "msg")
