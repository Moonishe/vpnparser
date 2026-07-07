"""Helpers for deriving the GitHub repository identity used in outputs."""

from __future__ import annotations

import os
import subprocess
from functools import lru_cache
from pathlib import Path

DEFAULT_REPO_SLUG = "Moonishe/vpnparser"


def github_repo_slug(default: str = DEFAULT_REPO_SLUG) -> str:
    """Return owner/repo from env, GitHub Actions, git remote, or default."""
    owner = (os.environ.get("GITHUB_OWNER") or "").strip().strip("/")
    repo = (os.environ.get("GITHUB_REPO") or "").strip().strip("/")
    if owner and repo:
        return f"{owner}/{repo}"

    repository = (os.environ.get("GITHUB_REPOSITORY") or "").strip().strip("/")
    if "/" in repository:
        return repository

    return _git_origin_slug() or default


def github_branch(default: str = "main") -> str:
    """Return the branch name for raw GitHub links."""
    branch = (
        os.environ.get("GITHUB_BRANCH")
        or os.environ.get("GITHUB_REF_NAME")
        or _branch_from_github_ref()
        or default
    )
    return branch.strip() or default


def _branch_from_github_ref() -> str | None:
    ref = (os.environ.get("GITHUB_REF") or "").strip()
    prefix = "refs/heads/"
    if ref.startswith(prefix):
        return ref[len(prefix) :]
    return None


@lru_cache(maxsize=1)
def _git_origin_slug() -> str | None:
    try:
        repo_root = Path(__file__).resolve().parents[1]
        proc = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            cwd=repo_root,
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except Exception:
        return None

    if proc.returncode != 0:
        return None
    return _slug_from_remote_url(proc.stdout.strip())


def _slug_from_remote_url(url: str) -> str | None:
    cleaned = url.strip()
    if cleaned.endswith(".git"):
        cleaned = cleaned[:-4]

    if "github.com:" in cleaned:
        tail = cleaned.split("github.com:", 1)[1]
    elif "github.com/" in cleaned:
        tail = cleaned.split("github.com/", 1)[1]
    else:
        return None

    parts = tail.strip("/").split("/")
    if len(parts) < 2:
        return None

    owner = parts[0].strip()
    repo = parts[1].split("?", 1)[0].split("#", 1)[0].strip()
    if not owner or not repo:
        return None
    return f"{owner}/{repo}"
