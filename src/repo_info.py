"""Helpers for deriving the GitHub repository identity used in outputs."""

from __future__ import annotations

import os
import subprocess
from functools import lru_cache
from pathlib import Path

DEFAULT_REPO_SLUG = "Moonishe/vpnparser"


def _valid_slug(slug: str) -> bool:
    """owner/repo charset guard (no newlines/spaces)."""
    import re

    return bool(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", slug))


def github_repo_slug(default: str = DEFAULT_REPO_SLUG) -> str:
    """Return owner/repo from env, GitHub Actions, git remote, or default."""
    owner = (os.environ.get("GITHUB_OWNER") or "").strip().strip("/")
    repo = (os.environ.get("GITHUB_REPO") or "").strip().strip("/")
    if owner and repo:
        slug = f"{owner}/{repo}"
        if _valid_slug(slug):
            return slug

    repository = (os.environ.get("GITHUB_REPOSITORY") or "").strip().strip("/")
    if "/" in repository and _valid_slug(repository):
        return repository

    return _git_origin_slug() or default


def _valid_branch(branch: str) -> bool:
    """Branch charset guard: safe for raw URLs, no traversal."""
    import re

    if not re.fullmatch(r"[A-Za-z0-9_./-]{1,128}", branch):
        return False
    return ".." not in branch


def github_branch(default: str = "main") -> str:
    """Return the branch name for raw GitHub links."""
    # Every candidate is stripped before the or-chain: a whitespace-only
    # GITHUB_BRANCH used to shadow the real GITHUB_REF-derived branch with
    # "   ", which then fell through to the default.
    branch = (
        (os.environ.get("GITHUB_BRANCH") or "").strip()
        or (os.environ.get("GITHUB_REF_NAME") or "").strip()
        or _branch_from_github_ref()
        or default
    )
    branch = branch.strip() or default
    if not _valid_branch(branch):
        return default
    return branch


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
    from urllib.parse import urlsplit

    cleaned = url.strip()
    cleaned = cleaned.removesuffix(".git")

    # Exact-host match only: "evilgithub.com/owner/repo" contains the
    # substring "github.com/" but must not be accepted as our slug.
    tail: str | None = None
    if cleaned.startswith("git@"):
        # scp-style git@github.com:owner/repo
        host_part, _, path_part = cleaned[4:].partition(":")
        if host_part.lower() == "github.com":
            tail = path_part
        else:
            return None
    else:
        try:
            host = (urlsplit(cleaned).hostname or "").lower()
        except ValueError:
            return None
        if host != "github.com":
            return None
        # hostname lowercases, but the URL may spell the host "GitHub.com":
        # a case-sensitive split("github.com") would then miss and raise
        # IndexError, crashing every caller. Locate the host
        # case-insensitively instead.
        marker = cleaned.lower().find("github.com")
        if marker == -1:
            return None
        tail = cleaned[marker + len("github.com") :].lstrip("/:")

    if not tail:
        return None
    parts = tail.strip("/").split("/")
    if len(parts) < 2:
        return None

    owner = parts[0].strip()
    # scp-style syntax is host:path; an ssh:// URL is host:PORT/path — the
    # port 22 used to surface here as the "owner" of "22/repo".
    if owner.isdigit():
        return None
    repo = parts[1].split("?", 1)[0].split("#", 1)[0].strip()
    if not owner or not repo:
        return None
    return f"{owner}/{repo}"
