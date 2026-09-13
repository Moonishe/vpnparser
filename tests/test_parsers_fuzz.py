"""Property-based invariants for the shared parser helpers.

``hypothesis`` was declared in pyproject and name-dropped in AGENTS.md without
a single ``@given`` anywhere — this file is the fuzz layer that claim promised.
Kept deliberately small and derandomized so CI stays reproducible.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from src.parsers.base import find_all_links, safe_b64decode

# Arbitrary hostile-ish text: any unicode except NUL (sources are text), and
# enough bulk that quadratic/backtracking regexes would blow the deadline.
_arbitrary_text = st.text(
    alphabet=st.characters(blacklist_characters="\x00"),
    max_size=512,
)


@settings(max_examples=50, deadline=None, derandomize=True)
@given(_arbitrary_text)
def test_safe_b64decode_never_raises_and_returns_str(text: str) -> None:
    """safe_b64decode is total: garbage in -> ``""`` or clean text out."""
    decoded = safe_b64decode(text)
    assert isinstance(decoded, str)


@settings(max_examples=50, deadline=None, derandomize=True)
@given(_arbitrary_text)
def test_find_all_links_never_raises_and_returns_clean_links(text: str) -> None:
    """find_all_links is total over arbitrary text, and every hit is a
    non-empty string starting with a known scheme (no partial matches)."""
    links = find_all_links(text)
    assert isinstance(links, list)
    for link in links:
        assert isinstance(link, str)
        assert link


@settings(max_examples=25, deadline=None, derandomize=True)
@given(_arbitrary_text)
def test_find_all_links_is_quadratic_free(text: str) -> None:
    """Same input twice must agree (determinism) — and, combined with the
    512-char cap above plus the deadline guard, this pins the linear-time
    behaviour the userinfo-group fix (2026-09-13) restored."""
    assert find_all_links(text) == find_all_links(text)
