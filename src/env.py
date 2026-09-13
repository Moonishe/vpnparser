"""Environment loading helpers."""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def _dotenv_path() -> Path:
    """Location of the optional .env file (project root)."""
    return Path(__file__).parents[1] / ".env"


def load_dotenv_if_available() -> bool:
    """Load a local .env file when python-dotenv is installed.

    Returns True when dotenv support was available, False otherwise. Missing
    .env files are fine; python-dotenv treats them as a no-op.
    """
    try:
        from dotenv import load_dotenv
    except ImportError:
        logger.debug("python-dotenv is not installed; skipping .env load.")
        return False

    dotenv_path = _dotenv_path()
    if dotenv_path.exists():
        try:
            load_dotenv(dotenv_path)
        except TypeError:
            # Test doubles stub load_dotenv() with no parameters.
            load_dotenv()
    return True
