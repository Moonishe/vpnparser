"""Environment loading helpers."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


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

    load_dotenv()
    return True
