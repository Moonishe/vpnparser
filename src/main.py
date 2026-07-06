"""CLI entry point for the VPN Config Parser.

Usage::

    python -m src.main --run
    python -m src.main --run --publish --output output/subscription.txt
    python -m src.main --run -v

Flags:
    --run       Run the full pipeline (fetch -> parse -> validate -> aggregate -> write).
    --publish   Also publish the result to a GitHub repo (needs GITHUB_TOKEN).
    --settings  Path to settings.yaml (default: config/settings.yaml).
    --sources   Path to sources.json (default: config/sources.json).
    --output    Path to the output subscription file (default: output/subscription.txt).
    --verbose   Enable DEBUG-level logging (default: INFO).
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys

from src.env import load_dotenv_if_available


def _setup_logging(verbose: bool) -> None:
    """Configure the root logger with a stream handler on stderr/stdout."""
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    logging.basicConfig(
        level=level,
        format=fmt,
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
        force=True,
    )
    # Quiet overly-noisy third-party loggers a bit.
    logging.getLogger("httpx").setLevel(
        logging.WARNING if not verbose else logging.INFO
    )
    logging.getLogger("httpcore").setLevel(
        logging.WARNING if not verbose else logging.INFO
    )


def _build_parser() -> argparse.ArgumentParser:
    """Build the argparse CLI parser."""
    parser = argparse.ArgumentParser(
        prog="vpn-config-parser",
        description="VPN Config Parser - fetch, validate, and publish proxy configs.",
    )
    parser.add_argument(
        "--run",
        action="store_true",
        help="Run the full pipeline (fetch -> parse -> validate -> aggregate -> write).",
    )
    parser.add_argument(
        "--publish",
        action="store_true",
        help="Publish the result to a GitHub repo (requires GITHUB_TOKEN).",
    )
    parser.add_argument(
        "--settings",
        default="config/settings.yaml",
        help="Path to settings.yaml (default: config/settings.yaml).",
    )
    parser.add_argument(
        "--sources",
        default="config/sources.json",
        help="Path to sources.json (default: config/sources.json).",
    )
    parser.add_argument(
        "--output",
        default="output/subscription.txt",
        help="Path to the output subscription file (default: output/subscription.txt).",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable DEBUG-level logging.",
    )
    return parser


def main() -> int:
    """CLI entry point. Returns a process exit code (0 = success)."""
    load_dotenv_if_available()

    args = _build_parser().parse_args()
    _setup_logging(args.verbose)
    logger = logging.getLogger("src.main")

    if not args.run:
        logger.error("No action specified. Use --run to execute the pipeline.")
        logger.info(
            "Example: python -m src.main --run [--publish] [--output path] [-v]"
        )
        return 2

    github_token = os.environ.get("GITHUB_TOKEN")
    if args.publish and not github_token:
        logger.warning(
            "--publish was set but GITHUB_TOKEN is not in the environment. "
            "The pipeline will run but the publish step will be skipped."
        )

    # Import lazily so that --help / argument errors do not require the full
    # dependency tree (and missing sibling modules) to be importable.
    try:
        from src.scheduler.runner import PipelineRunner
    except ImportError as exc:
        logger.error("Failed to import PipelineRunner: %s", exc)
        return 1

    runner = PipelineRunner(
        settings_path=args.settings,
        sources_path=args.sources,
        github_token=github_token,
    )

    try:
        count = asyncio.run(runner.run(output_file=args.output, publish=args.publish))
    except KeyboardInterrupt:
        logger.warning("Interrupted by user.")
        return 130
    except Exception as exc:
        logger.error("Pipeline crashed: %s", exc, exc_info=True)
        return 1

    if count > 0:
        logger.info("Done. %d configs written to %s.", count, args.output)
        if args.publish:
            logger.info("Result published to GitHub (check logs above for status).")
        return 0

    logger.warning("Pipeline completed but produced 0 configs.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
