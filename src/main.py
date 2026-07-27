"""CLI entry point for the VPN Config Parser.

Usage::

    python -m src.main --run
    python -m src.main --run --publish --output output/subscription.txt
    python -m src.main --run -v
    python -m src.main --run --continuous

Flags:
    --run        Run the full pipeline (fetch -> parse -> validate -> write).
    --publish    Also publish the result to a GitHub repo (needs GITHUB_TOKEN).
    --settings   Path to settings.yaml (default: config/settings.yaml).
    --sources    Path to sources.json (default: config/sources.json).
    --output     Path to the subscription file (default: output/subscription.txt).
    --verbose    Enable DEBUG-level logging (default: INFO).
    --continuous Keep running in a loop, backing off after a failed or empty run.

Exit codes:
    0   Pipeline ran (and, when --publish was given, publishing succeeded).
    1   Pipeline crashed, or PipelineRunner could not be imported.
    2   No action requested (missing --run).
    3   Pipeline wrote configs but --publish did not succeed (expired token,
        409/422, network error) — the published subscription is stale.
    130 Interrupted by the user (Ctrl-C).
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
import time
from typing import TYPE_CHECKING, Any, TextIO

from src.env import load_dotenv_if_available

#: Returned when the pipeline itself succeeded but the requested publish did
#: not — a stale subscription must not look like a green run in CI.
EXIT_PUBLISH_FAILED = 3

#: Backoff bounds for --continuous. A run that fails in milliseconds (broken
#: sources.json, no network) would otherwise spin the loop at full speed.
_CONTINUOUS_BACKOFF_START = 5.0
_CONTINUOUS_BACKOFF_MAX = 300.0

if TYPE_CHECKING:
    # StreamHandler is generic to type checkers only; subscripting it at
    # runtime is not supported on every interpreter we build against.
    _StreamHandlerBase = logging.StreamHandler[TextIO]
else:
    _StreamHandlerBase = logging.StreamHandler


class _EncodingSafeStreamHandler(_StreamHandlerBase):
    """Stream handler that survives streams unable to encode the message.

    Windows consoles run on legacy code pages (cp1251, cp866, cp437 ...) and
    raise ``UnicodeEncodeError`` on characters they cannot represent. The retry
    re-encodes through the *stream's own* encoding, not a hardcoded one, so the
    record is never silently dropped on a console with a different code page.
    """

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            stream = self.stream
            try:
                stream.write(msg + self.terminator)
            except UnicodeEncodeError:
                stream.write(self._downgrade(msg) + self.terminator)
            self.flush()
        except Exception:
            self.handleError(record)

    def _downgrade(self, msg: str) -> str:
        """Return ``msg`` with every character the stream cannot encode replaced."""
        encoding = getattr(self.stream, "encoding", None) or "utf-8"
        try:
            return msg.encode(encoding, errors="replace").decode(
                encoding,
                errors="replace",
            )
        except LookupError:
            # Unknown codec name on the stream — ASCII always exists.
            return msg.encode("ascii", errors="replace").decode("ascii")


def _setup_logging(verbose: bool) -> None:
    """Configure the root logger with an encoding-safe stream handler."""
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    logging.basicConfig(
        level=level,
        format=fmt,
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
        force=True,
    )
    # Replace the default StreamHandler with our encoding-safe version.
    root = logging.getLogger()
    handler = _EncodingSafeStreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(fmt, datefmt="%Y-%m-%d %H:%M:%S"))
    root.handlers = [handler]
    root.setLevel(level)
    # Quiet overly-noisy third-party loggers a bit.
    logging.getLogger("httpx").setLevel(
        logging.WARNING if not verbose else logging.INFO,
    )
    logging.getLogger("httpcore").setLevel(
        logging.WARNING if not verbose else logging.INFO,
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
        help=(
            "Run the full pipeline (fetch -> parse -> validate -> aggregate -> write)."
        ),
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
    parser.add_argument(
        "--continuous",
        action="store_true",
        help="Keep running in a loop, backing off after a failed or empty run.",
    )
    parser.add_argument(
        "--notify",
        action="store_true",
        help="Send Telegram notification after run.",
    )
    return parser


def _status_summary_file(runner: Any) -> str:
    """Return the run-summary path this run actually wrote, or ``""``.

    ``publisher.status_output_file`` is optional, and when it is missing the
    runner writes no summary at all (``PipelineRunner._status_output_file()``
    returns ``None``). Substituting the literal default path here made the
    notifier read whatever ``output/run-summary.json`` was left on disk — the
    counts and the ``status`` field of a *previous* run — and report it as the
    result of this one.

    Args:
        runner: The :class:`~src.scheduler.runner.PipelineRunner` that ran.

    Returns:
        The configured path, or ``""`` when no summary was written.
    """
    settings = getattr(runner, "settings", None)
    publisher = settings.get("publisher") if isinstance(settings, dict) else None
    raw = publisher.get("status_output_file") if isinstance(publisher, dict) else None
    return str(raw) if raw else ""


def _notify(
    args: argparse.Namespace,
    runner: Any,
    count: int,
    logger: logging.Logger,
) -> None:
    """Send the Telegram notification for a finished run.

    Called for every run, including one that produced nothing: a pipeline that
    silently zeroed every subscription is exactly the run an operator must hear
    about, and skipping the message there left the failure invisible in both CI
    and Telegram.
    """
    try:
        from src.notify import telegram as tg

        tg.send_notification(
            configs_count=count,
            subscription_file=args.output,
            status_file=_status_summary_file(runner),
        )
    except Exception as exc:
        logger.warning("Telegram notification failed: %s", exc)


def _run_once(
    args: argparse.Namespace,
    github_token: str | None,
    logger: logging.Logger,
) -> tuple[int, bool]:
    """Execute a single pipeline run.

    Returns:
        Tuple of ``(config count, publish_ok)``. ``publish_ok`` is ``True``
        when ``--publish`` was not requested, so callers can read it as
        "nothing was left undone". Raises whatever the pipeline raises.
    """
    from src.scheduler.runner import PipelineRunner

    runner = PipelineRunner(
        settings_path=args.settings,
        sources_path=args.sources,
        github_token=github_token,
    )
    count = asyncio.run(runner.run(output_file=args.output, publish=args.publish))
    # An empty run publishes its (empty) artifacts through
    # PipelineRunner._finish_empty_run(), which does not record the outcome in
    # ``_publish_ok``.  Reading the flag there would report every empty run as
    # a failed publish — exit 3 plus a --continuous backoff for a run that
    # actually published fine.
    publish_ok = (
        not args.publish or count == 0 or bool(getattr(runner, "_publish_ok", False))
    )

    if count > 0:
        logger.info("Done. %d configs written to %s.", count, args.output)
        if args.publish and publish_ok:
            logger.info("Result published to GitHub.")
        elif args.publish:
            logger.warning(
                "Publish was requested but failed — check logs above for details."
            )
    else:
        logger.warning("Pipeline completed but produced 0 configs.")
        if args.publish:
            logger.info(
                "Empty-run artifacts were handed to the publisher — see the "
                "publish log above for the outcome.",
            )
    if args.notify:
        _notify(args, runner, count, logger)
    return count, publish_ok


def main() -> int:
    """CLI entry point. Returns a process exit code (0 = success)."""
    load_dotenv_if_available()

    args = _build_parser().parse_args()
    _setup_logging(args.verbose)
    logger = logging.getLogger("src.main")

    if not args.run:
        if args.publish:
            logger.error(
                "--publish requires --run — it only publishes the result of "
                "a pipeline run, it does not run the pipeline itself.",
            )
        else:
            logger.error("No action specified. Use --run to execute the pipeline.")
        logger.info(
            "Example: python -m src.main --run [--publish] [--output path] [-v]",
        )
        return 2

    github_token = os.environ.get("GITHUB_TOKEN")
    if args.publish and not github_token:
        logger.warning(
            "--publish was set but GITHUB_TOKEN is not in the environment. "
            "The pipeline will run but the publish step will be skipped.",
        )

    # Import lazily so that --help / argument errors do not require the full
    # dependency tree (and missing sibling modules) to be importable.
    try:
        from src.scheduler.runner import PipelineRunner  # noqa: F401
    except ImportError:
        logger.exception("Failed to import PipelineRunner")
        return 1

    def single_run() -> tuple[int, bool]:
        """Run the pipeline once. Returns ``(exit code, produced configs)``."""
        try:
            count, publish_ok = _run_once(args, github_token, logger)
        except KeyboardInterrupt:
            logger.warning("Interrupted by user.")
            return 130, False
        except Exception as exc:
            logger.error("Pipeline crashed: %s", exc, exc_info=True)
            return 1, False
        # _run_once returns the config count, but the process exit code must be
        # 0 on success - returning the count makes shells/CI mark runs failed.
        # A requested-but-failed publish is a real failure: the pipeline wrote
        # local files while the published subscription stayed stale.
        if not publish_ok:
            return EXIT_PUBLISH_FAILED, count > 0
        return 0, count > 0

    if not args.continuous:
        return single_run()[0]

    # --continuous mode: loop until interrupted.
    logger.info("Continuous mode enabled — looping until interrupted.")
    backoff = _CONTINUOUS_BACKOFF_START
    try:
        while True:
            exit_code, produced = single_run()
            if exit_code == 130:
                logger.warning("Exiting continuous loop due to KeyboardInterrupt.")
                return 130
            if exit_code == 0 and produced:
                backoff = _CONTINUOUS_BACKOFF_START
                logger.info("Run finished (exit=0). Starting next run immediately.")
                continue
            if exit_code == 0:
                # A run that reaches no source at all (unreadable sources.json,
                # every mirror down) writes 0 configs and still exits 0.  Without
                # a backoff here that run restarts in milliseconds and spins the
                # loop at dozens of full pipelines per second, rewriting every
                # output file — and, with --publish, hammering the GitHub API
                # until abuse detection trips.
                logger.warning(
                    "Run produced 0 configs. Waiting %.0fs before the next run.",
                    backoff,
                )
            else:
                logger.warning(
                    "Run finished (exit=%d). Waiting %.0fs before the next run.",
                    exit_code,
                    backoff,
                )
            time.sleep(backoff)
            backoff = min(backoff * 2, _CONTINUOUS_BACKOFF_MAX)
    except KeyboardInterrupt:
        # Ctrl-C between runs (during logging or the backoff sleep) lands here.
        logger.warning("Interrupted by user.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
