"""Command line interface for the harness."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from . import controller, policy, runners

logger = logging.getLogger(__name__)


def configure_logging(verbosity: int) -> None:
    """Route console output through the standard logging framework.

    Default stays quiet (warnings and errors only); ``-v`` shows each
    harness stage and ``-vv`` adds debug detail such as executed commands.
    """
    if verbosity >= 2:
        level = logging.DEBUG
    elif verbosity == 1:
        level = logging.INFO
    else:
        level = logging.WARNING
    root = logging.getLogger()
    root.setLevel(level)
    for handler in root.handlers:
        handler.setLevel(level)
    if not any(isinstance(item, logging.StreamHandler) for item in root.handlers):
        handler = logging.StreamHandler()
        handler.setLevel(level)
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)s %(name)s: %(message)s",
                datefmt="%H:%M:%S",
            )
        )
        root.addHandler(handler)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="A minimal deterministic harness around one model-backed discovery step."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="run the minimal security harness")
    scan.add_argument(
        "--policy", type=Path, default=Path("policies/default.json")
    )
    scan.add_argument(
        "--target", type=Path, default=Path("targets/invoice-demo/target.json")
    )
    scan.add_argument(
        "--runner", choices=("codex", "claude", "muse", "mock")
    )
    scan.add_argument("--output-dir", type=Path)
    scan.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="increase console log detail; repeat for debug output",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(args.verbose)
    try:
        if args.command == "scan":
            return controller.run_scan(
                policy_path=args.policy.resolve(),
                target_path=args.target.resolve(),
                runner_override=args.runner,
                output_dir=(args.output_dir or controller.default_output_dir()).resolve(),
            )
    except (policy.PolicyError, runners.RunnerError) as exc:
        logger.error("%s", exc)
        return 1
    return 1
