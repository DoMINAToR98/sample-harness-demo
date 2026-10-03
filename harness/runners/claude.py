"""Claude CLI adapter (reasoning-only, restricted tools)."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from ._common import RunnerError, _model_args, _parse_json_value, _run

logger = logging.getLogger(__name__)


def build_claude_command(
    *,
    schema: dict[str, Any],
    model: str | None,
    effort: str | None,
) -> list[str]:
    command = [
        "claude",
        "--print",
        "--restricted",
        "--tools",
        "",
        "--permission-mode",
        "dontAsk",
        "--no-session-persistence",
        "--output-format",
        "json",
        "--json-schema",
        json.dumps(schema, separators=(",", ":")),
    ]
    command.extend(_model_args(model, "--model"))
    if effort:
        command.extend(["--effort", effort])
    return command


def _parse_claude_output(stdout: str) -> dict[str, Any]:
    try:
        envelope = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RunnerError("Claude returned output that was not JSON") from exc

    if isinstance(envelope, dict):
        for key in ("structured_output", "result", "output", "content"):
            parsed = _parse_json_value(envelope.get(key))
            if parsed is not None:
                return parsed
        if isinstance(envelope.get("findings"), list):
            return envelope
    raise RunnerError("Claude did not return the expected structured result")


def run(
    *,
    prompt: str,
    schema: dict[str, Any],
    output_dir: Path,
    model: str | None,
    effort: str | None,
    timeout: int,
    cwd: Path,
) -> dict[str, Any]:
    completed = _run(
        build_claude_command(schema=schema, model=model, effort=effort),
        prompt=prompt,
        timeout=timeout,
        cwd=cwd,
    )
    (output_dir / "runner-response.json").write_text(
        completed.stdout, encoding="utf-8"
    )
    (output_dir / "runner-stderr.log").write_text(completed.stderr, encoding="utf-8")
    if completed.returncode != 0:
        raise RunnerError(f"Claude exited with status {completed.returncode}")
    return _parse_claude_output(completed.stdout)
