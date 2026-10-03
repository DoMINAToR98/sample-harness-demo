"""Muse CLI adapter (reasoning-only, write/shell/web tools disabled)."""

from __future__ import annotations

import contextlib
import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any, Iterator

from ._common import RunnerError, _model_args, _parse_json_value, _run

logger = logging.getLogger(__name__)


def build_muse_command(
    *,
    schema_path: Path,
    prompt_path: Path,
    model: str | None,
    effort: str | None,
) -> list[str]:
    command = [
        "muse",
        "exec",
        "--json",
        "--output-schema",
        str(schema_path),
        "--prompt-file",
        str(prompt_path),
        "--disable-write",
        "--disable-shell",
        "--disable-web-tools",
        "--no-session-log",
    ]
    command.extend(_model_args(model, "--model"))
    if effort:
        command.extend(["--reasoning-effort", effort])
    return command


def _strip_code_fence(text: str) -> str:
    stripped = text.strip()
    if not stripped.startswith("```"):
        return stripped
    lines = stripped.splitlines()[1:]
    if lines and lines[-1].strip().startswith("```"):
        lines = lines[:-1]
    return "\n".join(lines).strip()


def _parse_muse_output(stdout: str) -> dict[str, Any]:
    terminal_text: Any = None
    terminal_status: Any = None
    reason: Any = None
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        payload = event.get("payload")
        if not isinstance(payload, dict):
            continue
        if (
            event.get("payload_type") == "run.terminal.completed"
            or payload.get("kind") == "run_terminal"
        ):
            terminal_status = payload.get("terminal")
            terminal_text = payload.get("text")
            reason = payload.get("reason")

    if not isinstance(terminal_text, str) or not terminal_text.strip():
        raise RunnerError("Muse did not return a terminal result")
    if terminal_status is not None and terminal_status != "completed":
        raise RunnerError(f"Muse run ended with status {terminal_status}: {reason}")

    parsed = _parse_json_value(terminal_text)
    if parsed is None:
        parsed = _parse_json_value(_strip_code_fence(terminal_text))
    if parsed is None:
        start = terminal_text.find("{")
        end = terminal_text.rfind("}")
        if start != -1 and end > start:
            parsed = _parse_json_value(terminal_text[start : end + 1])
    if parsed is None:
        raise RunnerError("Muse did not return the expected structured result")
    return parsed


@contextlib.contextmanager
def _temporary_prompt_file(prompt: str) -> Iterator[Path]:
    """Stage the prompt where --prompt-file can read it, outside runs/."""
    fd, name = tempfile.mkstemp(prefix="muse-prompt-", suffix=".txt")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(prompt)
        yield Path(name)
    finally:
        os.unlink(name)


def run(
    *,
    prompt: str,
    schema_path: Path,
    output_dir: Path,
    model: str | None,
    effort: str | None,
    timeout: int,
    cwd: Path,
) -> dict[str, Any]:
    with _temporary_prompt_file(prompt) as prompt_path:
        completed = _run(
            build_muse_command(
                schema_path=schema_path,
                prompt_path=prompt_path,
                model=model,
                effort=effort,
            ),
            # The prompt travels via --prompt-file; keep stdin empty.
            prompt="",
            timeout=timeout,
            cwd=cwd,
        )
        (output_dir / "runner-trace.jsonl").write_text(
            completed.stdout, encoding="utf-8"
        )
        (output_dir / "runner-stderr.log").write_text(
            completed.stderr, encoding="utf-8"
        )
        if completed.returncode != 0:
            raise RunnerError(f"Muse exited with status {completed.returncode}")
        result = _parse_muse_output(completed.stdout)
        (output_dir / "runner-result.json").write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8"
        )
        return result
