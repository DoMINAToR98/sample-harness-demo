"""Codex CLI adapter (reasoning-only, read-only sandbox)."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from ._common import RunnerError, _model_args, _run

logger = logging.getLogger(__name__)


def build_codex_command(
    *,
    schema_path: Path,
    result_path: Path,
    model: str | None,
    effort: str | None,
) -> list[str]:
    command = [
        "codex",
        "exec",
        "--color",
        "never",
        "--json",
        "--ephemeral",
        "--skip-git-repo-check",
        "--sandbox",
        "read-only",
        "--output-schema",
        str(schema_path),
        "--output-last-message",
        str(result_path),
    ]
    command.extend(_model_args(model, "--model"))
    if effort:
        command.extend(["-c", f'model_reasoning_effort="{effort}"'])
    command.append("-")
    return command


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
    result_path = output_dir / "runner-result.json"
    completed = _run(
        build_codex_command(
            schema_path=schema_path,
            result_path=result_path,
            model=model,
            effort=effort,
        ),
        prompt=prompt,
        timeout=timeout,
        cwd=cwd,
    )
    (output_dir / "runner-trace.jsonl").write_text(completed.stdout, encoding="utf-8")
    (output_dir / "runner-stderr.log").write_text(completed.stderr, encoding="utf-8")
    if completed.returncode != 0:
        raise RunnerError(f"Codex exited with status {completed.returncode}")
    if not result_path.exists():
        raise RunnerError("Codex did not write the structured result")
    try:
        result = json.loads(result_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RunnerError("Codex returned output that was not JSON") from exc
    if not isinstance(result, dict):
        raise RunnerError("Codex returned a non-object JSON value")
    return result
