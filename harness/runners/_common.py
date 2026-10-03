"""Shared runner plumbing: subprocess execution and JSON helpers."""

from __future__ import annotations

import json
import logging
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Any


class RunnerError(RuntimeError):
    """Raised when a configured model runner cannot return a result."""


logger = logging.getLogger(__name__)


def _model_args(model: str | None, flag: str) -> list[str]:
    if not model or model == "default":
        return []
    return [flag, model]


def _summarize_command(command: list[str], limit: int = 160) -> str:
    parts = []
    for arg in command:
        if len(arg) > limit:
            arg = arg[: limit - 3] + "..."
        parts.append(shlex.quote(arg))
    return " ".join(parts)


def _run(
    command: list[str],
    *,
    prompt: str,
    timeout: int,
    cwd: Path,
) -> subprocess.CompletedProcess[str]:
    binary = shutil.which(command[0])
    if binary is None:
        raise RunnerError(f"{command[0]} CLI was not found on PATH")
    command = [binary, *command[1:]]
    logger.debug(
        "exec: %s (timeout=%ds, cwd=%s)",
        _summarize_command(command),
        timeout,
        cwd,
    )
    try:
        completed = subprocess.run(
            command,
            input=prompt,
            text=True,
            capture_output=True,
            cwd=cwd,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RunnerError(f"{command[0]} timed out after {timeout} seconds") from exc
    logger.debug(
        "exec finished: exit=%s stdout=%dB stderr=%dB",
        completed.returncode,
        len(completed.stdout or ""),
        len(completed.stderr or ""),
    )
    return completed


def _parse_json_value(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        return None
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None
