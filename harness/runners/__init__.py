"""Runner-neutral model adapters for the harness."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from . import claude, codex, mock, muse
from ._common import RunnerError

__all__ = ["RunnerError", "analyze"]

logger = logging.getLogger(__name__)


def analyze(
    runner: str,
    *,
    prompt: str,
    schema_path: Path,
    fixture_path: Path,
    output_dir: Path,
    model: str | None,
    effort: str | None,
    timeout: int,
    cwd: Path,
) -> dict[str, Any]:
    """Run one reasoning-only discovery call and return its JSON object."""

    logger.info(
        "starting runner %r (model=%s, effort=%s, timeout=%ds)",
        runner,
        model,
        effort,
        timeout,
    )
    if runner == "mock":
        return mock.run(fixture_path=fixture_path)

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    output_dir.mkdir(parents=True, exist_ok=True)

    if runner == "codex":
        return codex.run(
            prompt=prompt,
            schema_path=schema_path,
            output_dir=output_dir,
            model=model,
            effort=effort,
            timeout=timeout,
            cwd=cwd,
        )
    if runner == "claude":
        return claude.run(
            prompt=prompt,
            schema=schema,
            output_dir=output_dir,
            model=model,
            effort=effort,
            timeout=timeout,
            cwd=cwd,
        )
    if runner == "muse":
        return muse.run(
            prompt=prompt,
            schema_path=schema_path,
            output_dir=output_dir,
            model=model,
            effort=effort,
            timeout=timeout,
            cwd=cwd,
        )
    raise RunnerError(f"unsupported runner: {runner}")
