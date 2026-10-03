"""Deterministic fixture adapter (no model call)."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def run(*, fixture_path: Path) -> dict[str, Any]:
    logger.debug("reading mock fixture: %s", fixture_path)
    return json.loads(fixture_path.read_text(encoding="utf-8"))
