"""Policy and target manifests plus their contract gates."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class PolicyError(ValueError):
    """Raised when policy or model output violates the harness contract."""


RUNNERS = ("codex", "claude", "muse", "mock")


def load_policy(path: Path) -> dict[str, Any]:
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyError(f"cannot load policy: {exc}") from exc

    for key in ("permissions", "limits", "steps"):
        if not isinstance(policy.get(key), dict):
            raise PolicyError(f"policy requires an object named {key!r}")
    discovery = policy["steps"].get("discover")
    if not isinstance(discovery, dict):
        raise PolicyError("policy requires steps.discover")
    if discovery.get("runner") not in RUNNERS:
        raise PolicyError("steps.discover.runner must be codex, claude, muse, or mock")
    return policy


def load_target(path: Path) -> dict[str, Any]:
    try:
        target = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyError(f"cannot load target: {exc}") from exc

    for key in ("source", "discovery"):
        if not isinstance(target.get(key), dict):
            raise PolicyError(f"target requires an object named {key!r}")
    if "validation" in target and not isinstance(target["validation"], dict):
        raise PolicyError("target validation must be an object")
    return target
