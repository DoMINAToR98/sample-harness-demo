"""Source collection and discovery-prompt construction."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .policy import PolicyError


def collect_sources(
    target_path: Path,
    target: dict[str, Any],
    policy: dict[str, Any],
) -> list[dict[str, Any]]:
    if not policy["permissions"].get("allow_source_read", False):
        raise PolicyError("source reads are disabled by policy")

    source = target["source"]
    root = (target_path.parent / source.get("root", ".")).resolve()
    if not root.is_dir():
        raise PolicyError(f"source root does not exist: {root}")

    allowed = set(source.get("allowed_extensions", []))
    if not allowed or not all(isinstance(item, str) for item in allowed):
        raise PolicyError("target source requires allowed_extensions")
    byte_limit = int(policy["limits"].get("max_source_bytes", 65536))
    file_limit = int(policy["limits"].get("max_source_files", 100))
    records: list[dict[str, Any]] = []
    total = 0

    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        if path.suffix not in allowed:
            continue
        if len(records) >= file_limit:
            raise PolicyError(f"source collection exceeds {file_limit} files")
        raw = path.read_bytes()
        total += len(raw)
        if total > byte_limit:
            raise PolicyError(f"source collection exceeds {byte_limit} bytes")
        text = raw.decode("utf-8")
        relative = path.relative_to(root).as_posix()
        records.append(
            {
                "path": relative,
                "text": text,
                "line_count": len(text.splitlines()),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )

    if not records:
        raise PolicyError("source collection returned no allowed files")
    return records


def build_prompt(
    sources: list[dict[str, Any]],
    target: dict[str, Any],
    *,
    call_graph_text: str = "",
    cluster_text: str = "",
) -> str:
    sections = []
    for source in sources:
        numbered = "\n".join(
            f"{number:04d}: {line}"
            for number, line in enumerate(source["text"].splitlines(), start=1)
        )
        sections.append(f"FILE {source['path']}\n{numbered}")

    discovery = target["discovery"]
    objective = discovery.get(
        "objective", "Review the supplied source for security weaknesses."
    )
    constraints = []
    if discovery.get("allowed_endpoints"):
        constraints.append(
            "Allowed endpoints: " + ", ".join(discovery["allowed_endpoints"])
        )

    parts = [
        "You are a security engineer trying to find vulnerabilities in the application.",
        objective,
        "The application is intentionally small. Return every distinct finding the evidence supports as an item in the findings array of the supplied JSON schema.",
        "Label each finding with its CWE identifier.",
        "Use only the supplied source. Do not request tools, run commands, or propose destructive testing.",
        "Evidence paths and line numbers must refer to the numbered source below.",
        *constraints,
        *sections,
    ]
    if cluster_text:
        parts.append(
            "ASSIGNED CLUSTER (your scope for this call; the numbered source above is shared context):\n"
            + cluster_text
        )
    elif call_graph_text:
        parts.append(
            "STATIC CALL GRAPH (extracted from the same source; use it to trace calls between functions):\n"
            + call_graph_text
        )
    return "\n\n".join(parts)
