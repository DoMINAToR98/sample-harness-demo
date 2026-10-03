"""Durable run records: event log, finding artifact, and human report."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class EventLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, event: str, **details: Any) -> None:
        record = {"timestamp": utc_now(), "event": event, **details}
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")


def write_finding(path: Path, result: dict[str, Any]) -> None:
    path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


def write_report(path: Path, result: dict[str, Any]) -> None:
    lines = [
        "# Demo Security Findings",
        "",
        "These results come from an intentionally vulnerable localhost application.",
        "",
        f"Run status: **{result['status']}**",
        "",
    ]
    if result.get("missing_cwes"):
        lines.append(
            "Missing validated findings for: " + ", ".join(result["missing_cwes"])
        )
        lines.append("")
    for item in result["findings"]:
        finding = item["finding"]
        evidence = "\n".join(
            f"- `{entry['path']}:{entry['line_start']}-{entry['line_end']}`: {entry['note']}"
            for entry in finding["evidence"]
        )
        lines.extend(
            [
                f"## {finding['title']}",
                "",
                f"- Verdict: **{item['verdict']}**",
                f"- Weakness: `{finding['cwe']}`",
                f"- Endpoint: `{finding['endpoint']}`",
                f"- Claim: {finding['claim']}",
                "",
                "### Source evidence",
                "",
                evidence,
                "",
                "### Runtime evidence",
                "",
                item["reason"],
                "",
            ]
        )
    if result.get("quarantined"):
        lines.extend(
            [
                "## Out of scope",
                "",
                "The model proposed these, but the gate excluded them:",
                "",
            ]
        )
        for entry in result["quarantined"]:
            raw = entry["finding"] if isinstance(entry["finding"], dict) else {}
            lines.append(
                f"- {raw.get('title', '?')} "
                f"(`{raw.get('cwe', '?')}`): {entry['reason']}"
            )
        lines.append("")
    lines.append(result["reason"])
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")
