"""Scan orchestration: collect, cluster, analyze per cluster, validate, report."""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from . import cpg, policy, reporting, runners, sources, validation

logger = logging.getLogger(__name__)


def invoke_with_retry(
    call: Callable[[], dict[str, Any]],
    *,
    retries: int,
    max_calls: int,
    log: reporting.EventLog,
) -> dict[str, Any]:
    attempts = min(retries + 1, max_calls)
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        log.write("runner_invoked", attempt=attempt, max_calls=max_calls)
        logger.info("runner attempt %d of %d", attempt, attempts)
        try:
            result = call()
            log.write("runner_completed", attempt=attempt)
            logger.info("runner attempt %d completed", attempt)
            return result
        except runners.RunnerError as exc:
            last_error = exc
            log.write("runner_failed", attempt=attempt, error=str(exc))
            logger.warning("runner attempt %d failed: %s", attempt, exc)
            if attempt < attempts:
                logger.debug("retrying after %.2f seconds", 0.25)
                time.sleep(0.25)
    if last_error is None:
        raise runners.RunnerError("model-call policy permits no attempts")
    raise last_error


STEPS = (
    "collect sources",
    "build call graph",
    "partition clusters",
    "find vulnerabilities",
    "merge and gate findings",
    "validate and report",
)


def _step(
    log: reporting.EventLog, number: int, detail: str = ""
) -> None:
    """Emit one numbered scan step to the event log and the console."""
    name = STEPS[number - 1]
    log.write(
        "step_started",
        step=number,
        total=len(STEPS),
        name=name,
        detail=detail,
    )
    if detail:
        logger.info("step %d/%d: %s (%s)", number, len(STEPS), name, detail)
    else:
        logger.info("step %d/%d: %s", number, len(STEPS), name)


def merge_reports(
    reports: list[dict[str, Any]],
) -> tuple[dict[str, Any], int]:
    """Merge per-cluster reports, dropping duplicate (cwe, endpoint) findings.

    Empty per-cluster reports are normal: a clean cluster reports nothing.
    Returns the merged report plus the duplicate count.
    """
    merged: list[dict[str, Any]] = []
    seen: set[tuple[Any, Any]] = set()
    duplicates = 0
    for position, report in enumerate(reports, start=1):
        if not isinstance(report, dict) or not isinstance(
            report.get("findings"), list
        ):
            raise runners.RunnerError(
                f"cluster call {position} did not return a report"
            )
        for finding in report["findings"]:
            if isinstance(finding, dict):
                key = (finding.get("cwe"), finding.get("endpoint"))
            else:
                key = ("", len(merged))
            if key in seen:
                duplicates += 1
                continue
            seen.add(key)
            merged.append(finding)
    return {"findings": merged}, duplicates


def run_scan(
    *,
    policy_path: Path,
    target_path: Path,
    runner_override: str | None,
    output_dir: Path,
) -> int:
    loaded_policy = policy.load_policy(policy_path)
    target = policy.load_target(target_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    log = reporting.EventLog(output_dir / "events.jsonl")
    log.write("run_started", policy=str(policy_path), target=str(target_path))
    logger.info(
        "scan started: policy=%s target=%s output=%s",
        policy_path,
        target_path,
        output_dir,
    )

    _step(log, 1)
    collected = sources.collect_sources(target_path, target, loaded_policy)
    log.write(
        "source_collected",
        files=[
            {"path": item["path"], "sha256": item["sha256"]} for item in collected
        ],
    )
    logger.info("collected %d source files", len(collected))
    logger.debug("source files: %s", ", ".join(item["path"] for item in collected))

    _step(log, 2)
    call_graph = cpg.build_call_graph(collected)
    if call_graph is None:
        log.write("cpg_skipped", reason="tree-sitter backend not installed")
        logger.info("call graph skipped: tree-sitter backend not installed")
        graph_text = ""
    else:
        (output_dir / "cpg.json").write_text(
            json.dumps(call_graph, indent=2) + "\n", encoding="utf-8"
        )
        log.write(
            "cpg_built",
            functions=len(call_graph["nodes"]),
            edges=len(call_graph["edges"]),
        )
        logger.info(
            "built call graph: %d functions, %d edges",
            len(call_graph["nodes"]),
            len(call_graph["edges"]),
        )
        graph_text = cpg.render_call_graph_text(call_graph)

    _step(log, 3)
    clusters: list[dict[str, Any]] = []
    if call_graph is None:
        logger.info("cluster partition skipped: no call graph")
    else:
        clusters = cpg.cluster_call_graph(call_graph)
        (output_dir / "clusters.json").write_text(
            json.dumps(clusters, indent=2) + "\n", encoding="utf-8"
        )
        names = [cluster["name"] for cluster in clusters]
        log.write("clusters_built", clusters=names)
        logger.info(
            "partitioned call graph into %d clusters: %s",
            len(clusters),
            ", ".join(names),
        )

    discovery = loaded_policy["steps"]["discover"]
    runner = runner_override or discovery["runner"]
    if runner not in policy.RUNNERS:
        raise policy.PolicyError(f"unsupported runner override: {runner}")
    logger.info(
        "selected runner: %s (model=%s effort=%s)",
        runner,
        discovery.get("model"),
        discovery.get("effort"),
    )
    root = policy_path.parent
    schema_path = (root / discovery["schema"]).resolve()
    fixture = target["discovery"].get("mock_fixture")
    if not isinstance(fixture, str):
        raise policy.PolicyError("target discovery requires mock_fixture")
    fixture_path = (target_path.parent / fixture).resolve()
    timeout = int(loaded_policy["limits"].get("runner_timeout_seconds", 180))
    retries = int(loaded_policy["limits"].get("retries", 0))
    max_calls = int(loaded_policy["limits"].get("max_model_calls", 1))

    calls_needed = len(clusters) if clusters else 1
    attempts_needed = calls_needed * (retries + 1)
    if max_calls < attempts_needed:
        raise policy.PolicyError(
            f"discovery needs {attempts_needed} model calls; "
            f"policy allows {max_calls}"
        )

    noun = "call" if calls_needed == 1 else "calls"
    _step(log, 4, f"{calls_needed} reasoning {noun}")
    if clusters:
        reports = []
        for position, cluster in enumerate(clusters, start=1):
            cluster_prompt = sources.build_prompt(
                collected,
                target,
                cluster_text=cpg.render_cluster_text(
                    cluster, index=position, total=len(clusters)
                ),
            )
            logger.debug(
                "built cluster prompt for %r: %d characters",
                cluster["name"],
                len(cluster_prompt),
            )
            cluster_dir = output_dir / "clusters" / cluster["name"]
            log.write(
                "cluster_started",
                cluster=cluster["name"],
                position=position,
                total=len(clusters),
            )
            logger.info(
                "cluster %r (%d/%d): starting reasoning call",
                cluster["name"],
                position,
                len(clusters),
            )
            cluster_report = invoke_with_retry(
                lambda prompt=cluster_prompt, outdir=cluster_dir: runners.analyze(
                    runner,
                    prompt=prompt,
                    schema_path=schema_path,
                    fixture_path=fixture_path,
                    output_dir=outdir,
                    model=discovery.get("model"),
                    effort=discovery.get("effort"),
                    timeout=timeout,
                    cwd=root,
                ),
                retries=retries,
                max_calls=retries + 1,
                log=log,
            )
            found = cluster_report.get("findings", [])
            count = len(found) if isinstance(found, list) else 0
            log.write(
                "cluster_completed", cluster=cluster["name"], findings=count
            )
            logger.info(
                "cluster %r (%d/%d): %d findings",
                cluster["name"],
                position,
                len(clusters),
                count,
            )
            reports.append(cluster_report)
        _step(log, 5)
        report, duplicates = merge_reports(reports)
        log.write(
            "reports_merged",
            clusters=len(reports),
            findings=len(report["findings"]),
            duplicates=duplicates,
        )
        logger.info(
            "merged %d cluster reports: %d findings (%d duplicates)",
            len(reports),
            len(report["findings"]),
            duplicates,
        )
    else:
        prompt = sources.build_prompt(
            collected, target, call_graph_text=graph_text
        )
        logger.debug("built discovery prompt: %d characters", len(prompt))
        report = invoke_with_retry(
            lambda: runners.analyze(
                runner,
                prompt=prompt,
                schema_path=schema_path,
                fixture_path=fixture_path,
                output_dir=output_dir,
                model=discovery.get("model"),
                effort=discovery.get("effort"),
                timeout=timeout,
                cwd=root,
            ),
            retries=retries,
            max_calls=max_calls,
            log=log,
        )
        _step(log, 5)
    findings, quarantined = validation.validate_report(
        report, sources=collected, target=target
    )
    for entry in quarantined:
        raw = entry["finding"] if isinstance(entry["finding"], dict) else {}
        log.write(
            "finding_quarantined",
            title=raw.get("title", "?"),
            cwe=raw.get("cwe", "?"),
            reason=entry["reason"],
        )
    for finding in findings:
        log.write(
            "candidate_accepted", title=finding["title"], cwe=finding["cwe"]
        )
        logger.info(
            "candidate accepted: %s (%s)", finding["title"], finding["cwe"]
        )

    _step(log, 6)
    validation_result = validation.validate_runtime(loaded_policy, target, findings)
    validation_result["quarantined"] = quarantined
    log.write(
        "runtime_validation_completed",
        status=validation_result["status"],
        verdicts=[
            {"cwe": item["finding"]["cwe"], "verdict": item["verdict"]}
            for item in validation_result["findings"]
        ],
        missing_cwes=validation_result["missing_cwes"],
    )
    reporting.write_finding(output_dir / "finding.json", validation_result)
    reporting.write_report(output_dir / "report.md", validation_result)
    log.write("run_completed", status=validation_result["status"])
    logger.info("run completed: %s", validation_result["status"])
    print(f"Run status: {validation_result['status']}")
    print(f"Artifacts: {output_dir}")
    return 0 if validation_result["status"] == "validated" else 2


def default_output_dir() -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return Path("runs") / stamp
