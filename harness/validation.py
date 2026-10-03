"""Finding gates and deterministic runtime validation."""

from __future__ import annotations

import ipaddress
import json
import logging
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

from .policy import PolicyError

logger = logging.getLogger(__name__)


def _host_matches_boundary(host: str | None, boundary: str) -> bool:
    """Return True only when ``host`` resolves to the approved loopback boundary."""
    if not host:
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    if address.version != 4:
        return False
    return address.is_loopback and str(address) == boundary


FINDING_FIELDS = {
    "title": str,
    "cwe": str,
    "endpoint": str,
    "actor": str,
    "resource": str,
    "claim": str,
    "evidence": list,
    "validation": str,
}


def _validate_finding(
    finding: dict[str, Any],
    *,
    sources: list[dict[str, Any]],
    target: dict[str, Any],
) -> dict[str, Any]:
    """Gate one finding against the target contract."""
    if not isinstance(finding, dict):
        raise PolicyError("each finding must be an object")
    for key, expected in FINDING_FIELDS.items():
        if not isinstance(finding.get(key), expected):
            raise PolicyError(f"finding field {key!r} has the wrong type")

    discovery = target["discovery"]
    allowed_cwes = set(discovery.get("allowed_cwes", []))
    if allowed_cwes and finding["cwe"] not in allowed_cwes:
        raise PolicyError("finding CWE falls outside target")

    allowed_endpoints = set(discovery.get("allowed_endpoints", []))
    if allowed_endpoints and finding["endpoint"] not in allowed_endpoints:
        raise PolicyError("finding endpoint falls outside target")

    indexed = {source["path"]: source for source in sources}
    if not finding["evidence"]:
        raise PolicyError("finding must contain evidence")
    for evidence in finding["evidence"]:
        if not isinstance(evidence, dict):
            raise PolicyError("each evidence entry must be an object")
        path = evidence.get("path")
        start = evidence.get("line_start")
        end = evidence.get("line_end")
        if path not in indexed:
            raise PolicyError(f"evidence path is outside collected source: {path}")
        if not isinstance(start, int) or not isinstance(end, int):
            raise PolicyError("evidence line numbers must be integers")
        if start < 1 or end < start or end > indexed[path]["line_count"]:
            raise PolicyError(f"evidence lines do not resolve: {path}:{start}-{end}")
    return finding


def validate_report(
    report: dict[str, Any],
    *,
    sources: list[dict[str, Any]],
    target: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Gate every finding in a model report.

    Returns (accepted, quarantined). Out-of-scope or malformed findings are
    quarantined with a reason instead of aborting the run; only an empty
    survivor list fails, since there is nothing left to prove.
    """
    if not isinstance(report, dict):
        raise PolicyError("report must be an object")
    findings = report.get("findings")
    if not isinstance(findings, list) or not findings:
        raise PolicyError("report must contain a non-empty findings list")
    accepted: list[dict[str, Any]] = []
    quarantined: list[dict[str, Any]] = []
    for item in findings:
        try:
            accepted.append(
                _validate_finding(item, sources=sources, target=target)
            )
        except PolicyError as exc:
            quarantined.append({"finding": item, "reason": str(exc)})
            logger.warning("quarantined finding: %s", exc)
    if not accepted:
        reasons = "; ".join(entry["reason"] for entry in quarantined)
        raise PolicyError(f"no in-scope findings survived the gate ({reasons})")
    return accepted, quarantined


def _request_body(
    url: str, method: str, headers: dict[str, str], timeout: int
) -> tuple[int, Any]:
    """Perform one loopback request; return (status, parsed JSON or text)."""
    request = Request(url, method=method, headers=headers)
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read()
            status = response.status
    except HTTPError as error:
        raw = error.read()
        status = error.code
    except URLError as error:
        raise PolicyError(f"cannot reach the demo application: {error.reason}")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("utf-8", errors="replace")
    try:
        return status, json.loads(text)
    except json.JSONDecodeError:
        return status, text


def _deferred(findings: list[dict[str, Any]], reason: str) -> dict[str, Any]:
    return {
        "status": "deferred",
        "missing_cwes": [],
        "reason": reason,
        "findings": [
            {
                "finding": finding,
                "verdict": "deferred",
                "checks": [],
                "reason": reason,
            }
            for finding in findings
        ],
    }


def validate_runtime(
    policy: dict[str, Any],
    target: dict[str, Any],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Prove each finding against the target's fixed checks.

    Checks carrying ``for_cwe`` apply only to findings with that CWE; checks
    without it apply to every finding. The run is ``validated`` only when
    every expected CWE has a validated finding and no finding was rejected.
    """
    permissions = policy["permissions"]
    runtime = target.get("validation")
    if not permissions.get("allow_active_validation", False):
        logger.info("runtime validation deferred: disabled by policy")
        return _deferred(findings, "active validation disabled by policy")
    if not runtime:
        logger.info("runtime validation deferred: target supplied no validation plan")
        return _deferred(findings, "target supplied no validation plan")

    base_url = runtime["base_url"]
    parsed = urlparse(base_url)
    if parsed.scheme != "http":
        raise PolicyError("validation URLs must use plain http on loopback")
    if not _host_matches_boundary(parsed.hostname, "127.0.0.1"):
        raise PolicyError("validation URL escapes the loopback boundary")

    checks = runtime.get("checks")
    if not isinstance(checks, list) or not checks:
        raise PolicyError("target validation requires at least one check")
    request_limit = int(policy["limits"].get("max_validation_requests", 1))
    if len(checks) > request_limit:
        raise PolicyError(
            f"target requests {len(checks)} checks; policy allows {request_limit}"
        )
    timeout = int(policy["limits"].get("request_timeout_seconds", 5))

    executed: list[tuple[dict[str, Any], str | None]] = []
    for check in checks:
        if not isinstance(check, dict):
            raise PolicyError("each validation check must be an object")
        request_spec = check.get("request", {})
        if not isinstance(request_spec, dict):
            raise PolicyError("check request must be an object")
        method = request_spec.get("method", "GET")
        if method != "GET":
            raise PolicyError("validation is GET-only in this demo")
        path = request_spec.get("path")
        if not isinstance(path, str) or not path:
            raise PolicyError("check request requires a path")
        headers = request_spec.get("headers", {})
        if not isinstance(headers, dict):
            raise PolicyError("check request headers must be an object")
        url = urljoin(base_url + "/", path.lstrip("/"))
        status, body = _request_body(url, method, headers, timeout)

        expect = check.get("expect", {})
        if not isinstance(expect, dict):
            raise PolicyError("check expect must be an object")
        for key in expect:
            if key not in ("status", "body_contains", "body_text_contains"):
                raise PolicyError(f"unsupported check expectation: {key}")
        matched = True
        if "status" in expect and status != expect["status"]:
            matched = False
        if "body_contains" in expect:
            wanted = expect["body_contains"]
            if not isinstance(wanted, dict) or not isinstance(body, dict):
                matched = False
            elif any(body.get(key) != value for key, value in wanted.items()):
                matched = False
        if "body_text_contains" in expect:
            haystack = body if isinstance(body, str) else json.dumps(body)
            if expect["body_text_contains"] not in haystack:
                matched = False

        name = check.get("name", path)
        outcome = {
            "name": name,
            "request": {"method": method, "url": url, "headers": headers},
            "status": status,
            "body": body,
            "matched": matched,
        }
        for_cwe = check.get("for_cwe")
        if for_cwe is not None and not isinstance(for_cwe, str):
            raise PolicyError("check for_cwe must be a string")
        executed.append((outcome, for_cwe))
        logger.info(
            "check %r [%s]: %s %s -> %s (matched=%s)",
            name,
            for_cwe or "all",
            method,
            path,
            status,
            matched,
        )

    results: list[dict[str, Any]] = []
    for finding in findings:
        mine = [
            outcome for outcome, cwe in executed if cwe is None or cwe == finding["cwe"]
        ]
        if not mine:
            verdict = "rejected"
            reason = f"target defines no checks for {finding['cwe']}"
        else:
            matched_count = sum(1 for item in mine if item["matched"])
            reason = f"{matched_count}/{len(mine)} fixed checks matched"
            verdict = "validated" if matched_count == len(mine) else "rejected"
        results.append(
            {
                "finding": finding,
                "verdict": verdict,
                "checks": mine,
                "reason": reason,
            }
        )
        logger.info("finding %s (%s): %s", finding["title"], finding["cwe"], verdict)

    discovery = target["discovery"]
    expected = set(discovery.get("expected_cwes") or discovery.get("allowed_cwes", []))
    covered = {
        item["finding"]["cwe"] for item in results if item["verdict"] == "validated"
    }
    missing = sorted(expected - covered)
    rejected = sorted(
        {item["finding"]["cwe"] for item in results if item["verdict"] != "validated"}
    )
    if not missing and not rejected:
        status = "validated"
        reason = runtime.get("success_reason", "All fixed checks matched.")
    else:
        status = "rejected"
        parts = []
        if missing:
            parts.append("missing validated findings for: " + ", ".join(missing))
        if rejected:
            parts.append("rejected findings for: " + ", ".join(rejected))
        reason = "; ".join(parts)
    logger.info("runtime validation status: %s", status)
    return {
        "status": status,
        "missing_cwes": missing,
        "reason": reason,
        "findings": results,
    }
