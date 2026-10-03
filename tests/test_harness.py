from __future__ import annotations

import json
import logging
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET_PATH = ROOT / "targets" / "invoice-demo" / "target.json"
BOLA_TARGET_PATH = ROOT / "targets" / "invoice-demo" / "bola.json"
XSS_TARGET_PATH = ROOT / "targets" / "invoice-demo" / "xss.json"
TRAVERSAL_TARGET_PATH = ROOT / "targets" / "invoice-demo" / "traversal.json"
APP_DIR = ROOT / "targets" / "invoice-demo" / "app"
POLICY_PATH = ROOT / "policies" / "default.json"
SCHEMA_PATH = ROOT / "schemas" / "finding.schema.json"
FIXTURE_PATH = ROOT / "fixtures" / "mock_candidate.json"
GENERIC_FIXTURE_PATH = ROOT / "fixtures" / "mock_all.json"
XSS_FIXTURE_PATH = ROOT / "fixtures" / "mock_xss.json"
TRAVERSAL_FIXTURE_PATH = ROOT / "fixtures" / "mock_traversal.json"
sys.path.insert(0, str(ROOT))

from harness import cli, controller, cpg, policy, reporting, runners, sources, validation
from harness.runners import claude, codex, muse


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def start_app(*, secure: bool) -> tuple[subprocess.Popen[str], int]:
    port = free_port()
    env = dict(os.environ, PORT=str(port), SECURE_MODE="1" if secure else "0")
    process = subprocess.Popen(
        ["node", str(APP_DIR / "server.js")],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    deadline = time.time() + 5
    while time.time() < deadline:
        if process.poll() is not None:
            raise RuntimeError("demo application exited during startup")
        try:
            status, _ = validation._request_body(
                f"http://127.0.0.1:{port}/api/invoices/invoice-alice",
                "GET",
                {"X-User-ID": "alice"},
                1,
            )
            if status == 200:
                return process, port
        except policy.PolicyError:
            pass
        time.sleep(0.05)
    process.terminate()
    raise RuntimeError("demo application did not start")


class HarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.vulnerable, cls.vulnerable_port = start_app(secure=False)
        cls.fixed, cls.fixed_port = start_app(secure=True)

    @classmethod
    def tearDownClass(cls) -> None:
        for process in (cls.vulnerable, cls.fixed):
            process.terminate()
            process.wait(timeout=5)

    def policy(self) -> dict:
        return json.loads(POLICY_PATH.read_text())

    def target(self, port: int | None = None) -> dict:
        value = json.loads(TARGET_PATH.read_text())
        if port is not None:
            value["validation"]["base_url"] = f"http://127.0.0.1:{port}"
        return value

    def bola_target(self, port: int | None = None) -> dict:
        value = json.loads(BOLA_TARGET_PATH.read_text())
        if port is not None:
            value["validation"]["base_url"] = f"http://127.0.0.1:{port}"
        return value

    def report(self) -> dict:
        return json.loads(FIXTURE_PATH.read_text())

    def generic_report(self) -> dict:
        return json.loads(GENERIC_FIXTURE_PATH.read_text())

    def xss_target(self, port: int | None = None) -> dict:
        value = json.loads(XSS_TARGET_PATH.read_text())
        if port is not None:
            value["validation"]["base_url"] = f"http://127.0.0.1:{port}"
        return value

    def traversal_target(self, port: int | None = None) -> dict:
        value = json.loads(TRAVERSAL_TARGET_PATH.read_text())
        if port is not None:
            value["validation"]["base_url"] = f"http://127.0.0.1:{port}"
        return value

    def xss_report(self) -> dict:
        return json.loads(XSS_FIXTURE_PATH.read_text())

    def traversal_report(self) -> dict:
        return json.loads(TRAVERSAL_FIXTURE_PATH.read_text())

    def test_app_boots_via_npm_start(self) -> None:
        npm = shutil.which("npm")
        self.assertIsNotNone(npm, "npm is required to boot the demo app")
        port = free_port()
        env = dict(os.environ, PORT=str(port), SECURE_MODE="0")
        process = subprocess.Popen(
            [npm, "start", "--prefix", str(APP_DIR)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        try:
            status = None
            deadline = time.time() + 20
            while time.time() < deadline:
                if process.poll() is not None:
                    break
                try:
                    status, _ = validation._request_body(
                        f"http://127.0.0.1:{port}/api/invoices/invoice-alice",
                        "GET",
                        {"X-User-ID": "alice"},
                        1,
                    )
                    if status == 200:
                        break
                except policy.PolicyError:
                    time.sleep(0.1)
            self.assertEqual(status, 200)
        finally:
            process.terminate()
            process.wait(timeout=10)
            if process.stdout:
                process.stdout.close()
            if process.stderr:
                process.stderr.close()

    def test_report_gate_accepts_the_fixture(self) -> None:
        accepted, quarantined = validation.validate_report(
            self.report(),
            sources=sources.collect_sources(TARGET_PATH, self.target(), self.policy()),
            target=self.target(),
        )
        self.assertEqual(accepted[0]["cwe"], "CWE-639")
        self.assertEqual(quarantined, [])

    def test_report_gate_rejects_path_escape(self) -> None:
        report = self.report()
        report["findings"][0]["evidence"][0]["path"] = "../secret.txt"
        with self.assertRaises(policy.PolicyError):
            validation.validate_report(
                report,
                sources=sources.collect_sources(
                    TARGET_PATH, self.target(), self.policy()
                ),
                target=self.target(),
            )

    def test_report_gate_rejects_invalid_line(self) -> None:
        report = self.report()
        report["findings"][0]["evidence"][0]["line_end"] = 9999
        with self.assertRaises(policy.PolicyError):
            validation.validate_report(
                report,
                sources=sources.collect_sources(
                    TARGET_PATH, self.target(), self.policy()
                ),
                target=self.target(),
            )

    def test_report_gate_rejects_unexpected_endpoint(self) -> None:
        report = self.report()
        report["findings"][0]["endpoint"] = "GET /api/admin"
        with self.assertRaises(policy.PolicyError):
            validation.validate_report(
                report,
                sources=sources.collect_sources(
                    TARGET_PATH, self.target(), self.policy()
                ),
                target=self.target(),
            )

    def test_report_gate_rejects_empty_findings(self) -> None:
        with self.assertRaises(policy.PolicyError):
            validation.validate_report(
                {"findings": []},
                sources=sources.collect_sources(
                    TARGET_PATH, self.target(), self.policy()
                ),
                target=self.target(),
            )

    def test_report_gate_quarantines_out_of_scope_finding(self) -> None:
        report = self.generic_report()
        report["findings"].append(
            {
                "title": "spoofed header identity",
                "cwe": "CWE-290",
                "endpoint": "GET /api/invoices/:id",
                "actor": "attacker",
                "resource": "identity",
                "claim": "the header is trusted without a credential",
                "evidence": [
                    {
                        "path": "server.js",
                        "line_start": 33,
                        "line_end": 36,
                        "note": "callerId trusts the header",
                    }
                ],
                "validation": "send any header value",
            }
        )
        accepted, quarantined = validation.validate_report(
            report,
            sources=sources.collect_sources(
                TARGET_PATH, self.target(), self.policy()
            ),
            target=self.target(),
        )
        self.assertEqual(len(accepted), 3)
        self.assertEqual(len(quarantined), 1)
        self.assertEqual(quarantined[0]["finding"]["cwe"], "CWE-290")
        self.assertIn("outside target", quarantined[0]["reason"])

    def test_runtime_confirms_vulnerable_mode(self) -> None:
        result = validation.validate_runtime(
            self.policy(),
            self.bola_target(self.vulnerable_port),
            self.report()["findings"],
        )
        self.assertEqual(result["status"], "validated")
        self.assertEqual(result["findings"][0]["verdict"], "validated")
        self.assertEqual(result["findings"][0]["checks"][1]["body"]["owner"], "bob")

    def test_runtime_rejects_fixed_mode(self) -> None:
        result = validation.validate_runtime(
            self.policy(),
            self.bola_target(self.fixed_port),
            self.report()["findings"],
        )
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["findings"][0]["verdict"], "rejected")
        self.assertEqual(result["findings"][0]["checks"][1]["status"], 403)
        self.assertEqual(result["missing_cwes"], ["CWE-639"])

    def test_runtime_rejects_unapproved_host(self) -> None:
        target = self.bola_target()
        target["validation"]["base_url"] = "http://example.com"
        with self.assertRaises(policy.PolicyError):
            validation.validate_runtime(
                self.policy(), target, self.report()["findings"]
            )

    def test_report_gate_accepts_xss_fixture(self) -> None:
        target = self.xss_target()
        accepted, quarantined = validation.validate_report(
            self.xss_report(),
            sources=sources.collect_sources(
                XSS_TARGET_PATH, target, self.policy()
            ),
            target=target,
        )
        self.assertEqual(accepted[0]["cwe"], "CWE-79")
        self.assertEqual(quarantined, [])

    def test_report_gate_accepts_traversal_fixture(self) -> None:
        target = self.traversal_target()
        accepted, quarantined = validation.validate_report(
            self.traversal_report(),
            sources=sources.collect_sources(
                TRAVERSAL_TARGET_PATH, target, self.policy()
            ),
            target=target,
        )
        self.assertEqual(accepted[0]["cwe"], "CWE-22")
        self.assertEqual(quarantined, [])

    def test_runtime_confirms_xss_reflection(self) -> None:
        result = validation.validate_runtime(
            self.policy(),
            self.xss_target(self.vulnerable_port),
            self.xss_report()["findings"],
        )
        self.assertEqual(result["status"], "validated")
        self.assertEqual(result["findings"][0]["verdict"], "validated")
        self.assertIn(
            "<script>alert(1)</script>", result["findings"][0]["checks"][1]["body"]
        )

    def test_runtime_confirms_traversal_escape(self) -> None:
        result = validation.validate_runtime(
            self.policy(),
            self.traversal_target(self.vulnerable_port),
            self.traversal_report()["findings"],
        )
        self.assertEqual(result["status"], "validated")
        self.assertEqual(result["findings"][0]["verdict"], "validated")
        self.assertEqual(
            result["findings"][0]["checks"][1]["body"]["name"],
            "localhost-invoice-demo",
        )

    def test_runtime_validates_all_three_expected_findings(self) -> None:
        result = validation.validate_runtime(
            self.policy(),
            self.target(self.vulnerable_port),
            self.generic_report()["findings"],
        )
        self.assertEqual(result["status"], "validated")
        self.assertEqual(result["missing_cwes"], [])
        self.assertEqual(
            [item["verdict"] for item in result["findings"]],
            ["validated", "validated", "validated"],
        )
        self.assertEqual(len(result["findings"][0]["checks"]), 2)

    def test_runtime_reports_missing_expected_findings(self) -> None:
        result = validation.validate_runtime(
            self.policy(),
            self.target(self.vulnerable_port),
            self.report()["findings"],
        )
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["missing_cwes"], ["CWE-22", "CWE-79"])
        self.assertEqual(result["findings"][0]["verdict"], "validated")

    def test_fixed_mode_leaves_xss_open(self) -> None:
        result = validation.validate_runtime(
            self.policy(),
            self.xss_target(self.fixed_port),
            self.xss_report()["findings"],
        )
        self.assertEqual(result["status"], "validated")

    def test_fixed_mode_leaves_traversal_open(self) -> None:
        result = validation.validate_runtime(
            self.policy(),
            self.traversal_target(self.fixed_port),
            self.traversal_report()["findings"],
        )
        self.assertEqual(result["status"], "validated")

    def test_app_serves_branded_ui(self) -> None:
        status, body = validation._request_body(
            f"http://127.0.0.1:{self.vulnerable_port}/", "GET", {}, 1
        )
        self.assertEqual(status, 200)
        self.assertIn("BSides Bloomington 2026", body)
        self.assertIn("Sample Test Application", body)

    def test_policy_is_target_neutral(self) -> None:
        encoded = json.dumps(self.policy()).lower()
        for target_detail in ("invoice", "cwe-639", "/api/"):
            self.assertNotIn(target_detail, encoded)

    def test_retry_and_call_budget(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log = reporting.EventLog(Path(directory) / "events.jsonl")
            calls = []

            def fail() -> dict:
                calls.append(1)
                raise runners.RunnerError("expected failure")

            with self.assertRaises(runners.RunnerError):
                controller.invoke_with_retry(fail, retries=5, max_calls=2, log=log)
            self.assertEqual(len(calls), 2)

    def test_verbose_flag_maps_to_logging_levels(self) -> None:
        cases = (
            ([], logging.WARNING),
            (["-v"], logging.INFO),
            (["-vv"], logging.DEBUG),
        )
        try:
            for flags, expected in cases:
                args = cli.build_parser().parse_args(["scan", *flags])
                cli.configure_logging(args.verbose)
                self.assertEqual(logging.getLogger().level, expected)
        finally:
            cli.configure_logging(0)

    def test_runner_attempts_emit_log_records(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log = reporting.EventLog(Path(directory) / "events.jsonl")
            with self.assertLogs("harness", level="INFO") as captured:
                result = controller.invoke_with_retry(
                    lambda: {"ok": True}, retries=0, max_calls=1, log=log
                )
            self.assertEqual(result, {"ok": True})
            self.assertTrue(
                any("attempt 1 of 1" in message for message in captured.output)
            )

    def test_runner_commands_are_read_only_and_structured(self) -> None:
        codex_command = codex.build_codex_command(
            schema_path=SCHEMA_PATH,
            result_path=ROOT / "result.json",
            model="default",
            effort="medium",
        )
        claude_command = claude.build_claude_command(
            schema=json.loads(SCHEMA_PATH.read_text()),
            model="default",
            effort="medium",
        )
        muse_command = muse.build_muse_command(
            schema_path=SCHEMA_PATH,
            prompt_path=ROOT / "prompt.txt",
            model="default",
            effort="medium",
        )
        self.assertIn("read-only", codex_command)
        self.assertIn("--output-schema", codex_command)
        self.assertIn("--restricted", claude_command)
        self.assertIn("--json-schema", claude_command)
        self.assertIn("--disable-write", muse_command)
        self.assertIn("--disable-shell", muse_command)
        self.assertIn("--disable-web-tools", muse_command)
        self.assertIn("--output-schema", muse_command)
        self.assertIn("--prompt-file", muse_command)
        self.assertIn("--json", muse_command)
        self.assertIn("--reasoning-effort", muse_command)

    def test_muse_output_parsing_extracts_terminal_result(self) -> None:
        report = self.report()
        trace = "\n".join(
            [
                json.dumps(
                    {
                        "payload_type": "run.output.delta",
                        "payload": {
                            "kind": "run_output_delta",
                            "text": "working...",
                        },
                    }
                ),
                "not-json",
                json.dumps(
                    {
                        "payload_type": "run.terminal.completed",
                        "payload": {
                            "kind": "run_terminal",
                            "terminal": "completed",
                            "text": json.dumps(report),
                            "reason": None,
                        },
                    }
                ),
            ]
        )
        self.assertEqual(muse._parse_muse_output(trace), report)

    def test_muse_prompt_stays_out_of_runs_dir(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            output.mkdir()
            with muse._temporary_prompt_file("hello") as path:
                self.assertTrue(path.is_file())
                self.assertNotEqual(path.parent.resolve(), output.resolve())
                self.assertEqual(path.read_text(encoding="utf-8"), "hello")
                staged = path
            self.assertFalse(staged.exists())

    def test_muse_output_parsing_rejects_missing_terminal_result(self) -> None:
        with self.assertRaises(runners.RunnerError):
            muse._parse_muse_output('{"payload_type": "other"}\nnot-json\n')
        failed = json.dumps(
            {
                "payload_type": "run.terminal.completed",
                "payload": {
                    "kind": "run_terminal",
                    "terminal": "failed",
                    "text": "{}",
                    "reason": "stopped",
                },
            }
        )
        with self.assertRaises(runners.RunnerError):
            muse._parse_muse_output(failed)

    def test_claude_output_parsing_accepts_report(self) -> None:
        report = self.report()
        wrapped = json.dumps({"structured_output": json.dumps(report)})
        self.assertEqual(claude._parse_claude_output(wrapped), report)
        self.assertEqual(claude._parse_claude_output(json.dumps(report)), report)

    @unittest.skipUnless(cpg.available(), "tree-sitter backend not installed")
    def test_call_graph_finds_app_functions_and_edges(self) -> None:
        collected = sources.collect_sources(
            TARGET_PATH, self.target(), self.policy()
        )
        graph = cpg.build_call_graph(collected)
        self.assertIsNotNone(graph)
        names = {node["name"] for node in graph["nodes"]}
        self.assertEqual(
            names,
            {
                "sendJson",
                "requestId",
                "callerId",
                "normalizeInvoiceId",
                "findInvoice",
                "clientVersion",
                "isLegacyClient",
                "policyForRequest",
                "invoiceIsVisibleTo",
                "recordAudit",
                "handleRoot",
                "handleHealth",
                "handleInvoiceRead",
                "handleNotFound",
                "route",
                "escapeHtml",
                "greetName",
                "renderGreeting",
                "handleGreet",
                "docsFilePath",
                "isWithinRoot",
                "handleDocs",
            },
        )
        edges = {
            (item["src"].split("#", 1)[1], item["dst_name"])
            for item in graph["edges"]
            if item["resolved"]
        }
        for expected in (
            ("route", "handleInvoiceRead"),
            ("route", "handleRoot"),
            ("route", "handleGreet"),
            ("route", "handleDocs"),
            ("handleInvoiceRead", "callerId"),
            ("handleInvoiceRead", "findInvoice"),
            ("handleInvoiceRead", "normalizeInvoiceId"),
            ("handleInvoiceRead", "policyForRequest"),
            ("handleInvoiceRead", "invoiceIsVisibleTo"),
            ("policyForRequest", "isLegacyClient"),
            ("isLegacyClient", "clientVersion"),
            ("handleGreet", "greetName"),
            ("handleGreet", "renderGreeting"),
            ("handleDocs", "docsFilePath"),
            ("handleDocs", "sendJson"),
        ):
            self.assertIn(expected, edges)
        external = {item["dst_name"] for item in graph["edges"] if not item["resolved"]}
        self.assertIn("Object.hasOwn", external)
        self.assertIn("path.join", external)

    def test_render_call_graph_text_marks_external_calls(self) -> None:
        text = cpg.render_call_graph_text(
            {
                "backend": "tree-sitter",
                "nodes": [
                    {
                        "id": "server.js#route",
                        "name": "route",
                        "path": "server.js",
                        "line_start": 1,
                        "line_end": 5,
                    }
                ],
                "edges": [
                    {
                        "src": "server.js#route",
                        "dst": "server.js#route",
                        "dst_name": "route",
                        "resolved": True,
                    },
                    {
                        "src": "server.js#route",
                        "dst": "external:console.log",
                        "dst_name": "console.log",
                        "resolved": False,
                    },
                ],
                "truncated": False,
            }
        )
        self.assertIn("1 functions, 2 edges", text)
        self.assertIn("- route -> route", text)
        self.assertIn("- route -> console.log (external)", text)

    @unittest.skipUnless(cpg.available(), "tree-sitter backend not installed")
    def test_clustering_groups_feature_handlers(self) -> None:
        collected = sources.collect_sources(
            TARGET_PATH, self.target(), self.policy()
        )
        graph = cpg.build_call_graph(collected)
        clusters = cpg.cluster_call_graph(graph)
        by_name = {cluster["name"]: cluster for cluster in clusters}
        self.assertEqual(
            set(by_name),
            {"handleInvoiceRead", "handleGreet", "handleDocs", "shared"},
        )
        invoice = by_name["handleInvoiceRead"]["functions"]
        for name in (
            "handleInvoiceRead",
            "policyForRequest",
            "invoiceIsVisibleTo",
            "clientVersion",
            "isLegacyClient",
            "callerId",
            "findInvoice",
        ):
            self.assertIn(name, invoice)
        greet = by_name["handleGreet"]["functions"]
        self.assertIn("greetName", greet)
        self.assertIn("renderGreeting", greet)
        docs = by_name["handleDocs"]["functions"]
        self.assertIn("docsFilePath", docs)
        shared = by_name["shared"]["functions"]
        for name in (
            "route",
            "requestId",
            "handleRoot",
            "handleHealth",
            "handleNotFound",
        ):
            self.assertIn(name, shared)

    def test_render_cluster_text_marks_scope(self) -> None:
        text = cpg.render_cluster_text(
            {
                "name": "demo",
                "entry": "demo",
                "functions": ["a", "b"],
                "nodes": [
                    {
                        "name": "a",
                        "path": "s.js",
                        "line_start": 1,
                        "line_end": 3,
                    },
                    {
                        "name": "b",
                        "path": "s.js",
                        "line_start": 5,
                        "line_end": 7,
                    },
                ],
                "edges": [
                    {
                        "src": "s.js#a",
                        "dst": "s.js#b",
                        "dst_name": "b",
                        "resolved": True,
                    },
                    {
                        "src": "s.js#b",
                        "dst": "external:x.y",
                        "dst_name": "x.y",
                        "resolved": False,
                    },
                    {
                        "src": "s.js#a",
                        "dst": "s.js#c",
                        "dst_name": "c",
                        "resolved": True,
                        "cross_cluster": True,
                    },
                ],
            },
            index=2,
            total=4,
        )
        self.assertIn("CLUSTER demo (2 of 4)", text)
        self.assertIn("- a s.js:1-3", text)
        self.assertIn("- a -> b", text)
        self.assertIn("- b -> x.y (external)", text)
        self.assertIn("- a -> c (another cluster)", text)
        self.assertIn("Focus your findings on this cluster", text)

    def test_merge_reports_dedupes_and_tolerates_empty(self) -> None:
        first = {
            "findings": [
                {"title": "a", "cwe": "CWE-1", "endpoint": "GET /a"},
                {"title": "b", "cwe": "CWE-2", "endpoint": "GET /b"},
            ]
        }
        second = {
            "findings": [
                {"title": "b again", "cwe": "CWE-2", "endpoint": "GET /b"},
                {"title": "c", "cwe": "CWE-3", "endpoint": "GET /c"},
            ]
        }
        merged, duplicates = controller.merge_reports(
            [first, second, {"findings": []}]
        )
        self.assertEqual(
            [item["title"] for item in merged["findings"]], ["a", "b", "c"]
        )
        self.assertEqual(duplicates, 1)
        with self.assertRaises(runners.RunnerError):
            controller.merge_reports([{"findings": "nope"}])

    def test_prompt_includes_call_graph_section_when_provided(self) -> None:
        target = self.target()
        collected = sources.collect_sources(TARGET_PATH, target, self.policy())
        plain = sources.build_prompt(collected, target)
        self.assertNotIn("STATIC CALL GRAPH", plain)
        self.assertIn("findings array", plain)
        self.assertIn("security engineer", plain)
        self.assertNotIn("CWE-", plain)
        graphed = sources.build_prompt(
            collected, target, call_graph_text="CALL GRAPH (demo)"
        )
        self.assertIn("STATIC CALL GRAPH", graphed)
        self.assertIn("CALL GRAPH (demo)", graphed)

    @unittest.skipUnless(cpg.available(), "tree-sitter backend not installed")
    def test_mock_run_writes_call_graph_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            loaded_policy = self.policy()
            policy_path = Path(directory) / "policy.json"
            loaded_policy["steps"]["discover"]["schema"] = str(SCHEMA_PATH)
            policy_path.write_text(json.dumps(loaded_policy))
            target = self.target(self.vulnerable_port)
            target["source"]["root"] = str(APP_DIR)
            target["discovery"]["mock_fixture"] = str(GENERIC_FIXTURE_PATH)
            target_path = Path(directory) / "target.json"
            target_path.write_text(json.dumps(target))
            output = Path(directory) / "output"
            code = controller.run_scan(
                policy_path=policy_path,
                target_path=target_path,
                runner_override="mock",
                output_dir=output,
            )
            self.assertEqual(code, 0)
            graph = json.loads((output / "cpg.json").read_text())
            self.assertGreater(len(graph["nodes"]), 0)
            self.assertGreater(len(graph["edges"]), 0)
            clusters = json.loads((output / "clusters.json").read_text())
            self.assertEqual(len(clusters), 4)

    def test_complete_mock_run_writes_contract_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            loaded_policy = self.policy()
            policy_path = Path(directory) / "policy.json"
            loaded_policy["steps"]["discover"]["schema"] = str(SCHEMA_PATH)
            policy_path.write_text(json.dumps(loaded_policy))
            target = self.target(self.vulnerable_port)
            target["source"]["root"] = str(APP_DIR)
            target["discovery"]["mock_fixture"] = str(GENERIC_FIXTURE_PATH)
            target_path = Path(directory) / "target.json"
            target_path.write_text(json.dumps(target))
            output = Path(directory) / "output"
            code = controller.run_scan(
                policy_path=policy_path,
                target_path=target_path,
                runner_override="mock",
                output_dir=output,
            )
            self.assertEqual(code, 0)
            for name in ("events.jsonl", "finding.json", "report.md"):
                self.assertTrue((output / name).exists())
            finding = json.loads((output / "finding.json").read_text())
            self.assertEqual(finding["status"], "validated")
            self.assertEqual(
                [item["verdict"] for item in finding["findings"]],
                ["validated", "validated", "validated"],
            )
            report = (output / "report.md").read_text()
            self.assertIn("Run status: **validated**", report)
            events = (output / "events.jsonl").read_text()
            self.assertIn("step_started", events)
            if cpg.available():
                self.assertIn("reports_merged", events)


if __name__ == "__main__":
    unittest.main()
