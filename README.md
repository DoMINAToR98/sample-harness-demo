# Minimal Security Harness Demo

> **Demonstration only.** This is a sample AI-generated harness, built only for
> demonstration purposes for the audience during a conference presentation. It
> hunts intentionally seeded bugs in a toy localhost app — it is not a
> production security tool. Do not point it at real systems.

This companion example shows how deterministic Python code can control one bounded model call. It collects a target's source, derives a static call graph, asks the model to reason over both with a standard "look for vulnerabilities" prompt, verifies each finding against a localhost deployment, and records every transition.

The demo application authenticates a caller through `X-User-ID`, then resolves a per-request access policy: requests without a modern `X-Client-Version` fall into a legacy profile that skips the invoice ownership check. It binds only to `127.0.0.1`.

## Structure

```text
harness/                controller, CLI, policy, sources, validation, reporting
harness/cpg.py          tree-sitter call-graph (mini-CPG) builder
harness/runners/        Codex, Claude, Muse, and mock adapters
policies/default.json   reusable permissions, budgets, and model route
schemas/                model output contract
targets/invoice-demo/   one app plus a hunt manifest per bug (BOLA, XSS, traversal)
fixtures/               deterministic conference fallback
tests/                  test suite (CPG tests skip without tree-sitter)
requirements.txt        optional static-analysis backend
runs/                   one folder per scan
```

Scan flow: collect source → build call graph (`cpg.json`) → partition it into clusters (`clusters.json`) → one reasoning call per cluster, each with the full source plus its subgraph → merge reports → gate each finding → run the target's fixed localhost checks per finding → write `finding.json` and `report.md`.

## Setup

The scans run on the standard library. The call-graph stage needs tree-sitter:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Without it the harness logs `cpg_skipped` and prompts with source only.

## Run the demo

### Phase 1: run the application with npm

Terminal 1, from this directory:

```bash
cd targets/invoice-demo/app && npm start
```

No install step is needed; the app has zero dependencies. Open
`http://127.0.0.1:3000` in your browser: keep the user `alice`, load
`invoice-alice` (works), then load `invoice-bob` — it also works, which is
the flaw. Re-run with client version `2.0` to see the standard profile block
it. The same requests from a shell, while the app is running:

```bash
cd targets/invoice-demo/app && npm run demo
```

For contrast, `npm run start:fixed` runs the corrected mode, where the
cross-user request returns 403 instead.

The same app also serves a greeting page and a docs reader (linked from the
UI). Show those flaws from a shell while the app is running:

```bash
cd targets/invoice-demo/app && npm run demo:xss
cd targets/invoice-demo/app && npm run demo:traversal
```

### Phase 2: run the harness to find the vulnerability

Terminal 2, from the repo root with the environment active, while the app
from Phase 1 is still running:

```bash
python -m harness scan --runner muse
```

Swap the runner without changing the controller (`codex`, `claude`, `muse`).
The default hunt is generic: one standard prompt casts the model as a
security engineer hunting vulnerabilities, names no weakness types, and the
run validates only when all three seeded bugs (BOLA, XSS, path traversal)
are found and proven. To hunt a single bug
instead, pick a focused manifest with `--target`:

```bash
python -m harness scan --runner muse --target targets/invoice-demo/bola.json
python -m harness scan --runner muse --target targets/invoice-demo/xss.json
python -m harness scan --runner muse --target targets/invoice-demo/traversal.json
```

Use the deterministic fallback if a conference network or model login fails:

```bash
python -m harness scan --runner mock
```

Add `-v` for step-by-step console logging via Python's `logging` module
(`step 1/6` through `step 6/6`, with per-cluster progress inside step 4), or
`-vv` for debug detail such as the executed runner command, prompt size, and
subprocess byte counts. The default output stays quiet; `events.jsonl` always
keeps the full audit trail. The model prompt is staged in a temporary file
outside `runs/` and removed after the call.

Each run creates a timestamped folder under `runs/` containing:

- `events.jsonl`: controller and policy decisions
- `cpg.json`: call-graph nodes and edges (when tree-sitter is installed)
- `clusters.json`: one entry-point cluster per feature area, plus shared code
- `clusters/<name>/`: per-cluster provider trace files when a live runner runs
- `finding.json`: per-finding verdicts, coverage gaps, and run status
- `report.md`: short human-readable result
- provider trace files at the run root when clustering is skipped (no tree-sitter)

The policy stays reusable. It grants source reads and localhost validation, sets budgets, and chooses the default runner. The target manifest describes this specific application and its fixed requests. A different target can use the same policy without adding application routes, identities, or weakness identifiers to the policy.

The controller supplies numbered source excerpts plus each cluster's call-graph slice to the model. The adapters do not grant shell, network, or write tools. Python quarantines findings outside the collected files or target scope (logged and listed in the report instead of aborting the run) and performs target-defined checks instead of executing model-proposed commands. Fixed checks match JSON bodies with `body_contains` and raw text (HTML, file bytes) with `body_text_contains`.

The traversal bug reads real files through the docs endpoint; like the other seeded bugs it is intentional, and the app binds only to `127.0.0.1` — run it locally and do not expose it to a network.

## Call graphs and Joern

`harness/cpg.py` is a tree-sitter backend that needs no JVM: it parses the
collected JavaScript into function nodes plus resolved/external call edges.
`runs/<scan>/cpg.json` is the interchange contract — a Joern exporter that
writes the same `{nodes, edges}` shape can replace the backend without
changing the controller, the prompt, or the runners.

## Test

With the environment active:

```bash
python -m unittest discover -s tests -v
```

The tests start vulnerable and corrected localhost instances, verify all three seeded bugs plus the missing-coverage report, exercise the policy gates, check the call-graph extraction, and confirm that all runners share the same output contract. They also pass on a bare interpreter, with the tree-sitter tests skipped.

The Muse adapter shells out to `muse exec` with the finding schema (`--output-schema`), the prompt via a temporary `--prompt-file`, machine-readable `--json` tracing, and write/shell/web tools disabled. If `muse` is not on `PATH` or not logged in, the run fails with a runner error and the mock fallback above still works.
