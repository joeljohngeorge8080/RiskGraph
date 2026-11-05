# Evaluation run book (X8)

How to measure every criterion of `docs/proposals/EXPANSION_A-D.md` §6 and fill in
`docs/evaluation/EVALUATION_EXPANSION.md`. The harness is `backend/evaluation/expansion.py`.

## Rules (from §6 and the blueprint)
- **The thresholds are pre-registered.** Do not change a target, a dataset or a metric after you see a result. If a result is weak, report it as it is.
- **Write labels before ranking.** A new scenario, or new ground truth for an old one, gets committed before its first run. The git history is the proof; `authz_scenario.py` (commit `99ae3ca`) shows how.
- **Never edit a generated report by hand.** Change the code or the inputs, then run the target again.
- `BASELINE.md` (X0) is frozen. Its known differences from a re-run are recorded in `HANDOFF.md` (X1 and X5 notes).

## What exists today (generated 2026-11-05)
| Command | Needs | Writes |
|---|---|---|
| `make eval-expansion` | nothing | `EVALUATION_EXPANSION.md`: A1–A3, B1–B3, D2; the rest NOT RUN |
| `make eval-expansion-full` | `make test-services` (the dev stack must be down: same ports). It empties `riskgraph_test` | the same, plus P1 |
| `make eval-baseline` | `make test-services` | `BASELINE.md`, `baseline_findings.csv` (X0) |
| `make eval-authz` | nothing | `AUTHZ_EVAL.md` (scenario I, F-4-1) |
| `uv run python -m evaluation.taint_suite write DIR` / `score DIR JSON` | Semgrep (tier 1) or the Joern image (tier 2) for new runs | a table on stdout |

The committed `EVALUATION_EXPANSION.md` came from `make eval-expansion-full`: **5 PASS, 3 FAIL, 5 NOT RUN**.

## Re-recording the inputs
### A: taint
**Tier 1** (real Semgrep, `make scanner-tools`):
```
cd backend
uv run python -m evaluation.taint_suite write /tmp/suite
semgrep scan --config riskgraph/modules/scanners/semgrep/taint_rules.yaml --json --metrics=off \
  -o /tmp/tier1.json /tmp/suite
uv run python -m evaluation.taint_suite score /tmp/suite /tmp/tier1.json
```
Copy the JSON to `tests/fixtures/semgrep_taint/real-<version>-suite-run.json`, then update `TIER1_RUN` in `expansion.py`.

**Tier 2** (Joern, `make scanner-images-deep`): run each Python case with the adapter's command in the ADR-0014 profile. The exact `docker run` line is in `docs/adr/0025-joern-tier2-deep-profile.md` and in the `JoernScanner.command` test. Save each `joern.json` to `tests/fixtures/joern/<tag>/adapter/<case>/`. The files under `/work` belong to uid 65534; remove them through a container, never with `sudo rm`.

### B: authorization
B is code only. The suites are `tests/test_authz_suite.py`, `tests/test_authz_findings_suite.py` and `evaluation/authz_scenario.py`. To add a framework, write its app and its labels first, in their own commit.

### P1: prioritization
Run `make test-services`, then `make eval-expansion-full`. Today:
- pooled nDCG@10 is 0.991 (RiskGraph) against 0.162 (M2);
- every method ties within each X0 scenario, so the pre-registered paired test over scenarios gives p = 1.00 (FAIL).

To give P1 statistical power, add scenarios where findings inside one repository differ in context: two services, or exposed and internal parts. Write their labels first.

## What is NOT RUN, and how to build it
Each item below is also in `docs/handover/BACKLOG.md`.

- **C1: known vulnerabilities in images.**
  1. Write a seeded list per repository first: the image refs from `tests/fixtures/images/` and, per ref, the CVE ids and EOL cycles you expect. Take them from a frozen Trivy DB, with the DB digest stored next to the list.
  2. Add `check_images()` to `expansion.py`. It replays the recorded `trivy image` reports through `scanners.trivy.parser.parse_image`, then checks that each seeded id is present with `package.version`, `fixed_version` (when one exists) and `data_as_of`.
- **D1 and D3: path accuracy and assurance calibration.**
  1. For each scenario A–H, write the expected node sequence of every attack path and, per edge, whether it is real. Write it before the run, in `evaluation/path_truth.py`.
  2. D1: a path is precise when every edge is in the truth.
  3. D3: group edges by stored assurance and count the share that is correct (target: verified ≥ 0.95, inferred ≥ 0.7).
- **P2: ablations.**
  1. Add one switch per expansion component to the pipeline, off by default:
     - −A drops taint (tier 1 and tier 2) findings and their evidence;
     - −B drops authz findings;
     - −C drops image and runtime findings;
     - −D skips the attack graph (no effective impact).
  2. Replay X0 once per switch (`evaluation.run.collect` with the switch set), then report nDCG@10, P@5 and P@10 per switch next to the full model.
  3. Use a test-only setting, so production never turns a component off by accident.
- **O1: overhead.**
  1. Run the five X0 scenario repositories with the real scanners (`make scanner-tools`, then `make e2e`-style inline runs), five times each, at the X0 commit and at HEAD.
  2. Report the p50 of `scan_jobs.finished_at - started_at`.
  3. Report deep-profile times separately (ADR-0025: about 13 s for 20 Python cases).
- **Realism.** OWASP Juice Shop and a Python vulnerable app (plan §6) are not wired in. NodeGoat was scanned (HANDOFF sessions 5–9), but it has no labels.

## Deep profile on the full stack (UNVERIFIED)
1. Set `RISKGRAPH_DEEP_PROFILE_ENABLED=true` in `.env`.
2. Run `make scanner-images-deep`, then `make dev`.
3. `POST /api/v1/scans` with `{"repo_url": "...", "profile": "deep"}`.

The pipeline path (DockerRunner, the Joern lock, cleanup) was measured inline on 2026-11-05: L-5 in `docs/auto/LOCAL_TASKS.md`. The full Compose stack with a deep scan has not been run.
