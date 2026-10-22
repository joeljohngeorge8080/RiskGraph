# PHASE MVP level 2, extended: reachability, attack paths, triage and history

**Status:** done (2026-10-22). Branch `mvp-level2-extended`, cut from `cloud-mvp-integration` (`1ccaa41`). Decisions: ADR-0012 (reachability), ADR-0013 (graph, paths, triage, history, gate). Builds on `PHASE_MVP2.md`.

## A. Objective
Extend MVP level 2 (context-aware scoring from `riskgraph.yaml`) with three capabilities from the blueprint:
1. **Reachability (Phase 8, L0–L2):** is the vulnerable package or code actually imported and reachable from an entry point? This fills R, the last "unknown" factor.
2. **Security graph and attack paths (Phases 9–10):** Internet or leaked credential → sensitive data, privileged identity or critical service, ranked by probability. Findings on a path get their impact raised (§14.4).
3. **Triage and scan history (Phase 14 subset):**
   - false positive / accepted risk / won't fix, with an audit trail;
   - new / existing / reopened / fixed between scans;
   - diff and per-repository trend;
   - a CI gate with a CLI.

## B. Why
Reachability and attack paths are what separate "contextual risk" from "CVSS + EPSS, sorted":
- a CVE in an unused package should drop;
- a medium bug on the way to PII should rise.

Triage and history make the list usable over time: noise can be suppressed with a reason, and every scan answers "what changed?".

## C. Architecture
```
analyze (worker), pure first, then one write transaction
  parse → fingerprint → merge → manifest → ContextResolver
  reachability: riskgraph-python -I -m …reachability.extract SRC OUT   (subprocess, no net, RLIMIT_AS 2 GiB)
               → import graph + entry points → TierClassifier (+ Trivy Relationship/DependsOn)
  EPSS/KEV → pass 1: score(context, reachability)
  graph.analyze(manifest, findings): attack graph → Yen k=3 per sink → effective impact per finding
  pass 2: rescore findings on paths with I_eff (factor I*)
  ── txn: findings, occurrences, scores+factors, reachability_results, graph_nodes/edges,
          attack_paths(+findings), apply_history (change, fixed/reopened), summary
finalize → workspace deleted
API: PATCH /findings/{id} · /scans/{id}/diff · /gate · /attack-paths · /graph · /repositories[/{id}]
CLI: python -m riskgraph.entrypoints.cli scan …  → exit 0/1/2, $GITHUB_STEP_SUMMARY
```

## D. Components
| Component | File(s) |
|---|---|
| Extractor (tree-sitter, separate process) | `backend/riskgraph/modules/reachability/extract.py` |
| Import graph, entry points, reachable set | `modules/reachability/graph.py` |
| Package → import names, "used without import" | `modules/reachability/package_names.py` |
| Tier rules incl. indirect inheritance | `modules/reachability/tiers.py` |
| Run and persist | `modules/reachability/service.py`, `models.py` |
| Attack graph, Yen paths, effective impact | `modules/graph/attack.py` |
| Graph persistence and queries, router | `modules/graph/{service,models,router}.py` |
| History (change, fixed/reopened, diff) | `modules/findings/history.py` |
| Triage and gate | `modules/findings/triage.py`, `modules/findings/router.py` |
| Audit log | `modules/audit/{models,service}.py` |
| Repository trend | `modules/repositories/router.py` |
| Model v1-ctx.2 (R, I*, L0 ceiling) | `modules/risk/{model,tables,service}.py` |
| Pipeline wiring | `modules/scans/pipeline.py` (`analyze`) |
| Runner: memory limit, `riskgraph-python` alias | `modules/scanners/runner.py` |
| Trivy dependency graph | `modules/scanners/trivy/parser.py` (`dependency_graph`) |
| CLI | `backend/riskgraph/entrypoints/cli.py` |
| UI | `frontend/src/features/scans/{AttackPathsPanel,GraphView}.tsx`, `features/findings/TriagePanel.tsx`, `features/repositories/RepositoryPage.tsx`, `lib/level2.ts` |
| Migration | `backend/alembic/versions/20261022_0709_level2_ext_triage_reachability_graph.py` |

## E. Technical decisions
See ADR-0012 and ADR-0013. In short:
- **Never demote on missing evidence.** Transitive dependencies inherit from their direct parents. Tools, CLIs, plugins and anything invoked from `package.json` scripts are `unknown`, never L0. When no entry points are found, an imported package is L2 with low confidence.
- **Extractor isolation.** It runs in its own process with an address-space limit, never in the worker's process. Repository code is parsed, never executed.
- **Two-pass scoring.** Edge probabilities come from pass-1 scores; effective impact comes from the paths; pass 2 only raises, through `max`.
- **History is derived from rows, so it is idempotent.** Fixed requires every reporting scanner to have succeeded. Triage is sticky.
- **Gate from a CLI for self-hosted runners.** The API has no auth (ADR-0010).
- **Credential node labels** read `aws credential · main.tf:3` instead of the scanner's long title.
- **Reuse:** `SubprocessRunner` runs the extractor; `Observed` (context) carries reachability provenance; `normalize_path`, `safe_resolve` and the families table are reused.

## F. Folder structure
Three new modules: `modules/reachability`, `modules/graph`, `modules/audit`. Cross-module imports go through `__init__`; the scans ↔ findings/repositories routers use a lazy import to avoid a cycle. No `utils/`.

## G. Database
One migration `b7dac1b028da` (revises `fc3b3ff80221`), reviewed by hand:
- **New tables:** `reachability_results`, `graph_nodes`, `graph_edges`, `attack_paths`, `attack_path_findings`, `audit_logs`.
- **`findings` columns:** `status_reason`, `status_changed_at`, `fixed_in_scan_id`; plus a CHECK on `status`.
- **`scan_findings.change`:** NOT NULL. The server default `existing` applies only during the migration, for existing rows.
- **`risk_scores.effective_impact`.**

Up/down/up is clean and `alembic check` reports no drift.

## H. API
| Method & path | Notes |
|---|---|
| `GET /scans/{id}/findings` | New filters `status` (default `open`), `change`, `reachability`. Items carry `status`, `change` and `reachability`. |
| `GET /findings/{id}` | Adds `status_reason`, `change`, `reachability{tier, confidence, evidence}`, `attack_paths[]`, `history[]` (audit), `risk.effective_impact` |
| `PATCH /findings/{id}` `{status, reason}` | 422 without a reason, for `fixed`, or for unknown values; audited |
| `GET /scans/{id}/diff?against=` | new / reopened / fixed |
| `GET /scans/{id}/gate?fail_on=&max_score=&new_only=&include_statuses=` | `{passed, violations[], policy, evaluated}` |
| `GET /scans/{id}/attack-paths` | ranked |
| `GET /scans/{id}/graph` | nodes and edges, ≤ 2,000 nodes |
| `GET /repositories`, `GET /repositories/{id}?history=` | summary and trend |

## I. Algorithms
- **Tiers:** see the ADR-0012 table. R values: L2 .8, L1 .5, L0 .1, unknown .6.
- **Attack graph:**
  - EXPLOIT `p = max geomean(E, R)` over a service's non-L0 code findings;
  - AUTHENTICATES_AS `p = E(secret)`;
  - control edges `p = 1`;
  - `w = −ln p`;
  - Yen k = 3 per sink, at most 8 hops, at least one attack edge;
  - `path_score = 100·∏p·I(sink)`.
- **Effective impact:** `I_eff(f) = max_paths I(sink)·P(π)/p(e_f)`, used if greater than I.
- **Override:** L0 with high confidence → priority ≤ Medium, unless KEV.

Hand-checked paths (`tests/test_attack_paths.py`):

| Path | P | Score |
|---|---|---|
| AWS key → api-role → orders-db | .9 | 81 |
| Internet → web → AWS key → api-role → orders-db | .54 | 48.6 |
| Internet → web → api → orders-db | .3 | 27 |

I_eff of the web SQLi = .9·.54/.6 = .81.

## J. Implementation
Build order:
1. baseline on the new branch;
2. models and migration;
3. history and triage;
4. extractor, graph and tiers, with tests;
5. model v1-ctx.2;
6. attack graph, with tests;
7. pipeline rewiring;
8. API;
9. CLI;
10. tests (unit, db, e2e);
11. UI;
12. live run;
13. docs.

## K. Commands
```bash
make test                     # 192 unit
make test-db                  # 32 db/API/pipeline (needs postgres+redis)
make e2e                      # 2 e2e with the real scanners (incl. manifest, paths, re-scan)
uv run python -m riskgraph.entrypoints.cli scan --repo https://github.com/OWASP/NodeGoat --fail-on high
```

## L. Configuration
- No new settings. Extractor limits are constants in `reachability/{extract,service}.py`: 2 MB per file, 50k files, 300 s, 2 GiB.
- Path search limits are in `graph/attack.py`: k = 3, 8 hops, 50 candidates per sink.

## M. Testing
- **Unit tests (192, +27):**
  - `test_reachability.py` (13): extraction for Python and JS/TS, hostile inputs (50k-deep nesting, binary files, big files, symlinks), import resolution, every tier rule including indirect inheritance and npm scripts, name mapping, the isolated runner, the memory limit.
  - `test_attack_paths.py` (6): hand-computed paths and probabilities, effective impact, k and hop limits, control-only paths, no manifest, credential families.
  - `test_risk_model.py` (+5): R, the L0 ceiling versus KEV, I* raises but never lowers, exploit likelihood.
  - `test_cli.py` (3): pass with summary, fail with escaping, errors.
- **DB tests (32, +8)** in `test_level2_ext_db.py`:
  - tiers on the kitchen sink;
  - paths, graph, I* through the API;
  - new → existing → fixed → reopened;
  - no fixed verdict when a reporting scanner failed;
  - triage validation, audit, stickiness, default filter;
  - gate (critical, `max_score`, `new_only`);
  - repository trend;
  - idempotent re-analysis with graph and history.
- **e2e (2, +1):** real scanners with the manifest. It checks:
  - django L0, requests L1, pyyaml L2;
  - an Internet path and a credential path to users-db;
  - effective impact > 0;
  - a re-scan has 0 new;
  - no raw secret in `graph_*`, `attack_paths`, `reachability_results` or `audit_logs`.
- **Frontend:** Vitest 8 (+3 for trend bars, path labels, history line).

## N. Security
| Threat | Mitigation |
|---|---|
| T-07 (hostile source vs parser) | tree-sitter in a separate process, RLIMIT_AS 2 GiB, CPU/file-size limits, timeout, no network, `-I`; iterative traversal; size, binary and symlink skips; output size-capped |
| T-02 (scanner/extractor output) | the extractor's JSON is read with a cap and treated as data; paths stay opaque strings |
| T-06 / T-09 (secrets) | credential nodes are labelled by family and location, never by value; e2e checks the new tables |
| T-12 (manifest poisoning) | `credentials` links are strictly validated, and every factor and edge carries its source |
| T-16 (repudiation) | `audit_logs` for every triage change (actor `local` until Phase 2) |
| Graph UI | Cytoscape labels are plain text; node keys are never interpolated into selectors |

## O. Validation
VERIFIED in this session's cloud container: Python 3.13 venv, Postgres 16, Redis, real trivy 0.76 / semgrep 1.182 / checkov 3.3.30 / gitleaks 8.30.1, no Docker daemon.
```
$ uv run ruff check . && uv run ruff format --check . && uv run mypy   → clean (130 files)
$ pytest -m "not db and not e2e"   → 192 passed
$ pytest -m "db and not e2e"       → 32 passed
$ pytest -m e2e                    → 2 passed (real scanners)
$ npm run lint && npm run typecheck && npm test && npm run build && npm audit
  → clean / clean / 8 passed / index 332 kB + GraphView 437 kB (lazy) / 0 vulnerabilities
Live (uvicorn + celery -c 4 + vite):
  OWASP/NodeGoat @ c5cb68a7: 108 findings; reachability 40 files, 20 entry points;
    SCA tiers L2 37 · L0 4 · unknown 61; express → qs/send/path-to-regexp inherit L2;
    re-scan → +0 new / −0 fixed, 108 existing
  bridgecrewio/terragoat: re-scan → 0 new, 1096 existing; reachability unknown (Java)
  kitchen sink + riskgraph.yaml (real scanners): 7 attack paths, top
    "aws credential · main.tf:3 → app-role → users-db" (81.0)
  CLI gate on NodeGoat: --fail-on critical --fail-on high → exit 1 (1 critical, 2 high);
    --new-only → exit 0
  Playwright: attack paths, graph highlight, drawer (I*, paths, triage), triage save,
    reachability evidence, repository trend; no console errors
```
BELIEVE (not runnable here): `make dev` with Docker. No new image steps are needed: tree-sitter wheels come in through `uv sync`, and the extractor uses the venv interpreter.

## P. Expected output
The scan page shows:
- "+N new · −M fixed vs previous scan" under the title;
- a reachability note with tier counts;
- an "Attack paths" panel: a scored list with chips, and a graph view in which a selected path is highlighted.

Finding drawer, from top to bottom:
1. triage controls;
2. the formula with `I*` when raised;
3. factor R from `reachability`;
4. a Reachability section (imported by, chain from the entry point, via);
5. "On N attack path(s)";
6. History.

## Q. Definition of done
- [x] L0/L1/L2 per finding with evidence; R in the score; L0 ceiling
- [x] Graph, ranked attack paths, effective impact (I*) with provenance
- [x] Triage with audit; new / existing / reopened / fixed; diff; repository trend
- [x] Gate endpoint and CLI (`$GITHUB_STEP_SUMMARY`, exit codes) with a self-hosted runner example
- [x] Lint, type, unit/db/e2e and frontend gates green; live scans; screenshots
- [x] ADR-0012, ADR-0013, this chapter, threat-model note, TECH_STACK, README, HANDOFF
- [ ] `make dev` with Docker on the dev machine
- [ ] CI observed green on GitHub

## R. Common failure modes
- **"Reachability: import extraction failed":** check the worker log for the extractor's exit code. RLIMIT_AS may be too low for a huge repository, but the scan still completes with R unknown.
- **Many `unknown` tiers:** the repository's language isn't Python or JS/TS, or there are no source files next to the manifest. Expected.
- **No attack paths:** there is no `riskgraph.yaml`, or no exposed service has a non-L0 code finding and no leaked credential links to an identity (`identities[].credentials`).
- **A finding is missing from the list after triage:** the list defaults to `status=open`. Tick the status filter.

## S. Next phase
- Phase 2 (auth) is still the gate for anything beyond localhost, including hosted CI runners and webhooks.
- Phase 3: DockerRunner (ADR-0009).
- Phase 7 proper: Compose, Kubernetes and Terraform topology, so paths exist without a manifest.
- Phase 8 rest: L3 via a Python call graph plus `vulnerable_symbols.yaml`.
