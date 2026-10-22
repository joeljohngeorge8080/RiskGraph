# PHASE MVP level 2: context-aware scoring

**Status:** done (2026-10-21). Branch `cloud-mvp-integration`. Decision: ADR-0011. Builds on `PHASE_MVP.md`.

## A. Objective
1. Run, test and debug the cloud-built MVP on the dev machine, including `make dev` with Docker, which the cloud session could not verify.
2. Make the score context-aware. A `riskgraph.yaml` in the scanned repository and the repository's visibility replace the "unknown" defaults for exposure (X), data sensitivity (D), privilege (P) and criticality (C), so the 70/45 bands are reached on evidence instead of only through overrides.

## B. Why
Context is what separates RiskGraph from "CVSS + EPSS, sorted". The MVP computed the §14.3 context-free score: every finding had X = D = P = C = unknown, and the base score topped out around 42–46. The blueprint already defines the manifest (§11.1), the factor tables (§14.2) and the 2-hop sensitivity rule. This phase wires them into the existing pipeline without new tables.

## C. Architecture
```
analyze (worker)
  parse → fingerprint → merge → EPSS/KEV
  load_manifest(workspace)          ← riskgraph.yaml / .yml at the checkout root (safe_resolve, 64 KiB)
  ContextResolver(manifest, public_repository=True)
     for each merged finding: service = longest path prefix of its file
                              X, D, P, C ← service (manifest), X ← visibility for secrets
  score(ScoreInput(..., context))  → risk_scores + risk_factors (source, confidence, evidence)
  summary.context                  → manifest status, warnings, services, unmapped count
finalize → workspace deleted
```

## D. Components
| Component | File |
|---|---|
| Manifest schema, loader, alias refusal | `backend/riskgraph/modules/context/manifest.py` |
| Per-finding context resolution, 2-hop BFS, summary | `backend/riskgraph/modules/context/environment.py` |
| Context value tables, model version | `backend/riskgraph/modules/risk/tables.py` |
| Context factors, KEV-isolated rule | `backend/riskgraph/modules/risk/model.py` |
| Wiring | `backend/riskgraph/modules/scans/pipeline.py` (`_manifest`, `analyze`) |
| UI | `frontend/src/features/scans/ContextPanel.tsx`, `FindingDrawer.tsx` (factor origin) |
| Example manifest | `docs/examples/riskgraph.yaml` |

## E. Technical decisions
See ADR-0011. In short:
- strict manifest, ignored as a whole when invalid;
- secrets in a public repository count as `internet_noauth`;
- an internet service with `auth` not declared counts as no auth, with confidence medium;
- D is the most sensitive store within 2 hops, with ties going to fewer hops;
- R stays unknown;
- the KEV floor is skipped for `isolated` services.

Two options were weighed for where context lives:
- (a) inside the risk model as new `ScoreInput` fields;
- (b) a separate `FindingContext` value passed in.

(b) won. The model stays pure, `score(inp)` without context is byte-for-byte the old model (so §14.3 tests still pin it), and the context module owns the manifest semantics.

## F. Folder structure
Two new files in `modules/context/`. No new modules, no `utils/`. `risk` imports `FindingContext` / `Observed` through `modules/context/__init__.py`.

## G. Database
No migration. Context provenance is stored in the existing `risk_factors` rows (`raw_value` = label, `source`, `confidence`, `evidence`). The scan's context summary is stored in `scan_jobs.summary.context` (jsonb). `risk_model_version` is `v1-ctx.1` for new scans.

## H. API
No new endpoints. `GET /scans/{id}` now returns `summary.context`:
```json
{"manifest": "valid", "file": "riskgraph.yaml", "warnings": [], "public_repository": true,
 "services": [{"name": "app", "path": "/", "exposure": "internet_noauth", "privilege": "admin",
               "data": "pii", "criticality": "high", "findings": 27}],
 "unmapped_findings": 0}
```
`manifest` is one of `absent`, `valid`, `invalid` or `unavailable`. `GET /findings/{id}` factors now carry context sources: `manifest` or `repository_visibility`.

## I. Algorithms
- **Mapping:** services are sorted by path length, descending, and the first prefix match wins. The finding's file is normalized first (leading `./` and `/` stripped).
- **Exposure:** `internet` + `none` → `internet_noauth`; `internet` + `required` → `internet_auth`; `internet` + not declared → `internet_noauth` (medium confidence); `internal`; `isolated`.
- **Data sensitivity:** breadth-first search from the service over service → `runs_as` identity, service → `connects_to`, identity → `can_access`, stopping at 2 hops. The pick is the maximum by (sensitivity rank, −hops). Ranks: credentials 4 > pii = financial 3 > confidential 2 > internal 1 > public 0. The evidence keeps the hop path.
- **Score:** unchanged formula (§14.2) with the context values `X {1.0, 0.7, 0.4, 0.15}`, `D {1.0, .9, .9, .7, .4, .1}`, `P {1.0, .8, .5, .3}`, `C {.9, .5, .2}`.

Hand-checked cases, asserted in `tests/test_risk_model.py`:

| Case | Score | Priority |
|---|---|---|
| SCA EPSS .05, impact 5.9, internet_noauth / pii / admin / high | 69.97 | High (R unknown keeps it under 70) |
| SAST SSRF high + HIGH confidence, same context | 72.43 | Critical (no override) |
| Generic secret, public repository | 48.41 | High (no override) |
| SCA EPSS .05 on isolated / public / read_only / low | < context-free | Low |
| KEV on an isolated service | no floor | not High |

## J. Implementation
Build order:
1. run the existing suites on the dev machine and fix what broke;
2. manifest loader with its tests;
3. resolver with its tests;
4. model context factors with their tests;
5. pipeline wiring and DB tests;
6. UI;
7. Docker stack and a live scan;
8. docs.

## K. Commands
```bash
make test                                   # unit tests (165)
POSTGRES_PORT=25432 REDIS_PORT=26379 make test-services
RISKGRAPH_DATABASE_URL=postgresql+psycopg://riskgraph:riskgraph@localhost:25432/riskgraph_test \
RISKGRAPH_REDIS_URL=redis://:riskgraph@localhost:26379/1 make test-db     # 24 db/API/pipeline
make dev                                    # full stack; then scan a repo with a riskgraph.yaml
```

## L. Configuration
No new settings. The manifest limits (64 KiB, 200 items per list) are constants in `context/manifest.py`.

## M. Testing
- `test_manifest.py` (28):
  - the valid example, including `docs/examples/riskgraph.yaml`;
  - 10 strict-validation rejections, each with a reason;
  - broken YAML, wrong top level, empty file, aliases, a 9⁹ alias bomb, an unsafe `!!python` tag;
  - 20,000-deep nesting (this crashed with `RecursionError` before the depth check), bounded warnings;
  - path normalization;
  - the yml fallback, oversize and non-UTF-8 files, a symlink out of the checkout.
- `test_environment.py` (7): longest prefix, exposure labels, the 2-hop pick, the 3-hop cut-off, secrets without a manifest, the summary.
- `test_risk_model.py` (+7): blueprint formula with full context, critical without override, quiet context lowers the score, secret visibility, KEV on an isolated service, unknown labels fall back, monotonicity in X (Hypothesis).
- `test_pipeline_db.py` (+2): a manifest raises no score and lifts critical findings from 2 to 14; an invalid manifest completes the scan with warnings.

## N. Security
| Threat | Mitigation |
|---|---|
| Hostile manifest (T-02, T-13) | fixed names, `safe_resolve`, 64 KiB, UTF-8, `safe_load`, aliases and depth > 8 refused from the event stream, strict schema, list caps, bounded warnings; never raises |
| Graph poisoning (T-12) | manifest factors are labelled `manifest` in every breakdown; the Context panel lists all services; the conflict flag waits for IaC extraction (Phase 7) |
| Data leakage | manifest content is not logged (status and file name only) |

## O. Validation
Dev machine (Parrot Linux, Python 3.12.15, Node 20.19, Docker 29.6).
```
$ uv run ruff check . && uv run ruff format --check . && uv run mypy   → clean
$ make test                                                            → 165 passed
$ make test-db (ports 25432/26379)                                     → 24 passed
$ npm run lint && npm run typecheck && npm test && npm run build       → clean / clean / 5 passed / 319 kB
```
`docker compose build` (api, worker with the four scanners, frontend images) → succeeded.
Not yet run: `make dev` end to end with a live scan through the UI.

## P. Expected output
A scan of a repository with a valid manifest shows a Context panel with one row per service. In the finding drawer, X / D / P / C read for example `internet_noauth · manifest · high · service app` and `pii · manifest · high · app → users-db`.

## Q. Definition of done
- [x] Existing suites green on the dev machine (after fixing the trivy-cache crash)
- [x] Manifest parsed strictly and safely; never fails a scan
- [x] X/D/P/C from manifest and visibility, with provenance; R still unknown
- [x] Without context the scores equal v1-cf.1 (existing fixtures unchanged)
- [x] UI shows context and factor origin
- [x] ADR-0011, threat-model note, README, HANDOFF
- [ ] CI observed green on GitHub (the `trivy-action@0.28.0` pin from Phase 1 is still unresolved)

## R. Common failure modes
- **The Context panel says "invalid":** read the warnings. The usual causes are an undeclared name in `runs_as` / `connects_to`, or a misspelled key (unknown keys are rejected).
- **A service shows 0 findings:** its `path` does not prefix the scanner-reported files. Paths are relative to the repository root, without a leading `/`.
- **Scanners FAILED with "internal error" on a host run:** `RISKGRAPH_TRIVY_CACHE_DIR` must be writable (`make worker-local` sets it).

## S. Next phase
- Phase 2, auth: still the gate before anything but localhost.
- Phase 7 proper: Compose/K8s/Terraform extraction below the manifest, plus an IaC-vs-manifest conflict flag (T-12).
- Phase 8, reachability: replaces the last unknown factor, R.
