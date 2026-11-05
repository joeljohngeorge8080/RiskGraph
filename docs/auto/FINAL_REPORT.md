# Final report: auto sessions 26–31 Oct 2026 (branch `extended_phase_auto`)

**Verdict: PARTIAL against the six-day schedule.** Everything that could be built in the
cloud was built, tested and pushed. X4 part 2 (Joern) was not built: it needs the owner's
spike (L-2, F-3-1). Seven flags wait for the owner; none blocks the code that is there.

## What was built, by phase
| Phase | Day | What | Decision | Migration |
|---|---|---|---|---|
| X2 part 2 | 1 | `scan_images` stage (`trivy image`, ≤ 5 refs, 2 GB cap, warnings only), image package findings, base-OS EOL, SBOM `image` | ADR-0018 amendment | `b8d3f1a6c2e9` |
| X3 part 1 | 1 | A graph from Compose and Kubernetes when the manifest declares no services | ADR-0019 | none |
| X3 part 2 | 2 | Two-pass search (hypotheses never change a score), `/attack-paths` grouped by assurance with `missing_evidence[]`, manifest `owns:` links | ADR-0020 | none |
| X4 part 1 | 2 | RiskGraph's own taint catalogue → 10 generated Semgrep rules, `taint_flow` evidence, the 40-case suite and scorer; **off by default** | ADR-0021 | none |
| X4 part 2 | 3 | Not built (Joern spike not run). Instead: tier-1 multi-line sink correlation | — | — |
| X5 part 1 | 3 | Extractor `ts-imports.4`, `modules/authz` guard catalogue and route inventory, `GET /scans/{id}/routes` | ADR-0022 | none |
| X5 part 2 | 4 | Authz findings (inconsistent, unguarded-sensitive, policy, BOLA hypothesis), manifest `authz:`, `GET /scans/{id}/authz/manual`, UNGUARDED / BOLA_SUSPECT edges without a probability | ADR-0023 | none |
| X6 | 5 | Risk model `v2.1`: factor tables for image packages, tier-1 taint, runtime EOL, inferred authz; image packages scored in their services' context; scenarios F–H | ADR-0024 | none |
| Integration | 6 | Frontend vocabulary, template remediation for runtime/authz, example manifest (below) | — | none |

Chapters: `docs/phases/PHASE_X2.md` … `PHASE_X6.md`. Day plans and reports: `docs/auto/DAY_<n>_{PLAN,REPORT}.md`.

## State at the end (VERIFIED, `43842f1`, 2026-10-31)
- Backend: ruff, ruff format and mypy clean; **661 unit**; **84 db, 2 skipped** (the real
  scanners); perf 4 passed (build + search 5,001 nodes / 22,596 edges in 0.65 s).
- Migrations: up / down -1 / up, **and a full downgrade to base and back up** (9 revisions
  each way), then `alembic check`: no new operations.
- Frontend: eslint and `tsc` clean, 11 Vitest tests, production build.
- X0: the pooled table equals `BASELINE.md`. The only differences are the three recorded
  since day 1: the model line (`v2.1`), the line saying authz findings are outside the set,
  and C's AWS key at rank 6 instead of 1 in the M4 top 10 (X1's intended change).
- For comparison, at the start of day 1: 386 unit, 66 db.

## Open flags (all `Status: OPEN`, in `FLAGS.md`)
| Flag | Question | Blocks | Recommendation |
|---|---|---|---|
| F-1-1 | Compose database images as `data_store` nodes? | NodeGoat-style paths without a manifest; scenario G's DB end | (a) yes, `confidential`, labelled as assumed |
| F-1-2 | CAN_ACCESS from RBAC bindings has no target | the plan's verified RBAC edge | (a) keep privilege on the identity |
| F-2-1 | Tier-1 taint rules on by default? | tier 1 in the default profile | (a) yes, after L-4 passes |
| F-3-1 | Joern spike not run | X4 part 2 entirely | run L-2 |
| F-4-1 | How the evaluation counts authz findings | authz labels in X0 | (a) keep out; a scenario with labels written first |
| F-4-2 | Declaring routes public on purpose | unguarded-sensitive precision (0.6) | (a) `authz.public: [patterns]` |
| F-5-1 | Every finding of an exposed service takes the path's I*? | nothing (current rule pinned) | (b) own support ≥ inferred, foothold categories only |

## Local tasks still TODO (`LOCAL_TASKS.md`)
| Id | Task | Unblocks |
|---|---|---|
| L-2 | Joern spike, `RESULT.md` + fixtures | F-3-1, X4 part 2 |
| L-3 | Real `trivy image` stage end to end, overhead per image | X2 part 2's overhead criterion |
| L-4 | Tier-1 rules on the real Semgrep, the 40-case suite | F-2-1 |
| L-5 | Joern through the runner on NodeGoat | after L-2 |
| L-6 | `make test-llm` after the new path and taint evidence | explanation quality |
| L-7 | `make dev`, apply migrations, click through the new API fields | the UI over the new data |
| L-8 | Trivy accepts `--max-image-size` with `--image-src remote` | every image run |
| L-9 | One scan with `RISKGRAPH_SCANNER_RUNNER=docker`, Trivy SUCCEEDED | container runner |
(L-1 is DONE.)

## Not decided anywhere yet (follow-ups, not flags)
- A probability for UNGUARDED / BOLA_SUSPECT edges (ADR-0024 leaves it open).
- Cross-file handlers for BOLA (NodeGoat's IDOR).
- X7: show a path's assurance and `missing_evidence[]` in the attack-paths panel and the
  drawer; the API serves both, the UI does not read them yet.
- X8: the evaluation the plan names.

## Things the owner should know
- Every commit on this branch is on `extended_phase_auto` only; nothing was merged or
  pushed elsewhere. PR #2 is untouched.
- Day 6's commits carry the sandbox's configured git identity, not the one of days 1–5
  (the run book says to use the configured one when it exists). The content rules hold.
- `1fd675c` (day 4) and `ea5a710` (day 2) were each pushed with a defect fixed in the
  next commit; see those days' reports.
