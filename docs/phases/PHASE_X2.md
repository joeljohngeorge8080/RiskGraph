# PHASE X2: runtime and image intelligence (expansion plan)

**Status:** part 1 done (2026-10-25); part 2 (image scanning) next. Decision: ADR-0018. Migration `a7c2e9f4b1d6`. Plan: `docs/proposals/EXPANSION_A-D.md` §3.C, §4 (X2).

## A. Objective
X2 row of the plan:
- collect image references (Dockerfile, Compose, Kubernetes);
- `trivy image` plus a Syft image SBOM under ADR-0014, with egress, caps and a 5-image limit;
- runtime declarations;
- an endoflife.date client plus a Beat refresh;
- freshness per scan.

Exit criteria:
1. A fixture repository with `FROM python:3.8-slim` + `node:14` gives EOL findings with dates. **Done (part 1).**
2. A recorded `trivy image` fixture is parsed (OS and runtime packages, fixed versions). **Part 2.**
3. Every C finding has an advisory id, a range, a matched version and `data_as_of`. **Done for runtime EOL; part 2 for image packages.**
4. Scan overhead is at most +90 s per image with a warm cache, measured. **Part 2.**

The work is split in two so that the network-facing half (image pulls) is reviewed on its own.

## B. Why
Today RiskGraph only sees a repository's own dependency files. The base image, the OS packages inside it and the interpreter version are often where the oldest known flaws are. Findings that rest on advisory data must also say *when* that data was current; a finding with no data date can quietly go stale.

## C. Architecture (part 1)
```
workspace ─▶ iac.extract (now keeps Compose image:, k8s container images)
          ─▶ runtime.image_refs: Dockerfile FROM (+ line) ∪ Compose ∪ Kubernetes
                 parse_ref → registry/repository/tag/digest; allowed only on the public allow-list
          ─▶ runtime.declarations: exact pins (.python-version, runtime.txt, .nvmrc, engines, image tag)
                                   ranges/minimums recorded, never a finding
Beat (daily) ─▶ endoflife.date /api/{python,nodejs,go}.json ─▶ runtime_eol (fetched_at)
analyze ─▶ load_feeds ─▶ runtime_findings (exact ∧ ended) ─▶ merged with scanner findings
          producer: the per-scan riskgraph run (no report; not in final status)
          evidence: eol (verified, data_as_of = feed fetch time)
          Trivy package_match evidence: data_as_of = DB UpdatedAt from `trivy --version`
          assets: container_image (allowed / reason) · summary: runtime, freshness
risk v1-ctx.3: interim runtime EOL factors (E 0.5, T 0.6); X1's assurance gate
```

## D. Components
| Component | File |
|---|---|
| Image references, Dockerfile parsing, allow-list | `backend/riskgraph/modules/runtime/images.py` |
| Runtime declarations | `modules/runtime/declarations.py` |
| Feed parsing, EOL status, findings | `modules/runtime/eol.py` |
| `runtime_eol` model; store, load, refresh | `modules/runtime/{models,service}.py` |
| Beat task `riskgraph.runtime.refresh_eol` (daily) | `modules/runtime/tasks.py`, `shared/celery.py` |
| Image references kept by the IaC extractor | `modules/context/iac.py` |
| Outbound allow-list (`endoflife.date/api/`) | `shared/http.py` |
| Producer `riskgraph`, interim scoring, model `v1-ctx.3` | `shared/vocabulary.py`, `modules/risk/{tables,model}.py` |
| Pipeline: riskgraph run, runtime findings, image assets, freshness; final status | `modules/scans/pipeline.py` |
| EOL evidence and Trivy data date | `modules/scans/finding_evidence.py` |
| Trivy cache in the command environment (freshness) | `modules/scanners/trivy/adapter.py` |
| Migration | `backend/alembic/versions/20261025_1600_runtime_eol.py` |
| Recorded endoflife.date feeds | `backend/tests/fixtures/eol/{python,nodejs,go}.json` |

## E. Technical decisions
See ADR-0018. The owner decided three of them:
- image package CVEs stay `sca`, marked with the image;
- registries come from a public allow-list;
- runtime EOL gets a small interim score.

Others, in short:
- **EOL data is never fetched on the scan path** (Beat, the ADR-0015 pattern). A scan without stored data gives no EOL finding and says so in its summary.
- **Exact pins only produce findings.** A range is a support claim, not a deployment fact.
- **`riskgraph` producer run.** It keeps the NOT NULL `scanner_run_id`, and X5 reuses it. It is excluded from the final status. A test proves a scan whose scanners all failed is still FAILED.
- **Freshness reuses the existing `trivy --version` run.** Adding `TRIVY_CACHE_DIR` makes it print the DB build time (verified against the pinned 0.76.0 image: `UpdatedAt: 2026-10-25 01:20:33 +0000 UTC`).
- **Model version.** `v1-ctx.3` covers X1's assurance gate as well; X1 changed scores without a version bump.

### Verified before relying on it
- endoflife.date's response shape: recorded fixtures. `eol` is a date or a boolean; `lts` is a date or a boolean.
- The Trivy DB time field, as above.
- The oldest supported cycles on 2026-10-25: Python 3.11 (3.10 has ended), Node.js 22. Two of my test expectations were wrong (3.10) and were corrected from the data.

## G. Database
Migration `a7c2e9f4b1d6`, reviewed by hand:
- `runtime_eol` (PK product, cycle; `eol_date`, `eol_flag`, `latest`, `release_date`, `fetched_at`);
- `scanner_name` CHECKs on `scanner_runs` and `finding_occurrences` add `riskgraph`. The downgrade refuses while such rows exist.

Up, down and up are clean; `alembic check` reports no drift.

## H. API
No new endpoints. Scan detail adds:
- the `riskgraph` run (no report);
- `summary.runtime` (images, allowed images, declarations, EOL findings, products with data);
- `summary.freshness` (`trivy_db`, `eol`).

Runtime findings appear in the findings list. Their `evidence[]` holds an `eol` record with `data_as_of`. `container_image` assets are in `GET /repositories/{id}/context`.

## L. Configuration
None new. The EOL refresh runs when `RISKGRAPH_ENRICHMENT_ENABLED` is true, like the other feeds.

## M. Testing
- **`test_runtime_images.py` (12, unit):**
  - reference normalization (7 cases);
  - the allow-list, which refuses internal hosts, `localhost` and IP addresses;
  - unresolved or malformed references;
  - Dockerfile stages, flags and continuations;
  - Compose and Kubernetes merged and deduplicated;
  - oversized or binary files skipped.
- **`test_runtime_eol.py` (9, unit):**
  - the recorded feed parses dates and booleans; malformed entries are skipped;
  - exact versus range declarations from 7 file kinds and image tags;
  - EOL status and the oldest supported cycle;
  - findings only for exact ended cycles, with advisory, package, dates and `data_as_of`;
  - no data, no finding.
- **`test_runtime_eol_db.py` (4, db):**
  - a `FROM python:3.8-slim` + `node:14` repository gives two dated findings from the riskgraph run;
  - those findings carry the interim score, verified `eol` evidence with the feed date, Trivy evidence with the DB date, `summary.freshness`, and `container_image` assets (the internal registry refused, with the reason);
  - no data, no findings;
  - the Beat refresh keeps old data when a product fails;
  - the feed is on the allow-list, and another path on the same host is refused.
- **`test_finding_evidence.py` (+2):** the Trivy data date, and EOL evidence.
- **`test_risk_model.py` (+1):** runtime gets its own interim factors.
- **`test_merge.py`:** from X1.
- **Changed tests, with the reason in each:**
  - `test_pipeline_db.py`, `test_api.py`: assert on scanner runs; the riskgraph run is listed with no report.
  - `test_canvas.py`: `ALL_SCANNERS`, because riskgraph is never a task.
  - `test_evidence_db.py`: drop the riskgraph run before downgrading through X2.
  - `test_risks_db.py`: model `v1-ctx.3`.

## O. Validation (part 1)
```
make lint                → ruff: All checks passed! · 214 files already formatted
                           mypy: Success: no issues found in 205 source files · eslint, tsc clean
make test                → 382 passed
make test-db             → 66 passed, 2 skipped (e2e: no host scanners)
alembic upgrade/downgrade/upgrade; alembic check → a7c2e9f4b1d6 (head) · no drift
X0 evaluation re-run     → same 59 findings; only C's AWS key differs from BASELINE.md (X1's change)
```

## Part 2 (next): image scanning
- A new stage after the scanner chord: for each allowed reference (at most 5), run `trivy image` and `syft` in the egress container profile, with the size cap and per-reference caching. Warnings on failure.
- Parse into `sca` findings marked with the image; reachability not assessable; image SBOM components.
- Exit criteria 2–4: a recorded `trivy image` fixture, and overhead measured with a warm cache.

## Q. Known limits (part 1)
- The runtime EOL score is interim (X6).
- Ranges never produce findings.
- EPSS and KEV fetch times are not in `summary.freshness`.
- CronJob pod specs are not read (existing gap).
- Go is only detected from `golang` images (the `go.mod` line is a minimum).
