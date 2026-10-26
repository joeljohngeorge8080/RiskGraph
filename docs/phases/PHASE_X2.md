# PHASE X2: runtime and image intelligence (expansion plan)

**Status:** part 1 done (2026-10-25); part 2 (image scanning) built and tested with recorded fixtures on 2026-10-26. The real container run and the overhead measurement are the owner's (L-3, L-8). Decision: ADR-0018 (amended 2026-10-26). Migrations `a7c2e9f4b1d6`, `b8d3f1a6c2e9`. Plan: `docs/proposals/EXPANSION_A-D.md` §3.C, §4 (X2).

## A. Objective
X2 row of the plan:
- collect image references (Dockerfile, Compose, Kubernetes);
- `trivy image` plus a Syft image SBOM under ADR-0014, with egress, caps and a 5-image limit;
- runtime declarations;
- an endoflife.date client plus a Beat refresh;
- freshness per scan.

Exit criteria:
1. A fixture repository with `FROM python:3.8-slim` + `node:14` gives EOL findings with dates. **Done (part 1).**
2. A recorded `trivy image` fixture is parsed (OS and runtime packages, fixed versions). **Done (part 2).**
3. Every C finding has an advisory id, a range, a matched version and `data_as_of`. **Done** (runtime EOL in part 1, image packages and the base OS in part 2).
4. Scan overhead is at most +90 s per image with a warm cache, measured. **Not measurable in the cloud: L-3.**

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

## Part 2: image scanning (2026-10-26)

### C. Architecture
```
collect ─▶ scan_images (scan queue; needs a SUCCEEDED trivy run)
             image_refs ∩ allowed, sorted, first 5 ─▶ trivy image --image-src remote --list-all-pkgs
             egress network, Trivy lock, 300 s each, size cap (flag + Metadata.Size)
             redacted report ─▶ scan_output/<scan>/images/<k>.json ; index.json last (idempotent)
             warnings only: pull failure, cap, no DB, cancelled, out of time
analyze ─▶ parse_image: sca findings (package.image, location = declaring file, resource = ref)
           fingerprint + merge key scoped by image; reachability n_a; evidence image_package
           EOSL base OS ─▶ runtime-eol:os:<family>:<name> (riskgraph producer, data_as_of = CreatedAt)
           SBOM: image inventory (sbom_components.image); history: fixed only if the image was rescanned
```

### D. Components
| Component | File |
|---|---|
| `trivy image` command | `modules/scanners/trivy/adapter.py` (`image_command`) |
| Image report parser, inventory | `modules/scanners/trivy/parser.py` (`parse_image`, `ImageReport`) |
| Base-OS EOL finding | `modules/runtime/eol.py` (`os_eol_finding`) |
| Stage, analysis of the results | `modules/scans/pipeline.py` (`scan_images`, `_image_results`) |
| Canvas, task | `modules/scans/orchestration.py`, `tasks.py` |
| Report storage | `modules/scans/storage.py` (image reports and index) |
| Image scoping of keys | `modules/normalization/{fingerprint,merge}.py` |
| Fixed detection per image | `modules/findings/history.py` |
| SBOM `image`, `origin` filter | `modules/sbom/{models,service,router}.py` |
| Settings | `image_scan_max_refs` (5), `image_scan_max_bytes` (2 GiB), `timeout_trivy_image_s` (300) |
| Fake runner for images | `tests/pipeline_support.py` (`FixtureRunner.images`, `IMAGE_FIXTURES`) |

### E. Technical decisions
See the ADR-0018 amendment. In short:
- The stage needs a clean Trivy run. Without the DB, an image scan would download one or fail, and freshness would be unknown.
- The location is the file that names the image, and the image is the resource. Context (exposure from Compose) then applies to the image's findings.
- Image keys are scoped by the image **only when there is one**. Repository findings keep their fingerprints and merge keys (test).
- Image evidence has no raw pointer. It is not in the Trivy run's stored report, and pointing there would be false provenance.
- Downgrading the migration refuses while image packages exist (the old key cannot hold them), as `a7c2e9f4b1d6` does.

**Found and fixed on the way:** `TRIVY_CACHE_DIR` (X2 part 1) was not on the container env allow-list, so Trivy failed under the docker runner (`1f6f069`; test over every adapter; L-9 to confirm live).

### G. Database
Migration `b8d3f1a6c2e9`, by hand:
- adds `sbom_components.image VARCHAR(255) NULL`;
- replaces `uq_sbom_components_scan_purl` with `uq_sbom_components_scan_purl_image` (scan, purl, image; NULLS NOT DISTINCT).

Up/down/up clean; `alembic check`: no new operations.

### H. API
- `GET /scans/{id}/sbom`: each component has `image` (null for repository packages); optional `origin=all|repository|image` (default `all`). The other fields are unchanged.
- Scan detail: `summary.images` (`scanned`, per-reference `results` with status and warning, `warnings`, `findings`, `eol_findings`) and `summary.sbom.image_packages`.
- Image findings are in the findings list, with `package.image` and `image_package` evidence.

### M. Testing
- `test_image_scan.py` (17, unit):
  - command flags and the reference last;
  - option-shaped references refused, both by the command and by `parse_ref`;
  - both fixtures parsed: OS and language packages, fixed versions, purls, size, EOSL;
  - malformed reports;
  - image scoping of fingerprint and merge key, with repository keys unchanged;
  - the OS EOL finding;
  - image evidence data dates.
- `test_image_scan_db.py` (9, db):
  - stage and warnings (the internal registry is never pulled);
  - findings, evidence and n/a reachability;
  - the EOSL finding;
  - the SBOM endpoint;
  - the cap of 5 (set to 1);
  - no clean Trivy run means no pull;
  - a failed pull does not mark findings fixed. A mutation check showed this test fails without the guard;
  - idempotency;
  - a cancelled scan stops pulling.
- `test_containers.py` (+5): every adapter's command passes the container profile.
- `test_canvas.py`: changed for the new stage.

### O. Validation
See `docs/auto/DAY_1_REPORT.md` for the commands and output: lint, types, 421 unit, 77 db (2 skipped), migrations, X0 identical.

### Q. Known limits (part 2)
- Not run against a real registry or container here (L-3), and `--max-image-size` is unconfirmed on 0.76.0 (L-8).
- The image's findings attach to the first file that names it (references are deduplicated).
- Image packages score with the SCA model and unknown reachability (R 0.6) until X6 gives "not assessable" its own factor (R 0.5).
- No digest cache across scans: each scan pulls again (Trivy's layer cache is in memory).

## Q. Known limits (part 1)
- The runtime EOL score is interim (X6).
- Ranges never produce findings.
- EPSS and KEV fetch times are not in `summary.freshness`.
- CronJob pod specs are not read (existing gap).
- Go is only detected from `golang` images (the `go.mod` line is a minimum).
