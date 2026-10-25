# PHASE MVP — Scan, normalize, merge, prioritize (vertical slice)

**Status:** done (2026-10-21). Branch `claude/great-mendel-b58dhj`. Decisions: ADR-0009 (subprocess runner), ADR-0010 (scope and deviations).

## A. Objective
Paste a public GitHub URL into a web UI, and RiskGraph:
1. clones the repository;
2. runs **Trivy, Semgrep, Checkov and Gitleaks**;
3. normalizes the four reports into one canonical finding model;
4. merges duplicates across scanners;
5. scores every finding with the blueprint's risk model (context-free variant, live EPSS/KEV);
6. shows a prioritized, filterable list with a per-factor score breakdown.

## B. Why
The owner wanted a working product before continuing the 20-phase roadmap. The slice proves the core loop end to end:
- scanner orchestration;
- the redaction rules;
- normalization and merging;
- the explainable score.

Every module is placed where the blueprint puts it, so later phases (auth, context, reachability, graph) extend it rather than replace it.

## C. Architecture
```
Browser (React, Vite)  ──/api/v1──▶  FastAPI (api)  ──enqueue──▶  Redis  ──▶  Celery worker
                                        │                                       │
                                        └──────────── PostgreSQL ◀──────────────┘
Worker canvas (ADR-0007):
  chain( clone ─▶ chord( run_scanner × {trivy, semgrep, checkov, gitleaks} ) ─▶ collect ─▶ analyze ─▶ finalize )

clone      git clone --depth 1 (hooks off, https only, no submodules) → workspaces/<id>/src (read-only), .git removed
run_scanner SubprocessRunner: argv list, env allow-list, timeout → process-group kill, rlimits
collect    read fixed out/<scanner>/<file> (size cap) → gitleaks redact (HMAC) → other redactors → scrub
           every report of every raw secret → scan_output/<id>/<scanner>.json (atomic) + sha256
analyze    parse → fingerprint → merge → EPSS/KEV/CVSS → upsert findings → occurrences → scores + factors
finalize   COMPLETED | PARTIAL | FAILED, delete workspace
```
Scan states: `PENDING → QUEUED → CLONING → SCANNING → ANALYZING → COMPLETED | PARTIAL`, and any of them can go to `FAILED`. Every transition is a compare-and-set `UPDATE … WHERE status = :from`, so redelivered Celery messages are no-ops.

## D. Components
| Component | File(s) |
|---|---|
| Vocabulary (enums shared by tables) | `backend/riskgraph/shared/vocabulary.py` |
| Celery factory (shared by API and worker) | `backend/riskgraph/shared/celery.py` |
| Outbound HTTP (host/path allow-list, no redirects, size cap) | `backend/riskgraph/shared/http.py` |
| Repository URL/ref validation | `modules/repositories/service.py` |
| Scanner protocol, runner, redaction, registry | `modules/scanners/{base,runner,redact,registry}.py` |
| Scanner adapters and parsers | `modules/scanners/{trivy,semgrep,checkov,gitleaks}/{adapter,parser}.py` |
| Canonical model, paths, severity, categories, fingerprints, merge tables, merge | `modules/normalization/*.py` |
| CVSS sub-scores, EPSS/KEV feeds, vulnerability cache | `modules/context/{cvss,feeds,service,models}.py` |
| Risk model, tables, persistence | `modules/risk/{model,tables,service,models}.py` |
| Findings persistence and queries | `modules/findings/{service,router,schemas,models}.py` |
| Scans: workspace, clone, storage, state, pipeline, tasks, canvas, service, API | `modules/scans/*.py` |
| Migration | `backend/alembic/versions/20261021_0255_create_mvp_scan_tables.py` |
| Frontend | `frontend/src/{api,lib,app,features/scans,features/findings}/`, `src/styles.css` |
| Scanner install | `infrastructure/scripts/install-scanners.sh`, `docker/scanner-versions.env` |
| Images and Compose | `docker/backend.Dockerfile` (targets `runtime`, `worker`), `docker-compose.yml` |
| Tests | `backend/tests/test_*.py`, `tests/e2e/`, `tests/fixtures/{repos,scanners}/` |

## E. Technical decisions
- **Subprocess runner behind a protocol** (ADR-0009). Adapters return `Command(argv, env)` built from `ScanPaths`, never a string.
- **Trivy runs `vuln,secret,misconfig`** (ADR-0010) so the four reports overlap and merging is real.
- **Checkov runs only IaC frameworks**: its `secrets` and `sca_package` frameworks would duplicate Gitleaks and Trivy without curated mappings.
- **Semgrep rules are vendored at install time.** The script tries the registry `p/default` first, then falls back to `semgrep/semgrep-rules@<pinned sha>` `*/security/*.yaml`. Scans need no network.
  - `semgrep --version` hangs without network unless `SEMGREP_ENABLE_VERSION_CHECK=0`, so version probes reuse the scan command's env.
- **Version probe and run share one environment**, so whatever a tool needs to start (HOME, version-check off) is set once.
- **Merging is conservative.** Merge keys:
  - secrets: same file, same credential family, overlapping lines. Gitleaks reports a PEM key at lines 1–15 and Trivy at 2–14.
  - IaC: same file, curated topic, same resource.
  - SAST: same file, line and primary CWE (four Semgrep rules flag one `shell=True` line).
  - Unmapped IaC checks never merge.
- **Celery folds post-chord tasks into the chord body.** `chain(clone, chord(h, collect), analyze, finalize)` becomes `chain(clone, chord(h, chain(collect, analyze, finalize)))`. Behaviour is the same; the test asserts the real shape.
- **Commit before enqueue.** `POST /scans` commits the PENDING row, CAS-updates it to QUEUED, commits again, then enqueues. If the broker is down the scan is marked FAILED and the API returns 503.
- **KEV fallback.** www.cisa.gov first, then CISA's own GitHub mirror (`raw.githubusercontent.com/cisagov/kev-data/…`, path-prefix allow-listed). This session's network blocks api.first.org and www.cisa.gov.

## F. Folder structure
Matches `docs/blueprint/05_REPO_STRUCTURE.md`:
- New modules under `backend/riskgraph/modules/`: `repositories`, `scans`, `scanners`, `normalization`, `findings`, `context` and `risk`.
- Cross-module imports go through each package's `__init__.py`, except the scan pipeline's internal submodules.
- No `utils/` folders.

## G. Database
One migration (`fc3b3ff80221`), autogenerated and reviewed by hand. Enums are stored as varchar plus CHECK, and all keys are UUIDv7.

| Table | Key points |
|---|---|
| `repositories` | `full_name` unique (lower-case) |
| `scan_jobs` | partial unique index on active `(repository_id, requested_ref)` for dedup; `summary` jsonb |
| `scanner_runs` | uq(scan, scanner); output path relative to the output root, sha256, bytes, error excerpt |
| `findings` | one merged issue per repository; uq(repository_id, merge_key); `detected_by[]`; first/last seen |
| `finding_occurrences` | every native result; uq(scan, scanner, fingerprint); redacted, capped evidence |
| `scan_findings` | which findings a scan saw, and by which scanners |
| `vulnerabilities` | CVSS vector and sub-scores, EPSS, KEV, fetched-at timestamps |
| `risk_scores` | likelihood, impact, corroboration, score, priority, priority_rank, overrides |
| `risk_factors` | E X R T D P C K, each with value, raw_value, source, confidence, applicable, evidence |

## H. API
All endpoints are under `/api/v1` and return RFC 7807 errors.

| Method & path | Notes |
|---|---|
| `POST /scans {repo_url, ref?}` | 202; 200 with `deduplicated: true`; 422 for `invalid-repository-url`, `invalid-ref` or `validation-error`; 429 `too-many-active-scans`; 503 when the queue is down |
| `GET /scans?status&limit&offset` | list, newest first |
| `GET /scans/{id}` | status, `scanner_runs[]`, summary |
| `GET /scans/{id}/findings` | filters `priority`, `source_type`, `scanner`, `severity` (all repeatable), `q`, `min_score`; sort `risk` (default), `score`, `severity`, `title`, `file`; `order`; `limit` ≤ 200; `offset` |
| `GET /findings/{id}?scan_id=` | merged finding, occurrences, score and factors, vulnerability intel |
| `GET /scans/{id}/reports/{scanner}` | redacted raw report download (`nosniff`, attachment) |

## I. Algorithms
**Fingerprints (§10.2).** Each is a sha256 over:
- sca: repo, vulnerability id, purl, file;
- sast: repo, rule, file, sha256 of the whitespace-collapsed matched lines, read through `workspace.safe_resolve`;
- secret: repo, rule, file, HMAC(secret);
- iac: repo, check, file, resource.

**Merge.** The keys are described in E. The representative is chosen by source type: Trivy for SCA, Semgrep for SAST, Gitleaks over Trivy for secrets, Checkov over Trivy over Semgrep for IaC. The merged severity is the highest member severity.

**Risk model `v1-cf.1`** (`risk/model.py`, pure):
```
L = geomean(E, X, R[applicable])        I = mean(T, D, P, C)        K = 1 + 0.05·min(n_scanners−1, 2)
score = min(100, 100·L·I·K)             bands: critical ≥ 70, high ≥ 45, medium ≥ 20, low
```

Exploitability (E):

| Finding type | E |
|---|---|
| CVE in KEV | 1.0 |
| CVE with EPSS | clamp((log10 epss + 4)/4, .05, 1) |
| CVE without EPSS | min(.7, .7·CVSS_exploitability/3.9) |
| CVE without CVSS | severity table |
| Secret | .9 for a live credential, .6 generic |
| SAST | high .7 / medium .45 / low .2, +.1 when Semgrep confidence is HIGH |
| IaC | public .6 / iam .5 / hygiene, encryption, logging .25 |

Technical impact (T):

| Finding type | T |
|---|---|
| CVE | CVSS impact sub-score / 6 |
| Secret | 1.0 |
| SAST | CWE category (injection, RCE, SSRF .9 … hygiene .2) |
| IaC | family (public .9 … hygiene .2) |

Context factors use the unknown defaults: X = .5, R = .6 (not applicable for secrets and IaC), D = P = C = .5.

Overrides:
- KEV and exposure not isolated → priority at least High;
- live credential → Critical.

Hand-computed fixtures, asserted in `tests/test_risk_model.py`:

| Case | Score | Priority |
|---|---|---|
| SCA, EPSS .05, impact 5.9 | 36.45 | Medium |
| SCA, EPSS 1e-4 | 15.31 | Low |
| KEV | 41.56 | High (override) |
| Live secret, Gitleaks only | 41.93 | Critical (override) |
| Live secret, Gitleaks + Trivy | 44.02 | Critical (override) |
| Generic secret | 34.23 | Medium |
| SAST high | 35.66 | Medium |
| SAST high, confidence HIGH | 37.29 | Medium |
| IaC public, Checkov + Trivy | 34.51 | Medium |
| IaC logging | 15.91 | Low |

## J. Implementation
Build order:
1. settings and the Celery/HTTP refactor;
2. models and migration;
3. runner;
4. kitchen-sink fixture repo and recorded fixtures from the real tools;
5. adapters and parsers;
6. normalization and merge;
7. context;
8. risk;
9. pipeline and orchestration;
10. API;
11. frontend;
12. packaging;
13. docs.

## K. Commands
```bash
make scanner-tools                   # host: trivy, gitleaks (checksum-verified), semgrep, checkov (uv tool), rules
make dev                             # compose: worker image includes the scanners (target "worker")
make api-local / make worker-local   # host runs (set RISKGRAPH_DATABASE_URL/REDIS_URL in .env)
make test                            # unit (123)
make test-services && make test-db   # db + API + pipeline with recorded reports (22)
make e2e                             # real scanners on the kitchen-sink repo (1)
uv run python -m tests.fixtures.scanners.record   # re-record fixtures after a scanner version bump
```

## L. Configuration
New settings, all prefixed `RISKGRAPH_`:
- `DATA_DIR` (`workspaces/` and `scan_output/` live under it), `SCANNER_BIN_DIR`, `SEMGREP_RULES_PATH`, `TRIVY_CACHE_DIR`;
- `TIMEOUT_{TRIVY,SEMGREP,CHECKOV,GITLEAKS}_S` (600/900/600/300);
- `CLONE_TIMEOUT_S` (180), `CLONE_MAX_BYTES` (500 MB), `CLONE_MAX_FILES` (100k);
- `RAW_REPORT_MAX_BYTES` (50 MB), `MAX_ACTIVE_SCANS` (3);
- `ENRICHMENT_ENABLED`, `EPSS_TTL_HOURS` (24), `KEV_TTL_HOURS` (12);
- `KEEP_WORKSPACES`.

Scanner versions are pinned in `docker/scanner-versions.env`: trivy 0.76.0, gitleaks 8.30.1, semgrep 1.182.0, checkov 3.3.30, and semgrep-rules `17e31e1`.

## M. Testing
- **Unit tests (123):**
  - URL and ref validation, including look-alike hosts, credentials, ports, IP literals and option-like refs;
  - runner: string argv rejected, env allow-list, grandchild killed with the process group, stdin closed;
  - workspace containment and symlinks; state machine;
  - parsers on recorded fixtures (shapes, garbage input, `../` paths); redaction and scrubbing;
  - merge: real fixtures, determinism, negative cases;
  - CVSS sub-scores against NVD values; EPSS batching; KEV fallback; outbound redirect, host and port refusal; body cap;
  - risk fixtures, EPSS mapping points, K = 1 equals the §14.3 formula, Hypothesis monotonicity in EPSS, impact and agreement;
  - canvas shape and queues.
- **DB tests (22):**
  - migration round trip;
  - full pipeline with recorded reports (47 raw results → 27 findings, 2 critical);
  - idempotent re-analysis, and a re-scan reuses findings;
  - one scanner failing → PARTIAL; all timing out → FAILED; clone failure → runs SKIPPED;
  - mocked EPSS/KEV drive E and the KEV override;
  - dedup index;
  - API: 202/200/422/429/503, list and get, filters and sorts, LIKE escaping, detail, report download, prod guard.
- **e2e (1):** the real scanners on the kitchen-sink repo. All four SUCCEEDED; secret and IaC findings merged across tools; **no raw secret in any table or stored report.**
- **Frontend:** Vitest on the pure helpers (5).

## N. Security
| Threat | Mitigation |
|---|---|
| T-01 | Weaker than the blueprint (ADR-0009). Env allow-list, non-root, read-only checkout, localhost-only API |
| T-02 | Paths from scanner output are normalized and opaque; the only file opened from them is through `safe_resolve` (inside `src`, regular file, ≤ 2 MB); reports are read only from fixed names, with size caps; React text-only rendering |
| T-03 | No shell; the clone URL is rebuilt; `ref` is regex-validated and passed after `--branch`, with `--` before the URL |
| T-05 | Host exactly github.com, https, no userinfo, port, query or redirects; git `protocol.allow=never` except https; outbound HTTP allow-lists host and path prefix |
| T-06 | Gitleaks values replaced by HMAC plus mask in memory; every report scrubbed of every raw secret; snippet fields dropped from all reports; the e2e test greps the DB and reports |
| T-13 | Clone depth 1, size and file caps, scanner timeouts, report caps, max active scans, active-scan dedup |

Unchanged gaps: no auth (ADR-0010), no rate limiting.

## O. Validation
VERIFIED in this session's cloud container (Python 3.13 venv, local Postgres 16 and Redis, no Docker daemon).
```
$ uv run ruff check . && uv run ruff format --check . && uv run mypy
All checks passed! / 105 files already formatted / Success: no issues found in 103 source files
$ uv run pytest -m "not db and not docker and not e2e and not perf" -q   → 123 passed
$ uv run pytest -m "db and not e2e" -q                                  → 22 passed
$ uv run pytest -m e2e -q                                                → 1 passed in 52.65s (real scanners)
$ npm run lint / npm run typecheck / npm test / npm run build            → clean / clean / 5 passed / 316 kB (98.7 kB gzip)
$ npm audit                                                              → found 0 vulnerabilities (after npm audit fix)

Live: uvicorn + celery worker -c 4 + vite; POST /scans {"repo_url":"https://github.com/bridgecrewio/terragoat"}
→ COMPLETED in 57 s, commit 729f8da6. Runs: checkov 472 results (6.5 s), gitleaks 4 (1.4 s), semgrep 0 (41.8 s), trivy 690 (6.8 s)
→ summary: raw 1155 → 1096 findings, 34 found by 2+ scanners; critical 2, high 2, medium 574, low 518
→ KEV via CISA GitHub mirror: 2 listed (CVE-2021-44228, CVE-2021-45046 → High by override); EPSS unavailable (host blocked here)
→ Playwright: home, scan, drawer, filter screenshots; no console errors
```
BELIEVE (could not run here): `make dev` with the new `worker` image target (no Docker daemon in this container).

## P. Expected output
Worker log: `scanner_done scanner=trivy status=SUCCEEDED`, then `scan_finished status=COMPLETED`.

`GET /scans/{id}` summary:
```
{"raw_findings":1155,"findings":1096,"cross_scanner":34,"by_priority":{"critical":2,"high":2,…},"intel":{"kev_listed":2,…}}
```

The UI's top rows are the two live AWS credentials (Critical, detected by gitleaks and trivy), then the KEV-listed Log4j CVEs.

## Q. Definition of done
- [x] GitHub URL in, four scanners run, four redacted reports stored and downloadable
- [x] Reports normalized into one model; duplicates merged across scanners with `detected_by`
- [x] Every finding scored, with factors and provenance; prioritized list with filters and sorting
- [x] Web UI (FastAPI + React + TS) shows scan progress, scanner cards, summary, findings, score breakdown
- [x] Lint, type and unit/DB/e2e tests green; raw secrets never persisted (e2e)
- [x] ADR-0009, ADR-0010, this chapter, TECH_STACK, threat-model note
- [ ] `make dev` verified with Docker (BELIEVE; run on the dev machine)
- [ ] CI observed green on GitHub

## R. Common failure modes
- **`semgrep --version` hangs:** network blocked and version check on. Set `SEMGREP_ENABLE_VERSION_CHECK=0` (done in the adapter env).
- **Scan FAILED "repository not found or not public":** private repo, typo, or no egress to github.com.
- **Trivy run TIMED_OUT "waited too long for the trivy cache lock":** another scan's Trivy run held the lock longer than 15 minutes.
- **Read-only checkout surprises when running as root:** root ignores permission bits. Tests skip that assertion for uid 0.
- **EPSS shows "unavailable":** api.first.org unreachable. E falls back to CVSS exploitability, recorded in the factor's `source`.

## S. Next phase
Back on the roadmap:
- **Phase 2:** auth skeleton. It must be in place before the API listens on anything but localhost.
- **Phase 3:** DockerRunner behind `ScannerRunner`, the ADR-0009 trigger.
- **Phases 7–8:** context and reachability, which make X, R, D, P, C real and the 70/45 bands reachable without overrides.
