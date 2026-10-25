# Work done — session 1 (2026-09-19)

Chronological, with what was verified. Companion to `HANDOFF.md` (how to resume).

## 1. Orientation
- Repo had one commit (`208bb70`, README only). Read prior memory (`riskgraph_spec.md`, developer profile) and the intelligence-kit docs 03/04/05/18/22.
- Reconciled the earlier frozen spec with the new, larger brief. Superseded: additive 0.35/0.35/0.30 risk formula, Jinja2 frontend option, k3s deployment, 6-milestone plan.

## 2. Blueprint (`docs/blueprint/`, 9 files, ~18.8k words)
- `00_BLUEPRINT.md` — executive summary, exact problem, scope, non-goals, honest novelty table vs DefectDojo / Dependency-Track / dep-scan / Snyk-Wiz, 12-step demo script, 11 project risks, MVP vs stretch list.
- `01_ARCHITECTURE.md` — 13 brief layers mapped to 5 process types; module map; 16-step scan data flow; job/scanner state machines; Celery canvas; full container isolation profile (non-root, cap-drop ALL, read-only, network none, seccomp, limits, socket proxy); Scanner protocol; canonical finding model; per-source fingerprinting; severity mapping; context sources and `riskgraph.yaml` manifest schema; reachability tiers L0–L3; graph node/edge schema with invariants; attack-graph derivation with `w = -ln p`, Dijkstra + Yen's k-shortest, rejected alternatives; hybrid risk model (geometric-mean likelihood × arithmetic-mean impact, floors 0.05, rule overrides, effective impact from paths, thresholds 70/45/20), worked scenarios A–E (verified numerically), sensitivity/calibration/limits; AI explanation pipeline with EvidencePack, validator, fallback.
- `02_DATA_AND_API.md` — 20 V1 tables with keys/indexes, deferred entities, retention; API cross-cutting rules (JWT/API key, RBAC, RFC 7807, cursor pagination, rate limits, CORS, audit) and ~35 endpoints; frontend stack and feature folders; two CI/CD integration paths (webhook, polling Action), policy YAML, RiskGraph's own CI pipeline.
- `03_THREAT_MODEL.md` — STRIDE: 7 assets, 6 actors, 12 surfaces, 20 threats with mitigations by phase and residuals, 7 testable security invariants.
- `04_TECH_STACK.md` — every choice vs runner-up with reversal trigger (Neo4j rejected; Celery+Redis accepted with justification; AWS limited to EC2/S3/IAM).
- `05_REPO_STRUCTURE.md` — domain-module monorepo layout (replaces the brief's type-first layout).
- `06_ROADMAP.md` — phase dependency graph; 20 phases with weeks and DoD; total 37 + 3 buffer weeks with the 30-week cut list. P6 merged into P5; auth skeleton moved to P2; P16 = 1-week consolidation.
- `07_TESTING_AND_EVALUATION.md` — test layers/markers, 13 dataset directories, evaluation RQ/hypotheses, 4 methods, constructed + blind ground truth, KEV hold-out, metrics, bootstrap CIs, ablations, threats to validity.
- `08_DEPLOYMENT.md` — Compose prod topology, 11 NFR targets, 13-row failure-handling table.
- Self-attack fixes applied: roadmap week arithmetic corrected (37 not 36); §14.3 "reduces to CVSS+EPSS" claim narrowed to "context-free = function of EPSS and CVSS impact only"; image scanning limited to `FROM` base images (never `docker build` a hostile repo); socket-proxy variable names marked BELIEVE.

## 3. Phase 0 (docs)
- `docs/PROJECT_SPEC.md` — problem, 6 assumptions, RQ, success criteria S1–S8 with evidence, 7 principles.
- `docs/THREAT_MODEL.md` — living copy of blueprint 03.
- `docs/adr/README.md` + ADR 0001 monolith, 0002 stack, 0003 UUIDv7/single-tenant/deletion, 0004 auth, 0005 hosting, 0006 graph storage, 0007 Celery+Redis, 0008 sync SQLAlchemy.
- `docs/phases/PHASE_00.md`.

## 4. Phase 1 (code) — see `docs/phases/PHASE_01.md` for the full chapter
Backend (`backend/`): `pyproject.toml` (uv, ruff strict select, mypy strict, pytest markers), `riskgraph/shared/{config,logging,problems,request_id,redis,health}.py`, `shared/db/{session,base,uuid7}.py`, `entrypoints/{api,worker}.py`, Alembic (`alembic.ini`, `env.py`, `script.py.mako`), tests (`conftest`, `test_config`, `test_health`, `test_worker`, `test_uuid7`) — 16 tests.
Frontend (`frontend/`): Vite 8 + React 19 + TS 5.9 + TanStack Query, ESLint 10 flat config banning `dangerouslySetInnerHTML`, `App.tsx` showing healthz/readyz.
Infra: `docker/backend.Dockerfile` (uv, non-root, healthcheck), `docker/frontend.Dockerfile`, `docker-compose.yml` (7 services, configurable ports, source-only mounts, per-service healthchecks), `docker-compose.test.yml`, `infrastructure/postgres/init-test-db.sh`, `.env.example`, `Makefile`, `.pre-commit-config.yaml`, `.github/workflows/ci.yml` (backend, frontend, security self-scan, image build+scan), `.gitignore`, `.dockerignore`, `CLAUDE.md`, `README.md`.

### Problems hit and fixed during Phase 1
| Problem | Fix |
|---|---|
| hatchling: readme outside project dir | removed `readme` from pyproject |
| ruff: import order, unused noqa, N818 on `Problem` | auto-fix; explicit `noqa: N818` with reason |
| mypy: 3 unused `type: ignore` | removed |
| test asserted `env == "dev"` while conftest sets `test` | test passes `env="dev"` |
| npm audit: 7 vulns (vite 5, vitest 2, router 6) | rewrote devDependencies to current majors, clean install → 0 vulns |
| npm ERESOLVE: TypeScript 7 vs typescript-eslint | TS pinned `^5.9.3` |
| compose: port 5432 then 5433 taken by other projects | ports parameterised; `.env` uses 15432/16379/18000/15173 |
| compose: `exit 127` from migrate (host venv shadowing image venv) | source-only bind mounts |
| worker/beat "unhealthy" (inherited HTTP healthcheck) | `celery inspect ping` for worker; disabled for beat |

### Verified results
ruff clean · mypy clean (22 files) · 15 unit tests pass · 1 db test passes against Compose · frontend lint/typecheck/build clean, 0 audit findings · all Compose services healthy · `readyz` 200 with real DB+Redis · `ping.delay().get()` → `pong` through the real worker · Vite proxy returns API JSON.

## 5. Commit
`da286b2 Add blueprint, phase 0 docs and phase 1 dev environment` — 77 files, no `.env`/venv/node_modules.

## 6. After the commit (uncommitted at time of writing)
`docs/phases/PHASE_01.md`, README port note, `HANDOFF.md`, `workdone.md`; memory updated.


# Work done: session 2 (2026-10-21): MVP vertical slice

The owner asked for an MVP, answering the clarifying questions as follows:
- scanners run as binaries in the worker;
- no auth, localhost only;
- the blueprint score in its context-free form, plus EPSS/KEV;
- overlapping scanners merged into one finding.

The owner kept the 70/45/20 bands. Plan approved; built on `claude/great-mendel-b58dhj`.

## What was built
- **Backend modules:** `repositories`, `scans` (workspace, clone, storage, state machine, pipeline stages, Celery tasks and canvas, service, router), `scanners` (protocol, `SubprocessRunner`, redaction, four adapters and parsers), `normalization` (canonical model, paths, severity, CWE categories, fingerprints, curated merge families, merge), `findings`, `context` (CVSS sub-scores, EPSS, KEV with CISA GitHub-mirror fallback), `risk` (model `v1-cf.1`).
- **Data:** one migration with 9 tables.
- **Shared:** `shared/celery.py` (factory moved out of the worker entrypoint), `shared/http.py` (allow-listed outbound client), `shared/vocabulary.py`.
- **Frontend:** router, new-scan form, scan list, scan detail (scanner cards, summary tiles, findings table with URL-synced filters and sort, score-breakdown drawer).
- **Packaging:** `install-scanners.sh` (checksum-verified tarballs, uv tool venvs, vendored Semgrep rules), Dockerfile `worker` target, Compose volumes, Make targets (`scanner-tools`, `api-local`, `worker-local`, `e2e`), CI tweaks.
- **Docs:** ADR-0009, ADR-0010, `PHASE_MVP.md`, `TECH_STACK.md`, threat-model note, README.

## Problems hit and fixed
| Problem | Fix |
|---|---|
| semgrep.dev, api.first.org and www.cisa.gov blocked by this session's proxy | Rules from `semgrep/semgrep-rules` at a pinned sha; KEV from CISA's GitHub mirror; EPSS degrades to CVSS |
| `semgrep --version` hangs with no network | Version probe reuses the scan env (`SEMGREP_ENABLE_VERSION_CHECK=0`) |
| Trivy misconfig IDs are now `AWS-0086`, not `AVD-AWS-0086` | `normalize_check_id` accepts all three historic forms |
| Gitleaks and Trivy report the same PEM key with different line ranges | Secret merge uses overlapping ranges within a credential family |
| Semgrep check ids prefixed by the local rules path | `clean_rule_id` |
| CVSS sub-scores off by 0.1 | NVD rounds half-up (not CVSS Roundup) for sub-scores |
| API returned a stale PENDING status after CAS to QUEUED | `session.expire_all()` after `start_scan` |
| Celery folds post-chord tasks into the chord body | Canvas test asserts the real shape |
| Controlled checkboxes snapped back (React Router URL updates are transitions) | Findings view state is local and mirrored to the URL |
| 2 new high npm advisories in the existing lockfile (Vite, source-map-js) | `npm audit fix` gives 0 |


# Work done: session 4 (2026-10-22): MVP level 2 extended

The owner had built MVP level 2 (manifest context) on `cloud-mvp-integration` and asked to extend it with reachability, attack paths + graph, and triage + scan history. The work went on a new branch, `mvp-level2-extended`. The plan was approved.

## What was built
- **`modules/reachability`:**
  - a tree-sitter extractor that runs as an isolated subprocess (runner gains `memory_limit` and the `riskgraph-python` alias);
  - an import graph with entry points;
  - tiers L0/L1/L2, with indirect dependencies inheriting through Trivy's `Relationship`/`DependsOn` (new `trivy.parser.dependency_graph`), and a "used without import" list plus npm script commands;
  - a `reachability_results` table.
- **`modules/graph`:**
  - an attack graph from the manifest and findings (the manifest gains an optional `identities[].credentials` key);
  - NetworkX Yen paths;
  - effective impact;
  - `graph_nodes`, `graph_edges`, `attack_paths` and `attack_path_findings` tables, and a router.
- **`modules/audit`:** `audit_logs`.
- **Findings:**
  - `history.py` (change, fixed/reopened, diff);
  - `triage.py` (status changes, gate policy);
  - router: `PATCH`, diff, gate, new filters.
- **Repositories router:** trend.
- **Risk model `v1-ctx.2`:** R from reachability, the `I*` adjustment, the L0 ceiling.
- **`analyze`:** restructured into pure passes followed by one write transaction.
- **CLI:** `entrypoints/cli.py`.
- **Frontend:**
  - attack paths panel, a lazy Cytoscape graph view, triage panel, reachability column and filters, history line, repository page;
  - `lib/level2.ts` with tests;
  - `cytoscape` 3.34.3 and `vitest` 5.0.3, both pinned.
- **Tests:**
  - kitchen-sink extended (a yaml route, `scripts/legacy.py`, `MANIFEST`);
  - fixtures re-recorded, with Trivy's trim made round-robin per package;
  - new test files `test_reachability`, `test_attack_paths`, `test_cli`, `test_level2_ext_db`;
  - e2e extended.

## Problems hit and fixed
| Problem | Fix |
|---|---|
| `dict(result.tuples())` called `Result.keys()` | `.tuples().all()` |
| The trimmed Trivy fixture kept only django CVEs | Round-robin trim per package |
| NodeGoat: deps of `forever` (started from npm scripts) came out L0 | Extractor reads `package.json` script commands; such packages are "used without import" → unknown |
| `npm install` crashed in arborist (`edgesOut`) when pinning vitest | Restore the lock, `npm ci`, then pin step by step |
| vitest ≤ 5.0.2 advisories | Pinned 5.0.3 (more than 2 weeks old) |
| Cytoscape tripled the bundle | `React.lazy` graph chunk (main 332 kB) |
| Long scanner titles as credential labels | `<family> credential · file:line` |
| `setSearchParams` during render | View state is the source of truth; an effect mirrors it to the URL |
