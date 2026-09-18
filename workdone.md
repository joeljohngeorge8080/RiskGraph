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
