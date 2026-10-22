# HANDOFF: resume here (updated 2026-10-22, session 5: integration and graphify)

## Session 5 (2026-10-22, local): integrate, fix CI, graph — current state
- **Branch:** `mvp-level2-integration` at `74b40f3`, pushed. It is `cloud-mvp-integration` (`1ccaa41`) plus `mvp-level2-extended` (`392e68f`, a fast-forward), then the fixes and the graphify commit. `main` is still at `8fa3a97`.
- **PR:** draft **#2** `mvp-level2-integration` → `main`. CI green on `74b40f3`: backend, frontend, security-self-scan, images. Mark ready and merge when you're happy. **PR #1** (`claude/great-mendel-b58dhj`) is superseded by #2 and still open; close it after #2 merges.
- **CI fixes (`d253adc`, `e708cbb`):**
  - `aquasecurity/trivy-action@0.28.0` no longer exists upstream; pinned to v0.36.0 by commit `ed142fd0…`. This was why the security and image jobs died at setup.
  - The image scan then found a **critical** advisory in `certifi 2026.7.22` (GHSA-6q48-6c7w-9gw2, emSign CA keys). Bumped to `2026.10.19`, which is two days old at the time.
  - `httpx2==2.13.1` added as a dev dependency so Starlette's TestClient stops warning about httpx. Its transitive `truststore` is held at `0.10.4`, which is my choice: 0.10.5 was under two weeks old and I didn't check with you before holding it back.
  - `make test-db`, `test-all` and `e2e` now read the database and Redis ports from `.env` (`15432`/`16379` here).
- **Verified here:** ruff, format and mypy clean; 192 unit tests passed; 32 db tests passed (2 e2e skipped: no scanners on the host); migration round trip; frontend lint, typecheck, 8 tests, build, npm audit 0.
- **Verified live (`make dev`, Docker):** all services healthy; migration at head `b7dac1b028da`; readyz OK. Live scan of OWASP/NodeGoat: COMPLETED, 124 findings (1 critical), reachability L0 4 / L1 3 / L2 37 / unknown 74. A rescan showed 0 new, 0 fixed, 124 existing, and the gate went from fail to pass after one finding was marked `accepted_risk`.
- **Not verified:** attack paths on a live scan. NodeGoat has no `riskgraph.yaml`, so its graph is empty. The DB tests cover the path logic. Scanning a repo with a manifest would close this.
- **Dev DB leftovers:** two NodeGoat scans and one `accepted_risk` finding (reason "integration test").
- **graphify:** `graphify-out/` built: 2021 nodes, 5827 edges, 91 communities. Committed in `74b40f3` with the `CLAUDE.md` section, `.claude/settings.json` hook-guards and `.gitattributes`. The graph was built by Claude subagents over the docs and the AST over code; the Gemini extraction was discarded as too sparse.
  - The git post-commit hook rebuilds the graph after every commit and leaves uncommitted changes in `graphify-out/`. How to handle this is still undecided (see Open items).
  - `.claude/settings.json` points at `/home/jojo/.local/bin/graphify`, which only exists on this machine.
- **Gotchas found this session:**
  - Dev and test compose both bind 15432/16379 from `.env`. Run one stack at a time; `make test-db` works while `make dev` is up.
  - Starlette 1.6.0 still emits one `anyio` deprecation warning. Starlette 1.7+ removes it.
- **Next:** Phase 2 auth (`docs/adr/0004-auth-model.md`); it gates hosted CI and webhooks.

## Open items (decide before Phase 2)
- Graphify post-commit hook: keep it and ignore its outputs (add `.pending`, `.sig` and the dated snapshot folder to `.gitignore`), or remove it with `graphify hook uninstall` and rebuild by hand with `graphify update .`.
- Commit the rebuilt `graphify-out/graph.json`, or leave it uncommitted. Cloud sessions only see it if it is committed.
- Move `.claude/settings.json` to `.claude/settings.local.json` if its machine-specific graphify path is a problem for cloud sessions.
- Mark PR #2 ready, merge to `main`, and close PR #1.
- `docs/TECH_STACK.md` dependency log is still not created (see the session 1 open items).

---

## Session 4 (2026-10-22, cloud): MVP level 2 extended, done
- Branch `mvp-level2-extended`, cut from `cloud-mvp-integration`. Chapter: `docs/phases/PHASE_MVP2_EXT.md`. Decisions: ADR-0012 (reachability L0–L2) and ADR-0013 (graph and attack paths, effective impact, triage, history, CI gate).
- **Added:**
  - tree-sitter reachability in an isolated subprocess (R factor, L0 ceiling), model `v1-ctx.2`;
  - per-scan security graph and Yen top-3 attack paths, with I* effective impact;
  - triage with `audit_logs`; new / existing / reopened / fixed; diff; repository trend;
  - gate endpoint and CLI;
  - UI: attack paths panel, Cytoscape graph (lazy), triage panel, repository page.
  - One migration: `b7dac1b028da`.
- **Verified here:** 192 unit, 32 db and 2 e2e tests with the real scanners; frontend gates; live scans of NodeGoat and terragoat plus the kitchen sink with a manifest; the CLI gate; Playwright screenshots. **Not verified:** `make dev` with Docker.
- **Next:** Phase 2 auth (it gates hosted CI and webhooks), Phase 3 DockerRunner, Phase 7 IaC topology (paths without a manifest), Phase 8 L3.

---
# Session 3 handoff (2026-10-21, session 3: MVP level 2)

## Session 3 (2026-10-21): run, debug, MVP level 2 (context-aware scoring), done
- Branch `cloud-mvp-integration` (main + the cloud MVP merge `3c44f97` + this work). Chapter: `docs/phases/PHASE_MVP2.md`. Decision: ADR-0011.
- **Level 2:** `riskgraph.yaml` manifest (strict, hardened) plus repository visibility give X/D/P/C per finding. Model `v1-ctx.1`, identical to `v1-cf.1` without context. Context panel in the UI; the drawer shows the factor origin.
- **Bugs fixed:** non-trivy scanners crashed on a non-root host because the pipeline created the Trivy cache dir for every scanner; `tsconfig.app.tsbuildinfo` was tracked.
- **Verified on the dev machine:** 165 unit + 24 db tests, frontend gate, `docker compose build` (incl. worker image with scanners). **Not yet run:** `make dev` with a live scan.
- **Next:** Phase 2 (auth) is still required before anything but localhost. Then Phase 7 proper (IaC/Compose/K8s extraction under the manifest, conflict flag for T-12) and Phase 8 (reachability, the last unknown factor R).

---
# Session 2 handoff (2026-10-21)

## Session 2 (2026-10-21): MVP vertical slice, done
- Branch `claude/great-mendel-b58dhj`. The owner asked for an MVP ahead of the roadmap: a GitHub URL goes in; Trivy, Semgrep, Checkov and Gitleaks run; reports are normalized and merged; findings are scored; a FastAPI + React UI shows the result. Full chapter: `docs/phases/PHASE_MVP.md`. Decisions: ADR-0009 (subprocess runner) and ADR-0010 (scope deviations, including **no auth**).
- Verified in a cloud container without Docker: 123 unit, 22 db and 1 e2e test (real scanners), plus a live Celery run on terragoat. **Not verified:** `make dev` with the new `worker` image target. Run it on the dev machine first.
- **Next:** Phase 2 (auth skeleton) on top of migration `fc3b3ff80221`, then Phase 3 (DockerRunner behind `ScannerRunner`, the ADR-0009 trigger).
- Host runs need scanners: `make scanner-tools` installs them into `~/.local/share/riskgraph-tools`.

---
# Session 1 handoff (2026-09-19)

## Where things stand
- **Blueprint complete** (`docs/blueprint/00–08`), **Phase 0 done** (`docs/PROJECT_SPEC.md`, `docs/THREAT_MODEL.md`, `docs/adr/0001–0008`, `docs/phases/PHASE_00.md`), **Phase 1 done and verified** (`docs/phases/PHASE_01.md`).
- Commits: `da286b2` (blueprint, Phase 0, Phase 1 code) and `1c2ac72` (Phase 1 chapter, HANDOFF.md, workdone.md, README port note). Working tree was clean at end of session.
- **Next step: `START PHASE 2`** — domain model, Alembic migrations for V1 tables, auth skeleton (users/roles/JWT/refresh/API keys), repositories module. Design: `docs/blueprint/02_DATA_AND_API.md` §16–17, ADR-0003/0004/0008.

## This machine (important, non-obvious)
- Other projects occupy the default ports (native Postgres on 5432, `hma-postgres` on 5433, `dna-stego-*` on 8000 and 5173, Supabase on 5432x). **Do not stop those containers.**
- RiskGraph therefore uses, via `.env` (git-ignored, already created with a generated dev secret):
  `POSTGRES_PORT=15432  REDIS_PORT=16379  API_PORT=18000  FRONTEND_PORT=15173`
- URLs: API http://127.0.0.1:18000/api/v1/healthz · Swagger http://127.0.0.1:18000/api/v1/docs · Dashboard http://127.0.0.1:15173
- The Compose stack (`riskgraph-*` containers) was left **running** at the end of the session. `make down` stops it; `make dev-detached` restarts it.
- Host toolchain verified: Python 3.13 (uv creates a 3.12.13 venv in `backend/.venv`), uv 0.11.28, Node 20.19.2, npm 9.2, Docker 29.6.2, Compose 2.26. RAM 15 GB (only ~3 GB free with everything running).

## Commands that are known to work
```bash
make dev-detached                       # full stack in background
docker compose ps                       # expect: postgres/redis/api/worker healthy, migrate Exited(0), beat/frontend Up
curl -s 127.0.0.1:18000/api/v1/readyz  # {"status":"ok","checks":{"database":"ok","redis":"ok"}}
cd backend && uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest -m "not db and not docker" -q
make test-db                            # reads .env ports; needs make dev or make test-services running
cd frontend && npm run lint && npm run typecheck && npm run build
docker compose exec api python -c "from riskgraph.entrypoints.worker import ping; print(ping.delay().get(timeout=20))"   # pong
```

## Gotchas already hit (so you don't hit them again)
1. Mounting `./backend:/app` shadows the image venv → `exit 127`. Compose mounts `riskgraph/`, `alembic/`, `alembic.ini`, `tests/` only. Keep it that way when adding folders (add a new mount line per new top-level backend folder).
2. `pyproject.toml` must not reference `../README.md` (hatchling).
3. `conftest.py` sets `RISKGRAPH_ENV=test`; unit tests that assert on `env` must pass it explicitly.
4. Frontend: TypeScript 7 is on npm but typescript-eslint 8.70 needs <6.1 → TS pinned `^5.9.3`. Bump dev deps by editing `package.json` and clean-installing, not with `npm install -D a@latest b@latest …` (ERESOLVE).
5. Worker/beat must not inherit the image HTTP healthcheck (already handled in Compose).
6. `ruff` on the host PATH is an ancient 0.0.291; always use `uv run ruff`.

## Open items (small, do at the start of Phase 2)
- Verify `.pre-commit-config.yaml` hook revs (`uvx pre-commit autoupdate`) and the GitHub Action versions in `.github/workflows/ci.yml` (`setup-uv@v5`, `trivy-action@0.28.0`, `gitleaks-action@v2`, `build-push-action@v6`) against current releases. They are BELIEVE, not verified.
- Push to a GitHub remote and watch CI go green once.
- `docs/TECH_STACK.md` (dependency log per kit doc 04) not yet created; `docs/blueprint/04_TECH_STACK.md` holds the decisions. Create it when Phase 2 adds its first dependencies (`pwdlib[argon2]`, `PyJWT`).

## Rules of engagement (from the brief and CLAUDE.md)
- Implement one phase per `START PHASE N`; each phase writes `docs/phases/PHASE_NN.md` with chapters A–S.
- Never re-decide an ADR; write a superseding one.
- Report with VERIFIED / CONFIDENT / BELIEVE / GUESS labels; paste real output.
