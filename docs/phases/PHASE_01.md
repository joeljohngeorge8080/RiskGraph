# PHASE 1 — Repository & Development Environment

**Status:** done (2026-09-19). Committed in `da286b2` (chapter written after the commit).

## A. Objective
A reproducible local environment where every later phase runs: backend package, frontend skeleton, PostgreSQL, Redis, Celery worker and beat, Docker Compose, linting, typing, tests and CI — with health endpoints proving each part is wired.

## B. Why
Every phase must end with a running increment. That is impossible without a stack that starts with one command, tests that run without services, and CI that refuses unformatted, untyped or failing code. Doing this first also pins the security defaults (non-root images, no pickle in Celery, secrets only via env) before any feature code copies a bad pattern.

## C. Architecture
```
make dev
 ├─ postgres:16-alpine  (healthcheck pg_isready; creates riskgraph_test db via init script)
 ├─ redis:7-alpine      (requirepass; no persistence; healthcheck ping)
 ├─ migrate             (backend image; alembic upgrade head; runs once)
 ├─ api                 (uvicorn --factory riskgraph.entrypoints.api:create_app --reload)
 ├─ worker              (celery worker -Q scan,analysis; healthcheck celery inspect ping)
 ├─ beat                (celery beat; empty schedule)
 └─ frontend            (vite dev server; proxies /api → http://api:8000)
Host ports come from .env: POSTGRES_PORT, REDIS_PORT, API_PORT, FRONTEND_PORT.
```

## D. Components
| Component | File(s) |
|---|---|
| Settings (validated, crash on invalid) | `backend/riskgraph/shared/config.py` |
| Structured logging | `backend/riskgraph/shared/logging.py` |
| RFC 7807 problems + handlers | `backend/riskgraph/shared/problems.py` |
| Request-id middleware | `backend/riskgraph/shared/request_id.py` |
| DB engine/session/base/UUIDv7 | `backend/riskgraph/shared/db/{session,base,uuid7}.py` |
| Redis client | `backend/riskgraph/shared/redis.py` |
| Health/readiness router | `backend/riskgraph/shared/health.py` |
| API factory | `backend/riskgraph/entrypoints/api.py` |
| Celery app + ping task | `backend/riskgraph/entrypoints/worker.py` |
| Alembic | `backend/alembic.ini`, `backend/alembic/env.py`, `script.py.mako` |
| Tests | `backend/tests/test_{config,health,worker,uuid7}.py`, `conftest.py` |
| Frontend skeleton | `frontend/src/{main.tsx,app/App.tsx,api/client.ts}`, Vite/TS/ESLint config |
| Images | `docker/backend.Dockerfile`, `docker/frontend.Dockerfile` |
| Compose | `docker-compose.yml`, `docker-compose.test.yml`, `infrastructure/postgres/init-test-db.sh` |
| Tooling | `Makefile`, `.pre-commit-config.yaml`, `.env.example`, `.gitignore`, `.dockerignore` |
| CI | `.github/workflows/ci.yml` |

## E. Technical decisions
- **App factory, no module-level app** (`uvicorn --factory`): importing the API module never reads the environment, so tests build apps with explicit settings. The Celery module *does* instantiate at import because the Celery CLI needs an attribute and a misconfigured worker must not start.
- **Sync SQLAlchemy** (ADR-0008) over async: one session flavour for API and worker.
- **Source-only bind mounts** in Compose (`./backend/riskgraph:/app/riskgraph:ro` etc.) instead of `./backend:/app`. The whole-directory mount overlaid the image's `.venv` with the host's, whose interpreter path does not exist in the container (`exit 127`). Found and fixed during validation.
- **Configurable host ports**: this machine already runs other projects on 5432, 5433, 8000 and 5173. Ports are `${VAR:-default}` in Compose and set in `.env`.
- **Per-service healthchecks**: the image healthcheck hits HTTP, which worker/beat do not serve; worker uses `celery inspect ping`, beat disables the check.
- **Frontend on current majors** (Vite 8, Vitest 5, React 19, React Router 7, ESLint 10, TypeScript 5.9): the first `package.json` used 2024-era pins and `npm audit` reported 7 vulnerabilities (1 critical) in them; a clean install on current versions reports 0. TypeScript 7 exists but typescript-eslint 8.70 requires <6.1, so TS is pinned `^5.9.3`.
- **UUID v7 in-app** (ADR-0003): small standard implementation with a per-millisecond counter; Python 3.14's `uuid.uuid7` can replace it later.
- **ESLint bans `dangerouslySetInnerHTML`** repo-wide from day one (threat T-02/T-11).

## F. Folder structure
See `docs/blueprint/05_REPO_STRUCTURE.md`; everything created in this phase follows it. `backend/riskgraph/modules/` exists and is empty until Phase 2.

## G. Database
No tables yet. Alembic is wired (`env.py` takes the URL from settings and metadata from `riskgraph.shared.db.Base`); `alembic upgrade head` runs successfully with zero revisions. The compose init script creates `riskgraph_test` next to `riskgraph`.

## H. API
| Endpoint | Behaviour |
|---|---|
| `GET /api/v1/healthz` | `{"status":"ok","version":"0.1.0"}`; never touches dependencies |
| `GET /api/v1/readyz` | `{"status":"ok","checks":{"database":"ok","redis":"ok"}}` or `503 application/problem+json` with per-check errors |
| `GET /api/v1/docs`, `/api/v1/openapi.json` | Swagger UI; disabled when `RISKGRAPH_ENV=prod` or `RISKGRAPH_API_DOCS_ENABLED=false` |
| any unknown route | `404 application/problem+json` with `type`, `title`, `status`, `instance`, `request_id` |
Every response carries `X-Request-ID` (echoed if the incoming value matches `^[A-Za-z0-9._-]{1,128}$`, else generated) and `Cache-Control: no-store`.

## I. Algorithms
UUID v7: 48-bit unix ms · version nibble 7 · 12-bit sequence (random start, increments within the same ms, borrows the next ms on overflow) · variant bits · 62 random bits. Property tested: 5 000 consecutive ids are strictly increasing and unique.

## J. Implementation
All code is in the repository at `da286b2`; see D for the file map. Nothing in this chapter is pseudo-code.

## K. Commands
```bash
cp .env.example .env         # set RISKGRAPH_SECRET_KEY; adjust *_PORT if defaults are taken
make dev                     # or: docker compose up --build -d
make install                 # uv sync + npm install (host tooling)
make lint                    # ruff check/format, mypy --strict, eslint, tsc
make test                    # unit tests, no services
make test-services && make test-db   # db-marked tests against docker-compose.test.yml
make down                    # stop; make nuke to also delete volumes
```
Host-run db tests against the *dev* stack on non-default ports:
```bash
cd backend && RISKGRAPH_DATABASE_URL=postgresql+psycopg://riskgraph:riskgraph@localhost:15432/riskgraph_test \
  RISKGRAPH_REDIS_URL=redis://:riskgraph@localhost:16379/1 uv run pytest -m db
```

## L. Configuration
`RISKGRAPH_ENV` (dev|test|prod) · `RISKGRAPH_LOG_LEVEL` · `RISKGRAPH_LOG_JSON` · `RISKGRAPH_SECRET_KEY` (≥ 32 chars, `SecretStr`, never in repr) · `RISKGRAPH_DATABASE_URL` (must be `postgresql+psycopg://`) · `RISKGRAPH_REDIS_URL` (`redis://` or `rediss://`) · `RISKGRAPH_CORS_ORIGINS` (JSON list) · `RISKGRAPH_API_DOCS_ENABLED`. Compose derives the two URLs from `POSTGRES_*`/`REDIS_PASSWORD`. Ports: `POSTGRES_PORT`, `REDIS_PORT`, `API_PORT`, `FRONTEND_PORT`. No real secrets anywhere in the repo; `.env` is git-ignored.

## M. Testing
16 backend tests: settings validation (scheme checks, secret length, missing vars, masked repr), healthz, request-id echo/sanitise, 404 problem+json shape, readyz 503 with dependencies monkeypatched down, readyz 200 against real services (`db` marker), Celery config safety (json only, acks late, both queues), ping task eager, UUIDv7 version/variant/ordering. Frontend: `eslint`, `tsc -b`, `vite build` pass; vitest configured, no component tests yet (Phase 13).

## N. Security
- Images run as uid 10001; no secrets baked in; `.dockerignore` excludes `.env`, `.git`, venvs.
- Celery accepts JSON only (pickle would let anyone with Redis access execute code).
- Redis requires a password even in dev; Postgres/Redis/API/frontend bind to `127.0.0.1` only.
- Error responses never include stack traces; logs never include bodies; `SecretStr` for the key.
- CORS is an allow-list; `Cache-Control: no-store` on every API response.
- `dangerouslySetInnerHTML` banned by ESLint.
- Not yet: auth (Phase 2 skeleton), rate limiting and security headers (Phase 15), socket proxy (Phase 3).

## O. Validation (all VERIFIED this session)
```
$ uv run ruff check . && uv run ruff format --check .      → All checks passed! / 23 files already formatted
$ uv run mypy                                              → Success: no issues found in 22 source files
$ uv run pytest -m "not db and not docker" -q              → 15 passed, 1 deselected in 0.14s
$ RISKGRAPH_DATABASE_URL=…15432… uv run pytest -m db -q    → 1 passed, 15 deselected
$ npm run lint && npm run typecheck && npm run build       → clean; dist/assets/index-*.js 254 kB (78.8 kB gzip)
$ npm audit                                                → found 0 vulnerabilities
$ docker compose ps                                        → postgres healthy, redis healthy, migrate Exited (0),
                                                             api healthy, worker healthy, beat up, frontend up
$ curl -i 127.0.0.1:18000/api/v1/readyz                    → HTTP/1.1 200 OK {"status":"ok","checks":{"database":"ok","redis":"ok"}}
$ docker compose exec api python -c "…ping.delay().get()"  → task_id 7dbb1eaf-… -> pong state SUCCESS
$ curl 127.0.0.1:15173/api/v1/readyz  (via Vite proxy)     → {"status":"ok","checks":{"database":"ok","redis":"ok"}}
```

## P. Expected output
API log line (JSON): `{"method":"GET","path":"/api/v1/healthz","duration_ms":2.0,"event":"request","request_id":"73b3df98-…","level":"info","logger":"riskgraph.http","timestamp":"2026-09-18T19:16:20Z"}`
Worker log: `Task riskgraph.ping[…] succeeded in 0.007s: 'pong'`
Migrate log: `INFO [alembic.runtime.migration] Context impl PostgresqlImpl.`

## Q. Definition of done
- [x] `make dev` starts postgres, redis, migrate, api, worker, beat, frontend, all healthy
- [x] `/healthz` and `/readyz` green against real services
- [x] Frontend skeleton renders and reaches the API through the proxy
- [x] Backend lint, format, mypy strict, unit tests green
- [x] Frontend lint, typecheck, build green, 0 audit findings
- [x] CI workflow committed (lint, typecheck, unit + integration tests, self-scan, image build + scan)
- [x] pre-commit config committed
- [ ] pre-commit hook revisions and GitHub Action versions verified against current releases (BELIEVE; do at start of Phase 2)
- [ ] CI run observed green on GitHub (needs a push to a GitHub remote)

## R. Common failure modes
- `exit 127` from migrate/api: a bind mount is shadowing `/app/.venv`; mount source folders only.
- `port is already allocated`: set `*_PORT` in `.env`; check `ss -ltnp` and `docker ps`.
- `npm install` ERESOLVE when bumping several dev deps at once: rewrite `package.json` to current majors and clean-install.
- Tests fail with `env == "dev"`: conftest sets `RISKGRAPH_ENV=test`; pass `env` explicitly in unit tests.
- Worker "unhealthy": it inherited the HTTP healthcheck; use `celery inspect ping`.
- hatchling refuses `readme = "../README.md"`: readme must be inside the project directory.

## S. Next phase
Phase 2 adds the domain model, Alembic migrations for the V1 tables, the auth skeleton (users, roles, JWT, refresh, API keys) and the repositories module, all on top of `shared/db` and the app factory from this phase.
