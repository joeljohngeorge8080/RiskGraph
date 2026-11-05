# Start here

RiskGraph scans a repository with Trivy, Semgrep, Checkov, Gitleaks and Syft (plus Joern in the opt-in `deep` profile). Each scanner runs in a hardened container. RiskGraph merges what they report, adds context the scanners cannot see (reachability, exposure, identity, data sensitivity, authorization), builds an attack graph, and ranks every finding with a deterministic score. Every claim carries evidence and an assurance level. An optional local model explains a finding; it never decides one.

## Read in this order
1. `STATE.md`: what is built, what is verified, and what the previous owner left open.
2. `BACKLOG.md`: what to work on, with "done when" for each item.
3. `../../CONTRIBUTING.md`: how changes are made here (rules, tests, migrations, ADRs).
4. `../blueprint/00_BLUEPRINT.md`: the design index. Then `01_ARCHITECTURE.md` and `02_DATA_AND_API.md`.
5. The ADRs in `../adr/` for the area you touch. They are decisions: do not re-decide one; write a superseding ADR.
6. The phase chapter in `../phases/` for that area (each has chapters A–S).

`HISTORY.md` holds every past session in detail, with the gotchas. Search it before you debug something odd.

## First run
```bash
cp .env.example .env              # set RISKGRAPH_SECRET_KEY; change *_PORT if the defaults are taken
make install                      # uv sync + npm install
make test                         # unit tests, no services (about 50 s)
make test-services && make test-db
make scanner-images               # the five scanner images (ADR-0014)
make dev                          # full stack: postgres, redis, migrate, api, worker, beat, frontend
```
- API docs: `http://localhost:${API_PORT:-8000}/api/v1/docs`. Dashboard: `http://localhost:${FRONTEND_PORT:-5173}`.
- The local model for explanations is optional (`make dev` loads it if Ollama is installed; see `PHASE_12.md` §L).
- The deep profile needs `RISKGRAPH_DEEP_PROFILE_ENABLED=true` and `make scanner-images-deep` (a 3.6 GB image).

**There is no authentication yet (AUTH-1).** Never expose the stack beyond localhost.

## Where things live
| Path | What |
|---|---|
| `backend/riskgraph/modules/<domain>/` | One module per domain: `router` (parse, call), `service` (rules), `repo` (SQL), `schemas`, `models`, `tasks`. Cross-module imports only through `modules/<x>/__init__.py` |
| `backend/riskgraph/shared/` | Config, DB, Celery, problems (RFC 7807 errors), vocabulary |
| `backend/alembic/versions/` | Migrations: hand-reviewed, every one round-trips |
| `backend/tests/` | Unit (default), `db`, `docker`, `llm`, `e2e` markers. Fixtures are recorded from real tools |
| `backend/evaluation/` | X0 baseline, taint suite, authz scenario, X8 harness |
| `scanners/<name>/` | Scanner image Dockerfiles; `docker/scanner-versions.env` pins every version |
| `frontend/src/` | React dashboard; `frontend/src/api/types.ts` mirrors the backend enums (a test checks it) |
| `docs/` | Blueprint, ADRs, phase chapters, evaluation reports, `auto/` (the nightly-run logs and flags) |

## How work was organised (keep it, it worked)
- **Phases.** One phase at a time. Each phase ends with its chapter in `docs/phases/`, its ADRs, green tests, and local commits.
- **Flags.** When a question needs the project owner, write it in `docs/auto/FLAGS.md` with options and a recommendation. Then park that item and carry on with the rest. Answers are logged in `docs/auto/OWNER_DECISIONS.md`.
- **Honest numbers.** Write the labels before running, and report results as found. Mark claims VERIFIED (run), CONFIDENT (read in code), BELIEVE or GUESS.
- **No timelines.** Plans are phase by phase, not calendar estimates.
