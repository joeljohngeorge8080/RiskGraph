# RiskGraph

**Context-aware security risk prioritization and attack-path analysis.**

Scanners tell you what is *vulnerable*. RiskGraph tells you what is *dangerous here*. It runs
open-source scanners against a repository, merges their findings, adds what the scanners
cannot see (is the code reachable, is the service internet-facing, what identity does it run
as, what data can it touch), links the results into a security graph, finds the attack paths
through it, and scores every finding with a deterministic, explainable model. An optional AI
layer writes a plain-language explanation of a finding, but **it never decides a score**.

> **Status (handed over 2026-11-05):** the MVP, Level 2, blueprint phases P3 to P12 and
> expansion phases X0 to X6 are built. X7 (dashboard additions) and part of X8 (evaluation)
> are open. **There is no authentication yet. Run it on localhost only.** What's left is in
> [`docs/handover/BACKLOG.md`](docs/handover/BACKLOG.md).

## Contents
- [What it does](#what-it-does) · [How it works](#how-it-works) · [Scoring](#scoring)
- [Quickstart](#quickstart) · [Configuration](#configuration) · [Context manifest](#context-manifest-riskgraphyaml)
- [CLI and CI gate](#cli-and-ci-gate) · [API](#api) · [Repository layout](#repository-layout)
- [Development](#development) · [Evaluation](#evaluation) · [Security notes](#security-notes) · [Documentation](#documentation)

## What it does
- **Scans a GitHub repository** (paste a URL) with Trivy, Semgrep, Gitleaks, Checkov and
  Syft, each in a hardened, pinned container. Joern runs as an opt-in `deep` profile.
- **Normalizes and merges** findings from different tools into one record, and counts how
  many scanners agree.
- **Checks reachability** of vulnerable code, from L0 (declared) to L3 (intraprocedural call
  graph), using tree-sitter import and call extraction.
- **Builds a security graph** from Docker Compose and Kubernetes manifests: services, images,
  identities, data stores, exposure and credentials. Every edge carries its evidence and an
  assurance level.
- **Finds attack paths** (k-shortest paths) and raises the impact of the findings on them.
- **Scans runtime and image intelligence**: packages inside container images and
  end-of-life runtimes.
- **Detects taint flows** (Semgrep tier 1; Joern tier 2 for Python) and **authorization
  problems** (route inventory, unguarded sensitive routes).
- **Tracks history**: triage states (false positive, accepted risk, won't fix; audited), and
  what is new, fixed or reopened since the previous scan of the same ref.
- **Gates CI**: a CLI fails a pipeline on chosen severities, optionally only for new findings.
- **Explains findings** with a local model (Ollama), validated against the evidence, with a
  deterministic template fallback when the model is off or unavailable.

## How it works
```
 GitHub URL
     |
     v
 git-fetcher --> scanner containers (trivy, semgrep, gitleaks, checkov, syft, [joern])
                        |  raw reports (stored, downloadable)
                        v
        normalize --> merge duplicates --> enrich (EPSS, CISA KEV)
                        |
   riskgraph.yaml ------+--> reachability (L0-L3) --> security graph --> attack paths
   (service context)    |
                        v
              deterministic risk score (model v2.1) --> triage / history / CI gate
                        |
                        v
        optional explanation (evidence-grounded, validated, template fallback)
```
It is a **modular monolith** with an API role and a worker role ([ADR-0001](docs/adr/0001-modular-monolith.md)).
The worker reaches Docker only through a socket proxy that allows a minimal set of calls
([ADR-0014](docs/adr/0014-container-scanner-runner.md)). The stack is five containers plus
the frontend: Postgres 16, Redis 7, the API, a Celery worker and a Celery beat scheduler.

| Layer | Technology |
|---|---|
| Backend | Python 3.12+, FastAPI, SQLAlchemy 2 (sync), Alembic, Celery + Redis, structlog, pydantic-settings |
| Graph | Postgres tables plus NetworkX ([ADR-0006](docs/adr/0006-graph-storage.md)) |
| Frontend | React 19, TypeScript, Vite, Cytoscape (lazy-loaded graph view) |
| Scanners | Trivy, Semgrep, Gitleaks, Checkov, Syft; Joern (deep profile) |
| Tooling | uv, ruff, mypy, pytest, hypothesis, vitest, eslint, pre-commit |

Versions are pinned in [`docker/scanner-versions.env`](docker/scanner-versions.env) (scanners)
and logged in [`docs/TECH_STACK.md`](docs/TECH_STACK.md) (everything else).

## Scoring
Risk is a pure function: the same input always gives the same score, and every factor is
returned with where it came from.

```
L     = geometric mean of the applicable likelihood factors   E (exploitability), X (exposure), R (reachability)
I     = mean of the impact factors                            T (technical), D (data), P (privilege), C (criticality)
K     = 1 + 0.05 * min(scanners agreeing - 1, 2)
score = min(100, 100 * L * I * K)
```
- Factors the scanners cannot supply (X, D, P, C) come from the context manifest. Missing
  ones fall back to a documented "unknown" value, so a scan with no manifest still scores.
- A finding that is evidence on an attack path takes the path's effective impact.
- Model **v2.1** adds factor tables for image packages, taint flows, runtime end-of-life and
  authorization findings ([ADR-0024](docs/adr/0024-risk-model-v2.md)). Without those inputs
  it scores exactly as v1.
- An AI explanation can never change a score or a priority.

## Quickstart
Requires Docker with Compose, `uv`, and Node.js (for `make install`).
```bash
cp .env.example .env            # set RISKGRAPH_SECRET_KEY; change *_PORT if 5432/6379/8000/5173 are taken
make scanner-images             # build the pinned scanner images (first run only)
make dev                        # postgres, redis, migrate, api, worker, beat, frontend
curl -s localhost:${API_PORT:-8000}/api/v1/readyz
```
Then open `http://localhost:5173` and paste a repository URL, for example
`https://github.com/bridgecrewio/terragoat`. The interactive API docs are at
`http://localhost:8000/api/v1/docs`.

`make down` stops the stack (keeps data); `make nuke` also deletes the volumes.
`make help` lists every target.

### Run without Docker
```bash
make scanner-tools              # trivy, gitleaks, semgrep, checkov into ~/.local/share/riskgraph-tools
# in .env: uncomment RISKGRAPH_DATABASE_URL / RISKGRAPH_REDIS_URL for your local Postgres/Redis
make api-local                  # terminal 1
make worker-local               # terminal 2
cd frontend && npm run dev      # terminal 3, http://localhost:5173
```

### Deep profile (Joern)
Tier-2 taint for Python is opt-in. It needs a 3.6 GB image and one Joern run at a time:
```bash
make scanner-images-deep
# .env: RISKGRAPH_DEEP_PROFILE_ENABLED=true   (memory: RISKGRAPH_JOERN_MEMORY, default 3g)
```
Then send `"profile": "deep"` with the scan request ([ADR-0025](docs/adr/0025-joern-tier2-deep-profile.md)).

## Configuration
All settings are environment variables in `.env` (see [`.env.example`](.env.example) for the full list).

| Variable | Purpose |
|---|---|
| `RISKGRAPH_SECRET_KEY` | Required. Generate with `python -c "import secrets; print(secrets.token_urlsafe(48))"` |
| `POSTGRES_*`, `REDIS_PASSWORD` | Credentials compose uses to create and reach the database and queue |
| `API_PORT`, `FRONTEND_PORT`, `POSTGRES_PORT`, `REDIS_PORT` | Host ports (published on `127.0.0.1` only) |
| `RISKGRAPH_MAX_ACTIVE_SCANS` | Concurrent scans (default 3) |
| `RISKGRAPH_ENRICHMENT_ENABLED` | EPSS (api.first.org) and CISA KEV lookups |
| `RISKGRAPH_LLM_PROVIDER` | `ollama` or `none` (always use the template) |
| `RISKGRAPH_OLLAMA_URL`, `RISKGRAPH_OLLAMA_MODEL` | Local model for explanations (default `qwen3:4b`) |
| `RISKGRAPH_DEEP_PROFILE_ENABLED` | Allow the Joern deep profile |

## Context manifest (`riskgraph.yaml`)
Add a `riskgraph.yaml` at the root of the repository you scan to tell RiskGraph what the
scanners cannot see: which services are internet-facing, which identity they run as, which
data they reach, and how critical they are. Findings are mapped to services by path, and the
exposure, privilege, data-sensitivity and criticality factors replace the "unknown" defaults.
`identities[].credentials: [aws, ...]` links leaked keys to the identity they authenticate as,
which is what makes attack paths assurance-aware. An invalid manifest is shown as a warning on
the scan and ignored; the scan still completes.

Example and field reference: [`docs/examples/riskgraph.yaml`](docs/examples/riskgraph.yaml).

## CLI and CI gate
Gate a pipeline from a self-hosted runner next to RiskGraph
(see [`docs/examples/riskgraph-ci.yml`](docs/examples/riskgraph-ci.yml)):
```bash
cd backend && uv run python -m riskgraph.entrypoints.cli scan \
    --repo https://github.com/owner/repo --fail-on critical --fail-on high --new-only
```
Exit code `0` = passed, `1` = gate failed, `2` = scan or API error. `--new-only` ignores
findings that already existed in the previous scan of the same ref.

## API
Base path `/api/v1` (interactive docs at `/api/v1/docs` while `RISKGRAPH_API_DOCS_ENABLED=true`).

| Area | Endpoints |
|---|---|
| Scans | `POST /scans`, `GET /scans`, `GET /scans/{id}`, `POST /scans/{id}/cancel`, `GET /scans/{id}/reports/{scanner}` |
| Findings | `GET /scans/{id}/findings`, `GET /findings/{id}`, `GET /scans/{id}/diff`, `GET /scans/{id}/gate` |
| Risks | `GET /risks`, `GET /risks/{finding_id}` |
| Graph | `GET /scans/{id}/graph`, `/graph/reach`, `/attack-paths` |
| SBOM | `GET /scans/{id}/sbom` |
| Authorization | `GET /scans/{id}/routes`, `/authz/manual` |
| Explanations | `GET` and `POST /findings/{id}/explanation` |
| Repositories | `GET /repositories`, `/repositories/{id}`, `/repositories/{id}/context` |
| Health | `/readyz` |

Errors are RFC 7807-style problem responses raised from `riskgraph.shared.problems`.

## Repository layout
```
backend/riskgraph/
  modules/<domain>/{router,service,repo,schemas,models,tasks}.py
     audit authz context evidence explain findings graph normalization
     reachability repositories risk runtime sbom scanners scans
  shared/        config, db, problems, vocabulary, logging, http
  entrypoints/   api.py, worker.py, cli.py
backend/evaluation/   evaluation harness and scenarios
frontend/src/         api, app, features, lib
docker/               scanner images, scanner-versions.env
scanners/             scanner image build context (Checkov)
infrastructure/       Postgres init, image build, scanner install and model scripts
docs/                 handover, blueprint, adr, phases, evaluation, examples
```
Routers parse and call services; services hold the rules; repos hold the SQL. Cross-module
imports go only through a module's `__init__.py`.

## Development
```bash
make install                    # uv sync + npm install
make test                       # unit tests, no services
make test-services && make test-db   # DB tests (or just make test-db while make dev is up)
make e2e                        # real scanners end to end (after make scanner-tools)
make lint                       # ruff, mypy, eslint, tsc
make fmt                        # auto-format the backend
make migration m="add findings" # Alembic autogenerate; review by hand
```
`make test-db` and `make dev` use the same ports: run only one at a time.

At handover the suite had 759 unit tests and 86 database tests passing, with ruff, mypy,
eslint and tsc clean. CI runs `backend`, `frontend`, `images` and `security-self-scan`;
all four are required to merge into `main`.

Ground rules (details in [`CONTRIBUTING.md`](CONTRIBUTING.md)): plan before editing, smallest
correct change, tests first where there is a runtime surface, migrations only through Alembic,
new vocabulary in `shared/vocabulary.py` and `frontend/src/api/types.ts`, new dependencies
logged in `docs/TECH_STACK.md`, and decisions recorded in `docs/adr/` (amend or supersede, never
silently reverse).

## Evaluation
The evaluation is designed so the result cannot be tuned after the fact: labels are committed
before the first run, thresholds are pre-registered, and generated reports are never edited by hand.

- **Baseline (X0, frozen):** on a constructed set of 59 findings across five scenarios (labels
  set by construction), RiskGraph's ranking reaches P@5 = 1.00 against 0.20 for CVSS-only and 0.00 for CVSS+EPSS.
  This is a small, synthetic dataset; the intervals are wide. See [`docs/evaluation/BASELINE.md`](docs/evaluation/BASELINE.md).
- **Expansion (X8):** of 13 pre-registered criteria, **5 pass, 3 fail and 5 have not been run**.
  Failures are reported as found, for example interprocedural taint recall of 0.50 against a
  0.6 threshold. See [`docs/evaluation/EVALUATION_EXPANSION.md`](docs/evaluation/EVALUATION_EXPANSION.md).
- **Authorization:** [`docs/evaluation/AUTHZ_EVAL.md`](docs/evaluation/AUTHZ_EVAL.md).

Commands: `make eval-baseline`, `make eval-expansion`, `make eval-expansion-full`, `make eval-authz`
(the first and third need test services and an empty `riskgraph_test` database).

## Security notes
- **No authentication yet.** The API, worker and frontend publish only on `127.0.0.1`. Do not expose them.
- Scanners run as pinned containers started by the worker through a Docker socket proxy that allows a minimal set of calls ([ADR-0014](docs/adr/0014-container-scanner-runner.md)); only the proxy mounts the raw socket, not the worker.
- Scanner output is untrusted: paths derived from it are never opened outside the scan workspace,
  request bodies and finding evidence are never logged, and raw secrets are never stored.
- Threat model: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Documentation
| Start here | |
|---|---|
| [`docs/handover/README.md`](docs/handover/README.md) | Where things live, how to start |
| [`docs/handover/STATE.md`](docs/handover/STATE.md) | What is built and verified, open owner items, gotchas |
| [`docs/handover/BACKLOG.md`](docs/handover/BACKLOG.md) | Remaining work, each item with a "done when" |
| [`docs/blueprint/`](docs/blueprint/00_BLUEPRINT.md) | Architecture, data model and API, threat model, roadmap, testing |
| [`docs/adr/`](docs/adr/README.md) | Architecture decision records (0001 to 0025) |
| [`docs/phases/`](docs/phases) | One chapter per implemented phase |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Rules, and how to add a scanner, a migration or an ADR |

The same documents are mirrored on the [project wiki](https://github.com/joeljohngeorge8080/RiskGraph/wiki).
The repository copy is the source of truth.

## License
Apache-2.0, as declared in `backend/pyproject.toml`.
