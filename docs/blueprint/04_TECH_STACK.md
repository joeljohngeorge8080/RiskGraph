# RiskGraph — Technology Selection (section 21)

Each row is a decision with its live alternative and the condition that would
reverse it. Phase 0 copies the graph, queue, auth and frontend rows into
`docs/adr/` as full ADRs. Kit criteria applied: training saturation, fit,
operational weight, one-language pressure, ecosystem health.

| Area | Choice | Runner-up (real pros) | Why the choice wins | Reverse when |
|---|---|---|---|---|
| Language | Python 3.12 | TypeScript end-to-end (one language with the frontend) | Scanner/security/graph ecosystem (tree-sitter bindings, NetworkX, Celery, cyclonedx libs) lives in Python; author fluency; the frontend stays TS but is thin | never for V1 |
| API | FastAPI + Pydantic v2 + uvicorn | Django + DRF (batteries, admin, auth built in) | Schema-first validation, async SSE, OpenAPI for free, small surface; Django's admin/auth are nice but drag an ORM style and template stack we do not want | — |
| ORM / migrations | SQLAlchemy 2.x + Alembic | SQLModel (less boilerplate) | SQLAlchemy 2 typed mappings are the standard; SQLModel lags on advanced features (partial indexes, JSONB ops) we need | — |
| Package/toolchain | uv + ruff (lint+format) + mypy | poetry + black + flake8 | One fast tool for envs and locks; ruff replaces black+isort+flake8; mypy `--strict` on modules | — |
| Database | PostgreSQL 16 | — (no live alternative) | Relational + JSONB + recursive CTEs + partial indexes; one thing to back up | — |
| Graph | **PostgreSQL tables (`graph_nodes/edges`) + NetworkX in-process** | Neo4j Community (native Cypher traversals, visual browser, GDS-lite algorithms) | Per-scan graphs are 10³–10⁴ nodes: NetworkX loads one in < 1 s and gives Dijkstra/Yen/centrality directly with full control for the thesis; Neo4j adds a second stateful service (backup, auth, memory ≥ 2 GB), a second query language, cross-store consistency, and GDS algorithms are enterprise-gated; Apache AGE (Postgres extension) considered but immature tooling. Dashboard neighbourhood queries use recursive CTEs | Org-wide cross-repo graph > 10⁶ edges or sub-second multi-hop queries across scans → Apache AGE or Neo4j alongside Postgres, behind the `graph.repo` seam |
| Graph analysis lib | NetworkX | igraph (10–100× faster) | Speed is irrelevant at our sizes; NetworkX has `shortest_simple_paths` (Yen), is pure Python, and the code reads like the thesis pseudocode | graphs > 10⁵ edges → igraph |
| Task queue | Celery 5 + Redis 7 | Postgres job table + worker loop (kit default; transactional enqueue, one fewer service) | Fan-out/fan-in (`chord`) of 5 scanners, per-task soft/hard time limits, revoke, Beat scheduling and retries out of the box; hand-rolling a chord on a job table is real work; Redis is also used for rate limiting and the scanner-slot semaphore, so it is not a queue-only dependency | if Celery's operational quirks (result backend growth, chord edge cases) cost > 2 weeks → arq or a job table |
| Scanner execution | Docker Engine API via `docker` SDK through `docker-socket-proxy` | Kubernetes Jobs (proper scheduling, isolation via pod security) | Local demo on one machine; K8s is a team, not a tool; `ScannerRunner` protocol keeps `K8sJobRunner` a bounded addition | production multi-node → K8s Jobs |
| Sandbox hardening | Docker default seccomp + cap-drop + non-root + no network | gVisor `runsc` | gVisor is the better sandbox but needs host install; adopt in Phase 18 if the host supports it | — |
| Code parsing | tree-sitter (`tree-sitter`, `tree-sitter-python`, `tree-sitter-javascript`, `tree-sitter-typescript` bindings) | Python `ast` + Babel/ts-morph for JS | One parser API for all languages, error-tolerant, no execution of target code; `ast` is Python-only and Babel would need Node in the worker | — |
| Call graph | own resolver on tree-sitter output (name-based) | PyCG (Python call graph, research tool) | PyCG is unmaintained (BELIEVE) and Python-only; our tiered method needs import graph first, call graph second; keep scope honest | — |
| Vuln data | NVD 2.0 API (with key, cached), FIRST EPSS CSV, CISA KEV JSON | OSV.dev (fast, batch, ecosystem-aware) | NVD gives CVSS vectors/subscores needed by the model; OSV is the runner-up for GHSA-only ids and is a Phase 7 stretch source | NVD rate limits hurt → OSV first, NVD fallback |
| SBOM format | CycloneDX 1.5 JSON (Syft output) | SPDX | Dependency graph in CycloneDX is explicit; Trivy also emits CycloneDX; tooling in Python (`cyclonedx-python-lib`) | — |
| LLM | Ollama (local) default; Anthropic API optional, behind one adapter | OpenAI-compatible generic adapter | Zero budget and offline demo → local; Anthropic structured outputs are the best cloud option when a key exists; adapter makes the provider a config value | — |
| Auth | Local users, argon2id (`pwdlib`), JWT via `PyJWT` (HS256 with 256-bit key from env; RS256 if a second verifier appears), rotating refresh tokens | GitHub OAuth (fewer passwords) | Self-hosted, no external dependency for login; OAuth is a Phase 15 stretch; never hand-roll crypto — libraries only | — |
| Rate limiting | Redis token bucket in middleware | slowapi | slowapi is fine but wraps the same idea with global state; 60 lines of our own is testable; either is acceptable | — |
| Frontend | React 18 + TypeScript + Vite + TanStack Query/Table + Tailwind + Cytoscape.js + Recharts | FastAPI + Jinja2 + HTMX (earlier draft's lighter option) | The brief requires a professional React dashboard with a graph view; Cytoscape and interactive tables are the deciding features; the API-first order (dashboard last) contains the cost | timeline slips past week 30 → cut stretch views, not the stack |
| Reverse proxy / TLS | Caddy 2 | nginx + certbot | Automatic HTTPS, two-line config, sane headers | — |
| Observability | structlog JSON logs; `prometheus-fastapi-instrumentator` + Celery exporter → `/metrics`; Grafana dashboards as a Compose profile (stretch) | OpenTelemetry traces + Tempo/Jaeger | Traces are valuable but a third stack; metrics + request/task ids in logs cover the NFRs | if debugging cross-process latency becomes a recurring problem |
| Testing | pytest, pytest-asyncio, Hypothesis (risk model properties), testcontainers-python or Compose test profile for Postgres/Redis, recorded scanner fixtures, Playwright smoke for frontend, vitest | — | Real DB in integration tests (no mocked SQL); pure parsers/risk engine tested without Docker | — |
| CI/CD | GitHub Actions, GHCR | GitLab CI | The product integrates with GitHub; dog-fooding | — |
| Deployment | Docker Compose prod profile on one VM (local or AWS EC2 t3.medium); nightly `pg_dump` to volume, optional S3 | k3s (previous draft) / ECS | One VM, one Compose file, one operator; k3s adds ops surface with no demo value | — |
| AWS usage (optional) | EC2 (host), S3 (backups), IAM (one deploy user, one backup role), Secrets Manager **not** used (env file with 0600 on the VM is simpler and equally safe for one host), ECR **not** used (GHCR free), CloudWatch **not** used (Grafana/logs local) | — | Every service must earn its place; three do | — |

Dependency gate reminder (kit doc 04): every new package must (1) not
duplicate stdlib/existing, (2) be healthy and typed, (3) replace ≥ 30 lines or
be security-critical, (4) be logged in `docs/TECH_STACK.md` with date and reason.
