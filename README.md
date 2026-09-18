# RiskGraph

Context-aware security risk prioritization and attack-path analysis platform.
RiskGraph orchestrates Trivy, Semgrep, Gitleaks, Checkov and Syft in isolated
containers, normalizes and correlates their findings, enriches them with exploit
likelihood, code reachability, network exposure, identity privilege and data
sensitivity, builds a security graph, discovers attack paths, and scores
contextual risk deterministically — with an AI layer that explains, never decides.

**Status:** Phase 1 (development environment). See `docs/blueprint/06_ROADMAP.md`.

## Quickstart
```bash
cp .env.example .env            # set RISKGRAPH_SECRET_KEY; change *_PORT if 5432/6379/8000/5173 are taken
make dev                        # postgres, redis, migrate, api, worker, beat, frontend
curl -s localhost:${API_PORT:-8000}/api/v1/readyz
open http://localhost:${FRONTEND_PORT:-5173}      # dashboard skeleton
open http://localhost:${API_PORT:-8000}/api/v1/docs
```

## Develop
```bash
make install                    # uv sync + npm install
make test                       # unit tests, no services
make test-services && make test-db
make lint                       # ruff, mypy, eslint, tsc
```

## Documentation
- `docs/blueprint/` — architecture, data model, API, threat model, roadmap, evaluation plan
- `docs/adr/` — decision records
- `docs/PROJECT_SPEC.md`, `docs/THREAT_MODEL.md`
- `docs/phases/` — one chapter per implemented phase

License: Apache-2.0
