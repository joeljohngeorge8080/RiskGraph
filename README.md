# RiskGraph

Context-aware security risk prioritization and attack-path analysis platform.
RiskGraph orchestrates Trivy, Semgrep, Gitleaks, Checkov and Syft in isolated
containers, normalizes and correlates their findings, enriches them with exploit
likelihood, code reachability, network exposure, identity privilege and data
sensitivity, builds a security graph, discovers attack paths, and scores
contextual risk deterministically — with an AI layer that explains, never decides.

**Status:** MVP vertical slice: scan a public GitHub repo with Trivy, Semgrep, Checkov and
Gitleaks, normalize and merge their reports, and rank findings by risk in a web UI
(`docs/phases/PHASE_MVP.md`). Level 2 adds context-aware scoring from a `riskgraph.yaml`
manifest in the scanned repository (`docs/phases/PHASE_MVP2.md`), extended with
reachability (L0/L1/L2 from a tree-sitter import graph), attack paths with effective impact,
triage, scan history and a CI gate (`docs/phases/PHASE_MVP2_EXT.md`). The MVP has **no
authentication**: keep it on localhost. Roadmap: `docs/blueprint/06_ROADMAP.md`.

## Context-aware scoring
Add a `riskgraph.yaml` at the root of the repository you scan to tell RiskGraph what the
scanners cannot see: which services are internet-facing, which identity they run as, which
data they reach, and how critical they are. Findings are mapped to services by path, and the
exposure, privilege, data-sensitivity and criticality factors replace the "unknown" defaults.
Example and field reference: `docs/examples/riskgraph.yaml`. An invalid manifest is shown as
a warning on the scan and ignored; the scan still completes.

## Quickstart
```bash
cp .env.example .env            # set RISKGRAPH_SECRET_KEY; change *_PORT if 5432/6379/8000/5173 are taken
make dev                        # postgres, redis, migrate, api, worker, beat, frontend
curl -s localhost:${API_PORT:-8000}/api/v1/readyz
open http://localhost:${FRONTEND_PORT:-5173}      # paste a GitHub URL, e.g. https://github.com/bridgecrewio/terragoat
open http://localhost:${API_PORT:-8000}/api/v1/docs
```

## Run without Docker
```bash
make scanner-tools              # trivy, gitleaks, semgrep, checkov into ~/.local/share/riskgraph-tools
# in .env: uncomment RISKGRAPH_DATABASE_URL / RISKGRAPH_REDIS_URL for your local Postgres/Redis
make api-local                  # terminal 1
make worker-local               # terminal 2
cd frontend && npm run dev      # terminal 3 → http://localhost:5173
```

## Triage, history and the CI gate
- Mark findings *false positive*, *accepted risk* or *won't fix* in the finding panel (audited);
  each scan reports what is new, fixed or reopened since the previous scan of the same ref.
- Gate a pipeline (self-hosted runner next to RiskGraph; see `docs/examples/riskgraph-ci.yml`):
  ```bash
  cd backend && uv run python -m riskgraph.entrypoints.cli scan \
      --repo https://github.com/owner/repo --fail-on critical --fail-on high --new-only
  ```
  Exit code 0 = passed, 1 = gate failed, 2 = scan/API error.
- Attack paths need a `riskgraph.yaml`; `identities[].credentials: [aws, …]` links leaked
  keys to the identity they authenticate as.

## Develop
```bash
make install                    # uv sync + npm install
make test                       # unit tests, no services
make test-services && make test-db   # or just make test-db while make dev is up (same .env ports)
make e2e                        # real scanners end to end (after make scanner-tools)
make lint                       # ruff, mypy, eslint, tsc
```

## Documentation
- `docs/blueprint/` — architecture, data model, API, threat model, roadmap, evaluation plan
- `docs/adr/` — decision records
- `docs/PROJECT_SPEC.md`, `docs/THREAT_MODEL.md`
- `docs/phases/` — one chapter per implemented phase

License: Apache-2.0
