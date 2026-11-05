# RiskGraph

Context-aware security risk prioritization and attack-path analysis platform.
RiskGraph orchestrates Trivy, Semgrep, Gitleaks, Checkov and Syft in isolated
containers, normalizes and correlates their findings, enriches them with exploit
likelihood, code reachability, network exposure, identity privilege and data
sensitivity, builds a security graph, discovers attack paths, and scores
contextual risk deterministically — with an AI layer that explains, never decides.

**Status (2026-11-05, handed over to collaborators):** the MVP and Level 2 are built, along with blueprint phases P3–P12 and expansion phases X0–X6. That covers:
- hardened scanner containers, SBOM, reachability L0–L3 and a graph from Compose and Kubernetes;
- evidence and assurance on every claim, image and runtime end-of-life findings;
- tier-1 taint (Semgrep) and tier-2 taint (Joern, opt-in `deep` profile);
- route inventory and authorization findings, and risk model v2.

An X8 evaluation harness exists. X7 (dashboard additions) and the rest of X8 are open. **There is no authentication yet:** keep it on localhost. Start at `docs/handover/README.md`; what's left is in `docs/handover/BACKLOG.md`.

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
- `docs/handover/`: start here. State, backlog, history; plus `CONTRIBUTING.md` at the root
- `docs/blueprint/` — architecture, data model, API, threat model, roadmap, evaluation plan
- `docs/adr/` — decision records
- `docs/PROJECT_SPEC.md`, `docs/THREAT_MODEL.md`
- `docs/phases/` — one chapter per implemented phase

License: Apache-2.0
