# RiskGraph — Repository Structure (section 22)

The brief's proposed layout is type-first (`api/`, `models/`, `schemas/`,
`services/`). Rejected in favour of **domain modules**: a phase task then
touches one folder (`modules/risk/`), tests sit next to the code, and the
module list mirrors the pipeline stages in the architecture. The pipeline
stage names in the brief (normalization, context, graph, risk, ai) survive as
module names.

```
riskgraph/
├── README.md                         what, why, quickstart, architecture picture
├── CLAUDE.md                         AI entry point: points at docs/, conventions, commands
├── LICENSE                           Apache-2.0
├── docker-compose.yml                dev: postgres, redis, api, worker, beat, frontend, docker-socket-proxy, ollama(profile)
├── docker-compose.prod.yml           prod overrides: caddy, no published db ports, restart policies
├── docker-compose.test.yml           test profile: postgres+redis only
├── .env.example                      every variable, no real values
├── .pre-commit-config.yaml           ruff, mypy, gitleaks, eslint, prettier
├── Makefile                          make dev / test / lint / migrate / scan-self
│
├── docs/
│   ├── blueprint/                    THIS blueprint (00–08)
│   ├── adr/                          0001-… decision records (Phase 0 seeds 6)
│   ├── phases/                       PHASE_NN.md — the chapter output of each phase
│   ├── THREAT_MODEL.md               living threat model (from blueprint 03)
│   ├── TECH_STACK.md                 dependency log (from blueprint 04)
│   ├── api/                          exported OpenAPI json + guide
│   └── thesis/                       chapters assembled in Phase 19
│
├── backend/
│   ├── pyproject.toml                uv-managed; ruff, mypy, pytest config
│   ├── uv.lock
│   ├── alembic.ini
│   ├── alembic/
│   │   └── versions/                 YYYYMMDD_HHMM_<verb>_<thing>.py
│   ├── riskgraph/
│   │   ├── __init__.py
│   │   ├── entrypoints/
│   │   │   ├── api.py                create_app()
│   │   │   ├── worker.py             create_celery()
│   │   │   └── cli.py                typer: users create, scan run, db seed (ops only)
│   │   ├── shared/
│   │   │   ├── config.py             Settings (pydantic-settings), validated at import
│   │   │   ├── db/                   engine, session, Base, uuid7, mixins
│   │   │   ├── logging.py            structlog setup, request/task id binding
│   │   │   ├── security.py           hashing, jwt encode/decode (library-backed), compare_digest
│   │   │   ├── docker/               proxy client, container_spec.py (only mount builder)
│   │   │   ├── http.py               outbound client with host allow-list, no redirects
│   │   │   └── problems.py           RFC 7807 exceptions + handlers
│   │   └── modules/
│   │       ├── auth/                 models.py schemas.py service.py repo.py router.py deps.py tests/
│   │       ├── repositories/         + manifest.py (riskgraph.yaml schema & parser)
│   │       ├── scans/                + orchestration.py (canvas) tasks.py state.py
│   │       ├── scanners/
│   │       │   ├── base.py           Scanner protocol, RawFinding, ContainerSpec
│   │       │   ├── registry.py
│   │       │   ├── runner.py         ScannerRunner protocol + DockerRunner
│   │       │   ├── trivy/            adapter.py parser.py tests/
│   │       │   ├── semgrep/          …
│   │       │   ├── gitleaks/         …
│   │       │   ├── checkov/          …
│   │       │   └── syft/             …
│   │       ├── normalization/        canonical.py fingerprint.py severity.py dedup.py correlate.py
│   │       ├── sbom/                 components, dependency edges, purl utils
│   │       ├── context/              nvd.py epss.py kev.py manifest_context.py extractors/{k8s,compose,terraform}.py
│   │       ├── reachability/         parsers/ (tree-sitter wrappers) imports.py callgraph.py entrypoints.py tiers.py vulnerable_symbols.yaml
│   │       ├── graph/                schema.py builder.py loader.py queries.py
│   │       ├── attack_paths/         derive.py search.py score.py
│   │       ├── risk/                 factors.py model.py thresholds.py overrides.py versions/v1.py
│   │       ├── explain/              adapter.py ollama.py anthropic.py null.py prompt.py evidence.py validator.py template.py
│   │       ├── dashboard/            summary queries
│   │       ├── webhooks/             github.py (signature, events)
│   │       └── audit/                writer.py
│   └── tests/
│       ├── conftest.py               db fixtures (Compose test profile), factories
│       ├── fixtures/scanners/<name>/<version>/*.json     recorded outputs
│       ├── fixtures/evidence/        golden EvidencePacks for explain validator
│       ├── integration/              api→celery, collector→normalizer, graph→risk
│       ├── security/                 authz matrix, injection, ssrf, traversal, secret exposure
│       └── e2e/                      full pipeline on datasets/ repos (marked docker)
│
├── frontend/
│   ├── package.json  vite.config.ts  tsconfig.json  tailwind.config.ts
│   ├── src/                          see 02_DATA_AND_API.md §18
│   └── tests/                        vitest units, playwright/ smoke
│
├── scanners/                         Dockerfiles for hardened scanner images
│   ├── git-fetcher/Dockerfile
│   ├── trivy/Dockerfile              + entrypoint that only ever runs the fixed command
│   ├── semgrep/Dockerfile            + rules/ vendored packs (pinned commit)
│   ├── gitleaks/Dockerfile
│   ├── checkov/Dockerfile
│   └── syft/Dockerfile
│
├── action/                           GitHub Action (composite): action.yml, src/, README
│
├── infrastructure/
│   ├── caddy/Caddyfile
│   ├── prometheus/prometheus.yml  grafana/dashboards/   (profile: observability)
│   ├── docker-socket-proxy/          env for allow-list
│   └── scripts/                      backup.sh restore.sh deploy.sh (each with --help)
│
├── datasets/                         see 07_TESTING_AND_EVALUATION.md
│   ├── README.md                     how each dataset is generated, licences
│   ├── scenarios/                    A–E + kitchen-sink synthetic repos (each a git repo built by a script)
│   ├── sast/  sca/  secrets/  iac/  containers/  attack_paths/
│   ├── external/                     fetch scripts for Juice Shop, TerraGoat, etc. (not vendored)
│   └── ground_truth/                 labels.csv per dataset + labelling protocol
│
├── evaluation/                       Phase 17: notebooks/, metrics.py, run_eval.py, results/
│
└── .github/
    ├── workflows/ci.yml  release.yml  deploy.yml  nightly-eval.yml
    └── dependabot.yml
```

Rules (from kit doc 05): depth ≤ 4 from `backend/riskgraph`; files ≤ 300
lines soft / 500 hard; no `utils/`; cross-module imports only through
`modules/<x>/__init__.py`; enforced by a ruff `banned-api`/import-linter
contract in Phase 1.
