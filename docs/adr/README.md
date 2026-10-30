# Architecture Decision Records

| # | Title | Status |
|---|---|---|
| [0001](0001-modular-monolith.md) | Modular monolith with API and worker roles | accepted |
| [0002](0002-stack.md) | Python/FastAPI/SQLAlchemy/Celery/React stack | accepted |
| [0003](0003-ids-tenancy-deletion.md) | UUID v7 ids, single tenant, deletion policy | accepted |
| [0004](0004-auth-model.md) | Local users, argon2id, JWT + rotating refresh, RBAC, API keys | accepted |
| [0005](0005-hosting.md) | Docker Compose on one VM; AWS optional | accepted |
| [0006](0006-graph-storage.md) | Postgres graph tables + NetworkX; Neo4j rejected | accepted |
| [0007](0007-task-queue.md) | Celery + Redis instead of a Postgres job table | accepted |
| [0008](0008-sync-sqlalchemy.md) | Synchronous SQLAlchemy sessions in API and worker | accepted |
| [0009](0009-subprocess-scanner-runner.md) | MVP runs scanners as subprocesses in the worker (DockerRunner deferred) | accepted |
| [0010](0010-mvp-scope.md) | MVP vertical slice and its deviations from the blueprint | accepted |
| [0011](0011-manifest-context-scoring.md) | Context-aware scoring from the repository manifest (MVP level 2) | accepted |
| [0012](0012-reachability-tiers-mvp.md) | Reachability tiers L0–L2 in the MVP (tree-sitter import graph) | accepted |
| [0013](0013-graph-paths-triage-history.md) | Attack paths with effective impact; triage, history and the CI gate | accepted |
| [0014](0014-container-scanner-runner.md) | Scanners run as hardened containers (DockerRunner), with pinned images | accepted |
| [0015](0015-l3-call-graph-and-nvd-refresh.md) | L3 reachability by intraprocedural call graph; NVD refreshed by Beat | accepted |
| [0016](0016-ai-explanation.md) | Evidence-grounded explanations with a local model and a template fallback | accepted |
| [0017](0017-evidence-and-assurance.md) | One evidence and assurance contract; no edge without evidence | accepted |
| [0018](0018-runtime-and-image-intel.md) | Runtime and image intelligence: EOL from a stored feed, image scans behind an allow-list | accepted |
| [0019](0019-graph-from-compose-and-kubernetes.md) | A graph from Compose and Kubernetes when the manifest declares no services | accepted (owner review pending) |
| [0020](0020-assurance-aware-paths-and-credential-links.md) | Assurance-aware path search, missing evidence, and manifest credential links | accepted |
| [0021](0021-tier1-taint-catalogue.md) | Tier-1 taint rules from one RiskGraph catalogue; the taint evidence contract | accepted (off by default until F-2-1) |
| [0022](0022-route-inventory-and-guards.md) | Route inventory and guard detection, stored as evidence, with an honest guard status | accepted |
| [0023](0023-authorization-findings.md) | Authorization findings, the manifest `authz:` section, an interim Low ceiling, non-traversable authz edges | accepted (interim score replaced by 0024) |
| [0024](0024-risk-model-v2.md) | Risk model v2: factor tables for image packages, taint, runtime end-of-life and authorization findings | accepted |
