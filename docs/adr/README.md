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
