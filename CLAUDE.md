# RiskGraph — AI session entry point

Read first: `docs/blueprint/00_BLUEPRINT.md` (index of the design), then the phase you
are working on in `docs/phases/`. Decisions live in `docs/adr/`; do not re-decide them.

## Conventions
- Backend: `backend/riskgraph/modules/<domain>/{router,service,repo,schemas,models,tasks}.py`.
  Routers parse and call services; services hold rules; repos hold SQL. Cross-module
  imports only via `modules/<x>/__init__.py`. No `utils/` folders.
- Errors: raise `riskgraph.shared.problems.Problem` subclasses; never build error JSON.
- Never `subprocess` with strings; never open a path derived from scanner output outside
  the scan workspace; never log request bodies or finding evidence; never store raw secrets.
- Migrations only via Alembic (`make migration m="..."`), reviewed by hand.
- Every phase writes `docs/phases/PHASE_NN.md` with the A–S chapter template.

## Commands
`make dev` · `make test` · `make test-services && make test-db` · `make lint` · `make fmt`
