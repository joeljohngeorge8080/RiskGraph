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

## Current state
Read `HANDOFF.md` for where work stands. The newest session section is first. Active branch
and PR are in there, along with the open items. `docs/phases/` has the chapter for the phase
in progress.

## Commands
`make dev` · `make test` · `make test-db` · `make test-all` · `make lint` · `make fmt` · `make e2e`
- `make test-db` reads postgres and redis ports from `.env` and runs against the dev stack
  (`make dev`) or `make test-services`. Run only one of those at a time: both use the same ports.
- `make e2e` needs the scanners installed (`make scanner-tools`), or it skips.

## Dependencies
- New dev or runtime packages go in `backend/pyproject.toml` and are locked with `uv lock`.
  Commit `uv.lock` in the same change.
- CI pins third-party actions by commit SHA, not by tag, because tags can be removed upstream.

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- When graphify-out/graph.json exists, run `graphify query "<question>"` before your first grep, search or source-file read for a codebase question, and put this rule in every subagent prompt that explores code. Read raw files only for lines the graph or an earlier read already located. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
- A committed graphify-out/graph.json is rewritten whole on every build, so a large diff to it in a pull request is expected. Do not flag it as churn or suggest skipping the graph rebuild or its hooks.
