# RiskGraph: AI session entry point

## Read first
1. `docs/handover/STATE.md`: what is built and verified, open owner items, gotchas.
2. `docs/handover/BACKLOG.md`: the work, each item with "done when".
3. `CONTRIBUTING.md`: the rules below in full, plus how to add a scanner, a migration or an ADR.
4. `docs/blueprint/00_BLUEPRINT.md` (design index), then the chapter for your area in `docs/phases/`.

Decisions live in `docs/adr/`. Do not re-decide one: amend it with a dated note, or write a superseding ADR. `docs/handover/HISTORY.md` has every past session; search it before debugging something odd.

## How to work here
- **Plan before editing.** Restate the task, the acceptance criteria and what is out of scope; list the steps. Read every file you will touch and match the nearest existing analog: the Joern adapter (`modules/scanners/joern/`) is the latest worked example of a full feature.
- **Smallest correct change.** Test first where there is a runtime surface. Cover empty and hostile input.
- **Verify before claiming done.** Run `make lint`, `make test`, and `make test-db` when the DB is touched. Paste the real output. Label claims VERIFIED / CONFIDENT / BELIEVE / GUESS; if you could not run something, say UNVERIFIED.
- **Stop and ask** before:
  - new dependencies;
  - schema redesign;
  - module-boundary changes;
  - deletion;
  - anything outward-facing (push, PR, external services);
  - scoring or risk-model changes;
  - contradicting an ADR.

  Write the question with its options in `docs/auto/FLAGS.md`, and carry on with what does not depend on it.
- **Evaluation honesty.** Labels are committed before the first run. Thresholds are pre-registered (`docs/proposals/EXPANSION_A-D.md` §6). Results are reported as found, and generated reports are never edited by hand.
- **No calendar estimates** in plans: phases and sizes only.

## Conventions
- Backend: `backend/riskgraph/modules/<domain>/{router,service,repo,schemas,models,tasks}.py`. Routers parse and call services; services hold rules; repos hold SQL. Cross-module imports only via `modules/<x>/__init__.py`. No `utils/` folders.
- Errors: raise `riskgraph.shared.problems.Problem` subclasses; never build error JSON; never swallow an exception.
- Never `subprocess` with strings; never open a path derived from scanner output outside the scan workspace; never log request bodies or finding evidence; never store raw secrets.
- Migrations only via Alembic (`make migration m="..."`), reviewed by hand, round-trip tested.
- New vocabulary goes in `shared/vocabulary.py` and `frontend/src/api/types.ts` (a test compares them), plus a migration if the value is stored.
- Every phase writes `docs/phases/PHASE_<id>.md` with the A–S chapter template.
- Never weaken or delete a failing test. A pin that changes on purpose is flipped with its reason in a comment.

## Commands
`make dev` · `make test` · `make test-db` · `make test-all` · `make lint` · `make fmt` · `make e2e` · `make help` (all targets)
- `make test-db` reads the postgres and redis ports from `.env` and runs against the dev stack (`make dev`) or `make test-services`. Run only one of those at a time: both use the same ports.
- `make e2e` needs the scanners installed (`make scanner-tools`), or it skips.
- Evaluation:
  - `make eval-baseline` (X0, frozen report) and `make eval-expansion-full` (X8): both need test services and empty `riskgraph_test`.
  - `make eval-expansion` (offline X8 criteria) and `make eval-authz`: need no services.
- Images: `make scanner-images`; `make scanner-images-deep` adds Joern (3.6 GB, deep profile only).

## Dependencies
- New dev or runtime packages go in `backend/pyproject.toml` and are locked with `uv lock`. Commit `uv.lock` in the same change, and add a row to `docs/TECH_STACK.md`.
- Scanner versions: `docker/scanner-versions.env` is the single source of truth; bumping one means re-recording its fixtures.
- CI pins third-party actions by commit SHA, not by tag, because tags can be removed upstream.

## graphify (optional)
If `graphify` is installed and `graphify-out/graph.json` exists, use it for codebase questions before grepping:
- `graphify query "<question>"`
- `graphify path "<A>" "<B>"`
- `graphify explain "<concept>"`

These return a scoped subgraph, much smaller than raw grep output. Put this rule in every subagent prompt that explores code. Run `graphify update .` after changing code (AST only, no API cost).

`graphify-out/graph.json` is rewritten whole on every build, so a large diff to it is expected. Commit it separately; do not flag it as churn. Without graphify, read `docs/handover/README.md` ("Where things live") and grep as usual.
