# Contributing to RiskGraph

Start with `docs/handover/README.md`. This file is the set of rules every change follows. Most of them exist because a past session found a bug the hard way (`docs/handover/HISTORY.md`).

## Never (a change that breaks one of these is not mergeable)
- **Secrets**: never in code, fixtures or history. Test secrets are built at test time (see `tests/fixtures/repos/kitchen_sink.py`). Stored findings keep an HMAC of a secret, never the value.
- **Subprocess**: never with a string or `shell=True`. `argv` is a tuple; `SubprocessRunner` and `DockerRunner` refuse strings.
- **Built strings**: no SQL, shell or HTML built from strings. Use SQLAlchemy, argv and the frontend's escaping.
- **Scanner output**: never open a path taken from it outside the scan workspace. Paths go through `normalization.normalize_path`.
- **Logs**: never log request bodies or finding evidence.
- **Errors**: never build error JSON. Raise a `riskgraph.shared.problems.Problem` subclass.
- **Exceptions**: never swallow one. Log it with context and report a status (see `pipeline._authz`).
- **Tests**: never weaken or delete a failing test to get green. A pin that changes on purpose is flipped in the same commit, with the reason in a comment, and the old number stays pinned if it is still true (see `test_authz_findings_suite.py`).
- **Schema**: change it only through Alembic: `make migration m="..."`, then review by hand. Upgrade and downgrade must both work; a downgrade that would lose data refuses with a clear message.
- **Folders**: no `utils/`. A helper lives in the module that owns the concept.

## Shape of the code
- `router.py` parses and calls the service. `service.py` holds the rules. `repo.py` holds the SQL. Pure functions (analysis, scoring, parsing) take data in and give data out, with no I/O, so they are tested without services.
- Another module is imported only through its `__init__.py`.
- New vocabulary (a scanner name, a source type, a status) goes in `shared/vocabulary.py`, the matching union in `frontend/src/api/types.ts`, and, if the value is stored, a migration for the check constraint.

## Adding a scanner (the Joern adapter is the latest worked example)
1. `modules/scanners/<name>/{adapter,parser}.py`. `parser.parse` is pure and survives hostile input: a malformed report gives no finding, never an exception. Add caps on counts and lengths.
2. Redaction: rebuild the report from known keys only, or drop snippet keys. A report is stored after redaction, never before.
3. Register it in `registry.py` (`SCANNERS`, `REDACTION_ORDER`), and add the name to the vocabulary, a migration, and `types.ts`.
4. Image: `scanners/<name>/Dockerfile`, `USER 65534:65534`. Pin the version in `docker/scanner-versions.env` and the base by digest. Add a line to `build-scanner-images.sh`.
5. Container profile: the env allow-list is in `containers.py`. Add a name only with a comment saying why.
6. Fixtures recorded from the **real** tool in `tests/fixtures/scanners/<name>/<version>/`. Golden tests on them, and a `test_scanner_images.py` entry.
7. An ADR with measured numbers, and a chapter section.

## Tests
| Command | Runs | Needs |
|---|---|---|
| `make test` | unit tests (the default) | nothing |
| `make test-db` | `db`-marked tests | `make test-services` **or** `make dev`, never both (same ports) |
| `make test-llm` | real local model | Ollama + test services |
| `make e2e` | real scanners end to end | `make scanner-tools` |
| `make lint` | ruff, mypy, eslint, tsc | |

- Write the test first when there is a runtime surface, and cover the empty and hostile input, not just the happy path.
- Property tests (Hypothesis) guard the risk model's invariants (monotonicity, reduction) and the graph's (no edge without evidence; a hypothesis never raises a score).

## Evaluation
- Labels come before ranking, committed first. Thresholds are pre-registered in `docs/proposals/EXPANSION_A-D.md` §6 and never changed after a result. A weak result is reported as found.
- `docs/evaluation/BASELINE.md` is frozen. Generated reports are never edited by hand. The run book is `docs/evaluation/EVALUATION_RUNBOOK.md`.

## Decisions and docs
- A decision someone could reasonably make differently gets an ADR in `docs/adr/` (Context, Decision, Consequences, Rejected) and a row in `docs/adr/README.md`. Never rewrite an accepted ADR; amend it with a dated note or supersede it.
- Each phase writes `docs/phases/PHASE_<id>.md` (the A–S chapter template).
- A dependency gets a row in `docs/TECH_STACK.md` in the same change. Backend packages go in `backend/pyproject.toml`, locked with `uv lock`, and `uv.lock` is committed with them. Use a release that is at least two weeks old.
- CI pins third-party actions by commit SHA, with the tag in a comment.

## Commits and branches
- Make small commits, each one green. Write the message in plain prose: what changed and why, the measured effect if there is one.
- Work on a branch; open a PR to `main`. Do not push to `main` directly.
- `graphify-out/` is rewritten by a post-commit hook (if you use graphify). A big diff there is expected; commit it separately.
