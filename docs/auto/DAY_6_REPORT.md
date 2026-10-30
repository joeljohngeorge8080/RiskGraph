# Day 6 report (Sat 2026-10-31): integration pass

**Verdict: COMPLETE.**
- X6 was built on day 5, so today was the integration pass (DAY_6_PLAN).
- Every suite was run before and after; three cross-phase gaps were found and fixed, each
  with a test, each pushed green.
- No new flag, no new local task. F-1-1, F-1-2, F-2-1, F-3-1, F-4-1, F-4-2 and F-5-1 are
  still OPEN; nothing today builds on them.
- The six-day summary is `docs/auto/FINAL_REPORT.md`.

Start `0716d64`. Commits today:

| Commit | What |
|---|---|
| `044affc` | Day 6 plan |
| `de027d7` | Frontend vocabulary: `runtime`/`authz` source types, `syft`/`riskgraph` producers, `CANCELLED` is terminal; a drift test against the backend enums |
| `f9a8e81` | Template explanation: runtime and authz findings get their own remediation steps |
| `43842f1` | Example manifest: a credential family is a hypothesis; `owns:` shown |
| (this commit) | Reports, handoff, todo, `PHASE_X6.md` integration section |

## Per plan step
| # | Step | Result | Label |
|---|---|---|---|
| 1 | Frontend vocabulary | Done. The drift test failed first on exactly three unions: ScanStatus (`CANCELLED`), ScannerName (`riskgraph`, `syft`), SourceType (`authz`, `runtime`). Now 11 passed | VERIFIED |
| 2 | Re-run every suite, fix breakage | Two more gaps found by reading across phases (below), both fixed test-first | VERIFIED |
| 3 | X0 re-run | Identical to day 5; pooled table equals `BASELINE.md` | VERIFIED |
| 4 | Self-attack | Below | VERIFIED |
| 5 | Write-up | This report, FINAL_REPORT, HANDOFF, todo, PHASE_X6 §R | VERIFIED |

**The three gaps:**
1. **Frontend vocabulary** (X2, X5 × MVP UI). A runtime or authz finding showed an empty
   type chip and could not be filtered; the `syft`/`riskgraph` run cards had no role.
   `CANCELLED` (backend since 23 Oct, before these six days) was not terminal in the UI,
   so a cancelled scan's page polled every 2 s forever. `tests/test_frontend_vocabulary.py`
   now compares all nine mirrored unions with their enums.
2. **Fallback explanation** (X2, X5 × P12). Without the local model, an EOL runtime or a
   missing route guard was told to "fix the flagged code". Now: "move … to a supported
   release" and "add or align the access check on the route in …". The prompt version is
   not bumped: the steps only appear when the template is used, and bumping it would
   re-run the model for every cached explanation. Cached template explanations for such
   findings keep the old text until their evidence changes (BELIEVE it is rare; CONFIDENT
   it is harmless).
3. **Example manifest** (X1/X3 × docs). It still said a credential family "authenticates
   as" the identity; since ADR-0017/0020 that is a hypothesis that never scores. It now
   says so and shows `owns:`; `test_documented_example_manifest_is_valid` still passes.

## Test output (after the last code commit, `43842f1`)
```
$ uv run ruff check . ; uv run ruff format --check . ; uv run mypy
All checks passed!
248 files already formatted
Success: no issues found in 238 source files
$ uv run pytest -m "not db and not docker and not e2e and not perf and not llm" -q
661 passed, 92 deselected, 1 warning in 22.16s
$ uv run pytest -m "db and not llm" -q
84 passed, 2 skipped, 667 deselected, 1 warning in 110.22s (0:01:50)
$ uv run pytest -m perf -q -s
loader: 5000 nodes, 19990 edges, 0.039s
search: 30 paths for 10 sinks, 0.316s
search (two passes): 55 paths, 27 hypotheses, 0.185s
build+search: 5001 nodes, 22596 edges, 50 paths, 0.653s
4 passed
$ npm run lint && npm run typecheck && npx vitest run && npm run build   (frontend, after npm ci)
Test Files  2 passed (2)   Tests  11 passed (11)   ✓ built in 837ms
$ alembic upgrade head; downgrade -1; upgrade head; downgrade base; upgrade head; check   (fresh riskgraph_mig)
… 9 downgrades, 9 upgrades … No new upgrade operations detected.
```
- Start of day: 648 unit, 84 db (2 skipped), perf 4, frontend 10 Vitest tests.
- New: 11 unit (drift test 9 + parser 2) and 2 explain tests; 1 Vitest test plus 2
  assertions. No test changed or weakened.
- The full downgrade to base is new today: every migration of the project round-trips.

## Evaluation (X0)
Re-run at `de027d7` (no scoring code changed today). Against `BASELINE.md`, log lines
stripped: the model line, the `OUTSIDE_X0` line, and C's AWS key at rank 6 in the M4 top
10, the same three as on days 1–5. **The pooled table is identical** (VERIFIED).

## Self-attack
1. **The drift test's parser on hostile input.** A union that is not plain string literals
   (`"x" | string`, `string`, a comment inside) raises instead of comparing a subset; a
   name that is a prefix of another (`AB` for `A`) is not matched. Tests for each.
2. **Do the new tiles show a false 0?** The scan page now has runtime and authz tiles. The
   pipeline counts RiskGraph's own findings in `by_source_type` (`pipeline.py`: merged
   with scanner results before counting), and `test_pipeline_db.py` pins
   `by_source_type["authz"] == 3` (VERIFIED by reading and the passing db test).
3. **A value the frontend lists but the backend does not** fails the same test ("unknown
   to the backend"), so removing an enum value is caught too.
4. **Justified, not fixed:** the drift test couples the backend suite to a frontend file.
   It is read-only and needs no Node; a generated schema would be X7-sized.

## UNVERIFIED (needs the owner's machine)
- The UI changes were checked by `tsc`, eslint, Vitest and the build, not in a browser
  over a live scan (L-7 covers it).
- Nothing else new.

## New flags and local tasks
None.

## Note on commit identity
Today's commits carry the sandbox's configured git identity (RUNBOOK §4: "use the
configured one"), not the identity days 1–5 used. Messages follow the other rules.
