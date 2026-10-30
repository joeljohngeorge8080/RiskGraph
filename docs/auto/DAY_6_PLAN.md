# Day 6 plan (Sat 2026-10-31): integration pass

## The task
SCHEDULE day 6 is X6 (risk v2, scenarios F–H, ADR) plus an integration pass. X6 was built
on day 5 to its exit criteria (DAY_5_REPORT: model `v2.1`, ADR-0024, reduction and
monotonicity properties, scenarios F–H with labels written first, X0 re-run). So today is
the **integration pass**:
- run every suite (backend and frontend);
- fix cross-phase breakage;
- the six-day summary in `HANDOFF.md` and `todo1150.md`;
- `docs/auto/FINAL_REPORT.md` with every open flag and local task.

Catch-up (RUNBOOK §0.4): day 5 is `COMPLETE`; nothing of days 1–5 is open and unflagged
(VERIFIED: DAY_5_REPORT, FLAGS.md). F-1-1, F-1-2, F-2-1, F-3-1, F-4-1, F-4-2 and F-5-1 are
all `OPEN` (VERIFIED), and `docs/auto/spikes/joern/RESULT.md` still says "Not run yet", so
X4 part 2 stays parked and nothing below builds on any open flag.

### Acceptance
- Every suite green at the end, with the real output in the report: ruff, ruff format,
  mypy, unit, db, perf, migration round trip and `alembic check`, frontend lint,
  typecheck, Vitest and build.
- Every cross-phase breakage found today is fixed with a test, or flagged.
- X0 re-run: equal to the day-5 run (no model change is planned today); the pooled table
  equals `BASELINE.md`.
- `FINAL_REPORT.md` lists every open flag and local task with what each one blocks.

### Out of scope today
- Anything an open flag holds (above).
- New features of X7 (dashboard) and X8 (evaluation). In particular, showing a path's
  assurance and `missing_evidence[]` in the UI is X7 work; it is recorded as a follow-up,
  not built.
- Any weight or table change (the baseline is frozen; plan §8).

## What I read
`CLAUDE.md`, `HANDOFF.md` (top), `todo1150.md`, `docs/auto/{RUNBOOK,SCHEDULE,FLAGS,LOCAL_TASKS}.md`,
`DAY_5_REPORT.md`, `DAY_5_PLAN.md`, `docs/adr/README.md`, `frontend/src/api/types.ts`,
`frontend/src/lib/format.ts`, `frontend/src/features/scans/{ScannerStatusCards,GraphView,AttackPathsPanel}.tsx`,
`frontend/src/features/findings/FindingFilters.tsx`, `backend/riskgraph/shared/vocabulary.py`,
`backend/riskgraph/modules/findings/{router,schemas}.py`.

## Start state (before any edit)
- Backend: ruff and mypy clean; 648 unit passed (VERIFIED). db and perf in the report.
- Frontend (`npm ci`): lint, typecheck, 10 Vitest tests and the build pass (VERIFIED).

## Cross-phase breakage found while reading (before any edit)
1. **The frontend vocabulary stops at the MVP.** `types.ts` has
   `SourceType = "sca" | "sast" | "secret" | "iac"` and four scanners. The backend now
   produces `runtime` (X2) and `authz` (X5) findings and `syft`/`riskgraph` scanner runs
   (VERIFIED: `shared/vocabulary.py`, `runtime/eol.py`, `authz/findings.py`,
   `scans/pipeline.py`). Effects: a runtime or authz finding shows an empty type chip in
   the table and the drawer; the filters cannot select them; the scan page's per-type
   tiles omit them; the `syft` and `riskgraph` run cards have no role line.
   Nearest analog: the existing `SOURCE_LABEL`/`ROLE` maps.

## Steps
1. **Frontend vocabulary.** Add `runtime` and `authz` to `SourceType`, `SOURCE_TYPES` and
   `SOURCE_LABEL`; add `syft` and `riskgraph` to `ScannerName`, the filter list and `ROLE`.
   Test: a backend drift test (`tests/test_frontend_vocabulary.py`) that reads the
   `SourceType` and `ScannerName` unions in `frontend/src/api/types.ts` and asserts they
   equal the backend enums, so the next producer cannot drift silently; `Record<SourceType, …>`
   then makes `tsc` refuse a missing label. Vitest: the label map covers every type.
2. **Re-run every suite** after step 1; read any failure as cross-phase breakage and fix
   it with a test (each fix its own commit), or flag after two failed attempts.
3. **X0 re-run** and diff against the day-5 run and `BASELINE.md`.
4. **Self-attack** on today's change (hostile or empty input to the drift test's parser;
   an enum value the frontend lists but the backend does not).
5. **Write-up:** `DAY_6_REPORT.md`, `FINAL_REPORT.md`, the six-day summary in
   `HANDOFF.md` and `todo1150.md`, an integration section in `PHASE_X6.md`.

## Risks and decisions
- A backend test reading a frontend file couples the two trees. It is read-only, needs no
  Node, and fails with a clear message; the alternative (a generated schema) is X7-sized.
  CONFIDENT this is the smallest guard that works.
- No new dependency, no migration, no ADR-level decision is expected. If one appears, it
  becomes a flag.
