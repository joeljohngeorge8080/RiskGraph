# Day 4 plan (Thu 2026-10-29): X5 part 2, authorization findings

## The task
SCHEDULE day 4 is X5 part 1 (route inventory and guards). Day 3 already built it to its
exit criteria (DAY_3_REPORT: recall 30/31 = 0.968, every status as labelled), so by the
schedule's own order the next work is **X5 part 2** (SCHEDULE day 5). Day 5 then finishes
whatever of X5 part 2 is left, and day 6 stays X6.

Catch-up (RUNBOOK §0.4): day 3 is `COMPLETE`; no earlier step is open and unflagged
(VERIFIED, DAY_3_REPORT and FLAGS.md). F-1-1, F-1-2, F-2-1 and F-3-1 are all `OPEN`
(nothing was answered), so X4 part 2 stays parked and nothing below builds on any of them.

### Acceptance (plan X5 row, §3.B, §6; SCHEDULE day 5)
- Findings with `source_type = authz`:
  - **unguarded-sensitive**: a route with no guard (only `none_found`, never `unresolved`
    or `unknown_framework`) that is sensitive: a mutating method, or a SAST finding inside
    its handler. Inferred.
  - **inconsistent guarding**: sibling routes on the same resource where the others are
    guarded and this one is not, or the read is guarded and a write is not. Inferred.
  - **manifest policy diff**: an additive, optional `authz:` section in the manifest
    (strict validation); a route that matches a rule and lacks the required guard.
  - **BOLA**: an object-id parameter that the handler loads by, with no ownership predicate
    in the handler. **Always `hypothesis`, never scored above Low.**
- A "manual verification required" list in the API.
- Inconsistency precision ≥ 0.8 on a labelled suite; **zero** BOLA findings above
  `hypothesis`; route-inventory recall unchanged (≥ 0.95); all earlier tests green.
- First refinement named by DAY_3_REPORT: an Express `app` passed into a module
  (`routes(app, db)`, NodeGoat's style) is resolved through the call site, so those routes
  are no longer `unresolved`.

### Out of scope today
- The Joern adapter (F-3-1), tier 1 on by default (F-2-1), Compose data stores (F-1-1),
  CAN_ACCESS from RBAC (F-1-2).
- Risk v2 factor tables (X6). Authz findings get an **interim** score (step 6), as the
  runtime EOL findings did before X6 (ADR-0018).
- Django/DRF, dynamic tests, GraphQL (plan §5, deferred).
- Graph edges UNGUARDED and BOLA_SUSPECT are step 8. They are last because they touch the
  attack graph; if the day runs out, they are day 5's first item.

## Files read and nearest analogs
- `CLAUDE.md`, `HANDOFF.md`, `todo1150.md`, `FLAGS.md`, `LOCAL_TASKS.md`, `DAY_3_REPORT.md`,
  `SCHEDULE.md` (days 4–6), plan §2.4, §3.B, §3.D (UNGUARDED, BOLA_SUSPECT), §4 X5/X6 rows,
  §5, §6, §8; ADR-0017, 0018, 0020, 0022.
- `modules/reachability/routes.py` → the extractor additions (call sites, handler facts)
  go next to `js_routes` / `_python_function`, same caps and helpers.
- `modules/authz/inventory.py` → call-site resolution goes into the mount walk.
- `modules/runtime/eol.py::runtime_findings` → analog for building `RawFinding`s from
  RiskGraph's own producer (`ScannerName.RISKGRAPH`).
- `modules/context/manifest.py` (`owns:`, ADR-0020) → analog for an additive, strict,
  optional manifest section.
- `modules/risk/model.py` (`not_imported_ceiling_medium`, the runtime interim) → analog for
  the interim authz factors and the hypothesis ceiling.
- `modules/scans/finding_evidence.py`, `modules/scans/pipeline.py::analyze` → wiring.
- `modules/authz/router.py` → analog for the manual-verification endpoint.
- `tests/test_authz_suite.py`, `tests/test_authz_inventory.py` → test style.

## Steps (each with the test that proves it)
1. **Extractor `ts-imports.5`** (additive to the `http` section):
   - JS: call sites whose arguments are plain names (`routes(app, db)`,
     `require("./routes")(app, db)`), and the parameter names of exported functions
     (`module.exports = index` with `const index = (app, db) => …`, `module.exports =
     function (app) …`, `export default function …`);
   - per route, facts about the handler body when the handler is in the same file (Python
     `def` under the decorators; JS inline function or a function of that name in the
     file): its line span, which path parameters it passes into a call (`loads`), and
     whether any comparison or keyword argument mentions an owner or the current user
     (`ownership`). Caps as before.
   Test: `test_route_extract.py` cases for each shape, hostile input (deep nesting, huge
   bodies) stays capped.
2. **Passed-in Express apps** (`authz/inventory.py`): a route whose receiver is a parameter
   of its file's exported function is bound through the call sites that call that export
   with a receiver in that position. The caller's earlier `use()` calls count (before the
   call's line). One call site is used; several are noted. Tests: a NodeGoat-shaped
   fixture (session middleware before `routes(app, db)`, `isLoggedIn` per route): the
   routes become `custom`/`none_found` and `mounted`; an uncalled export stays
   `unresolved`. Real check on OWASP NodeGoat (cloned read-only into the scratchpad).
3. **Manifest `authz:`** (additive, optional, strict): `guards: [names]` (extra guard names,
   counted as catalogued) and `rules: [{path, methods?, require}]` where `require` is
   `authenticated` (any guard) or a list of guard names. Path patterns use `*` (one
   segment) and `**` (any). Tests: valid and invalid documents in `test_manifest.py`;
   an existing manifest without `authz:` validates unchanged.
4. **`authz.analyze(routes, policy, sast_lines) -> list[AuthzIssue]`** (pure, new
   `authz/analysis.py`): the four rules above, with the route evidence ids each issue rests
   on and, for hypotheses, the missing evidence. Tests: unit cases per rule, the empty
   cases (no routes, all public, all unresolved), and that `unresolved` and
   `unknown_framework` never produce an "unguarded" issue.
5. **Labelled authz suite** (`tests/test_authz_findings_suite.py`): per framework, routes
   labelled with the expected issue (or none): inconsistent, unguarded-sensitive, public
   on purpose, BOLA with and without ownership, policy. Metrics: inconsistency precision
   ≥ 0.8 (and recall reported), zero BOLA above hypothesis, and the day-3 suite still at
   0.968.
6. **Findings, interim score, evidence** (ADR-0023): issues become `RawFinding`s of
   producer `riskgraph` and `source_type = authz`, rule ids `authz:<rule>`; their evidence
   is the route and guard evidence they rest on (linked by id, nothing copied). Interim
   factors until X6: E and T from the existing SAST tables with category `auth`; a
   hypothesis finding is capped at Low (priority and score), like the existing ceilings.
   Model `v1-ctx.4` (only authz findings score differently; nothing else changes). Tests:
   the reduction property (every existing scoring test unchanged), BOLA always Low,
   hypothesis findings never raise anything.
7. **Pipeline and API**: authz findings in `analyze` (routes computed before the merge),
   `summary.authz`; `GET /scans/{id}/authz/manual` lists what needs a person: BOLA
   hypotheses, `custom`, `unresolved` and `unknown_framework` routes, and policy rules a
   route could not be checked against. Tests: db test through the real pipeline; the API
   is additive.
8. **Graph edges** UNGUARDED (internet → endpoint, inferred, from an unguarded-sensitive or
   inconsistent finding) and BOLA_SUSPECT (endpoint → data store, hypothesis), endpoint
   nodes, X1/X3 rules (evidence required, hypotheses never change a score). Tests: the
   existing graph property tests, plus a test that these edges change no score. If time
   is short, this step moves to day 5 whole.
9. **Test stage**: lint, types, unit, db, perf, migration round trip (no migration
   planned), the X0 evaluation against `BASELINE.md` (the model line changes to
   `v1-ctx.4`; the X0 scenarios have no routes, so no score should change), self-attack,
   labels. Then report, `PHASE_X5.md`, ADR-0023, handoff, todo.

## Risks and decisions
- **Interim authz score (step 6).** The plan defers authz factor tables to X6 but requires
  "hypotheses never above Low" for X5. Reusing the SAST `auth` entries is a mapping onto
  existing tables, not a new weight, and it is recorded in ADR-0023 as interim. If it had
  needed a new number, it would have been a flag.
- **Manifest `authz:`** is additive and optional, exactly as plan §3.B names it
  (`authz: [{path, requires}]`, extended by `authz.guards:` from the X5 row). The plan's
  example is a list; with `guards:` next to it, it has to be a mapping. That is a shape
  detail inside the plan's own feature, not a change to any existing field, so it goes
  into ADR-0023 and is not a flag.
- **Heuristics.** "Ownership" and "loads by id" are textual and recorded as such; their only
  effect is a hypothesis listed for a person to test. Sensitivity from "a data store the
  manifest marks ≥ confidential" needs knowing which store a handler touches; nothing
  states that, so it is not used (noted in the ADR).
- No new dependency, no migration, no module boundary change (authz reads reachability
  and context through their `__init__`).
