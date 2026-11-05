# Day 3 plan (Wed 2026-10-28): X4 part 2 is gated, so tier-1 hardening and X5 part 1 early

## The task
SCHEDULE day 3 is X4 part 2 (Joern adapter). Its precondition is the owner's spike (L-2):
`docs/auto/spikes/joern/RESULT.md` with `GO` and recorded fixtures under
`backend/tests/fixtures/joern/`. At the start of this run `RESULT.md` still says "Not run
yet" and there is no `fixtures/joern/` directory (VERIFIED, `ls` and `cat`).

So, as SCHEDULE day 3 says for this case:
1. **Flag F-3-1** and build nothing of the Joern adapter.
2. **Tier-1 hardening** (more merge tests and the one correlation gap found while reading).
3. **Start X5 part 1 early** (day 4 scope): extractor `ts-imports.4`, `modules/authz` with the
   route inventory and the guard catalogue, the route inventory API.

Catch-up: day 2 is `COMPLETE`; no earlier step is open or unflagged (VERIFIED, DAY_2_REPORT).
Flags F-1-1, F-1-2, F-2-1 are `OPEN`; nothing below builds on them.

### Acceptance (from the plan's X5 row and SCHEDULE day 4)
- Extractor `ts-imports.4` records route declarations, auth decorators / dependencies /
  middleware and route parameters for Flask, FastAPI and Express, in the same sandboxed
  subprocess with the same caps. Django/DRF stay deferred (plan §5).
- `modules/authz`: `route_inventory(extract) -> Route[]`, a guard catalogue in YAML
  (RiskGraph-authored), guard detection with honest assurance:
  - a route declaration we parsed is `verified`; a catalogued guard is **`inferred`, never
    `verified`** (SCHEDULE day 4; this is stricter than plan §3.B's table, which says
    "verified when a guard is found". The schedule is the owner's later word, so I follow it
    and record the difference in the ADR);
  - "no guard found" is `inferred` and only said when the framework is known and every
    place a guard could come from was resolved;
  - an unknown framework is reported as "unknown framework", never as "no guard".
- API: the route inventory per scan, additive. Evidence kinds `route` and `auth_guard`
  (both already in `evidence.KINDS`).
- Route inventory recall ≥ 0.95 on a labelled suite written as test code: per framework
  guarded, unguarded, inconsistent, custom guard, id parameter with and without an
  ownership check.

### Out of scope today
- The Joern adapter, the `deep` profile, tier-2 correlation (F-3-1).
- Authorization **findings**, UNGUARDED / BOLA_SUSPECT edges, the manifest `authz:` section
  and `authz.guards:` extension, the manual-verification list (all day 5).
- Any score or graph change. The X0 evaluation is re-run anyway at the end, because the
  analyzer version changes and the pipeline gains a step; it must be unchanged.

## Files read and nearest analogs
- `CLAUDE.md`, `HANDOFF.md`, `todo1150.md`, `FLAGS.md`, `LOCAL_TASKS.md`, `DAY_2_REPORT.md`,
  `SCHEDULE.md`, plan §2.4, §3.A, §3.B, §4 (X4, X5 rows), §5, §6, §8.
- `modules/reachability/extract.py` → new route extraction lives next to `_python_calls`
  and `_js`, same `_walk`/`_text`/`_dotted` helpers, same caps style.
- `modules/reachability/service.py` (`ReachabilityRun`) → carries the route slice of the
  extract to the pipeline.
- `modules/evidence/{contract,service,models}.py` → `route`/`auth_guard` evidence, stored
  scan-scoped with `persist_evidence`; read back by kind.
- `modules/scanners/semgrep/taint.py` + `taint_catalogue.yaml` → analog for the guard
  catalogue (strict loader, RiskGraph-authored YAML header).
- `modules/graph/router.py` → analog for the new `GET /scans/{id}/routes`.
- `modules/normalization/merge.py::_join_taint_hits` → hardening step.
- `tests/test_taint_tier1.py`, `tests/test_reachability.py` → test style.

## Steps (each with the test that proves it)
1. **F-3-1** in `FLAGS.md`; `PHASE_X4.md` gets a "Part 2: gated" note. (Doc only.)
2. **Tier-1 hardening: multi-line sinks.** The generated rules focus on `$SINK`, so a
   tier-1 hit starts at the tainted argument. A generic Semgrep rule that matches the whole
   call starts at the call. For a call written over several lines the two lines differ, and
   today they stay two findings. Fix: after the exact-line join, join a taint-only group to a
   generic group in the same file and CWE family whose line span contains the taint line
   (bounded look-back, so it stays linear). Tests: the multi-line join; a taint hit outside
   the span stays apart; a different family stays apart; the scaling test still passes.
3. **Extractor `ts-imports.4`.** Per file, additive keys: `routes`, `routers`, `mounts`,
   `uses`, `hooks`, `depends`, `schemes`, `bindings`, `exports`. Flask (`route`/verb
   decorators, `methods=`, `add_url_rule`, Blueprints with `url_prefix`,
   `register_blueprint`, `before_request`), FastAPI (verb/`api_route` decorators,
   `Depends`/`Security` in parameters and in `dependencies=`, `APIRouter`/`FastAPI`
   `dependencies=`, `include_router`, security scheme instances), Express (`app`/`router`
   verb calls with middleware chains, `.route(p).get(...)`, `app.use` with prefixes,
   middleware and routers, relative `require`/`import` bindings, exports). Path parameters
   from `<id>`, `{id}`, `:id`. Tests: one per construct, plus hostile input (dynamic paths,
   huge argument lists, deeply nested code) and the caps.
4. **`modules/authz`: inventory and guards.** `guards.yaml` (catalogue, strict loader),
   `route_inventory(extract) -> list[Route]`: resolves prefixes and mounts (same file and
   relative imports), applies route-level, router-level, mount-level and ordered app-level
   guards, resolves FastAPI dependencies transitively by name (depth-capped), and sets
   `guard_status` ∈ `guarded | custom | none_found | unresolved | unknown_framework`.
   `route_evidence(routes)` gives `route` (verified, or inferred when the framework was
   inferred from a name) and `auth_guard` (inferred) evidence. ADR-0022 records the rules.
   Tests: each status, each guard source, cycles in dependencies, ordering of `app.use`.
5. **Labelled suite and recall.** Test code that writes small Flask, FastAPI and Express
   apps with labels (method, full path, handler, guard status, id parameters); runs the
   real extractor and the inventory; asserts recall ≥ 0.95 and reports guard-status
   accuracy. The ownership-check cases only check the parameter today (BOLA is day 5).
6. **Pipeline + API.** `ReachabilityRun.routes` (the route slice of the extract); the
   pipeline stores the evidence after `clear_evidence` and adds `summary.routes`;
   `GET /scans/{id}/routes` (new `authz` router). Tests: unit for the schema mapping; a db
   test that a scan of a small Flask repo serves its routes and that the rest of the
   summary is unchanged; 404 for an unknown scan.
7. **Test stage:** lint, types, unit, db, perf; migration round trip of the existing head
   (no migration today) and `alembic check`; X0 evaluation re-run against `BASELINE.md`;
   self-attack; report, handoff, todo, `PHASE_X5.md`.

## Risks and decisions
- **Guard assurance (plan §3.B vs SCHEDULE day 4).** Following the schedule (inferred). Not
  a flag: it is the owner's own later instruction and it only lowers a claim.
- **Storage.** The inventory is stored as `route`/`auth_guard` evidence rows (scan-scoped,
  already migrated in X1), not a new table. No migration. Recorded in ADR-0022. If the owner
  wants a table later, it is additive.
- **Custom guards.** An uncatalogued decorator, dependency or middleware whose name looks
  like authentication (`auth`, `login`, `jwt`, `token`, `permission`, `role`, `admin`, …)
  makes the route `custom` (a possible guard, listed by name), never `none_found`. This keeps
  day 5's "unguarded" findings from firing on custom auth. It is a documented rule in the
  ADR and the catalogue, not a score input.
- **Express receivers passed in as parameters** (`module.exports = (app) => { app.get(…) }`,
  NodeGoat's style): app-level middleware registered elsewhere cannot be ordered against
  them, so without a route-level guard such a route is `unresolved`, not `none_found`.
- **Analyzer version bump** changes `analyzer_version` on new reachability rows. Old rows
  keep theirs. No reader compares it.
- No new dependency (tree-sitter and PyYAML are already used). No schema change. No manifest
  change today.
