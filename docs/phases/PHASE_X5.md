# PHASE X5: business logic and authorization (expansion plan)

**Status:** part 1 (extractor `ts-imports.4`, `modules/authz` route inventory and guard catalogue, `GET /scans/{id}/routes`, the labelled suite) done on 2026-10-28, a day early, because X4 part 2 is gated (F-3-1). Part 2 (extractor `ts-imports.5`, passed-in Express apps, the manifest `authz:` section, authorization findings with an interim Low score, UNGUARDED/BOLA_SUSPECT edges, the manual-verification list, the labelled authz suite) done on 2026-10-29, SCHEDULE day 4, a day early as well. Decisions: ADR-0022 (part 1), ADR-0023 (part 2). No migration. Plan: `docs/proposals/EXPANSION_A-D.md` §3.B, §3.D, §4 (X5), §5, §6.

## A. Objective
X5 row of the plan: static authorization findings with honest assurance. Part 1 is the inventory those findings rest on: every route, its full path and parameters, and every place a guard could come from.

Day 4 exit criteria (SCHEDULE), and where they stand:
1. Extractor `ts-imports.4` collects route declarations, auth decorators, dependencies and middleware, and route parameters for Flask, FastAPI and Express, in the same sandboxed subprocess with the same caps. **Done.**
2. `modules/authz`: `route_inventory(extract) -> Route[]`, a guard catalogue in YAML, and guard detection where a catalogued guard is `inferred` and an unknown framework is reported as "unknown framework". **Done.**
3. API: the route inventory per scan, additive; evidence kinds `route` and `auth_guard`. **Done.**
4. Route-inventory recall ≥ 0.95 on a labelled suite written as test code. **Done: 30/31 = 0.968.** The miss is a computed-member route (`app[verb](…)`), left in on purpose. Every guard status matches its label.

## B. Why
Authorization flaws are invisible to the five scanners. The cheapest strong signal is a route whose guard is missing where its siblings have one. That needs a route list whose "no guard" can be trusted, so the inventory keeps "we could not tell" (`unresolved`, `unknown_framework`) apart from "nothing found" (`none_found`).

## C. Architecture
```
extract.py (sandboxed) ── per file "http": routes, assigns, bindings, mounts, hooks, depends | routes, uses, exports
        │  (records only; no catalogue)
        ▼
ReachabilityRun.extracted ──▶ authz.route_inventory (pure)
        receivers (guards.yaml frameworks) ─▶ mounts across files (reachability resolvers) ─▶ full path
        guard sources: decorators/hooks | Depends (transitive) | middleware + earlier use() + mounts
        status: guarded | custom | none_found | unresolved | unknown_framework
        ▼
authz.route_evidence ──▶ evidence rows: route (verified | inferred), auth_guard (inferred)
        ▼
GET /scans/{id}/routes ; summary.routes
```

## D. Components
| Component | File |
|---|---|
| Route extraction | `backend/riskgraph/modules/reachability/routes.py` |
| Shared tree-sitter helpers | `modules/reachability/syntax.py` |
| Import resolvers (public) | `modules/reachability/graph.py` (`python_module_index`, `module_of_file`, `resolve_python_name`, `resolve_js_module`) |
| Guard catalogue | `modules/authz/guards.yaml`, loader `guards.py` |
| Inventory | `modules/authz/inventory.py` |
| Evidence, summary, reads | `modules/authz/service.py` |
| API | `modules/authz/router.py`, `schemas.py` |
| Pipeline step | `modules/scans/pipeline.py::_routes` |

## E. Technical decisions
See ADR-0022.
- A catalogued guard is `inferred`, never `verified`. This follows SCHEDULE day 4, which is stricter than plan §3.B's table.
- `none_found` is said only when every guard source was resolved. Otherwise the route is `unresolved`.
- A name that looks like authentication makes a route `custom` (a possible guard, listed), never `none_found`.
- A guard decorator above the route decorator does not count, and the route gets a note saying so.
- Routes are stored as evidence. There is no new table.

## G. Database
None. Routes are `evidence` rows of kind `route` and `auth_guard` (ADR-0017's table), scan-scoped.

## H. API
`GET /api/v1/scans/{id}/routes?status=&framework=` returns `{items: [RouteOut], total, by_status}`. Each `RouteOut` has:
- `id`, `file`, `line`, `framework`, `basis`;
- `methods`, `path`, `full_path`, `handler`, `params`;
- `guard_status`, `guards`, `custom_guards`, `mounted`, `notes`;
- `assurance`, `confidence`.

`summary.routes` on the scan: `{status, routes, by_status, by_framework}`. Scans from before X5 have no routes.

## L. Configuration
None. To extend the catalogue, edit `guards.yaml`. The loader is strict and a test checks it.

## M. Testing
- `test_route_extract.py` (7, unit):
  - Flask decorator order (below/above), methods, blueprints, hooks, `add_url_rule`, bindings;
  - FastAPI `Depends`/`Security` in defaults, `Annotated`, `dependencies=` on routes, routers and mounts;
  - Express chains, `use()` arguments (names, required modules, `require(...)(app)`), bindings, exports; settings reads and dynamic paths are not routes, template paths are;
  - TypeScript and passed-in receivers;
  - files without routes;
  - hostile input: 1,050 routes in a file, a 5,000-character path, 100 decorators, 300 middleware, deep nesting.
- `test_authz_inventory.py` (40, unit):
  - catalogue matching and hints (11 names);
  - a broken catalogue is refused (9);
  - Flask statuses, prefix override, hooks, the misplaced guard, an unregistered blueprint;
  - unknown and repository-inferred frameworks;
  - FastAPI transitive dependencies across files, cycles, `Security`, `include_router` dependencies, an orphan router;
  - Express middleware order, prefix boundaries (`/secure` does not cover `/securely`), express-jwt bound by module, nested cross-file routers, passed-in receivers, inline middleware;
  - malformed extracts (6), a mount cycle;
  - evidence assurance, confidence and stable ids;
  - the pipeline step's failure handling;
  - two scale tests: 45,000 files with 5,000 routes, and 5,000 Express mounts, each under 2 s.
- `test_authz_suite.py` (5, unit): the labelled suite. Recall, status and parameter accuracy, no unlabelled route found, every pattern present.
- `test_authz_db.py` (2, db): a real pipeline scan serves its routes (statuses, filters, a 422 for a bad status, summary counts), and an unknown scan is a 404.

## O. Validation
See `docs/auto/DAY_3_REPORT.md`. On OWASP NodeGoat at `c5cb68a`, the inventory finds all 20 route declarations: 12 `custom` (`isLoggedIn`) and 8 `unresolved` (the app is passed in).

## Q. Known limits (part 1)
- ~~An Express app passed into a routes module stays `unresolved` until its call sites are followed.~~ Fixed in part 2.
- Custom-hint matching is a word heuristic (ADR-0022, consequences).
- Ordering compares line numbers.
- Flask app hooks apply to every Flask route in the repository.
- Django/DRF are deferred (plan §5).
- ~~No authorization findings yet.~~ Part 2, below.


---

# Part 2: authorization findings (2026-10-29)

## A. Objective
SCHEDULE day 5 (done on day 4), and where each criterion stands:
1. Findings with `source_type = authz`:
   - inconsistent guarding;
   - unguarded-sensitive routes;
   - the manifest policy diff (an additive, optional `authz:` section, strict);
   - BOLA, always `hypothesis` and never above Low.
   **Done.**
2. Graph edges UNGUARDED (inferred) and BOLA_SUSPECT (hypothesis) with evidence, under the X1/X3 rules. **Done.** They have no probability yet, so they cannot change any path (ADR-0023).
3. A "manual verification required" list in the API. **Done:** `GET /scans/{id}/authz/manual`.
4. Inconsistency precision ≥ 0.8 on the labelled suite. **Done: 4/4 (1.0), recall 4/4.**
5. Zero BOLA findings above `hypothesis`. **Done**, by test (suite, random inventories, scoring property, db).
6. Inventory recall unchanged. **Done:** 30/31 = 0.968.
7. All earlier tests green. **Done.**

Also done: the refinement DAY_3_REPORT named. A passed-in Express app is now bound through its call site (NodeGoat: 8 `unresolved` routes are now resolved).

## B. Why
The inventory alone says where guards are. Part 2 says where one is missing and matters, at the assurance the evidence supports. It sends what cannot be decided statically (BOLA, undecided routes) to a person instead of guessing.

## C. Architecture
```
extract.py ts-imports.5 ── + route.body {span, loads, ownership}; JS calls, exported params
        ▼
authz.route_inventory(extracted, extra_guards=manifest.authz.guards)
        passed-in Express apps bound through call sites
        ▼
authz.analyze(routes, manifest.authz.rules, SAST lines by file) ─▶ AuthzIssue[] + policy-unchecked
        ▼
authz.issue_findings ─▶ RawFinding(authz, riskgraph) ─▶ merge ─▶ score (v1-ctx.4, Low cap)
        evidence = the route/guard evidence ids it rests on
        ▼
graph._authz_edges: endpoint nodes, UNGUARDED (inferred), BOLA_SUSPECT (hypothesis), p = None
        ▼
GET /scans/{id}/findings?source_type=authz ; GET /scans/{id}/authz/manual ; summary.authz
```

## D. Components
| Component | File |
|---|---|
| Handler bodies, call sites, exported parameters | `modules/reachability/routes.py` (`_body`, `_js_call_site`, `_js_params`) |
| Call-site binding | `modules/authz/inventory.py` (`_collect_calls`, `_bound`, `_earlier`) |
| Public-by-design words, manifest guards | `modules/authz/guards.yaml` (`public_hints`), `guards.py` (`with_guards`, `public_by_design`) |
| Manifest section | `modules/context/manifest.py` (`AuthzDecl`, `AuthzRule`) |
| Rules | `modules/authz/analysis.py` |
| Findings | `modules/authz/findings.py` |
| Interim score | `modules/risk/tables.py`, `model.py` (`authz_interim`, the Low ceiling) |
| Edges | `modules/graph/attack.py::_authz_edges` |
| Manual list | `modules/authz/service.py::manual_checks`, `router.py` |
| Pipeline | `modules/scans/pipeline.py::_authz` (routes now come before the merge) |
| Evaluation | `evaluation/run.py` (`OUTSIDE_X0`) |

## E. Technical decisions
See ADR-0023.
- Only `none_found` is ever "unguarded".
- Reads are compared with reads.
- Login, signup, callback, health and webhook routes are not sensitive for writing alone.
- BOLA needs the handler code to be seen.
- Every authz finding is Low until X6.
- The new edges have no probability.
- Authz findings stay outside the X0 set (F-4-1).

## G. Database
None. Authz findings use the existing findings, occurrences and evidence tables. The extractor version changes (`ts-imports.5`). Model `v1-ctx.4`.

## H. API (all additive)
- `GET /api/v1/scans/{id}/authz/manual?kind=` returns `{items: [ManualCheckOut], total, by_kind}`. Each item has `kind` (`bola`, `policy_unchecked`, `unresolved`, `unknown_framework` or `custom`), `reason`, `finding_id`, `route_id`, `file`, `line`, `route` and `missing`.
- Authz findings appear in `/scans/{id}/findings` (`source_type=authz`) and `/findings/{id}`. Their `evidence[]` is the route and guard evidence.
- Route evidence facts gain `policy_unchecked` when a manifest rule could not be checked.
- `summary.authz` has `{status, findings, by_rule, hypotheses, policy_rules, policy_unchecked_routes}`.
- The graph has `endpoint` nodes with UNGUARDED and BOLA_SUSPECT edges.

## L. Configuration
The manifest section `authz: {guards: [...], rules: [{path, methods?, require}]}` is documented in `docs/examples/riskgraph.yaml`. Catalogue words are in `guards.yaml` `public_hints`.

## M. Testing
- `test_route_extract.py` (12, +5): handler bodies (lookup, ownership, formatting calls, attribute named like the id, `add_url_rule`), Express inline, named and cross-file handlers, call sites, the three export shapes, a 6,000-line body cut off at the node cap.
- `test_authz_inventory.py` (52, +12): a NodeGoat-shaped app (caller `use()` order, mounts and `use()` inside the module, an uncalled export), several call sites, a call that passes no receiver, public hints (8), manifest guard names.
- `test_manifest.py` (54, +26): the `authz:` section (9 refusals, valid parse, 14 path-matching cases, methods, a hostile pattern).
- `test_authz_analysis.py` (26, new):
  - the resource of a path (9 cases);
  - each rule's positive and negative cases;
  - undecided routes, both statuses;
  - BOLA's five cases, policy names;
  - empty input;
  - a Hypothesis property over random inventories;
  - findings anchored on the route;
  - two scale bounds.
- `test_authz_findings_suite.py` (5, new): the labelled suite. It pins every rule's TP/FP/FN.
- `test_authz_graph.py` (5, new): edge assurance, evidence and targets; no path or effective-impact change, also as a property.
- `test_risk_model.py` (34, +3): interim factors, the Low ceiling over random context and paths, `assurance` inert elsewhere.
- `test_authz_db.py` (5, +3):
  - findings rest on route evidence, are Low, and keep their ids on a rescan;
  - the manual list (order, kinds, filter, 422, 404, policy-unchecked);
  - edges are stored and not on any path.
- Updated for the kitchen sink's 3 new, correct authz findings (29 → 32): `test_api`, `test_pipeline_db`, `test_level2_ext_db`, `test_risks_db`; and `test_evidence_db` (X1's backfill test leaves X5's rows aside).

## O. Validation
See `docs/auto/DAY_4_REPORT.md`.
- **Suite:**
  - inconsistency 4/0/0 (TP/FP/FN);
  - unguarded-sensitive 3/2/0;
  - policy 1/0/0;
  - BOLA 6/1/0.
- **NodeGoat at `c5cb68a`:** 20/20 routes resolved, no authz issue raised. Its IDOR is missed (cross-file handler).
- **X0:** the pooled table equals `BASELINE.md` (authz outside the set).

## Q. Known limits (part 2)
- Unguarded-sensitive precision is 0.6 on the suite: public forms (F-4-2).
- BOLA needs the handler code in the route's file. Cross-file handlers, such as methods of handler objects (NodeGoat's style), are not read.
- Ownership and lookup are words. Calls that only format are skipped by name.
- The handler-span check only uses code findings whose line is inside the handler, not ones in functions it calls.
- Edges are not traversable until X6 gives them a probability. The interim Low cap also lasts until X6.
- The evaluation leaves authz out (F-4-1).
