# PHASE X5: business logic and authorization (expansion plan)

**Status:** part 1 (extractor `ts-imports.4`, `modules/authz` route inventory and guard catalogue, `GET /scans/{id}/routes`, the labelled suite) done on 2026-10-28. It was started a day early, because X4 part 2 is gated (F-3-1). Part 2 (authorization findings, UNGUARDED/BOLA_SUSPECT edges, the manifest `authz:` section, the manual-verification list) is SCHEDULE day 5. Decision: ADR-0022. No migration. Plan: `docs/proposals/EXPANSION_A-D.md` §3.B, §4 (X5), §5, §6.

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
- An Express app passed into a routes module stays `unresolved` until its call sites are followed. That is the first refinement for part 2.
- Custom-hint matching is a word heuristic (ADR-0022, consequences).
- Ordering compares line numbers.
- Flask app hooks apply to every Flask route in the repository.
- Django/DRF are deferred (plan §5).
- No authorization findings yet (part 2).
