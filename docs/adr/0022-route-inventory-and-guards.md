# ADR-0022: Route inventory and guard detection; stored as evidence; honest guard status

Status: accepted · Date: 2026-10-28 · Implements: expansion phase X5 part 1 (`docs/proposals/EXPANSION_A-D.md` §3.B, §4 X5, §5, §6; `docs/auto/SCHEDULE.md` day 4, started early on day 3) · Builds on: ADR-0012 (sandboxed extractor), ADR-0015 (L3 call graph), ADR-0017 (evidence and assurance)

## Context
X5 needs, for every HTTP route, where it is declared, its full path and parameters, and every place an authentication guard could come from. Day 5 builds authorization findings (unguarded-sensitive, inconsistent guarding, BOLA hypotheses) on top. A false "no guard" is the error that matters most: it turns into a false finding. The plan (§3.B) and the schedule (day 4) disagree on one point: the plan's table says a found guard is `verified`; the schedule says a catalogued guard is `inferred`, never `verified`. The schedule is the owner's later instruction, so this ADR follows it.

## Decision
**Extraction (`ts-imports.4`, `modules/reachability/routes.py`).** In the same sandboxed extractor process (no network, rlimits, file and size caps), each Python, JavaScript and TypeScript file gets an `http` section. It **records and decides nothing**; the catalogue lives in `modules/authz`, so changing it needs no re-extraction.
- Flask and FastAPI:
  - route decorators (`route`, verbs, `api_route`);
  - `add_url_rule` and `add_api_route`;
  - the decorators **below** each route decorator (applied to the view) and **above** it (never run for the route);
  - `Depends`/`Security` targets in parameters, including `Annotated[...]`, and in `dependencies=`;
  - module-level `name = Call(...)` assignments with `url_prefix`/`prefix`/`dependencies`;
  - import bindings, `register_blueprint`/`include_router` mounts, and `before_request` hooks.
- Express:
  - verb calls with a path that starts with `/` or `*` (a one-argument `app.get("x")` reads a setting and is not a route), with the middleware chain;
  - `route(p).get(…).post(…)` chains;
  - `use()` with its prefix and arguments (name, required module, or inline code);
  - `require`/`import` bindings and exports;
  - a template-literal path that starts with `/` is a route with an unknown path.
- Caps: 1,000 routes per file; 500 entries per other kind; 20 names per list; names 200 and paths 300 characters.

**Inventory (`modules/authz/inventory.py`, pure).**
- **Receivers.** A receiver is recognised from its constructor (`guards.yaml` `frameworks`: `Flask`/`Blueprint`, `FastAPI`/`APIRouter`, `express()`/`Router()`).
- **Framework.** Taken from the receiver's constructor, else from the file's imports, else from the repository when exactly one framework of that language is seen with certainty. This is recorded as `basis`: constructor, import, repository or unknown.
- **Mounts** are resolved across files through relative imports, using the reachability module's resolvers. They give the full path:
  - Flask: `register_blueprint(url_prefix=)` replaces the blueprint's own prefix;
  - FastAPI: the include prefix comes before the router prefix;
  - full paths have no trailing slash.
- **Guard sources:**
  - Flask: decorators below the route decorator, plus `before_request` hooks of the blueprint and of the app;
  - FastAPI: dependencies of the handler, the route, the router, the mount and the app. Each is resolved by name, at most 5 deep, and is a guard when it reaches an instance of a security class (`fastapi_schemes`) or a `Security(...)`;
  - Express: route middleware; then `use()` middleware registered **earlier** on the same receiver, in the same file, whose prefix covers the path; then the middleware of every mount up to the app.
- **Status:**
  - `guarded`: a catalogued library guard applies;
  - `custom`: no catalogued guard, but a name that looks like authentication applies. The words of the name are matched by prefix against `custom_hints` (auth, login, logged, jwt, token, role, admin, require, …). The route is listed with that name, never as "no guard";
  - `none_found`: the framework is known and every place a guard could come from was resolved. For Express and FastAPI, that means the mount chain reaches an app; Flask guards never come from a mount;
  - `unresolved`: the framework is known but the chain was not resolved, e.g. an Express `app` passed into a module, or a router no resolvable code mounts;
  - `unknown_framework`: never reported as "no guard".
- **Notes** are kept on the route: a catalogued guard above the route decorator, inline middleware that is not classified, a router mounted several times (the first mount is used), mount cycles.

**Assurance (evidence, `modules/authz/service.py`).** Producer `riskgraph.authz@1`.
- **`route`** evidence, one per route:
  - `verified` when the framework was told by a constructor or an import (a declaration we parsed);
  - `inferred` when it was told by the rest of the repository.
- **`auth_guard`** evidence, one per route with a catalogued or custom guard:
  - always **`inferred`**: a catalogued name says nothing about how the guard is configured;
  - confidence `high` for catalogued guards, `low` for custom-only.
- **"No guard found"** is `inferred` too. The route evidence carries it as `guard_status`.

**Storage.** Routes are stored as scan-scoped evidence rows (X1's `evidence` table), written by the pipeline right after `clear_evidence`. There is **no new table and no migration**. Nothing links these rows to a finding yet; day 5's authz findings and graph edges will link them. `summary.routes` has the counts.

**API.** `GET /scans/{id}/routes?status=&framework=` returns `{items, total, by_status}`, ordered by file and line. `by_status` counts the whole scan. It is additive.

## Consequences
- (+) Day 5 can raise "unguarded" findings only on `none_found` routes. The two ways the analysis can be wrong (an unknown framework, unresolved mounting) are separate statuses, not silent negatives.
- (+) The catalogue can change without re-extraction, and the manifest extension (`authz.guards:`) slots in as one more source of names.
- (+) The labelled suite gives route recall 30/31 = 0.968 (target ≥ 0.95), and every guard status matches its label. On OWASP NodeGoat at `c5cb68a`, the inventory finds all 20 route declarations.
- (−) Custom-hint matching is a word heuristic. It errs towards `custom`, which costs day-5 recall, not precision. A name like `@cache.cached` is ignored, and `@require_json` would wrongly read as a possible guard.
- (−) An Express `app` passed into a routes module (NodeGoat's style) stays `unresolved` until call sites are followed (`routes(app, db)` in `server.js`). That is the first refinement day 5 needs.
- (−) Ordering uses line numbers, so two calls on one line (minified code) compare as "not earlier".
- (−) App-level Flask hooks are applied to every Flask route in the repository, even when the repository has several Flask apps.
- (−) Django/DRF are deferred (plan §5). Class-based Flask views are found, but without a handler name.

## Rejected
- **A `routes` table.** It needs a migration for data that is evidence by the plan's own contract (§2.4 lists `route` and `auth_guard` as evidence kinds). It can be added later if querying needs it.
- **`verified` for a catalogued guard** (plan §3.B's table). The owner's day-4 instruction is stricter, and it is the honest level: the name proves the decorator is present, not that it checks the right thing.
- **Treating every uncatalogued decorator or middleware as a possible guard.** Nearly every route would be `custom` (`limiter.limit`, `cache.cached`, `express.json`), and day 5 would have nothing to say.
- **Deciding guards in the extractor.** A catalogue change would then need a re-scan, and the sandboxed process would grow policy it does not need.
