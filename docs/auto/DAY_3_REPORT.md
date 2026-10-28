# Day 3 report (Wed 2026-10-28): X4 part 2 gated; tier-1 hardening and X5 part 1

**Verdict: COMPLETE**, for the day as SCHEDULE defines it when the Joern spike is missing:
- flag F-3-1 and no Joern adapter;
- tier-1 hardening;
- X5 part 1 started early. In fact X5 part 1 is done to its day-4 exit criteria.

Everything planned is built, tested and pushed. Flags F-1-1, F-1-2 and F-2-1 are still OPEN, and nothing today builds on them.

Start `6a822ab`. Commits today, in order:

| Commit | What |
|---|---|
| `bd8c075` | Day 3 plan, flag F-3-1 |
| `1cc66af` | Tier-1 hardening: a taint hit joins the generic finding whose multi-line call covers its line |
| `0a068fa` | Extractor `ts-imports.4`: the `http` section (routes and every guard source), `syntax.py` |
| `1de154c` | `modules/authz`: guard catalogue, route inventory, evidence; the labelled suite; `add_api_route` |
| `ea01689` | Pipeline step, `summary.routes`, `GET /scans/{id}/routes` |
| `e821fe2` | Self-attack fix: two quadratic lookups in the inventory |
| `4aed1eb` | Express routes with a template-literal path (found on NodeGoat) |
| (this commit) | ADR-0022, `PHASE_X5.md`, `PHASE_X4.md` part 2, report, handoff, todo |

Every code commit went through a `set -eo pipefail` check script before it was pushed: ruff, format, mypy, unit and db tests. No commit was pushed red.

## Precondition check (VERIFIED)
- `docs/auto/spikes/joern/RESULT.md` says "_Not run yet (L-2 …)_".
- `backend/tests/fixtures/joern/` does not exist.
- So this is F-3-1 (OPEN), with a question and resume steps for both `GO` and `NO-GO`.

## Per plan step
| # | Step | Result | Label |
|---|---|---|---|
| 1 | F-3-1 | Flag written; `PHASE_X4.md` says part 2 is gated | VERIFIED |
| 2 | Multi-line sinks | After the exact-line join, a taint-only group joins a generic group of the same family that starts ≤ 30 lines above and covers its line. The nearest start wins; the generic key is kept. 4 new tests; a mutation check (look-back off) fails 2 of them | VERIFIED (unit). That Semgrep reports the argument's line for a focused sink: BELIEVE (L-4) |
| 3 | Extractor `ts-imports.4` | Flask, FastAPI, Express (+ TS): routes with decorators below and above, `Depends`/`Security` (also `Annotated`), prefixes, mounts, hooks, `use()` arguments, bindings, exports; caps; 7 tests incl. hostile input | VERIFIED |
| 4 | `modules/authz` | Strict `guards.yaml`, inventory with cross-file mounts and transitive FastAPI dependencies, five statuses, `route`/`auth_guard` evidence; 40 tests | VERIFIED |
| 5 | Labelled suite | 31 labelled routes across three apps: recall **30/31 = 0.968** (target ≥ 0.95). The miss is `app[verb](…)`, kept in on purpose. Every status and parameter list matches its label; no unlabelled route found | VERIFIED |
| 6 | Pipeline + API | `GET /scans/{id}/routes?status=&framework=` and `summary.routes`; a failing inventory is reported and the scan completes; db test through the real pipeline | VERIFIED |
| 7 | Test stage | Below | VERIFIED |

**The suite found two real gaps while it was being written.** Both were fixed in `1de154c`, before the commit:
- Full paths kept a trailing slash: Flask `"/orders" + "/"` gave `/orders/`, so siblings would not compare equal on day 5.
- The hint list missed `*_required`-style names (`team_member_required`). The hint `require` was added; it is a documented rule change, not a score input.

**Real-code check (VERIFIED).** I cloned OWASP NodeGoat from GitHub at `c5cb68a` into the scratchpad, read-only, and did not commit it. I ran the real extractor and the inventory on it:
- All 20 live route declarations are found. Lines 58–59 of `routes/index.js` are commented out and correctly not found.
- 12 routes are `custom` (`isLoggedIn`).
- 8 are `unresolved`: NodeGoat passes `app` into `routes(app, db)`, so app-level middleware cannot be ordered against them.
- The first run found 19. The template-literal tutorial route was missing; `4aed1eb` fixed it.

## Test output (run after the last code commit, `4aed1eb`)
```
$ uv run ruff check . && uv run ruff format --check . && uv run mypy
All checks passed!
240 files already formatted
Success: no issues found in 230 source files
$ uv run pytest -m "not db and not docker and not e2e and not perf and not llm" -q
528 passed, 88 deselected in 13.86s
$ uv run pytest -m "db and not llm" -q
80 passed, 2 skipped, 534 deselected in 67.09s (0:01:07)
$ uv run pytest -m perf -q -s
loader: 5000 nodes, 19990 edges, 0.033s
search: 30 paths for 10 sinks, 0.201s
search (two passes): 55 paths, 27 hypotheses, 0.140s
build+search: 5001 nodes, 22596 edges, 50 paths, 0.467s
4 passed, 612 deselected in 23.57s
$ alembic upgrade head; downgrade -1; upgrade head; check   (fresh database riskgraph_mig)
Running upgrade … -> b8d3f1a6c2e9 … Running downgrade b8d3f1a6c2e9 -> a7c2e9f4b1d6 … Running upgrade a7c2e9f4b1d6 -> b8d3f1a6c2e9
No new upgrade operations detected.
```
- Start of day: 472 unit, 78 db.
- The 2 skipped db tests need the real scanners.
- No migration today: the round trip is of the existing head. The routes use X1's `evidence` table.

## Evaluation (X0)
I re-ran the evaluation because the analyzer version changed and the pipeline gained a step:
```
uv run python -c "from evaluation.run import collect; from evaluation.report import render; print(render(collect()))"
```
After stripping log lines, the diff against `BASELINE.md` shows only the two differences already recorded on days 1 and 2:
- the model line (`v1-ctx.2` → `v1-ctx.3`, X2 part 1);
- C's AWS key at rank 6 in the M4 top 10 instead of rank 1 (X1's intended hypothesis change).

The pooled table is identical. Route evidence links to no finding and does not enter scoring, so no change was expected. VERIFIED. `BASELINE.md` was not touched.

## Self-attack
1. **Scale (fixed, `e821fe2`).** I built synthetic extracts at the extractor's caps and timed the inventory.
   - **Python:** a relative import searched the whole module index for the importing file's module: 5.23 s at 45,000 files and 5,000 routes. A file-to-module map built once brings it to 0.19 s.
   - **Express:** every mount scanned all receivers and every `use()`: 3.57 s at 5,000 mounts. With receivers indexed by file, and only `use()` calls that carry middleware kept, it takes 0.12 s.
   - Both cases are now tests with a 2 s bound.
   - A FastAPI dependency web (400 functions, 20 dependencies each, 5,000 routes) was already linear: 0.65 s. The `seen` set bounds each walk.
2. **Hostile input.** The extractor test covers:
   - 1,050 routes in a file (capped at 1,000);
   - a 5,000-character path (cut to 300);
   - 100 decorators and 300 middleware (20 kept);
   - 300 levels of parentheses;
   - f-string and empty-argument paths (`path: None`).
   The inventory takes six malformed extracts (non-dicts, wrong types, missing keys) without raising.
3. **False "no guard" (the error that matters on day 5).**
   - `none_found` needs a known framework and a mount chain that reaches an app. A test checks this over the whole suite.
   - Inline middleware is noted, not guessed.
   - A guard placed above `@app.route` is not counted, and the route says why.
4. **Ordering.** Express `use()` counts only when it comes earlier in the same file. A test checks a route registered before the middleware.
5. **Justified, not fixed:**
   - Minified code (two calls on one line) compares as "not earlier", so a guard on the same line is missed.
   - Flask app hooks apply to every Flask route in a repository with several apps.
   - The custom-hint heuristic. All three are recorded in ADR-0022.

## UNVERIFIED (needs the owner's machine)
- Nothing new that needs Docker, scanners or Ollama. The inventory runs in the existing extractor process, which the db tests ran for real.
- Still open from earlier days: the Joern spike (L-2, now F-3-1), and L-3, L-4, L-5, L-6, L-7, L-8, L-9. L-7 (`make dev` and clicking through the new API fields) now also covers `/scans/{id}/routes`.
- The real `focus-metavariable` line semantics behind the multi-line join (L-4).

## New flags and local tasks
- **F-3-1 (OPEN):** the Joern spike has not been run. Options: (a) run L-2 and a later run builds the adapter, or (b) skip Joern in this block. Recommendation: (a) when there is machine time; (b) costs nothing meanwhile.
- No new local tasks.

## For Day 4 (Thu 29 Oct)
- **Catch-up rule.** X4 part 2 stays parked unless the owner has answered F-3-1 with a `GO` and fixtures. In that case, build it first (F-3-1 resume steps).
- **Day 4's scope (X5 part 1) is done today**, to its exit criteria. The schedule's order holds, so day 4 can start X5 part 2 (day 5's scope).
  - Its first refinement: follow call sites so that an Express app passed into a module (`routes(app, db)`, NodeGoat) gets resolved app-level middleware. Without it, NodeGoat's unguarded routes stay `unresolved`, and day 5 cannot call them unguarded.
  - Then: inconsistency, unguarded-sensitive, the manifest `authz:` diff, and BOLA as hypothesis only.
- **Interfaces for day 5:**
  - `authz.route_inventory(reach.extracted) -> list[Route]`; each route has `status`, `guards` (with `catalogued` and `source`), `full_path`, `params`, `mounted`, `notes`;
  - the route evidence ids (`route_evidence`) are what UNGUARDED edges and authz findings should link to;
  - the manifest extension `authz.guards:` can feed `Catalogue` as extra guard names;
  - `handler_params` is in the raw extract, for BOLA.
- **No migration today.** The test DB is at head `b8d3f1a6c2e9`.
