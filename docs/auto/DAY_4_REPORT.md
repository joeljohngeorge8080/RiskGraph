# Day 4 report (Thu 2026-10-29): X5 part 2, authorization findings

**Verdict: COMPLETE.**
- Day 4's own scope (X5 part 1) was finished on day 3, so today did **X5 part 2** (SCHEDULE day 5's scope) to its exit criteria, including the graph edges.
- Every plan step is built, tested and pushed.
- New flags: **F-4-1** (how the evaluation counts authz findings) and **F-4-2** (a manifest way to declare public routes). Neither blocks anything.
- F-1-1, F-1-2, F-2-1 and F-3-1 are still OPEN and unanswered; nothing today builds on them.

Start `51f7b15`. Commits today, in order:

| Commit | What |
|---|---|
| `805bd8f` | Day 4 plan |
| `bd258f4` | Extractor `ts-imports.5`: handler bodies (span, loads, ownership), JS call sites, exported-function parameters |
| `9d07ec7` | A passed-in Express app is bound through its call site (NodeGoat) |
| `7ea70cf` | Manifest `authz:` (guards, rules), strict and optional |
| `1fd675c` | `authz.analyze`: inconsistent, unguarded-sensitive, policy, BOLA; manifest guard names; `public_hints` |
| `fe25182` | The labelled authz suite; reads compared with reads (a false positive the suite found); a lint fix for `1fd675c` (below) |
| `b7df109` | Authz findings, evidence links, interim score `v1-ctx.4` with the Low ceiling, pipeline order, X0 exclusion |
| `f387139` | `GET /scans/{id}/authz/manual` |
| `c4a55df` | UNGUARDED and BOLA_SUSPECT edges, without a probability |
| `8996a79` | Self-attack: the analysis stays linear on large inputs |
| (this commit) | ADR-0023, `PHASE_X5.md` part 2, flags, report, handoff, todo |

**One commit was pushed red on lint: `1fd675c`.**
- Its tests passed, but `ruff check` failed (RUF022, an unsorted `__all__`).
- Cause: my check script ran `ruff check . && ruff format --check . && mypy` under `set -e`. A failure inside an `&&` list does not stop such a script, so the failure scrolled past.
- The next commit, `fe25182`, fixed it, and the script now runs each check on its own line.
- I re-checked `bd258f4`, `9d07ec7` and `7ea70cf` for lint and format in a clean worktree: all clean (VERIFIED). Every later commit went through the fixed script.

## Per plan step
| # | Step | Result | Label |
|---|---|---|---|
| 1 | Extractor `ts-imports.5` | Same-file handler code gets `body {span, loads, ownership}`; JS records plain-function call sites and exported parameters. 5 new tests, incl. a 6,000-line body cut at the node cap | VERIFIED |
| 2 | Passed-in Express apps | The first call site's receiver is used; the caller's earlier `use()` counts, and so do `use()` and mounts inside the module. NodeGoat: 20/20 routes resolved, none `unresolved` (day 3: 8 `unresolved`) | VERIFIED |
| 3 | Manifest `authz:` | `guards` + `rules [{path, methods?, require}]`, strict; `*`/`**` matcher, linear | VERIFIED |
| 4 | `authz.analyze` | 4 rules; only `none_found` is ever unguarded (Hypothesis property); undecided routes go to the manual list | VERIFIED |
| 5 | Labelled suite | Inconsistency **4 TP / 0 FP / 0 FN** (target ≥ 0.8); unguarded-sensitive 3/2/0; policy 1/0/0; BOLA 6/1/0, all low hypotheses; inventory recall still 30/31 | VERIFIED |
| 6 | Findings and interim score | `authz` findings from the `riskgraph` run, anchored on `METHOD path`, linked to route evidence; model `v1-ctx.4`: SAST `auth` factors, **every authz finding capped at Low until X6**; BOLA Low for good | VERIFIED |
| 7 | Manual list | `GET /scans/{id}/authz/manual?kind=`: BOLA, policy-unchecked, unresolved, unknown_framework, custom | VERIFIED |
| 8 | Graph edges | `endpoint` nodes; UNGUARDED (inferred) for exposed services; BOLA_SUSPECT (hypothesis) to the stores the service connects to; **no probability**, so no path or score changes (property test + db test) | VERIFIED |
| 9 | Test stage | Below | VERIFIED |

**Found while building (fixed before commit):** in the first version, a public list next to guarded writes (`GET /posts` beside guarded `POST`/`PUT`/`DELETE`) was "inconsistent". An unguarded read is now compared with the other reads only.

## Test output (after the last code commit, `8996a79`)
```
$ uv run ruff check . ; uv run ruff format --check . ; uv run mypy
All checks passed!
245 files already formatted
Success: no issues found in 235 source files
$ uv run pytest -m "not db and not docker and not e2e and not perf and not llm" -q
610 passed, 91 deselected, 1 warning in 23.08s
$ uv run pytest -m "db and not llm" -q
83 passed, 2 skipped, 616 deselected, 1 warning in 111.28s (0:01:51)
$ uv run pytest -m perf -q -s
loader: 5000 nodes, 19990 edges, 0.044s
search: 30 paths for 10 sinks, 0.315s
search (two passes): 55 paths, 27 hypotheses, 0.230s
build+search: 5001 nodes, 22596 edges, 50 paths, 0.790s
4 passed
$ alembic upgrade head; downgrade -1; upgrade head; check   (fresh database riskgraph_mig)
Running upgrade … -> b8d3f1a6c2e9 … Running downgrade b8d3f1a6c2e9 -> a7c2e9f4b1d6 … Running upgrade a7c2e9f4b1d6 -> b8d3f1a6c2e9
No new upgrade operations detected.
```
- Start of day: 528 unit and 80 db passed.
- The 2 skipped db tests need the real scanners.
- No migration today; the round trip is of the existing head.

**Pinned counts that changed (and why).** The kitchen-sink fixture now has 3 authz findings. Its Flask routes `/user`, `/ping` and `POST /config` have no guard, and two of them hold the SQL and command injections the fixture is built around. The findings are correct, so the pinned counts move 29 → 32: `test_api`, `test_pipeline_db`, `test_level2_ext_db`, `test_risks_db`. Two other tests changed:
- `test_evidence_db`'s X1 backfill test now sets aside X5's rows (authz findings, UNGUARDED edges): no pre-X1 database can hold them.
- `test_risks_db` and `test_runtime_eol_db` pin the new model `v1-ctx.4`.

No assertion was weakened. `summary.merged_away` now counts RiskGraph's own findings too, so it keeps its meaning: 53 − 32 = 21, as before.

## Evaluation (X0), three runs
I re-ran the evaluation because scoring (`v1-ctx.4`), the findings set and the graph changed. Each run is diffed against `BASELINE.md`, with log lines stripped. `BASELINE.md` was not touched.

1. **Authz findings in, uncapped** (the first version of step 6). Scenarios B and E each got one `authz:unguarded-sensitive` finding. No X0 label covers them, so both counted as "not important" ("defaulted 2").
   - They ranked **6th and 9th** in the M4 top 10.
   - Pooled M4: P@10 0.7 → 0.6, nDCG@10 0.991 → 0.902, E90 9 → 11.
   - M1/M2 moved slightly too.

   That is a ranking decision before risk v2 exists, so I did not keep it.
2. **In, capped at Low.** The M4 row is identical to the baseline. M1/M2 still shift a little (e.g. M1 E90 26 → 28), because the two unlabelled findings join their CVSS-only ranking.
3. **Final: capped, and outside the X0 set** (`OUTSIDE_X0`, reported in the file). The diff is the same as on day 3:
   - the model line (`v1-ctx.2` → `v1-ctx.4`);
   - one new line saying authz findings are not in the set;
   - C's AWS key at rank 6 instead of 1 in the M4 top 10 (X1's intended change, recorded on day 1).

   **The pooled table is identical** (VERIFIED). Step 8's edges changed nothing further: that run was byte-identical to run 3.

Whether and how authz findings should enter the evaluation is the owner's call: **F-4-1**, recommendation (a), a separate authz scenario with labels written first.

## Self-attack
1. **Quadratic sibling check (fixed, `8996a79`).** 5,000 routes on one resource took 1.81 s, because siblings were rebuilt for every route. Counts per group bring it to 0.02 s. This is now a test (< 2 s).
2. **Hostile manifest policy.** A scanned repository's `riskgraph.yaml` is untrusted.
   - 200 rules (the cap) × 5,000 routes (the inventory cap) took 3.89 s.
   - Paths are now split once (cached), and a rule that starts with a literal stops at the first segment: 0.38 s for literal rules.
   - The worst case, every rule starting with `**`, is 2.85 s.
   - The matcher is iterative, worst case pattern × path steps, never exponential (a 40 × `**` pattern is a test). Justified, not capped further: bounded and only self-inflicted on that repository's own scan.
3. **False "unguarded".**
   - A Hypothesis property over random inventories: only `none_found` ever yields unguarded or inconsistent issues; BOLA is always a low hypothesis; nothing is verified.
   - `unresolved` and `unknown_framework` routes with code findings and matching rules yield no issue, only "policy unchecked".
4. **Graph safety.** A property test checks that random authz findings never change any path or effective impact. An authz finding without evidence ids is skipped, not built: an edge without evidence would raise and fail the analysis.
5. **Real code.** NodeGoat produces **no** authz issue. Its unguarded routes are login, signup, logout and the tutorial, so there are no false positives. But its documented IDOR (`GET /allocations/:userId`) is **missed**: the handler is a method of a handler object in another file, and only same-file handler code is read (3 of 20 bodies seen). This is a recall gap, recorded in ADR-0023 and `PHASE_X5.md`.
6. **Justified, not fixed:**
   - unguarded-sensitive precision 0.6 on the suite, below plan §6's 0.8 (two public forms; F-4-2 proposes a declaration);
   - ownership and lookup detection is by words.

## UNVERIFIED (needs the owner's machine)
- Nothing new needs Docker, scanners or Ollama. The analysis runs in the worker on the existing extractor output, which the db tests ran for real.
- The SAST categories that make a handler sensitive were tested with the recorded Semgrep fixtures, not a live Semgrep run (L-4 territory).
- Still open from earlier days: L-2 (F-3-1), L-3, L-4, L-5, L-6, L-7, L-8, L-9. L-7 (`make dev`, click through the new API fields) now also covers `/scans/{id}/authz/manual`, authz findings and `endpoint` nodes.

## New flags and local tasks
- **F-4-1 (OPEN):** authz findings in the evaluation. Recommendation (a): keep them out of X0, and add an authz scenario with labels written first.
- **F-4-2 (OPEN):** a manifest `authz.public:` list for routes public on purpose (a new field). Recommendation (a).
- No new local tasks.

## For Day 5 (Fri 30 Oct)
- **Catch-up.** Nothing of days 1–4 is open and unflagged. X4 part 2 stays parked unless F-3-1 is answered with `GO` and fixtures; in that case, build it first.
- **X5 part 2 is done**, so by the schedule's order day 5 can start **X6** (day 6's scope): risk v2.
- **What X6 inherits from today:**
  - Authz findings are scored by `v1-ctx.4`'s interim rule: SAST `auth` factors, every one capped at Low (`AUTHZ_SCORE_CEILING`). X6's authz factor table replaces it ("E for inferred unguarded; hypotheses never above Low"). The reduction property must still hold with no authz input.
  - UNGUARDED/BOLA_SUSPECT edges are stored with `p = None`. If X6 gives UNGUARDED a probability, inferred paths through endpoints become possible. That would change I\*, so it needs the X0 re-run and a reasoned report.
  - `OUTSIDE_X0 = {"authz"}` in `evaluation/run.py` stays until F-4-1 is answered.
- **Smaller follow-ups:**
  - read cross-file handlers for BOLA (NodeGoat's IDOR);
  - code findings in functions a handler calls (L3 spans);
  - F-4-2 if answered.
