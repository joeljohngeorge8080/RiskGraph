# Day 2 report (Tue 2026-10-27): X3 part 2 + X4 part 1

**Verdict: COMPLETE.** Every planned step is built, tested and pushed.
- One item is flagged instead of decided: F-2-1, whether tier-1 taint is on by default. It is built and off.
- Running the rules against the real Semgrep is the owner's task (L-4, now with exact steps).
- Flags F-1-1 and F-1-2 are still OPEN. Nothing today was built on them.

Start `10f3eb8`. Commits today, in order:

| Commit | What |
|---|---|
| `ec6c1c9` | Day 2 plan |
| `ccee5e9` | Two-pass search (hypotheses can no longer crowd out or capture the paths that set I\*), `missing` per hypothesis edge, manifest `owns:` links, `GraphFinding.line` |
| `ea5a710` | `/attack-paths` grouped by assurance, `missing_evidence[]` |
| `eb26c3b` | The level-2 db test expects the grouped order (see "Mistake" below) |
| `8aa9677` | Perf: build + search at 5k/20k; the two-pass search with function/endpoint nodes and mixed assurance |
| `b1398fb` | Taint catalogue, generator, committed rules, setting (off), trace redaction, parser contract, `taint_flow` evidence, correlation |
| `68c25b5` | The 40-case suite and its scorer |
| `f81b9cc` | Self-attack fix: correlation indexed by line instead of pairwise |
| (this commit) | ADR-0020, ADR-0021, `PHASE_X3.md` part 2, `PHASE_X4.md`, flags, local tasks, handoff |

**Mistake, corrected within minutes.** `ea5a710` was pushed with one db test failing. `test_level2_ext_db.py` still pinned the old score-only order, which the plan changes on purpose. My check command piped pytest into `grep`, so it read the word "failed" as success. `eb26c3b` fixed the test right away. From then on every commit went through a script with `set -eo pipefail` that stops on any failure (it also caught a lint error before `8aa9677` and a type error before `f81b9cc`). No other commit was pushed red.

## Found while reading (the main result of the day)
The plan's property "hypothesis paths never change any score" did **not** hold before today. The property test, written first, fails on the old search in 3 of its 5 tests (mutation check: the assured view switched off).
1. **Crowding.** Yen took the 3 cheapest paths per sink whatever their assurance. Three family-matched AWS keys pushed an inferred exploit path out, and its finding lost its I\*.
2. **Edge capture.** An L1 finding with a higher p took over a manifest service's EXPLOIT edge. The edge became a hypothesis, and the L2 finding under it lost its I\*.

Fix (ADR-0020):
- I\* now comes only from a search over the edges of at least `inferred`. A hypothesis EXPLOIT edge falls back to its best assured finding there.
- The full graph adds only its hypothesis paths.
- Stored edges are unchanged.

## Per plan step
| # | Step | Result | Label |
|---|---|---|---|
| 1 | `missing_evidence[]`, grouped order | Three texts (family match, image package, L1/unknown) stored in the path edge JSON; API order verified → inferred → hypothesis → pre-X1, each by score; old fields unchanged; old paths say "not recorded" | VERIFIED (unit + db) |
| 2 | Manifest credential link | `identities[].owns: [{file, line?, family?}]` gives a verified AUTHENTICATES_AS; at most one edge per key and identity; strict validation (7 hostile values refused); `credentials:` unchanged. Additive, so no flag | VERIFIED |
| 3 | Two-pass search | Crowding and capture tests pass, and fail with the fix removed | VERIFIED |
| 4 | Properties | Hypothesis-only facts never change a score (200 examples); path assurance = min of edges (150) | VERIFIED |
| 5 | Perf | build + search 0.625 s at 5,001 nodes / 22,596 edges; two-pass search with function/endpoint nodes 0.172 s; budget 2 s | VERIFIED (this sandbox) |
| 6 | Catalogue | 5 classes × Python/JS, sources for Flask, Django, FastAPI, Express; strict loader | VERIFIED (unit). That the patterns match real code: UNVERIFIED (L-4) |
| 7 | Generator + rules | 10 rules, committed, drift test, no anchors; `--config` only with `RISKGRAPH_SEMGREP_TAINT_RULES_PATH` | Structure VERIFIED. That Semgrep 1.182 accepts the file: UNVERIFIED (needs the owner's machine, L-4); BELIEVE it does |
| 8 | Contract | Trace → location-only steps before redaction (no code stored), ≤ 50 with the sink kept, malformed traces give no steps; `analysis = intraprocedural`; `taint_flow` evidence, inferred | VERIFIED on a hand-written report. Real trace shape: BELIEVE (L-4) |
| 9 | Correlation | Joins a generic finding at the same line when the CWEs share a family; the generic key is kept; generic keys unchanged; K stays 1 (one scanner) | VERIFIED |
| 10 | Suite | 40 cases, every class × variant × language once; Python parses, JS passes `node --check`; scorer matches hand-counted numbers | VERIFIED. **Recall not claimed** (L-4) |

## Test output (run at the end of the day, after the last code commit)
```
$ uv run ruff check . && uv run ruff format --check . && uv run mypy
All checks passed!
228 files already formatted
Success: no issues found in 218 source files
$ uv run pytest -m "not db and not docker and not e2e and not perf and not llm" -q
472 passed, 86 deselected, 1 warning in 15.64s
$ uv run pytest -m "db and not llm" -q
78 passed, 2 skipped, 478 deselected, 1 warning in 95.56s (0:01:35)
$ uv run pytest -m perf -q -s
loader: 5000 nodes, 19990 edges, 0.038s
search: 30 paths for 10 sinks, 0.277s
search (two passes): 55 paths, 27 hypotheses, 0.172s
build+search: 5001 nodes, 22596 edges, 50 paths, 0.625s
4 passed, 554 deselected, 1 warning in 30.71s
$ alembic upgrade head; downgrade -1; upgrade head; check   (fresh database riskgraph_mig)
Running upgrade a7c2e9f4b1d6 -> b8d3f1a6c2e9 … Running downgrade b8d3f1a6c2e9 -> a7c2e9f4b1d6 … Running upgrade a7c2e9f4b1d6 -> b8d3f1a6c2e9
No new upgrade operations detected.
```
- Start of day: 421 unit, 77 db.
- The 2 skipped db tests need the real scanners.
- The warning is Starlette's `BlockingPortal` deprecation, which predates today.
- No migration today. The round trip is of the existing head.

## Evaluation (X0)
The graph search changed, so I re-ran the evaluation twice: after X3 part 2, and at the end of the day.
- The two runs are identical (after stripping log lines).
- Against `BASELINE.md`, the **pooled table is identical**. The only differences are the two already recorded:
  - the model line (`v1-ctx.2` → `v1-ctx.3`, X2 part 1);
  - C's AWS key at rank 6 in the M4 top 10 instead of 1 (X1's intended hypothesis change).
- The two-pass search changed no score on the scenarios: no hypothesis there was crowding out an inferred path that carried a higher I\*. VERIFIED.
- The new taint code has no effect on them: the recorded Semgrep fixtures have no `riskgraph.taint.*` hits, and the setting is off. VERIFIED.
- `BASELINE.md` was not touched.

## Self-attack
1. **Scale: quadratic correlation (fixed, `f81b9cc`).** `_join_taint_hits` compared each taint-only group with every SAST group. 6,000 findings took 0.72 s, so about 18 s at 20,000. It now uses an index by (file, line): 0.04 s, with a test.
2. **Hostile input: stored steps.** A stored report is our redacted copy, but the parser still rebuilds every step with type checks. `../../etc/passwd`, `line: true`, an unknown role and non-dicts are dropped or normalized (test). Steps are never opened as files.
3. **Hostile input: links.** Absolute paths, `..`, directories, empty names, line 0, unknown families and unknown keys are all refused (7 cases).
4. **Ordering.** Paths within one assurance group keep the database order (score, sink, rank), because Python's sort is stable. Tested on the db scan.
5. **Justified, not fixed:**
   - An `owns:` link with only `file` covers every secret in that file. That is what it declares; ADR-0020 recommends `line`.
   - `line` must match the merged first line, which follows Gitleaks.
   - An L1 finding riding along an inferred edge still gets its I\* (ADR-0017 behaviour; the property is about other findings).

## UNVERIFIED (needs the owner's machine)
- Semgrep 1.182 loading `taint_rules.yaml`.
- The patterns matching the suite: recall and precision.
- The real `dataflow_trace` shape (L-4).
- The rules inside the Semgrep scanner image (F-2-1, resume step 1).

## New flags and local tasks
- **F-2-1 (OPEN):** tier-1 taint on by default after L-4? Recommendation (a): yes, after L-4 passes.
- **L-4** now has the exact commands (write the suite, run Semgrep, score) and the trace check.

## For Day 3 (X4 part 2, Joern)
- The precondition is `docs/auto/spikes/joern/RESULT.md` plus fixtures under `backend/tests/fixtures/joern/` (L-2).
- At the time of this report `RESULT.md` says "Not run yet", and there are no Joern fixtures. Unless the owner runs the spike before 05:00 IST on 28 Oct: flag F-3-1, then do tier-1 hardening and start X5 part 1 (SCHEDULE day 3).
- Reuse for tier 2:
  - catalogue: `taint.load_catalogue()`;
  - steps: `FlowStep` via `finding_evidence._match` (set `attrs.analysis = "interprocedural"`; extend the `== "intraprocedural"` check there);
  - correlation: `merge._join_taint_hits`. Joern is another scanner, so K rises;
  - scoring: `evaluation/taint_suite.score` (it reads Semgrep-shaped JSON; Joern flows need a small adapter).
- The test DB is at head `b8d3f1a6c2e9`. No migration today.
