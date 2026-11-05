# Day 5 report (Fri 2026-10-30): X6, risk v2

**Verdict: COMPLETE.**
- Day 5's own scope (X5 part 2) was finished on day 4, so today did **X6** (SCHEDULE day 6's scope) to its exit criteria.
- Every plan step is built, tested and pushed. Every commit was green on lint, types, unit and db before it was pushed.
- New flag: **F-5-1** (whether every finding of an exposed service should take the path's effective impact). It blocks nothing.
- F-1-1, F-1-2, F-2-1, F-3-1, F-4-1 and F-4-2 are still OPEN; nothing today builds on them. F-1-1 now also notes scenario G's database end.

Start `484f686`. Commits today, in order:

| Commit | What |
|---|---|
| `70d4f6b` | Day 5 plan, with the F–H labels written before any run |
| `be72147` | Model `v2.1`: factor tables, `input_for` wiring, reduction and monotonicity properties |
| `a84ffb9` | Image packages scored in the context of their services; scenarios F–H |
| `c6e0649` | Self-attack: the image context is built once per scan (1.9 s → linear) |
| `0fae2cc` | ADR-0024, `PHASE_X6.md`, F-5-1 |
| (this commit) | Report, handoff, todo |

## Per plan step
| # | Step | Result | Label |
|---|---|---|---|
| 1 | v2 tables and model | Four tables: image packages R = 0.5 `not_assessable`; taint E = max(SAST, `E_TAINT[cwe][confidence]`); EOL E by age (0.4 / 0.5 / 0.6, no date 0.5); authz `E_AUTHZ_INFERRED`, no interim cap, hypothesis ceiling kept | VERIFIED |
| 2 | Wiring | `input_for`: image flag, the taint hit from the members (the generic rule leads after a merge), EOL age from `data_as_of − eol_date` | VERIFIED |
| 3 | Scenarios F–H | All pass, including the pre-registered label ordering, **after a fix the first run called for** (below) | VERIFIED |
| 4 | ADR-0024, `PHASE_X6.md`, X0 re-run | Done; X0 below | VERIFIED |
| 5 | Test stage | Below | VERIFIED |

**What the first scenario run found** (before any fix, labels unchanged):
1. **An image finding had no context at all.**
   - Its file is the Kubernetes or Compose file that names the image, which maps to no service.
   - So G1 (a KEV CVE on a LoadBalancer workload bound to `cluster-admin`) scored 63.0 with exposure, privilege and data all "unknown". F2 (a weak hash) outranked it, and the label check failed.
   - Fix (`a84ffb9`): an image package takes the exposure and privilege of the services that run its image (worst case), only where its own file says nothing.
   - G1 is now 79.4, Critical, and the ordering holds: F1 92.8, G1 79.4, then the rest.
   - This is a correctness fix, not a weight change: no table value moved.
2. **Every code finding of an exposed service takes the path's effective impact.**
   - F2 (weak hash, L2) is 71.1, Critical; F3 (an L1 CVE, a hypothesis on its own) is 50.0; G2 (a non-KEV image CVE) is 44.4 instead of 28.9.
   - The rule predates v2 (§14.4, ADR-0013). Changing it is the owner's call, so I left it as is and pinned it in a test: **F-5-1**.
   - On the X0 replay (temporary patch, reverted): option (a), "own support ≥ inferred", changes nothing. Option (c), "leading finding only", swaps three neighbouring pairs in the M4 top 10, and the pooled table stays the same.

## Test output (after the last code commit, `c6e0649`)
```
$ uv run ruff check . ; uv run ruff format --check . ; uv run mypy
All checks passed!
247 files already formatted
Success: no issues found in 237 source files
$ uv run pytest -m "not db and not docker and not e2e and not perf and not llm" -q
648 passed, 92 deselected, 1 warning in 29.15s
$ uv run pytest -m "db and not llm" -q
84 passed, 2 skipped, 654 deselected, 1 warning in 127.64s (0:02:07)
$ uv run pytest -m perf -q -s
loader: 5000 nodes, 19990 edges, 0.054s
search: 30 paths for 10 sinks, 0.339s
search (two passes): 55 paths, 27 hypotheses, 0.254s
build+search: 5001 nodes, 22596 edges, 50 paths, 0.862s
4 passed
$ alembic upgrade head; downgrade -1; upgrade head; check   (fresh database riskgraph_mig)
Running upgrade … -> b8d3f1a6c2e9 … Running downgrade b8d3f1a6c2e9 -> a7c2e9f4b1d6 … Running upgrade a7c2e9f4b1d6 -> b8d3f1a6c2e9
No new upgrade operations detected.
```
- Start of day: 610 unit and 83 db passed.
- The 2 skipped db tests need the real scanners.
- No migration today; the round trip is of the existing head.

**Tests that changed, and why** (no assertion weakened):
- `test_risk_model.py`: the v1-ctx.4 test "an inferred authz finding stays Low" is replaced by its v2 counterpart (scored by the authz table, Critical with full context and a path). The hypothesis-stays-Low property is unchanged, and a second copy is in `test_risk_v2.py`.
- `test_authz_db.py`: the test is renamed `…_and_bola_stays_low`. The inconsistent DELETE is now pinned at 31.5 (Medium: E 0.6, X unknown 0.5, I 0.575); BOLA stays Low.
- `test_risks_db.py`, `test_runtime_eol_db.py`: the pinned model version is now `v2.1`.

## Evaluation (X0)
I re-ran X0 because the model changed. I diffed it against `BASELINE.md` and against the start-of-day run, with log lines stripped. `BASELINE.md` was not touched.
- Against the start of the day (`v1-ctx.4`): **the only difference is the model line** (`v1-ctx.4` → `v2.1`) (VERIFIED).
- Against `BASELINE.md`: the same differences as on days 1–4:
  - the model line;
  - the line saying authz findings are outside the set;
  - C's AWS key at rank 6 instead of 1 in the M4 top 10 (X1's intended change).
  **The pooled table is identical** (VERIFIED).
- Why nothing moved: the X0 scenarios have no image, tier-1 taint or EOL findings, and authz findings are outside the set (F-4-1). So v2's tables are not yet tested against labelled data beyond F–H. No weight was tuned to X0.

## Self-attack
1. **Quadratic image context (fixed, `c6e0649`).** Each image finding scanned every derived service and image: 1.89 s for 10,000 findings with 200 services × 20 images. It is now one index per scan, plus a test (< 0.5 s).
2. **Untrusted EOL dates.**
   - A missing, non-string or malformed `eol_date`/`data_as_of` gives "unknown" (E 0.5); there is a test per case.
   - A date after the snapshot (negative age) is also treated as unknown, not as "recent" (0.4). Otherwise a corrected feed could lower a score.
3. **Taint under merge.** After a merge the representative is usually the generic rule. The taint input is read from the members (test), choosing HIGH over MEDIUM, and a CWE outside the five classes adds nothing (test).
4. **Monotonicity and reduction under random inputs.** Three new Hypothesis properties, the reduction properties, and the unchanged §14.7 ladder test.
5. **Justified, not fixed:**
   - F-5-1 (co-located I* inheritance; flagged with measured options);
   - for a high-severity, HIGH-confidence SAST hit, the CWE-22/502/918 taint rows add nothing, because the SAST row (0.8) is already higher. That is intended by the max (ADR-0024).

## UNVERIFIED (needs the owner's machine)
- Nothing new needs Docker, scanners or Ollama.
- The taint table only matters once tier 1 is on (F-2-1) and has run with the real Semgrep (L-4).
- The image context was tested with the recorded image fixtures, not a live `trivy image` (L-3).
- L-7 (`make dev`, click through) now also covers the new factor sources in the finding detail.

## New flags and local tasks
- **F-5-1 (OPEN):** effective impact for co-located findings. Recommendation (b): only findings whose own support is at least inferred, and only foothold categories.
- No new local tasks.

## For Day 6 (Sat 31 Oct)
- **Catch-up:** nothing of days 1–5 is open and unflagged. X4 part 2 stays parked unless F-3-1 is answered with `GO` and fixtures; then it comes first.
- **X6 is built.** Day 6 is the **integration pass**:
  - run every suite;
  - fix cross-phase breakage;
  - the six-day summary in `HANDOFF.md` and `todo1150.md`;
  - `docs/auto/FINAL_REPORT.md` with every open flag and local task.
- If F-5-1 or F-4-1 is answered by then, its resume steps are small and come first.
