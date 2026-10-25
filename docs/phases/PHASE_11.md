# PHASE 11: Contextual risk engine (scenarios, properties, GET /risks)

**Status:** done (2026-10-25). Abbreviated chapter. Model `v1-ctx.2` is unchanged: no score moves in this phase. Decisions: ADR-0010/0011/0012/0013 (model versions); blueprint §14.

## A. Objective
Roadmap P11 definition of done:
- Scenario A–E fixture scores match §14.6;
- monotonicity property tests;
- a context-free reduction test;
- `GET /risks`.

## B. Built
- **`GET /risks?scan_id=`** (or `?repository_id=` for its latest finished scan; exactly one, else 422):
  - the scan's scores, highest first, ties by priority and then finding id (stable);
  - `rank`, `priority=` filter (repeatable), `limit` ≤ 200 and `offset`;
  - false positives and accepted risks are left out unless `include_excluded=true` (§14.5: "excluded from ranking, kept in audit"). `wont_fix` stays ranked, because §14.5 does not exclude it.
- **`GET /risks/{finding_id}?scan_id=`**: the score, factors and overrides, plus `reasons[]`, the non-default factors that moved the score off the §14.3 baseline (for example `X=internet_noauth (manifest)`, `I* (attack_path)`).
- `findings.router.risk_out` is now the one place that turns a stored score into its API shape; the finding detail and `/risks` both use it.
- Ranking SQL is in `risk/repo.py`. `risk/__init__` does not import it, because findings imports risk.

## M. Testing
- `test_risk_scenarios.py` (10 cases):
  - **A–E from §14.6** with E, L, I, score and priority each asserted. Scores are within ±0.1: the table was hand-computed from rounded intermediates (A: 16.95 against 16.9, from I = 0.5958 against the table's 0.595). B with criticality high gives 74.6.
  - The ordering is C > E > B > D > A; CVSS-only gives A > D > B.
  - **Monotonicity (Hypothesis, 1,000 examples):** raising any one of X, D, P, C, R, EPSS, CVSS impact, KEV or the agreeing-scanner count never lowers the score *or* the priority rank. This includes the KEV floor and the L0 ceiling, with random reachability confidence.
  - **Reduction (Hypothesis, 300 examples):** with no context, the score equals `100·geomean(E, 0.5, 0.6)·mean(T, 0.5, 0.5, 0.5)` exactly and every X/R/D/P/C factor is a default. A context-free secret drops R.
- `test_risks_db.py` (4, db):
  - 29 ranked items with ranks 1–29; the same order through `repository_id`; paging; the priority filter;
  - a false positive leaves the ranking (28) but stays retrievable;
  - a finding on an attack path shows `I*` in its reasons;
  - 422/404 cases.

## O. Validation
```
uv run ruff check . && uv run mypy                         → clean (162 files)
pytest -m "not db and not docker and not e2e and not perf"  → 273 passed
make test-db                                               → 50 passed, 2 skipped
```

## Not done
- Overrides from the manifest (per-finding analyst overrides of factor values): not in the roadmap definition of done. Triage covers the exclusion case.
- Calibration of bands and constants: Phase 17.
