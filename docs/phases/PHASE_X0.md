# PHASE X0: baseline dataset and metrics (expansion plan)

**Status:** done (2026-10-25). Plan: `docs/proposals/EXPANSION_A-D.md` §4 (X0) and §7. No ADR, no migration. Output: `docs/evaluation/BASELINE.md`.

## A. Objective
Expansion plan §7 definition of done:
- unit tests for every metric against hand-computed values;
- the generator is deterministic (a second run is byte-identical);
- `BASELINE.md` committed with the generator commit and the numbers;
- lint, unit and db suites green, output pasted here.

## B. Why
Every later expansion claim (X1–X8) is a claim that the ranking got better. Without numbers frozen before the work starts, "better" cannot be checked, and the scenarios could quietly be fitted to the model. So the dataset and labels are fixed first, then measured, and nothing is tuned.

## C. Architecture
```
scenarios.py  (templates + label rules, rubric §26.3)          ← labels written first (bd4e43c)
   │ build(dest)  (never committed: C holds a fake AWS key)
   ▼
record.py     pinned scanner images, once  ──▶ evaluation/fixtures/<scenario>/<scanner>/<ver>/report.json
              EPSS/KEV, once               ──▶ evaluation/fixtures/intel.json
   ▼
run.py        test DB only (name must end in _test): migrate, truncate, seed intel as fresh,
              run_pipeline_inline per scenario with FixtureRunner(fixture=…) + LocalDirCloner(build=…)
              ─▶ Row per finding: score, priority, CVSS base, EPSS, facts, label
   ▼
baselines.py  M1 CVSS-only · M2 CVSS×E · M4 RiskGraph        metrics.py  P@K R@K nDCG@K AP E90, bootstrap
   ▼
report.py     docs/evaluation/BASELINE.md + baseline_findings.csv    (make eval-baseline)
```

## D. Components
| Component | File |
|---|---|
| Scenarios A–E and label rules | `backend/evaluation/scenarios.py` (X0 part 1) |
| Recorder | `backend/evaluation/record.py` (X0 part 1) |
| Offline replay through the real pipeline | `backend/evaluation/run.py` |
| Metrics and bootstrap CIs | `backend/evaluation/metrics.py` |
| Ranking methods M1, M2, M4 | `backend/evaluation/baselines.py` |
| Report writer | `backend/evaluation/report.py` |
| Test doubles, now parameterised | `backend/tests/pipeline_support.py` (`FixtureRunner.fixture`, `LocalDirCloner.build`) |
| `epss_to_e` exported for M2 | `backend/riskgraph/modules/risk/__init__.py` |
| Make target | `make eval-baseline` |

## E. Technical decisions
- **Primary result is the pooled ranking.** All 59 findings ranked as one list, as an analyst triaging several repositories sees them. Each scenario is too small on its own; per scenario, all three methods tie (the report detects this and says so).
- **M4 ranks like the product:** `priority_rank`, then `score`, so the number measures what a user sees, including priority overrides such as live credentials.
- **M2 for findings without EPSS** (no CVE, or a CVE EPSS has not scored): E = 0.5, the transform's value at EPSS 1 %. This means "unknown". `epss_to_e` is shared with RiskGraph by design (blueprint §26.6), so the comparison isolates context.
- **Ties break on `findings.merge_key`**, not "scanner order" (blueprint §26.2): equally neutral, and stable across runs.
- **The run refuses any database whose name does not end in `_test`**, because it truncates. It restores the environment it changes, so importing it in tests leaks no settings.
- **Intel is seeded as fresh** (`epss_fetched_at`/`kev_checked_at` = now) with no outbound client, so the pipeline never calls a feed.
- **Bootstrap:** 2,000 resamples over findings, seed 20261025, percentile interval with numpy's linear interpolation. The same draws are used for every method (paired).

### Deviations from the plan
- `evaluation/` lives in `backend/`, not a top-level `datasets/`, so it shares the venv, ruff, mypy and pytest. There is no `datasets/build.py`: `Scenario.build` generates each repository from its template at run time and is never committed, because C holds a fake key.
- Labels are rules in `scenarios.py`, not a `ground_truth/labels.csv` per repository. `docs/evaluation/baseline_findings.csv` is the generated per-finding label file, with fingerprint, label and rationale for each finding.
- The paired permutation test (M4 against M2 across scenarios) is not in X0's definition of done; it belongs to X8.

## G. Database
No schema change. The run uses the test database (`riskgraph_test`) and empties `repositories` (cascade) and `vulnerabilities` first.

## H. API
None.

## L. Configuration
`make eval-baseline` reads the postgres and redis ports from `.env`, like `make test-db`. It needs `make test-services` (or the dev stack, which binds the same ports) and no network or Docker.

## M. Testing
- **`test_evaluation.py` (16, unit):**
  - P@K, R@K, nDCG@K, AP and E90 against hand-computed values (including P@K past the end of the list, nDCG = 0 versus undefined, and E90 at an exact 90 % boundary);
  - percentile interpolation against numpy's values; bootstrap seeding and undefined draws;
  - M1 CVSS, severity-equivalent and tie order; M2 EPSS transform and neutral E; M4 priority-first;
  - every scenario builds byte-identically twice; no recorded fixture holds the fake key.
- **`test_evaluation_db.py` (1, db):** B and C are replayed. Every finding is labelled by a rule (none defaulted), secrets are important and Critical/High, and the PyYAML CVEs carry the frozen EPSS. A second run gives identical rows, and the environment is restored afterwards.

## O. Validation
```
make lint                → ruff: All checks passed! · 193 files already formatted
                           mypy: Success: no issues found in 186 source files · eslint, tsc clean
make test                → 322 passed, 63 deselected
make test-db             → 57 passed, 2 skipped (e2e: no host scanners)
make eval-baseline ×2    → BASELINE.md and baseline_findings.csv byte-identical (cmp)
```

Label check before ranking (todo step 2): all 59 findings match a rule written in `bd4e43c`, and none are defaulted. B's `yaml.load` is category `deserialization`, and E's SSRF is `ssrf`, from two Semgrep rules. No rule was changed. The check printed scores next to labels, so it was not blind to scores; nothing was adjusted after it.

Baseline (pooled, 59 findings, 7 important; 95 % CI):

| Method | P@5 | P@10 | nDCG@10 | AP | E90 |
|---|---|---|---|---|---|
| M1 CVSS-only | 0.200 [0.000, 0.600] | 0.300 [0.000, 0.600] | 0.293 [0.000, 0.606] | 0.273 | 26 |
| M2 CVSS+EPSS | 0.000 [0.000, 0.200] | 0.200 [0.000, 0.400] | 0.162 [0.000, 0.341] | 0.152 | 37 |
| M4 RiskGraph `v1-ctx.2` | 1.000 [0.400, 1.000] | 0.700 [0.300, 1.000] | 0.991 [0.855, 1.000] | 0.968 | 9 |

## Q. Known limits
- **Construct bias:** the scenarios and labels were written by the model's author. RiskGraph's large lead is expected on scenarios built to show context, and is not evidence of real-world performance. Blueprint §26.6 and the X8 real-app study address this.
- **Small and sparse:** 59 findings with 11.9 % positives, against the blueprint's aim of 60–120 findings and 15–25 %. Scenario A supplies 44 of the 52 negatives (Django CVEs), which is what drives M1 and M2 down. More scenarios (F–H in plan §6) arrive in X3 and X8.
- E's SSRF counts twice (two Semgrep rules on one line, both important).
- No CVE here is in KEV, so KEV plays no part in any method.
- The intervals are wide: with 7 positives, one finding moves P@5 by 0.2.
