# PHASE X6: risk v2 (expansion plan)

**Status:** built on 2026-10-30 (auto day 5, a day early: X5 part 2 was finished on day 4). The integration pass and the six-day summary are day 6. Decision: ADR-0024. No migration. Plan: `docs/proposals/EXPANSION_A-D.md` §4 (X6 row), §6, §8.

## A. Objective
X6 row of the plan: bring C (images, runtime EOL), A (taint) and B (authorization) into scoring as model `v2`.

Exit criteria, and where they stand:
1. Factor tables for:
   - runtime EOL (replacing the interim ones);
   - container OS packages (R = 0.5, "not assessable");
   - taint (E by CWE and confidence);
   - authz (E for inferred unguarded; hypotheses not above Low).
   **Done** (`risk/tables.py`).
2. All v1 tests still pass when the new inputs are absent (reduction). **Done:** two Hypothesis properties, and every earlier pinned score unchanged.
3. Scenario ordering for the new cases matches the labels. **Done, after one fix** (image context, below). The labels were written before the first run (`DAY_5_PLAN.md`).
4. Monotonicity holds. **Done:** the §14.7 property is unchanged, plus three properties over the new inputs.
5. Scenarios F–H. **Done.** G's sink is the cluster-admin ServiceAccount, not a database (F-1-1).

## B. Why
Before v2, the four new kinds of finding were scored with stand-ins:
- an image CVE as if its reachability were merely unknown, and with no context at all;
- a traced taint flow as the pattern it merged with;
- an EOL runtime flat;
- authorization findings held at Low.

A ranking that treats a traced SQL injection like a grep hit, or a KEV CVE on an internet-facing cluster-admin workload like one with nothing known, misorders exactly the cases the expansion was built to find.

## C. Architecture
```
merged finding ──▶ risk.service.input_for
   package.image ───────────────▶ image_package      ──▶ R = 0.5 not_assessable
   members with analysis=intraprocedural ─▶ taint_cwe/confidence ─▶ E = max(SAST, E_TAINT)
   runtime: data_as_of − eol_date ─▶ eol_age_days    ──▶ E by age
   authz assurance ─────────────▶ E_AUTHZ_INFERRED; hypothesis ─▶ ceiling Low
context: resolver.for_finding(file) ──▶ image? fill_unknown(ctx, topology.image_contexts()[ref])
pass 1 score ──▶ attack graph (exploit_p from v2 E, R) ──▶ pass 2 rescore (I*)
```

## D. Components
| File | What |
|---|---|
| `risk/tables.py` | `MODEL_VERSION = "v2.1"`; `R_NOT_ASSESSABLE`, `E_TAINT`, `E_RUNTIME_EOL_BY_AGE`, `E_AUTHZ_INFERRED` |
| `risk/model.py` | `ScoreInput` fields `image_package`, `taint_cwe`, `taint_confidence`, `eol_age_days`; `_taint_exploitability`, `_eol_exploitability`; the interim authz cap removed, the hypothesis ceiling kept |
| `risk/service.py` | `input_for` reads the new inputs; `_taint` (from members), `_eol_age` (from the feed's dates) |
| `graph/topology.py` | `Topology.image_contexts()` (one index per scan), `fill_unknown` (exported as `graph.fill_image_context`) |
| `scans/pipeline.py` | the topology is built before pass 1; image findings get the image context |

## E. Technical decisions
All in ADR-0024, with the reasoning for each number. In short:
- E = max with the taint row: a flow never lowers E;
- EOL age from the feed snapshot, not the clock;
- authz 0.1 under the SAST row (0.05 for Low), because the guard catalogue can miss a custom guard;
- image context is the worst case over the services running the image, and only fills unknown factors.

## G. Database
No change. `risk_scores.model_version` reads `v2.1`.

## H. API
No new field. Factor provenance shows the new sources: `not_assessable`, `taint_tier1`, `runtime_eol` (with `eol_age_days`), `authz`, `topology`.

## L. Configuration
None.

## M. Testing
- `tests/test_risk_v2.py` (30 tests):
  - a test per table;
  - the reduction properties (500 + 300 examples);
  - monotonicity over EOL age, taint confidence and authz assurance;
  - `input_for` wiring: a taint hit under a generic representative, a related CWE mapped to its class, EOL age from the snapshot, a malformed date treated as unknown, image packages.
- `tests/test_risk_scenarios_v2.py` (6): F, G (with and without KEV), H (0 paths), the label ordering, and reduction on the scenarios.
- `tests/test_topology_graph.py` (+2): the image context (worst case; the file's own context wins) and a linear-time guard.
- `tests/test_image_scan_db.py` (+1): through the real pipeline, an image package has R `not_assessable` and the exposure of the Compose service that publishes it.
- `tests/test_risk_model.py`: the interim authz test is replaced by the v2 one; `tests/test_authz_db.py` pins the inconsistent DELETE at 31.5 (Medium), and BOLA stays Low.

## O. Validation
- Lint and types clean; 648 unit; 84 db, 2 skipped (real scanners); perf 4 passed.
- Migration round trip and `alembic check` clean (no new migration).
- X0 re-run: identical to the day-4 run except for the model line (`v1-ctx.4` → `v2.1`). The pooled table equals `BASELINE.md`.

## Q. Known limits
- **F-5-1:** co-located findings inherit the path's effective impact (F's weak hash is Critical). It predates v2; the options and their measured X0 effect are in the flag.
- The taint and EOL numbers are reasoned, not measured (L-4 is the first measurement of tier 1).
- Inferred authz findings now compete with scanner findings. They have not been checked against labels yet (F-4-1).
- UNGUARDED and BOLA_SUSPECT edges still have no probability.
- G's database end waits on F-1-1.

## R. Integration pass (day 6, 2026-10-31)
Every suite was run across the six days' work (`DAY_6_REPORT.md`). Three gaps between phases were fixed, none in scoring:
- the frontend's copy of the vocabulary (source types `runtime`/`authz`, producers `syft`/`riskgraph`, `CANCELLED` as terminal), with `tests/test_frontend_vocabulary.py` comparing every mirrored union with its enum;
- the template explanation's remediation steps for runtime and authz findings;
- the example manifest's description of credential families, and an `owns:` example.

Every migration now round-trips down to base and back. The X0 run is unchanged. The six-day summary and everything still open: `docs/auto/FINAL_REPORT.md`.
