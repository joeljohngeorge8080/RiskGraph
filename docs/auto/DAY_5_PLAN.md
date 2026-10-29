# Day 5 plan (Fri 2026-10-30): X6, risk v2

## The task
SCHEDULE day 5 is X5 part 2 (authorization findings). Day 4 already built it to its exit
criteria (DAY_4_REPORT: inconsistency 4/4, zero BOLA above hypothesis, inventory recall
unchanged), so by the schedule's order today's work is **X6, risk v2** (SCHEDULE day 6).
Day 6 then does whatever of X6 is left, plus the integration pass and `FINAL_REPORT.md`.

Catch-up (RUNBOOK §0.4): day 4 is `COMPLETE`; no earlier step is open and unflagged
(VERIFIED: DAY_4_REPORT, FLAGS.md). F-1-1, F-1-2, F-2-1, F-3-1, F-4-1 and F-4-2 are all
`OPEN`, so X4 part 2 stays parked and nothing below builds on any of them.

Start state (VERIFIED): the X0 replay at `484f686` differs from `BASELINE.md` only by the
differences recorded on days 1–4 (model line, the `OUTSIDE_X0` line, C's AWS key at rank 6
in the M4 top 10); the pooled table is identical. The X0 scenarios have no runtime, image
or tier-1 taint findings, and authz findings are outside the X0 set.

### Acceptance (plan X6 row, §6; SCHEDULE day 6)
- Factor tables for: runtime EOL (replacing the interim ones), container OS packages
  (R = 0.5, "not assessable"), taint (E by CWE and confidence), authz (E for inferred
  unguarded; hypotheses never above Low).
- Model `v2` with the **reduction property kept**: with the new inputs absent, v2 scores
  equal v1-ctx.3 on every existing test (tested, plus a property test).
- Scenarios F–H as fixtures: F (SSRF → metadata → identity), G (public image CVE on an
  internet service → sink), H (co-located findings with no relationship: **0 paths**).
  Scenario ordering for the new cases matches the labels (written below, before any run).
- Monotonicity (Hypothesis) still holds, extended to the new inputs.
- `MODEL_VERSION` bumped; an ADR for the model; X0 re-run and every change reported
  against `BASELINE.md`. **No weight is tuned to the X0 numbers** (plan §8).

### Out of scope today
- A probability for UNGUARDED / BOLA_SUSPECT edges (ADR-0023 left it to X6, but the X6 row
  does not name it; it would create new inferred paths through endpoints). Stays `None`;
  recorded in the ADR as a follow-up.
- Labels for authz findings in the evaluation (F-4-1, OPEN): no scenario with authz labels.
- Scenario G's database end: data stores from Compose are F-1-1 (OPEN). G is built with
  the sink the derived graph already has (a Kubernetes ServiceAccount bound to
  `cluster-admin`), and the DB end is recorded as waiting on F-1-1.
- Integration pass and `FINAL_REPORT.md` (day 6).

## Labels for F–H (written before any scoring run; not changed afterwards)
Pooled across F, G, H: every `important` finding must rank above every `not important` one
by v2 score; F and G each yield at least one path of at least inferred assurance through
their important finding; H yields **0 paths**.

| Scenario | Finding | Label |
|---|---|---|
| F (manifest: `api` internet, no auth, runs as `api-role` (admin) which can access `instance-metadata` (credentials)) | F1 tier-1 taint SSRF, CWE-918, in `api`, L3 | important |
| | F2 generic SAST `crypto` (weak hash), medium, in `api`, L2 | not important |
| | F3 SCA CVE, EPSS 0.001, CVSS impact 3.6, in `api`, L1 | not important |
| G (Kubernetes only: Deployment `web` behind a LoadBalancer, image `ghcr.io/acme/web:1`, ServiceAccount bound to `cluster-admin`) | G1 image OS package CVE, critical, KEV, EPSS 0.9, CVSS impact 5.9 | important |
| | G2 image OS package CVE, medium, EPSS 0.0005, CVSS impact 3.6, not KEV | not important |
| | G3 base OS end-of-life (runtime, no date) | not important |
| H (manifest: `batch` isolated, runs as `batch-role` (admin) with access to `orders-db`) | H1 SAST SQLi high, L2; H2 SCA CVE high, EPSS 0.02, L2; H3 IaC hygiene | not important |

## Files read and nearest analogs
- `docs/auto/{RUNBOOK,SCHEDULE,FLAGS,LOCAL_TASKS}.md`, `DAY_4_REPORT.md`, `HANDOFF.md`,
  `todo1150.md`; `EXPANSION_A-D.md` §4 (X6 row), §6, §8; ADR-0023 (authz interim score).
- `modules/risk/{model,tables,service}.py`: the tables get v2 rows; `model.py`'s
  `_exploitability` / `_reachability_factor` are the analogs for each new factor source.
- `tests/test_risk_model.py`, `tests/test_risk_scenarios.py` (A–E, monotonicity, reduction):
  analogs for the new unit and property tests.
- `tests/test_attack_paths.py` (scenario E) and `tests/test_topology_graph.py` (Kubernetes
  topology): analogs for F and G; `analyze()` is called the way the pipeline calls it.
- `modules/scans/pipeline.py` (pass 1 / pass 2 scoring), `modules/runtime/eol.py` (EOL
  attrs), `modules/scanners/semgrep/parser.py` (tier-1 `analysis` attr),
  `modules/normalization/merge.py` (a tier-1 hit can merge under a generic representative).

## Steps
1. **v2 factor tables and model** (`risk/tables.py`, `risk/model.py`). New `ScoreInput`
   fields, all defaulting to "absent": `image_package`, `taint_analysis` + `cwe_ids`,
   `eol_age_days` + `eol_kind`. Tables:
   - container OS / image packages: R = 0.5, source `not_assessable`;
   - taint: E = max(the SAST E, `E_TAINT[cwe]`) for a tier-1 (inferred) flow, so a traced
     flow never lowers E;
   - runtime EOL: E by time past end-of-life (unknown date = the interim 0.5), T 0.6;
   - authz: `E_AUTHZ_INFERRED` by severity for inferred findings, below the SAST row (the
     guard catalogue can miss a custom guard), no interim cap; hypotheses keep the Low
     ceiling.
   Tests: one unit test per table; reduction property (inputs without the new fields score
   with v1 factor sources only and by the v1 formula); monotonicity extended to taint,
   EOL age and authz assurance; existing A–E tests unchanged.
2. **Wiring** (`risk/service.py::input_for`): image flag from `package.image`, taint from
   any merged member with `analysis` (the representative may be the generic hit), CWE ids
   from the merged finding, EOL age from `eol_date` and `data_as_of` (never the wall clock,
   so a replay is deterministic). Tests: unit tests on `input_for`; db tests pin the new
   model version; the kitchen sink's authz finding scores are checked and explained.
3. **Scenarios F–H** (`tests/test_risk_scenarios_v2.py`): score → graph → rescore, as the
   pipeline does; the label check above; H has 0 paths; G non-KEV is a hypothesis path that
   changes no score.
4. **ADR-0024 and `PHASE_X6.md`**, X0 re-run diffed against `BASELINE.md`.
5. **Test stage** (lint, types, unit, db, perf, migration round trip, self-attack) and the
   report, handoff, todo.

## Risks and decisions
- The numbers in the new tables are not given by the plan (only R = 0.5 is). They are set
  from the existing tables' reasoning and written down with that reasoning in ADR-0024,
  before the X0 re-run; they are not adjusted afterwards. The schedule asks for "ADR 00NN
  for the model", so this is a detail the plan leaves to the ADR, not an owner's choice.
- Removing the authz interim cap moves the product ranking of kitchen-sink authz findings
  (not the X0 table: authz is outside it until F-4-1). This is the decision ADR-0023 left to
  X6, and the X6 row names it.
- Image packages now get R = 0.5 instead of the unknown 0.6: their scores drop slightly.
  The plan names this value.
