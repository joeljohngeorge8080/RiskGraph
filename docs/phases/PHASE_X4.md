# PHASE X4: deep code analysis (expansion plan)

**Status:** part 1 (tier-1 taint catalogue, generated Semgrep rules, the taint evidence contract, correlation, the 40-case suite) done on 2026-10-27. **Tier 1 is off by default** until the owner runs it against the real Semgrep (F-2-1, L-4). Part 2 (the Joern adapter) is day 3; it is gated by the owner's spike (L-2). Decision: ADR-0021. No migration. Plan: `docs/proposals/EXPANSION_A-D.md` §3.A, §4 (X4), §6.

## A. Objective
X4 row of the plan: interprocedural taint with evidence. Tier 1 comes from Semgrep CE with RiskGraph's own rules; tier 2 from Joern, if its spike passes. Part 1 is tier 1 and the contract both tiers share.

Day 2 exit criteria, and where they stand:
1. Catalogue, rule generator and parser are tested. **Done.**
2. The taint finding contract: `sast`, `analysis = intraprocedural`, `taint_flow` evidence with ordered steps (≤ 50), assurance `inferred`. **Done.**
3. A tier-1 hit and a generic Semgrep finding at the same sink merge as one finding with two occurrences. **Done**, for CWEs in one family.
4. The 40-case suite as code. **Done**, with a scorer.
5. Recall: **not claimed.** UNVERIFIED until L-4.

## B. Why
The vendored Semgrep rules flag patterns; they do not say that request data reaches the sink, and their licence keeps them separate from RiskGraph's own content (G12). A catalogue RiskGraph owns can feed both tiers, and a trace shows a reviewer the path from source to sink.

## C. Architecture
```
taint_catalogue.yaml ─▶ taint.load_catalogue (strict) ─▶ build_rules ─▶ taint_rules.yaml (committed, drift-tested)
semgrep scan --config <vendored rules> [--config taint_rules.yaml if semgrep_taint_rules_path]
redact:  dataflow_trace ─▶ riskgraph_taint_steps [{file, line, role}] (no code), then snippets dropped
parse:   riskgraph.taint.* ─▶ sast, attrs.analysis = intraprocedural, attrs.taint_steps
merge:   tier-1 group ─▶ joins a generic group at the same (file, line) with a CWE in its family
evidence: taint member ─▶ taint_flow, inferred, steps;  generic member ─▶ code_match, verified
```

## D. Components
| Component | File |
|---|---|
| Catalogue | `backend/riskgraph/modules/scanners/semgrep/taint_catalogue.yaml` |
| Loader and generator | `modules/scanners/semgrep/taint.py` |
| Generated rules | `modules/scanners/semgrep/taint_rules.yaml` |
| Trace redaction and parsing | `modules/scanners/semgrep/parser.py` (`taint_steps`, `keep_taint_steps`, `_stored_steps`), `adapter.py::redact` |
| Setting | `shared/config.py::semgrep_taint_rules_path` (default unset) |
| CWE families, rule prefix | `modules/normalization/families.py` |
| Correlation | `modules/normalization/merge.py::_join_taint_hits` |
| Evidence | `modules/scans/finding_evidence.py::_match` |
| Suite and scorer | `backend/evaluation/taint_suite.py` |

## E. Technical decisions
See ADR-0021.
- Tier 1 is off by default (F-2-1). One rule Semgrep refuses would fail every Semgrep run.
- Tier-1 evidence is `inferred`, never `verified`.
- The generic finding's merge key is kept, so existing finding history is unchanged.
- K stays 1 for two Semgrep rules: it counts scanners.
- Sink patterns mark the tainted argument with `$SINK`, so `cur.execute(q, params)` only matters through `q`.

## G. Database
None. `attrs` and evidence `steps` already exist (ADR-0017).

## H. API
No new fields. A tier-1 finding's `evidence[]` (finding detail) shows a `taint_flow` record with its steps.

## L. Configuration
`RISKGRAPH_SEMGREP_TAINT_RULES_PATH`:
- unset (default): tier 1 off;
- set to the rules file: tier 1 on. For the subprocess runner, that is `backend/riskgraph/modules/scanners/semgrep/taint_rules.yaml`. For the docker runner, the scanner image must contain the file (L-4).

## M. Testing
- `test_taint_tier1.py` (27, unit):
  - catalogue coverage;
  - a broken catalogue is refused (7 cases);
  - rule shape, and every catalogue entry reaches a rule;
  - the committed file has no drift and no anchors;
  - the adapter argv with and without the setting;
  - redaction drops the code and keeps the steps;
  - the parser contract (`CliLoc` and `CliCall` traces), the cap at 50 with the sink kept, malformed traces (5), hostile stored steps;
  - `taint_flow` evidence, inferred;
  - correlation: joined, kept apart, alone, generic keys unchanged;
  - joining at scale: 6,000 findings in 0.04 s, against 0.72 s before the self-attack fix.
- `test_taint_suite.py` (9, unit):
  - 40 cases, every combination once;
  - the classes match the catalogue;
  - one marked sink in the right file;
  - the Python cases parse (`ast`) and the JS cases pass `node --check`;
  - the written layout and labels;
  - the scorer against hand-counted results; a wrong class; empty documents.
- The sample report `tests/fixtures/semgrep_taint/sample.json` is hand-written. The real Semgrep was not run.

## O. Validation
See `docs/auto/DAY_2_REPORT.md`.

## Q. Known limits (part 1)
- No recall or precision numbers (L-4).
- The trace shape is BELIEVE until L-4.
- Sources are matched by name (`request`, `req`).
- JS SQL sinks match any `$DB.query`, so their confidence is `medium`.
- Tier 1 cannot see across functions or files; that is tier 2's job.
