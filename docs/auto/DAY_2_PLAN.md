# Day 2 plan (Tue 2026-10-27): X3 part 2 + X4 part 1

Start state: branch `extended_phase_auto` at `10f3eb8`, level with origin. Baseline before any edit (VERIFIED): 421 unit tests passed. Day 1 is `COMPLETE`, so there is nothing to catch up on. Flags F-1-1 and F-1-2 are still `OPEN`. Nothing today depends on them: no data stores from Compose, no CAN_ACCESS from RBAC.

## Read
- Run book files: `CLAUDE.md`, `HANDOFF.md` (top), `todo1150.md`, `docs/auto/{RUNBOOK,SCHEDULE,FLAGS,LOCAL_TASKS,DAY_1_REPORT}.md`.
- Plan `EXPANSION_A-D.md`: §3.A, §3.D, the §4 rows X3 and X4, §6, §7, §8.
- ADR-0017 and ADR-0019.
- Code:
  - `graph/{attack,service,router,__init__,models}.py`, `findings/{router,schemas}.py`;
  - `context/manifest.py`, `scans/pipeline.py` (graph inputs), `scans/finding_evidence.py`;
  - `normalization/merge.py`, `risk/model.py` (K);
  - `scanners/semgrep/{adapter,parser}.py`, `scanners/redact.py`, `shared/config.py`;
  - `reachability/{callgraph.py,vulnerable_symbols.yaml}` (the analog for a catalogue YAML);
  - `tests/test_graph_perf.py`.

## Found while reading (it decides step 3)
`_search` takes the K = 3 cheapest paths per sink whatever their assurance. A hypothesis path that is cheaper than an inferred one can take one of the three slots, and the inferred path then drops out. Its findings lose their effective impact. So adding a hypothesis-only fact (an AWS key with a family match) can **lower** another finding's score. That breaks the plan's property "hypothesis paths never change any score". Fix: search the graph that holds only edges of at least `inferred` for the paths that set I\*, and search the full graph only to list the hypothesis paths. The property test is written first and must fail on today's code.

## X3 part 2: assurance-aware paths
Acceptance (plan X3 row and SCHEDULE):
- `/attack-paths` is grouped by assurance, then by score;
- every hypothesis path has `missing_evidence[]`;
- a manifest link can make a credential edge verified;
- property tests: hypothesis paths never change a score, and a path's assurance is the minimum over its edges;
- build plus search ≤ 2 s at 5k/20k, 10 sinks, k = 3, including function and endpoint nodes;
- the X0 re-run shows only intended differences.

Out of scope: data stores from Compose (F-1-1), CAN_ACCESS from RBAC (F-1-2), endpoint/function nodes in the builder (X4/X5 produce them).

Analogs: `graph/attack.py::edge` (edge data), `service.path_assurance` (derived from the stored `edges` JSON), `IdentityDecl.credentials` (manifest field with strict validation), `test_graph_assurance.py`, `test_graph_invariants.py` (Hypothesis style).

| # | Step | Proving test |
|---|---|---|
| 1 | Every hypothesis edge records what would prove it (`missing`): AUTHENTICATES_AS, "no manifest link proves this `<family>` key authenticates as `<identity>`"; an image-package EXPLOIT, "reachability of `<package>` in `<image>` is not assessable"; an L1/unknown EXPLOIT, "no import or call chain shows `<finding>` is reached". The text goes into the path's edge JSON, so no migration. API: `missing_evidence: [{source, target, kind, needed}]` on each path (empty unless hypothesis), plus a `group` field. The list is ordered verified → inferred → hypothesis → unknown (pre-X1), then by score. Old fields are unchanged. | unit: each hypothesis kind has its text; db/API: the order and `missing_evidence` |
| 2 | Manifest: optional `owns:` on an identity, a list of `{file, line?, family?}`. It names exact secret locations. A secret at that file (and line and family, when given) gets a **verified** AUTHENTICATES_AS. The meaning of `credentials:` is unchanged (a family match stays a hypothesis). One edge per (secret, identity), the verified one when both apply. Strict validation: a relative path, no `..`, no absolute path, a known family, at most 32 entries. ADR-0020 records it. | unit: manifest validation (good and hostile values); a linked key gives a verified path that raises I\*; an unlinked key stays a hypothesis; a link at the wrong line gives no verified edge |
| 3 | Search in two passes (see "Found while reading") | Hypothesis property (random graphs): adding hypothesis-only facts never changes any effective impact; fails before the fix, passes after |
| 4 | Property: a path's assurance = min over its edges; a hypothesis path never appears in `effective` | Hypothesis, random manifests |
| 5 | Perf: build (`analyze` on a 5k-node / 20k-edge manifest graph) plus search ≤ 2 s; the search test gets function and endpoint node kinds and mixed assurance (two passes) | `pytest -m perf` |

## X4 part 1: tier-1 taint rules and the evidence contract
Acceptance (SCHEDULE, day 2):
- catalogue, rule generator and parser are tested;
- correlation with generic Semgrep findings at the same sink;
- the 40-case suite exists as test code;
- recall is **not claimed** (UNVERIFIED until L-4).

Out of scope: Joern (Day 3), cross-file claims, running the real Semgrep.

Analogs: `reachability/vulnerable_symbols.yaml` + `callgraph.load_symbols` (catalogue loading), `semgrep/parser.py`, `finding_evidence._match`, `merge.merge`.

| # | Step | Proving test |
|---|---|---|
| 6 | `scanners/semgrep/taint/catalogue.yaml`: RiskGraph-authored, Apache-2.0. Sources, sinks and sanitizers for Python (Flask, FastAPI, Django request objects) and JavaScript (Express `req.*`), for CWE 89, 78, 22, 502 and 918. A sink pattern marks the tainted argument with `$SINK`. Written from the APIs themselves, nothing from `semgrep-rules`. | unit: the catalogue loads; every class has a source, a sink and a CWE per language; unknown keys are rejected |
| 7 | `taint/generate.py`: catalogue → Semgrep taint-mode rules (`mode: taint`, `pattern-sources`, `pattern-sinks` with `focus-metavariable`, `pattern-sanitizers`, metadata `cwe`, `confidence`, `source: riskgraph`, `license`, `analysis: intraprocedural`). The generated `taint/rules.yaml` is committed. A drift test checks that generating again gives the committed file. A setting `semgrep_taint_rules` (default **off**) adds a second `--config` to the adapter. | unit: valid YAML; one rule per (language, class); ids are unique and prefixed `riskgraph.taint.`; the generated file has no drift; the adapter argv with and without the setting |
| 8 | Taint finding contract. Redaction turns `dataflow_trace` into location-only steps (`riskgraph_taint_steps`: file, line, role; no source text) before snippet keys are dropped. The parser sets `attrs.analysis = intraprocedural` and `attrs.taint_steps` (≤ 50) for `riskgraph.taint.*` rules. The finding evidence for such a member is kind `taint_flow`, assurance `inferred`, with the steps. | unit: a hand-written Semgrep JSON with a dataflow trace → steps in order, no content left after redaction, evidence `taint_flow`/`inferred`; a trace with more than 50 steps is capped; a malformed trace gives no steps and no error |
| 9 | Correlation: a tier-1 hit merges into a generic Semgrep SAST finding at the same file and line whose primary CWE is in the same family (89 ⊇ 564/943; 78 ⊇ 77; 22 ⊇ 23/36/73; 502; 918). It becomes one finding with two occurrences. The generic finding's merge key is kept, so existing fingerprints are unchanged. K counts distinct scanners, so it stays 1 for two Semgrep rules (ADR-0021 records this). | unit: same line, same family → 1 finding with 2 members; a different line → 2; existing merge keys golden-unchanged |
| 10 | The 40-case suite (`evaluation/taint_suite.py`): 5 CWEs × {intraprocedural, cross-function, cross-file, sanitized} × {Python, JS}, generated as code with labels. Plus a scorer: Semgrep JSON + labels → recall and precision per variant. `python -m evaluation.taint_suite <dir>` writes the cases for L-4. | unit: 40 cases, 20 per language, every CWE × variant once; the scorer on a hand-written result matches hand-computed numbers |

## Close
- Lint, types, unit, db, perf.
- Migrations: no new migration is planned. The up/down/up round trip and `alembic check` still run.
- X0 evaluation re-run, compared with `BASELINE.md`. Expected: identical. No scenario uses `owns:`, the taint setting is off, and the two-pass search only changes output where crowding occurred. CONFIDENT, to be checked.
- Self-attack.
- Write `DAY_2_REPORT.md`, `PHASE_X3.md` (part 2), `PHASE_X4.md` (part 1), ADR-0020 (credential links, missing evidence, two-pass search) and ADR-0021 (tier-1 taint catalogue and contract); update HANDOFF, todo1150 and LOCAL_TASKS.

## Risks and decisions
- **Tier 1 is off by default (F-2-1).** The rules cannot be checked against a real Semgrep here. One invalid rule in a `--config` fails the whole Semgrep run, and with it every SAST finding of every scan. The plan puts tier 1 in the default profile. I build it behind a setting that defaults to off and ask the owner to turn it on once L-4 passes. The scanner image also has to carry the rules file (a Dockerfile `COPY`), which is part of L-4.
- The trace shape of Semgrep 1.182 (`taint_source` / `intermediate_vars` / `taint_sink` with `CliLoc`) comes from my memory of the format: BELIEVE. The parser walks any location-shaped dict, so a shape change gives fewer steps, never an error. L-4 checks it on real output.
- `owns:` is additive and optional. Existing manifests validate unchanged, and `credentials:` keeps its meaning, so it needs no flag (RUNBOOK §3 allows additive optional fields the plan names; the plan names this link).
- The two-pass search can add paths, never remove one, and only where a hypothesis path crowded out an inferred one. If the X0 re-run differs, the report explains every row.
