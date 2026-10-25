# PHASE X1: evidence and assurance contracts (expansion plan)

**Status:** done (2026-10-25). Decision: ADR-0017. Migration `f3a9c1d7b2e8`. Plan: `docs/proposals/EXPANSION_A-D.md` §4 (X1), §2.4, §3.D.

## A. Objective
X1 row of the plan:
- ADR-0017;
- `modules/evidence`;
- one migration (`evidence`, link tables, `graph_edges.assurance`, `source_type` values);
- retrofit the current edges with assurance (credential-family edges become hypotheses; the Kubernetes name map becomes inferred);
- the builder invariant;
- `evidence[]` on the finding detail API.

Exit criteria:
- the migration goes up, down and up cleanly, and `alembic check` reports no drift;
- an invariant test shows that an edge without evidence raises;
- existing paths are unchanged except the credential-family ones, which are now hypotheses;
- their I\* contribution drops, as a documented, intended score change.

## B. Why
Before X1, "the manifest declares it" and "a name happens to match" were the same kind of edge. A secret raised its own score through a path whose first link only matched a family name. Every later phase (taint, authorization, images, the assured graph) needs to say what a claim rests on and how well. If that isn't fixed first, each phase invents its own format.

## C. Architecture
```
merged findings ──▶ finding_evidence()  one *_match per scanner rule hit (verified, RawRef → run)
                    + reachability      L3 verified · L0–L2 inferred · unknown/n_a: none
                         │ ids
                         ▼
manifest ───────▶ graph builder ──▶ Relationship(edge, assurance, evidence_ids, findings)
                  declarations as evidence      refuses an edge without evidence;
                                                attack edges also need finding evidence
                         ▼
                  paths (unchanged search) ─▶ path assurance = min(edges)
                         ▼
                  I* only from paths ≥ inferred; hypothesis paths listed, never scored
                         ▼
storage: evidence (scan, id) ◀─ finding_evidence, edge_evidence;  graph_edges.assurance
API: /findings/{id} evidence[] · attack-paths assurance · /graph edges assurance + evidence_ids
P12: path assurance in the EvidencePack; prompt explain.2 and the template call hypotheses unproven
```

## D. Components
| Component | File |
|---|---|
| Contract: `Assurance`, `Evidence`, `RawRef`, `FlowStep`, `Relationship`, `make_evidence`, `min_assurance` | `backend/riskgraph/modules/evidence/contract.py` |
| Models: `EvidenceRow`, `FindingEvidence`, `EdgeEvidence` | `modules/evidence/models.py` |
| Persist and read: `persist_evidence`, `link_finding`, `link_edge`, `evidence_for_finding`, `evidence_for_edges`, `clear` | `modules/evidence/service.py` |
| A finding's own evidence (pure) | `modules/scans/finding_evidence.py` |
| Builder: evidence, assurance, invariant, I\* gate, `exploit_assurance` | `modules/graph/attack.py` |
| Edge persistence and links, `path_assurance` | `modules/graph/service.py` |
| Pipeline wiring | `modules/scans/pipeline.py` (`analyze`) |
| API | `modules/findings/{schemas,router}.py`, `modules/graph/router.py` |
| Explanations | `modules/explain/{evidence,service,prompt,template}.py` |
| New source types, kept by normalization | `shared/vocabulary.py`, `normalization/{fingerprint,merge}.py` |
| Migration | `backend/alembic/versions/20261025_1400_evidence_assurance.py` |

## E. Technical decisions
See ADR-0017. In short:
- **Three levels, ordered.** Confidence grades evidence within a level and is never multiplied.
- **EXPLOIT takes the tier of the finding that sets `p`**, not the best tier among its findings. This is conservative and keeps every path's `p`, so paths are unchanged.
- **Attack edges need finding evidence**, not just any evidence. An EXPLOIT edge always carries the exposure declaration, so "non-empty evidence" alone could never fail.
- **Two fields added to the plan's contract.** `Evidence.facts` is bounded and display-safe, and is needed to say what was declared or found. `Relationship.findings` is needed for I\* and the API.
- **`RawRef` points at the whole report** (`""`). Element pointers need per-parser index tracking; that is a follow-up.
- **The SQL backfill applies the builder's own rules**, so a pre-X1 edge gets the assurance a fresh build would give it. A db test proves the two agree.
- **P12 explanations carry path assurance.** Without it, the model could narrate "the key authenticates as app-role" as fact. The prompt version is bumped to `explain.2`, so cached explanations regenerate.

### Deviations and notes
- **"Kubernetes name map → inferred": nothing to retrofit.** The graph is built from the manifest only (G3). Kubernetes facts reach finding factors, not edges. The rule is written into ADR-0017 for X3, which adds those edges.
- **No credential link can be verified yet.** The plan's edge table mentions a "manifest `credentials:` link (verified)", but the manifest can only list families. Adding a field that ties a specific secret to an identity is a manifest schema change and is left for X3.
- **Hypothesis EXPLOIT edges (L1 or unknown reachability) also stop raising I\*.** The plan's X1 row only names the credential edges, but this is the same rule (plan §3.D: "unknown reachability gives hypothesis"). On the X0 scenarios it changes nothing.
- **The ADR index was missing 0014–0016;** they are added along with 0017.

## G. Database
Migration `f3a9c1d7b2e8`, reviewed by hand:
- `evidence`: PK (`scan_job_id`, `id`); `producer`, `kind`; `assurance` and `confidence` with CHECKs; JSONB `payload`; `raw_run_id` (FK to scanner_runs, cascade); `raw_pointer`; `observed_at`; `data_as_of`.
- `finding_evidence` (PK scan, finding, evidence; index on `finding_id`) and `edge_evidence` (PK edge, evidence). Both use a composite FK to `evidence`, with cascade.
- `graph_edges.assurance`: NOT NULL plus a CHECK, backfilled by the ADR-0017 rules.
- The `findings.source_type` CHECK adds `runtime` and `authz`. The downgrade refuses if such rows exist.

## H. API
| Method & path | Change |
|---|---|
| `GET /findings/{id}?scan_id=` | `evidence[]`: id, producer, kind, assurance, confidence, locations, facts, steps, `raw_run_id`, `raw_pointer`, `observed_at`, `data_as_of` (strongest first) |
| `GET /scans/{id}/attack-paths` (and `attack_paths` on finding detail) | `assurance` per path (`null` for paths stored before X1) |
| `GET /scans/{id}/graph`, `GET /scans/{id}/graph/reach` | `assurance` and `evidence_ids` per edge |

All changes are additive, so the frontend is unchanged. Assurance badges are X7.

## L. Configuration
None.

## M. Testing
- **`test_evidence.py` (8, unit):**
  - the id is stable across time and key order and changes with the claim;
  - `RawRef` does not change the id;
  - facts are validated and clipped; steps are capped;
  - confidence and kind are validated;
  - assurance ordering and `min_assurance`;
  - a `Relationship` needs evidence.
- **`test_graph_assurance.py` (14, unit):**
  - assurance for each edge kind; the unknown identity is inferred; the EXPLOIT tier mapping (5 cases);
  - every edge's evidence exists and declarations point at the manifest file;
  - attack edges carry their findings' evidence, and an L0 finding adds none;
  - the builder refuses EXPLOIT and CONTAINS_SECRET without finding evidence;
  - path assurance is the minimum, and the summary counts paths by assurance;
  - a hypothesis path is listed but `effective == {}`; an L3 path still raises I\*;
  - evidence ids are stable across runs.
- **`test_finding_evidence.py` (6, unit):**
  - a scanner match is verified and linked to its run;
  - one record per rule hit, with Semgrep's own confidence;
  - reachability evidence follows the tier, with none for unknown or n/a;
  - odd verdict details are dropped, not fatal;
  - a secret's evidence holds only the rule, severity and family.
- **`test_evidence_db.py` (5, db):**
  - every stored edge has an assurance level and at least one evidence link, every finding has evidence, and Trivy matches point at the Trivy run;
  - hypothesis paths exist, and every stored `I*` factor names a path of at least `inferred`;
  - the API serves evidence, path assurance and edge evidence ids;
  - a redelivered `analyze` replaces evidence instead of adding to it;
  - a real scan downgraded and upgraded again gets the same assurance from the SQL backfill as from the builder.
- **Changed tests, with the reason in each:**
  - `test_attack_paths.py`: the inputs carry evidence ids. Finding 0's I\* is now 0.9·0.3/0.6 instead of 0.9·0.54/0.6, because the path through the AWS key is a hypothesis. The key has no I\* at all. Finding 2 is unchanged.
  - `test_graph_invariants.py`: edges are `Relationship` objects, and the message is "has no finding evidence".
  - `test_merge.py`: runtime and authz findings are kept.
  - `test_explain.py`: `keep_alive`, the socket, and a hypothesis path is called unproven.

## O. Validation
```
make lint                → ruff: All checks passed! · 203 files already formatted
                           mypy: Success: no issues found in 195 source files · eslint, tsc clean
make test                → 358 passed
make test-db             → 62 passed, 2 skipped (e2e: no host scanners)
alembic upgrade e1b7d3a9c2f4 → head → downgrade -1 → upgrade head; alembic check
                         → f3a9c1d7b2e8 (head) · No new upgrade operations detected.
make test-llm (qwen3:4b, prompt explain.2) → 2 passed
  first: status=validated attempts=1 latency_ms=18215 · unreachable: fallback (template)
```

Effect on the X0 scenarios (evaluation re-run into a scratch file; `BASELINE.md` stays frozen as the pre-expansion reference):
- 1 of 59 findings changes: `C_exposed_credential`, Gitleaks `aws-access-token`, 99.61 → 62.26. Its priority stays **critical**, set by the live-credential override.
- The pooled P@K, nDCG@K, AP and E90 for all three methods are identical to `BASELINE.md`.

## Q. Known limits
- Credentials can only be linked as hypotheses until the manifest can name a specific secret (X3).
- Raw pointers are whole-report pointers.
- Edges stored before X1 have no evidence links (assurance is backfilled).
- Paths are not yet grouped by assurance in the API or UI (X3/X7). `paths_by_assurance` is in the scan summary.
- `runtime` and `authz` findings would be scored by the current model's fallthrough branch; no producer emits them before X2 and X5, and their scoring is X6.
