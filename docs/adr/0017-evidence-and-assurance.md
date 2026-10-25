# ADR-0017: One evidence and assurance contract; no edge without evidence

Status: accepted · Date: 2026-10-25 · Implements: expansion phase X1 (`docs/proposals/EXPANSION_A-D.md` §2.4, §3.D) · Amends: ADR-0013 (graph edges and effective impact)

## Context
Gaps G1 and G2 of the expansion plan:
- **G1.** Graph edges had no assurance. "The manifest declares it" and "a name happens to match" were stored the same way. In particular, a secret was linked to every identity whose `credentials:` list names the secret's family. That match says nothing about whether this key belongs to that identity, yet it raised the secret's score through effective impact (I\*).
- **G2.** Evidence was ad-hoc JSONB per factor, edge or reachability row. It had no stable id, no producer version, no pointer into the raw report and no data date.

The later phases (taint flows, authorization, image intelligence, an assured graph) all need one way to say what a claim rests on and how well. The owner approved the expansion plan, including "assurance levels; edge requires evidence; today's credential-family edges become hypotheses, a visible score change" (plan §8, decision 1).

## Decision
**Assurance** has three levels, ordered: `verified` > `inferred` > `hypothesis`.
- **verified:** stated by an artifact we parsed (a manifest declaration, a scanner match, an L3 call chain).
- **inferred:** a documented rule applied to verified facts, with a known gap (import-level reachability, a name match).
- **hypothesis:** a pattern suggests it and no artifact supports it.

Confidence (`high` / `medium` / `low`) grades evidence *within* a level. It is shown, never multiplied into a score.

**Contract** (`riskgraph.modules.evidence`, frozen dataclasses, the fields of plan §2.4 plus two):
- `Evidence(id, producer, kind, assurance, confidence, locations, facts, observed_at, steps, raw, data_as_of)`.
  - `id` = sha256 of the canonical payload (producer, kind, assurance, confidence, locations, facts, steps). Time fields and `raw` are excluded, so re-analysis keeps the id.
  - **Added: `facts`.** Small, display-safe values: JSON scalars and lists of at most 20 strings, at most 24 keys, text clipped at 200 characters. Without it a declaration could not say *what* it declared, and reachability could not say which tier it found. Anything else is rejected by `make_evidence`; the pipeline drops odd reachability details rather than fail.
  - `steps` are capped at 50. `raw = RawRef(scanner_run_id, pointer)`, where `pointer` is RFC 6901 and `""` means the whole report.
  - `kind` is one of: `declaration`, `package_match`, `code_match`, `secret_match`, `misconfig`, `reachability`, plus the plan's later kinds (`taint_flow`, `route`, `auth_guard`, `rbac_binding`, `runtime_version`, `image_package`, `eol`).
- `Relationship(source, target, kind, assurance, evidence_ids, p, findings)`. It refuses empty `evidence_ids`.
  - **Added: `findings`.** The merged-list indices of the findings the edge rests on, needed for I\* and for the API's finding ids.

**Storage** (migration `f3a9c1d7b2e8`):
- `evidence` is scan-scoped, with primary key (scan_job_id, id), JSONB `payload`, `raw_run_id`, `raw_pointer`, `observed_at` and `data_as_of`. `finding_evidence` and `edge_evidence` link to it with a composite foreign key and cascade.
- `graph_edges.assurance` is NOT NULL with a CHECK.
- `findings.source_type` also accepts `runtime` and `authz`. Normalization keeps findings of these types instead of dropping them. Their scoring is still undefined (X6); no producer emits them before X2 and X5.

**Edge rules for the edges that exist today** (the builder is `graph/attack.py`):

| Edge | Evidence | Assurance |
|---|---|---|
| EXPOSES, RUNS_AS, CONNECTS_TO, CAN_ACCESS | manifest declaration | verified |
| RUNS_AS to the synthetic unknown identity | declaration of "no `runs_as`" | inferred |
| CONTAINS_SECRET | the secret finding's evidence (and the service path declaration) | verified |
| AUTHENTICATES_AS | the secret's evidence and the identity's `credentials:` declaration | **hypothesis** (a family match) |
| EXPLOIT | exposure or connection declaration, plus the findings' evidence | the tier of the finding that sets `p`: L3 verified, L2 inferred, L1 or unknown hypothesis |

- EXPLOIT takes its assurance from the finding that sets its probability, not from the best evidence among all its findings. The edge claims "`p`, because of that finding". Choosing the finding by assurance instead would change `p` and therefore every existing path. This choice is conservative and leaves paths unchanged.
- **Builder invariant.** Every edge needs evidence ids. EXPLOIT, AUTHENTICATES_AS and CONTAINS_SECRET also need *finding* evidence; the declaration alone is not enough. Otherwise the builder raises `GraphInvariantError`.
- **Paths.** A path's assurance is the minimum over its edges. Paths are found exactly as before.
- **Effective impact.** I\* is computed only from paths of at least `inferred`. Hypothesis paths are stored and returned with `assurance: "hypothesis"`; they never raise a score.

**Finding evidence** (pipeline):
- One `*_match` record per scanner rule hit (verified), linked to that scanner run's stored report with pointer `""`.
- Plus one `reachability` record when the analyzer made a claim: L3 verified; L0, L1 and L2 inferred; unknown and n/a make no claim and get no record.

**Explanations** (P12): each path in the evidence pack carries its assurance. The system prompt (now `explain.2`) and the template say that a hypothesis path is unproven.

## Consequences
- (+) Every edge, path and finding can show what it rests on, and every stored edge's evidence can be inspected (`GET /scans/{id}/graph`: `assurance` and `evidence_ids` per edge; `GET /findings/{id}`: `evidence[]`; attack paths: `assurance`).
- (−) **Intended score change.** A secret whose only path to a sink goes through a family match loses its I\*. On the X0 scenarios exactly one of 59 findings changes: C's AWS key, 99.61 → 62.26, still Critical because of the live-credential override. The pooled ranking metrics are unchanged. Before X1 the score was higher for a reason no artifact supported.
- (−) Hypothesis EXPLOIT edges (L1 or unknown reachability) also stop raising I\*. That follows the same rule.
- (−) There is no way yet to make a credential link verified: the manifest can only list families. A manifest field that ties a specific secret to an identity is left for X3, the assured graph.
- (−) `RawRef` points at the whole report. Element pointers need each parser to keep indices before it filters; that is a follow-up.
- (−) Edges stored before X1 are backfilled by the same rules, using the reachability tier of each EXPLOIT edge's first finding. They have no `edge_evidence` links, because their evidence was never recorded.

## Rejected
- **Discounting `p` by assurance.** It hides the uncertainty inside a number, so "verified 40" and "hypothesis 40" would look alike (plan §3.D).
- **Dropping hypothesis edges.** That loses "paths to verify", which is useful to a reviewer.
- **A free-form evidence `payload` dict.** The bounded `facts` keep evidence small, safe to display and hashable.
