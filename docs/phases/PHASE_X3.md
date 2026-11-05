# PHASE X3: the assured graph (expansion plan)

**Status:** part 1 (a graph from Compose and Kubernetes when there is no manifest) done on 2026-10-26. Part 2 (assurance-grouped paths, `missing_evidence[]`, the manifest credential link, properties, perf) done on 2026-10-27. Decisions: ADR-0019 (part 1), ADR-0020 (part 2). No migration. Plan: `docs/proposals/EXPANSION_A-D.md` §3.D, §4 (X3).

## A. Objective
X3 row of the plan:
- new node kinds (endpoint, function, container_image);
- the edge rules from §3.D;
- Compose/Kubernetes topology into the graph (closes G3);
- assurance-aware search, hypothesis listing, I\* gating.

Exit criteria, and where they stand:
1. A repository with no manifest gets ≥ 1 inferred path from its IaC. **Done for Kubernetes + Compose** (fixture repository, unit and db). NodeGoat itself (Compose only) also needs a data store sink: F-1-1.
2. A random graph built only from co-located findings with no edge rules yields 0 paths. **Done** (Hypothesis, 150 examples), plus "derived services without a sink yield 0 paths".
3. Hypothesis paths never change any score. **Done in part 2** (Hypothesis, 200 random manifests). The property found two ways it was broken: crowding and edge capture (ADR-0020).
4. Perf ≤ 2 s at 5k/20k. **Done in part 2:** build and search together take 0.56 s; the two-pass search over function, endpoint and mixed-assurance edges takes 0.36 s.
5. `/attack-paths` grouped by assurance with `missing_evidence[]` on hypotheses. **Done in part 2.**

## B. Why
Without a manifest the graph was empty, so a Kubernetes repository whose internet-facing workload runs as `cluster-admin` showed no path at all.

## C. Architecture (part 1)
```
IaC assets (P7 extractor) + Dockerfile FROMs ─▶ graph.topology.derive (pure)
    DerivedService: name, code path (Compose build context), exposure claim, images, account, RBAC
attack.analyze(manifest, findings, topology=…)
    manifest has services ─▶ unchanged (topology ignored)
    otherwise ─▶ _derive: service nodes, container_image nodes, identity:sa:<account>
                 EXPOSES (inferred) · EXPLOIT ≤ inferred · RUNS_IMAGE · RUNS_AS · CONTAINS_SECRET
                 evidence: declaration / rbac_binding from the IaC file (riskgraph.iac@1)
```

## D. Components
| Component | File |
|---|---|
| Topology from Compose and Kubernetes | `backend/riskgraph/modules/graph/topology.py` |
| Derived edges, image assurance | `modules/graph/attack.py` (`_derive`, `image_assurance`) |
| `GraphFinding.file`, `.image`, `.kev` | `modules/graph/attack.py` |
| Pipeline: topology, finding file/image/KEV | `modules/scans/pipeline.py` (`_topology`, `_image_of`) |

## E. Technical decisions
See ADR-0019. The ones with a choice in them:
- Only without manifest services. Manifest graphs are identical (test), so the X1 tests and X0 are unchanged.
- An EXPLOIT edge rests on the best-assured finding, then the most exploitable. It is capped at inferred, because its exposure is inferred.
- Image findings are hypotheses unless the advisory is in KEV, and they never join a manifest service's EXPLOIT pool.
- RBAC sets privilege (sink) with `rbac_binding` evidence on RUNS_AS. There is no CAN_ACCESS edge from RBAC (F-1-2).
- Names are cut to 120 characters, so keys fit their 160-character column. Found by the day's self-attack: a 160-character Compose name would have failed the analysis.

### Deviations from the plan, flagged
- F-1-1: no data stores from Compose, so NodeGoat gets no path yet.
- F-1-2: no CAN_ACCESS from RBAC.
- Endpoint nodes: X5. The extractor has entrypoint labels, not routes.

## G. Database
None. Node kinds and edge kinds are free strings (`graph_nodes.kind`, `graph_edges.kind`).

## H. API
No new fields. `GET /scans/{id}/graph` and `/attack-paths` now return derived services, `container_image` nodes, `identity:sa:*` identities and their edges, all with `assurance` and `evidence_ids`.

## M. Testing
- `test_topology_graph.py` (13, unit):
  - topology from a Compose + Kubernetes + Dockerfile fixture;
  - the inferred path and the evidence of every edge;
  - EXPLOIT capped at inferred;
  - image hypothesis versus KEV;
  - best-assured first;
  - no path when unexposed, unreachable or outside every service;
  - secrets in a build context;
  - a manifest ignores the topology;
  - image findings stay out of manifest EXPLOIT;
  - two Hypothesis properties;
  - hostile long names.
- `test_topology_db.py` (2, db): Compose + Kubernetes without a manifest gives an inferred path through the API; no IaC gives no path.
- `test_graph_perf.py` (changed): the synthetic edges get an `assurance` attribute. The search has needed it since X1. Without it the test failed before today's changes too (checked on the start-of-day commit).

## O. Validation
See `docs/auto/DAY_1_REPORT.md`.

## Q. Known limits (part 1)
- Derived exposure is always inferred: no derived path is ever verified.
- A Compose↔Kubernetes name join can join unrelated things.
- The last `FROM` may be a build stage when the final stage is `FROM <stage>`.
- Kubernetes workloads have no code path unless a Compose service of the same name builds one.

---

## Part 2 (2026-10-27): assurance-aware paths

### C. Architecture (part 2)
```
analyze(...) builds edges; a hypothesis edge carries `missing`, and a hypothesis EXPLOIT
edge carries an `Assured` fallback (its best finding of at least inferred)
_search, per sink:
    assured_view(g)  edges ≥ inferred, plus the fallbacks  ─▶ k best ─▶ these set I*
    g (full)                                                ─▶ k best ─▶ its hypotheses are listed
    ranked together by probability; a hypothesis edge's `missing` goes into the path's edge JSON
API /attack-paths: verified, inferred, hypothesis, then pre-X1; each by score; missing_evidence[]
manifest identities[].owns: [{file, line?, family?}] ─▶ verified AUTHENTICATES_AS
```

### D. Components (part 2)
| Component | File |
|---|---|
| Two-pass search, `assured_view`, `Assured`, `exploit_missing` | `backend/riskgraph/modules/graph/attack.py` |
| `SecretLink`, `IdentityDecl.owns` | `modules/context/manifest.py` |
| `GraphFinding.line` from the merged location | `modules/scans/pipeline.py` |
| `MissingEvidenceOut`, `missing_evidence` | `modules/findings/schemas.py`, `findings/router.py::path_out` |
| Group order | `modules/graph/router.py`, `graph/service.py::ASSURANCE_ORDER` |

### E. Technical decisions (part 2)
See ADR-0020.
- I\* comes only from the search over the assured graph. A hypothesis can be listed, but never takes an inferred path's slot.
- A hypothesis EXPLOIT edge falls back to its best assured finding for scoring. The stored edge is unchanged (ADR-0017).
- `missing` lives in the stored path edges (JSONB), so there is no migration. Older paths say "not recorded".
- `owns:` is additive and optional, and `credentials:` keeps its meaning. A link is verified because a declaration names that very secret.

### H. API (part 2)
- `GET /scans/{id}/attack-paths`: ordered by assurance group, then score.
- Every path has `missing_evidence: [{source, target, kind, needed}]`, empty unless it is a hypothesis path. Old fields are unchanged.
- Finding detail `attack_paths[]` gets the same field.

### M. Testing (part 2)
- `test_graph_paths_assurance.py` (16, unit):
  - crowding and edge capture, deterministic cases. Both fail with the assured view switched off (mutation check, 3 tests fail);
  - the text of each kind of missing evidence;
  - the property "hypothesis-only facts never change a score" (200 examples);
  - the property "a path's assurance = the minimum of its edges" (150);
  - `owns:` links: verified, wrong line, wrong family, hostile values (7 cases), normalization.
- `test_attack_paths.py`: k per sink is now "≤ k assured + ≤ k hypotheses".
- `test_evidence_db.py`: group order, score order within a group, `missing_evidence` matching the hypothesis edges.
- `test_level2_ext_db.py`: expects the grouped order.
- `test_graph_perf.py`: the two new perf tests above.

### O. Validation (part 2)
See `docs/auto/DAY_2_REPORT.md`. The X0 re-run differs from `BASELINE.md` only by the differences already recorded on day 1.

### Q. Known limits (part 2)
- A link with only `file` covers every secret in that file.
- `line` must equal the merged finding's first line.
- Up to 2k paths per sink.
- No endpoint or function nodes are built yet (X4 part 2, X5); the perf test includes them as node kinds only.
