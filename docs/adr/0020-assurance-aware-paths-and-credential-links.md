# ADR-0020: Assurance-aware path search, missing evidence, and manifest credential links

Status: accepted · Date: 2026-10-27 · Implements: expansion phase X3 part 2 (`docs/proposals/EXPANSION_A-D.md` §3.D, §4 X3) · Amends: ADR-0017 (effective impact, AUTHENTICATES_AS), ADR-0013 (k paths per sink)

## Context
After X1, a path's assurance is the minimum over its edges, and only paths of at least `inferred` raise effective impact (I\*). The plan's X3 row adds three requirements:
- hypothesis paths never change any score (a property test);
- `/attack-paths` is grouped by assurance, and every hypothesis path lists `missing_evidence[]`;
- the manifest gets a way to make a credential edge verified (X1 follow-up).

Writing the property test showed that the first requirement did not hold:
1. **Crowding.** The search took the K = 3 cheapest paths per sink whatever their assurance. A cheaper hypothesis path, such as a family-matched key, took a slot, and the inferred path it replaced lost its I\*.
2. **Edge capture.** A manifest service's EXPLOIT edge takes its p and its assurance from its most exploitable finding (ADR-0017). An L1 or unknown-tier finding with a higher p turned an inferred edge into a hypothesis edge, and the L2/L3 findings under it lost their I\*.

So adding a fact that is only a hypothesis could lower another finding's score.

## Decision
**Two searches per sink** (`graph/attack.py::_search`).
- The **assured graph** keeps only the edges of at least `inferred`.
  - A hypothesis EXPLOIT edge whose candidates include a finding of at least `inferred` keeps a fallback (`Assured`): that finding's p and level, and the candidates from it on.
  - The assured graph uses the fallback instead of the hypothesis edge.
  - Its k best paths per sink are the only ones that set I\*.
- The **full graph** (as stored) is searched as before. Its k best paths that are hypotheses are added, as paths to verify.
- Per sink, a path list now holds up to k assured paths plus up to k hypotheses, ranked together by probability.
- The stored edges are unchanged: an EXPLOIT edge still shows the top p and that finding's assurance, as ADR-0017 says. Only the score search looks past a hypothesis top.
- `exposed_by_design` is counted in the full search only, as before.

**Missing evidence.** Each hypothesis edge records what would prove it. The text is stored in the path's edge JSON as `missing`, so no migration is needed:

| Edge | Missing |
|---|---|
| AUTHENTICATES_AS (family match) | "no manifest link proves this `<family>` key authenticates as `<identity>` (an `owns:` entry would)" |
| EXPLOIT on an image package | "reachability of `<finding>` in `<image>` is not assessable" |
| EXPLOIT on L1/unknown reachability | "no import or call chain shows `<finding>` is reached (L2 or L3 would)" |

- The API derives `missing_evidence: [{source, target, kind, needed}]` per path, one entry per hypothesis edge; it is empty for verified and inferred paths.
- Paths stored before this change say `"not recorded"`.

**Ordering.** `GET /scans/{id}/attack-paths` lists verified paths first, then inferred, then hypothesis, then paths stored before X1 (no assurance). Each group is ordered by score. The response is still a list; every existing field is unchanged.

**Credential links.** An identity can name the secrets it owns:
```yaml
identities:
  - name: api-role
    privilege: admin
    credentials: [aws]            # unchanged: a family match, a hypothesis
    owns:
      - {file: deploy/.env, line: 3, family: aws}   # line and family optional
```
- A secret finding whose file matches (and whose first line and family match, when given) gets a **verified** AUTHENTICATES_AS edge. Its evidence is a manifest declaration with the link's facts.
- There is at most one edge per (key, identity): when both a link and a family match apply, the verified edge is built.
- Validation is strict:
  - `file` is a repository-relative file path, normalized like service paths;
  - absolute paths, `..`, directories and empty names are refused;
  - `line` ≥ 1, a known family, at most 32 entries, no unknown keys.
- This is additive and optional: every existing manifest validates unchanged, and `credentials:` keeps its meaning.

## Consequences
- (+) The property holds on random graphs (`test_graph_paths_assurance.py`, 200 examples): adding hypothesis-only facts leaves every effective impact unchanged.
- (+) A reviewer sees, per hypothesis, the artifact that would settle it.
- (+) A team can make a key's path verified by declaring it, and that path raises the key's score.
- (−) Up to 2k paths per sink instead of k. The scenario fixture of `test_attack_paths.py` now lists a fourth path to `orders-db`: an inferred path the hypotheses had crowded out. It carries the same I\* as one already listed, so no score changes. On the X0 scenarios the pooled table is unchanged (day 2 report).
- (−) A link with only `file` covers every secret in that file. That is what it declares; when a file holds several keys, give `line`.
- (−) `line` matches the merged finding's first line. Gitleaks and Trivy can differ by a line or two; the merged location follows Gitleaks.
- (−) The search runs twice. At 5k nodes / 20k edges with 10 sinks: 0.36 s for the search, 0.56 s for build and search (budget 2 s).
- (−) An L1 finding that rides on an inferred EXPLOIT edge (it is among the edge's evidence, not its top) still gets that edge's I\*. That is ADR-0017's existing behaviour; the property is about hypotheses changing *other* findings' scores.

## Rejected
- **One search, with k counted per assurance.** Yen's enumeration is by weight; skipping hypotheses until k assured paths appear can take up to MAX_CANDIDATES candidates per sink. Two bounded searches are simpler and cheaper.
- **Changing the stored EXPLOIT edge to its best-assured finding.** That would change p, and so every existing path, which ADR-0017 refused for the same reason.
- **A separate grouped endpoint.** A list ordered by group keeps every client working.
- **Making `credentials:` entries verified when the repository holds only one key of that family.** The repository's contents would then decide the assurance, not a declaration.
