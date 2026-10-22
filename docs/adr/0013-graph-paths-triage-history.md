# ADR-0013: Per-scan attack paths with effective impact; triage, history and the CI gate

Status: accepted · Date: 2026-10-22 · Implements part of: roadmap Phases 9, 10 and 14 (blueprint §12–§14.4, §19) · Builds on: ADR-0006, ADR-0011, ADR-0012

## Context
MVP level 2 scored each finding on its own context. The blueprint's core idea, "a moderate CVE on a path to PII matters more", needs a graph and attack paths. Users also need to triage noise and see what changed between scans, and CI needs a pass/fail signal.

## Decision
### Graph and attack paths
- **Security graph per scan, in Postgres:**
  - Tables `graph_nodes` and `graph_edges` (ADR-0006), analysed with NetworkX.
  - States: `internet`, services, identities, data stores, and credentials (one per secret finding).
  - Edges: EXPOSES, RUNS_AS, CAN_ACCESS, CONNECTS_TO, CONTAINS_SECRET, AUTHENTICATES_AS, EXPLOIT.
  - Code findings are folded into service-level EXPLOIT edges as evidence (§13.1). They are not graph nodes, which keeps the graph small.
  - The graph is a derived projection, deleted and rebuilt on every analysis.
- **Edge probabilities (§13.1):**
  - EXPLOIT into a service (from `internet` if exposed, or over CONNECTS_TO): `p = max geomean(E, R)` over its SCA/SAST findings that are not L0.
  - AUTHENTICATES_AS from a credential: `p = E(secret)`.
  - Control edges: `p = 1`.
  - Weight `w = -ln p`.
- **Search (§13.2):** Yen's k-shortest simple paths (`networkx.shortest_simple_paths`, Dijkstra-based), k = 3 per sink, at most 8 hops.
  - Sources: the Internet, plus every public credential (all MVP repositories are public).
  - Sinks: data stores with sensitivity ≥ confidential, identities with privilege ≥ elevated, services marked critical.
  - A path must contain an EXPLOIT or AUTHENTICATES_AS edge. Pure control paths are counted as "exposed by design".
  - `path_score = 100 · ∏p · I(sink)`.
- **Effective impact (§14.4):** scoring is two-pass. For each finding that is evidence on a path, `I_eff = max(I, I(sink) · P(path)/p(own edge))`. It is recorded as adjustment factor `I*` (source `attack_path`, evidence = the path), with `risk_scores.effective_impact`. It only ever raises.
- **Manifest v1, one optional key:** `identities[].credentials: [aws, github, …]`.
  - It names the credential families (from `normalization/families.py`) that authenticate as that identity, so a leaked key becomes a graph edge.
  - It is strictly validated; unknown families are rejected. Without it, leaked secrets stay unlinked nodes.

### Triage and history
- **Statuses:** `open | fixed | false_positive | accepted_risk | wont_fix`.
  - People set every status except `fixed` through `PATCH /findings/{id}`. A reason is required except for `open`, and every change is written to `audit_logs` in the same transaction; the actor is `local` until auth exists.
  - Triage statuses are never changed by scans.
  - The findings list defaults to `status=open`.
- **History per (repository, ref)** against the previous COMPLETED or PARTIAL scan:
  - each finding in the scan is `new`, `existing` or `reopened` (it was seen before but absent from the previous scan);
  - a finding that was open and is now absent becomes `fixed`, **but only if every scanner that reported it succeeded** in this scan (§10.2);
  - a `fixed` finding seen again goes back to `open`.
  - Everything is derived from stored rows, so re-analysis is idempotent.
- **`GET /scans/{id}/diff`** returns new, reopened and fixed findings against the previous scan or `?against=`.
- **`GET /repositories/{id}`** returns the per-scan trend.

### CI gate
- **`GET /scans/{id}/gate`** implements the §19 `fail_when` subset: `fail_on` priorities, `max_score`, `new_only`, `include_statuses`.
- **`python -m riskgraph.entrypoints.cli scan`** starts or joins a scan, waits, evaluates the gate, writes `$GITHUB_STEP_SUMMARY`, and exits 0 (pass), 1 (fail) or 2 (error).
- Because the API has no auth and listens on localhost, CI use means a **self-hosted runner** (`docs/examples/riskgraph-ci.yml`). The webhook and hosted-runner path wait for Phase 2 auth.

## Alternatives considered
- **Finding nodes in the stored graph:** rejected for now. They would multiply the node count with no new paths, since §13.1 folds them into edges anyway.
- **Effective impact as an additive bonus:** rejected, as in the blueprint. `max(I, …)` keeps the score explainable.
- **Auto-reopen triaged findings when they change:** rejected. Triage is a person's decision; scans only manage `fixed`.

## Consequences
- (+) On the kitchen-sink fixture with a manifest, both of these paths are found, and the findings on them are raised through `I*`:
  - "aws credential · main.tf:3 → app-role → users-db" (p 0.9, score 81);
  - "Internet → app → users-db".
- (+) Re-scanning an unchanged commit reports 0 new. Deleting a file marks its findings fixed. Restoring it reopens them.
- (−) Paths need a manifest. Without one the panel explains why it is empty. IaC/K8s-derived topology (Phase 7) will remove that dependency.
- (−) `internet_auth` services get the same exploit-edge probability as `internet_noauth`, following the blueprint §13.1 text. Calibration belongs to Phase 17.
- (−) The audit actor is anonymous until Phase 2.
