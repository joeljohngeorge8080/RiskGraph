# ADR-0019: A graph from Compose and Kubernetes when the manifest declares no services

Status: accepted for X3 part 1; owner review pending (see `docs/auto/FLAGS.md` F-1-1, F-1-2) · Date: 2026-10-26 · Implements: expansion phase X3 part 1 (`docs/proposals/EXPANSION_A-D.md` §3.D, §4) · Builds on: ADR-0006 (graph store), ADR-0013 (paths), ADR-0017 (evidence and assurance), ADR-0018 (image references)

## Context
Gap G3: a repository without a `riskgraph.yaml` got no attack graph, even when its Compose and Kubernetes files say what is exposed, what it runs and under which account. The plan's §3.D table names the edges; this ADR fixes the details the table leaves open.

## Decision
**When.** Only when the manifest is absent or declares no services. A manifest with services wins completely (precedence manifest > Kubernetes > Compose, unchanged); its graph is byte-for-byte what it was (test).

**Services** (`modules/graph/topology.py`, pure).
- A Compose service and a Kubernetes workload are each a service; the same name in both is one service.
- A Compose build context is the service's code path; findings map to a service by the longest path prefix.
- Names are cut to 120 characters, so `service:` and `identity:sa:` keys fit their 160-character column.

**Edges and their assurance.** Every edge has `declaration` (or `rbac_binding`) evidence from the file that states the fact, producer `riskgraph.iac@1`. The evidence is verified (the file says it); the edge's assurance says how much the conclusion adds.

| Edge | Rule | Assurance |
|---|---|---|
| EXPOSES internet → service | Kubernetes LoadBalancer/NodePort Service or an Ingress selects the workload; otherwise a Compose port published beyond loopback | inferred (nothing says whether a firewall or auth sits in front) |
| RUNS_IMAGE service → container_image | the Compose `image:` or the pod spec names it | verified |
| | the last `FROM` of the Dockerfile in the build context | inferred (the last stage is assumed to be the one that runs) |
| RUNS_AS service → identity | the pod spec names a ServiceAccount, and the service is only a Kubernetes workload | verified |
| | the implicit `default` account, or a Compose service joined to a workload by name | inferred |
| | neither: the synthetic unknown identity (as for manifests) | inferred |
| CONTAINS_SECRET service → credential | the secret's file is in the service's build context | verified |
| EXPLOIT internet → service | only where EXPOSES exists | min(the finding's level, inferred) |

- RBAC bindings that name the account set the identity's privilege; `elevated` or `admin` makes it a sink (`P` table, as for manifest identities). Their `rbac_binding` evidence is attached to the RUNS_AS edge.
- RUNS_IMAGE is not traversable (no probability): images are not attack states; an image's findings act on the service that runs it.
- **EXPLOIT candidates:** code findings (SCA/SAST, not L0) in the code path, and image package findings on the service's images.
  - Image packages have no reachability, so they are hypotheses. One whose advisory is in KEV is inferred at most.
  - The edge rests on the best-assured candidate first, then the most exploitable. A more exploitable hypothesis therefore never turns an inferred edge into a hypothesis.
  - The edge is capped at inferred: the exposure it starts from is only inferred, so an L3 finding cannot make the path verified.
- Image package findings never join a **manifest** service's EXPLOIT edge. Otherwise a Dockerfile in a manifest service's path would demote an existing inferred edge.

**Not built (flagged).**
- Data stores from Compose (F-1-1).
- CAN_ACCESS from RBAC (F-1-2).
- Without either, a Compose-only repository has no sinks and so no paths, which is the under-claim rule.
- Endpoint nodes wait for X5: the extractor yields entrypoint labels, not routes.

## Consequences
- (+) A repository with Kubernetes RBAC and an exposed workload gets an inferred path with no manifest; the X0 scenarios all have manifests and are unchanged.
- (+) Two findings in the same service are still never connected without an edge rule (Hypothesis property test).
- (−) Exposure from IaC is always inferred, so no derived path is ever verified.
- (−) The name join between Compose and Kubernetes can be wrong (two unrelated things with one name).
- (−) Multi-stage Dockerfiles whose final stage is `FROM <earlier stage>` give the last named image, which may be a builder.
- (−) No sinks from Compose until F-1-1 is answered.

## Rejected
- **Deriving services even when the manifest has them.** It would change every manifest graph and overrule what the owner of the repository declared.
- **Making image findings verified edges.** The image's packages are matched, but nothing shows the service's code uses the vulnerable package.
- **A `kubernetes_api` node as the CAN_ACCESS target.** It is a new node kind the plan does not name; asked as F-1-2.
