# Flags: things that need the owner

A run adds an entry here when the work needs a human decision or permission (RUNBOOK §3), then parks that item and carries on with everything that does not depend on it. **The owner answers by setting `Status: ANSWERED` and writing the answer under `Answer:`.** The next run continues from the resume steps. `OPEN` means: do not build on it.

## Template

```
### F-<day>-<k>: <short title>
- Status: OPEN | ANSWERED | WITHDRAWN
- Phase / step: <X3 part 2, step 2>
- Blocked: <what cannot be done until this is settled>
- Why it needs the owner: <hard stop it hit, or the choice that is the owner's>
- Done meanwhile: <what was built or skipped instead>
- Question: <the exact question, with the options and a recommendation>
- Resume: <exact steps to take once ANSWERED>
- Answer: <owner fills in>
```

## Entries

### F-1-1: Data stores from Compose (which images, which sensitivity)
- Status: OPEN
- Phase / step: X3 part 1, step 7 (derived topology)
- Blocked: data_store nodes for repositories without a manifest. Without them, a Compose-only repository has no sink, so no attack path (Kubernetes RBAC still gives identity sinks).
- Why it needs the owner: the plan's X3 row expects NodeGoat (Compose: app + mongo, no manifest) to get an inferred path, which needs a data store sink. Its sink impact comes from its sensitivity, and nothing in a Compose file states sensitivity. Choosing a default sensitivity is a scoring decision the plan does not make.
- Done meanwhile: nothing built. Compose services with a database image are ordinary services with their RUNS_IMAGE edge (ADR-0019, "Not built").
- Question: Should a Compose service whose image is a well-known database become a `data_store` node? The candidates are `postgres`, `mysql`, `mariadb`, `mongo`, `redis`, `elasticsearch`, `cassandra` and `couchdb`. Options:
  - (a) Yes, sensitivity `confidential` (impact D = 0.6). It is a sink; the CONNECTS_TO edge from a service comes from `depends_on`/`links` and is inferred.
  - (b) Yes, but sensitivity unknown, so it is not a sink. It is listed, and paths come only after a manifest says otherwise.
  - (c) No.
  - Recommendation: (a). It is what the plan's NodeGoat criterion needs. The sensitivity is labelled as assumed in the node and the edge evidence, and a manifest still overrides everything.
- Resume: in `graph/topology.py`, add a data-store detector over Compose services. In `graph/attack.py::_derive`, add the node, the inferred CONNECTS_TO edges from `depends_on`/`links` with declaration evidence, and the sink. Then add tests (a NodeGoat-shaped fixture gives ≥ 1 inferred path) and a line in ADR-0019.
- Answer:

### F-1-2: CAN_ACCESS from RBAC bindings has no target
- Status: OPEN
- Phase / step: X3 part 1, step 8 (edge rules)
- Blocked: the plan's "CAN_ACCESS identity → data_store/service from an RBAC binding (verified)".
- Why it needs the owner: a Kubernetes (Cluster)Role grants verbs on API resources (pods, secrets, deployments). It does not grant access to the application's services or data stores, which are the only CAN_ACCESS targets in the graph. Building the edge needs a new node kind, which is a design choice the plan does not make.
- Done meanwhile: a binding sets the account's privilege (`admin` for `cluster-admin`, `elevated` for any ClusterRoleBinding, the existing P7 rule). That makes the account a sink, and the binding is `rbac_binding` evidence on the RUNS_AS edge. No CAN_ACCESS edge is built from RBAC.
- Question: Options:
  - (a) Keep it as is: privilege on the identity, no edge.
  - (b) Add a `kubernetes_api` node (one per scan) as the CAN_ACCESS target of bindings, with the role's privilege as its impact. This is a new node kind and a second sink for the same fact.
  - (c) Map a role's `secrets` permissions to the credentials found in that namespace's manifests.
  - Recommendation: (a) for now. It gives the same paths without inventing a target; (c) is closer to the real risk but is X5/X6-sized work.
- Resume: (a) close the flag. (b) Add the node and the edges in `_derive`, the sink impact in `tables.py` (an ADR note), and tests. (c) Plan it as its own phase item.
- Answer:

### F-2-1: Turn the tier-1 taint rules on by default?
- Status: OPEN
- Phase / step: X4 part 1, step 7 (wiring)
- Blocked: tier 1 in the default scan profile, as plan §3.A puts it.
- Why it needs the owner: it contradicts the plan for now. The generated rules were only checked for structure here; the real Semgrep is not available in the cloud runs. If Semgrep refuses one rule, the whole Semgrep run fails, and every scan loses all its SAST findings. Checking needs the owner's machine (L-4), and the scanner image must carry the rules file.
- Done meanwhile: everything is built and tested: catalogue, generator, the committed rules, the parser and evidence contract, correlation, and the suite with its scorer. The adapter adds the rules only when `RISKGRAPH_SEMGREP_TAINT_RULES_PATH` is set; it is unset by default, so a default scan is unchanged.
- Question: once L-4 shows that Semgrep 1.182 accepts `taint_rules.yaml` and gives sensible numbers on the suite, should tier 1 be on by default? Options:
  - (a) Yes: copy the rules into the Semgrep scanner image and set the default path.
  - (b) Opt-in per deployment (keep the setting unset by default).
  - Recommendation: (a) after L-4 passes, which is what the plan intends.
- Resume:
  1. Add `COPY backend/riskgraph/modules/scanners/semgrep/taint_rules.yaml /opt/scanners/riskgraph-taint/taint_rules.yaml` to `scanners/semgrep/Dockerfile`, and the same path to `infrastructure/scripts/install-scanners.sh` for host tools.
  2. Set `semgrep_taint_rules_path: Path | None = Path("/opt/scanners/riskgraph-taint/taint_rules.yaml")` in `shared/config.py`, plus `RISKGRAPH_SEMGREP_TAINT_RULES_PATH` in `docker/backend.Dockerfile`.
  3. Update `test_the_rules_are_a_second_config_only_when_configured`.
  4. Re-run the X0 evaluation: the recorded Semgrep fixtures have no tier-1 hits, so no change is expected.
- Answer:

### F-3-1: Joern spike not run, so no Joern adapter
- Status: OPEN
- Phase / step: X4 part 2 (all of it: adapter, parser, `deep` profile, tier-1 + tier-2 correlation, ADR with the spike numbers)
- Blocked: the Joern adapter. SCHEDULE day 3 makes it conditional on `docs/auto/spikes/joern/RESULT.md` saying `GO`, with recorded Joern output under `backend/tests/fixtures/joern/` (L-2).
- Why it needs the owner: at the start of the day-3 run (2026-10-28, 05:00 IST) `RESULT.md` still said "Not run yet" and `backend/tests/fixtures/joern/` did not exist. The spike needs Docker and a JVM container, which the cloud runs do not have. Building a parser without recorded output would mean inventing Joern's output format.
- Done meanwhile: nothing of the adapter. Day 3 did the fallback SCHEDULE names: tier-1 hardening (multi-line sinks now join their generic finding) and X5 part 1 early (extractor `ts-imports.4`, `modules/authz` route inventory and guards, `GET /scans/{id}/routes`).
- Question: will you run the spike (L-2)? Options:
  - (a) Run L-2, write `RESULT.md` with `GO` or `NO-GO` and the numbers (recall, precision, peak RAM, time), and commit the fixtures. A later run builds the adapter (or, on `NO-GO`, records the fallback ADR the plan asks for).
  - (b) Skip Joern for this six-day block: the remaining days keep the schedule's order (X5, X6), and X4 part 2 goes back to the plan's queue.
  - Recommendation: (a) when you have the machine time, because X4's gate in the plan needs measured numbers; until then (b) costs nothing, since X5 and X6 do not depend on tier 2 (X6's taint factor table reads `analysis`, which tier 1 already sets).
- Resume: once `RESULT.md` says `GO` and the fixtures exist, do SCHEDULE day 3 as written (adapter in `modules/scanners/joern/`, parser golden tests on the fixtures, `deep` opt-in with one slot, correlation through `merge._join_taint_hits`, ADR with the spike numbers), before that day's own work. On `NO-GO`: an ADR recording the fallback (custom Python summaries, plan §3.A) and no adapter.
- Answer:
