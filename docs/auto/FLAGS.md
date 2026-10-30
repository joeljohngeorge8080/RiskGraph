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
- Also waiting on this (day 5): scenario G of X6 (plan §6: "public image CVE on an internet service → DB"). G is built with the ServiceAccount sink the derived graph has; once (a) is built, add a Compose `postgres` service with `depends_on` to `tests/test_risk_scenarios_v2.py` G and assert the inferred path to it.
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

### F-4-1: How should the evaluation count authorization findings?
- Status: OPEN
- Phase / step: X5 part 2, step 6 (findings), and X6 (re-evaluation)
- Blocked: labels for `authz` findings in the evaluation. Nothing else waits on this: the current behaviour is the conservative one.
- Why it needs the owner: the X0 labels were written before any ranking (plan §7–§8). Scenarios B and E now produce one `authz:unguarded-sensitive` finding each. Labelling them now, after seeing their ranks, would break that rule; leaving them in unlabelled counts them as "not important" by default. Either way it is a choice about the evaluation's method, which the plan does not make.
- Done meanwhile: the X0 replay leaves `authz` findings out and says so in the report (`OUTSIDE_X0`, ADR-0023). With that, the pooled table equals `BASELINE.md`. Also, every authz finding is capped at Low until X6 (ADR-0023), so the product ranking does not move either. Without the exclusion, M1/M2 pooled numbers shift slightly; uncapped, M4 nDCG@10 drops from 0.991 to 0.902 (DAY_4_REPORT).
- Question: Options:
  - (a) Keep authz out of the X0 set; add a separate authz scenario with labels written first (in X6 with F–H, or in X8).
  - (b) Label the two existing findings now by the §26.3 rubric (both are on unauthenticated internet routes with an injection: likely "important").
  - (c) Keep them in, unlabelled (defaulted to not important).
  - Recommendation: (a). It keeps the frozen comparison honest and gives authz a test written before its ranking.
- Resume: (a) In X6, write scenario I (or extend F–H) with authz routes and labels first, then decide whether `OUTSIDE_X0` stays. (b) Add `LabelRule`s for `source_type="authz"` to scenarios B and E, then remove `authz` from `OUTSIDE_X0`. (c) Remove `authz` from `OUTSIDE_X0`.
- Answer:

### F-4-2: A way to declare routes public on purpose?
- Status: OPEN
- Phase / step: X5 part 2, step 4 (unguarded-sensitive rule)
- Blocked: nothing. This is a precision improvement.
- Why it needs the owner: on the labelled suite, unguarded-sensitive precision is 3/5 = 0.6, below plan §6's 0.8 for "unguarded". The two false positives are a contact form and a feedback form: writes without a guard on purpose, and nothing in their name says so. The fix is a declaration, i.e. a new manifest field. The run book says a new field outside the plan's own list goes to the owner.
- Done meanwhile: a fixed `public_hints` word list in `guards.yaml` (login, signup, callback, health, webhook, …). The two false positives are pinned in a test, not hidden. The inconsistency target (≥ 0.8, the one SCHEDULE names) is met: 4/4.
- Question: Options:
  - (a) Add `authz.public: [path patterns]` (same matcher as `rules`): routes there are never "unguarded-sensitive" or "inconsistent", and are listed as declared public.
  - (b) Keep only the word list.
  - (c) Add `require: none` to `authz.rules` instead (one list for both).
  - Recommendation: (a). It is explicit and cannot be confused with a policy.
- Resume: (a) Add `public: tuple[str, ...]` to `AuthzDecl` (validated with the rule path validator), pass it to `authz.analyze`, skip those routes in `_inconsistent` and `_unguarded_sensitive`, and add tests plus a line in ADR-0023. (c) Add `"none"` to `AuthzRule.require` and do the same.
- Answer:

### F-5-1: Should every finding of an exposed service take the path's effective impact?
- Status: OPEN
- Phase / step: X6, scenarios F–H (DAY_5_PLAN step 3)
- Blocked: nothing. The current rule stays and is pinned in `test_f_ssrf_flow_reaches_the_admin_identity_and_the_metadata`.
- Why it needs the owner: scenario F showed that every code finding of a service is evidence on its EXPLOIT edge (up to `MAX_EVIDENCE`), and each one gets the path's effective impact I* (§14.4, ADR-0013). Changing that changes how I* is attributed, which ADR-0013 and the blueprint decided. One of the options also moves the frozen X0 ranking.
  - In F, a weak hash (medium, `crypto`, L2) next to a tier-1 SSRF scores 71.1, Critical.
  - An L1 CVE (only a hypothesis on its own, `exploit_assurance`) scores 50.0, High.
  - In G, a non-KEV image CVE (a hypothesis on its own) next to a KEV one takes I* too: 44.4 instead of 28.9.
  - The labelled ordering still holds, because the important findings score higher. But the inheritance is co-location, not an attack step.
- Done meanwhile: nothing changed. I measured two options on the X0 replay with a temporary patch (reverted):
  - (a) took nothing out of X0: byte-identical;
  - (c) left the pooled table equal, but swapped three neighbouring pairs in the M4 top 10 (ranks 2–3: B's deserialization ahead of E's second SSRF; 5–6: C's AWS key ahead of a pyyaml CVE; 7–8: two unlabelled E CVEs).
- Question: Options:
  - (a) I* only for findings whose **own** support of the edge is at least inferred (L2/L3; an image package only with KEV). It fixes F3 and G2, not F2 (a weak hash at L2 is "inferred"). X0: no change.
  - (b) (a), plus only categories that give a foothold: SCA, and SAST with T ≥ 0.8 (injection, deserialization, SSRF, path traversal, XXE, auth). That fixes F2 too. It needs `category` on `GraphFinding`. X0: not measured; E's two SSRFs and B's deserialization qualify, so I expect no change (BELIEVE).
  - (c) I* only for the edge's leading finding (the one whose p is the edge's p). X0: the three swapped pairs above.
  - (d) Keep the current rule: a finding in an exploitable, exposed service shares its fate.
  - Recommendation: (b). It matches what the EXPLOIT edge claims ("an attacker can exploit this service through this finding"). It keeps ADR-0020's rule that a hypothesis never raises a score. And as far as measured, it leaves X0 as it is.
- Resume: (a)/(b) In `graph/attack.py::_search`, skip `e["findings"]` entries whose own support is below inferred (`exploit_assurance(f.tier)`, or `image_assurance(f)` for image packages; pass a support map from `analyze`). For (b), also add `category` to `GraphFinding` (pipeline: `x.merged.representative.category`) and keep only SCA or SAST categories with `T_SAST ≥ 0.8`. Flip the F/G pins in `test_risk_scenarios_v2.py`, add a property test (a hypothesis-level finding never gets I*), re-run X0, and add an ADR-0024 note. (c) Use `e["findings"][:1]`, re-run X0 and report the reordering. (d) Close the flag and turn the pin into a documented rule in ADR-0024.
- Answer:
