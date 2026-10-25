# Schedule: X2 part 2, X3, X4, X5, X6 over six days

Runs start at **05:00 IST** (23:30 UTC the evening before). Day is chosen by the IST date (`TZ=Asia/Kolkata date +%F`). Branch: `extended_phase_auto`. Rules: `RUNBOOK.md`. Questions for the owner: `FLAGS.md`. Work only the owner's machine can do: `LOCAL_TASKS.md`.

Weights (relative effort, from the expansion plan rows): X2 part 2 = 0.5, X3 = 1.3, X4 = 1.6 (cloud part; the Joern spike is local), X5 = 1.7, X6 = 0.9. Total about 6 days.

| Day | Date (IST) | Work | Weight |
|---|---|---|---|
| 1 | Mon 2026-10-26 | X2 part 2 (image scan stage, from the recorded fixtures) + X3 part 1 (new node kinds, topology edges) | 0.5 + 0.5 |
| 2 | Tue 2026-10-27 | X3 part 2 (assurance-aware search, `missing_evidence[]`, properties, perf) + X4 part 1 (taint catalogue, own rules, taint evidence contract) | 0.8 + 0.5 |
| 3 | Wed 2026-10-28 | X4 part 2 (Joern adapter, parser and correlation, built on the owner's spike fixtures; deep profile) | 1.1 |
| 4 | Thu 2026-10-29 | X5 part 1 (extractor `ts-imports.4`, guard catalogue, route inventory, API) | 0.9 |
| 5 | Fri 2026-10-30 | X5 part 2 (inconsistency, unguarded-sensitive, policy diff, BOLA hypothesis, edges, labelled suite) | 0.8 |
| 6 | Sat 2026-10-31 | X6 (risk v2, scenarios F–H, ADR) + integration pass over everything | 0.9 |

If a day's work is flagged or runs out of budget, the next run **catches up first** (RUNBOOK §0.4). Later days shrink; the order never changes, because each phase builds on the one before (X3 on X1/X2, X4 on X3, X5 on X3/X4, X6 on all).

---

## Day 1 — Mon 26 Oct: X2 part 2 + X3 part 1

### X2 part 2: scan the images the repository names
Read `docs/phases/PHASE_X2.md` ("Part 2"), `docs/adr/0018-runtime-and-image-intel.md`, `docs/adr/0014-container-scanner-runner.md`, `backend/riskgraph/modules/runtime/images.py`, `modules/scanners/trivy/`.
**Decided (owner, 2026-10-25, and in ADR-0018):** image package CVEs stay `source_type = sca`, marked with the image; only refs where `ImageRef.allowed`; at most 5 refs per scan, 2 GB each; a pull failure, rate limit or size cap is a warning and **never fails the scan**; reachability for image packages is "not assessable" (n_a).
**Decided here (amendment to ADR-0018; write it in the ADR):** the image inventory comes from `trivy image --list-all-pkgs`. Syft stays offline (its image has no CA certificates and no reason to get network). One pull per image instead of two.
**Recorded input:** `backend/tests/fixtures/images/{python_3.8-slim,node_14}/trivy/0.76.0/report.json` (read `record.py` for how they were made; `Metadata.OS.EOSL` is Trivy's own end-of-support flag).
Build:
1. A `trivy image` command on the Trivy adapter (a target mode next to `fs`): `trivy image --image-src remote --format json --list-all-pkgs --scanners vuln --cache-backend memory --skip-db-update …` with the egress network; copy the exact flags from `record.py`.
2. A pipeline stage after the scanner chord that runs it for each allowed ref (≤ 5), through the existing runner. Tests use the fake runner pattern of `tests/pipeline_support.py` (add a way to serve an image fixture per ref). The real container run **cannot be done here**: log it in `LOCAL_TASKS.md` (L-3).
3. Parse into `sca` findings: reuse the Trivy parser; add the image (ref, OS family, layer-independent) to `attrs` and `package`; scope the fingerprint by image so the same CVE in two images stays two findings. Reachability n_a for image packages; scoring unchanged.
4. Image packages into the SBOM: additive, nullable `image` column on `sbom_components` (hand-written migration, up/down/up, `alembic check`). Keep `GET /scans/{id}/sbom` backward compatible.
5. `Metadata.OS.EOSL == true` becomes a `runtime` finding (`runtime-eol:os:<family>:<name>`, high severity, producer `riskgraph`, evidence kind `eol`, `data_as_of` from the report's creation time), with the same interim score as other EOL findings.
6. Freshness: every image finding's evidence carries the Trivy DB time already read for the scan.
Acceptance (plan X2 exit criteria 2–3): fixture parsed (OS and language packages, fixed versions); every image finding has an advisory id, range/installed version and `data_as_of`; a failing or refused ref produces a warning and the scan still completes. Criterion 4 (overhead ≤ +90 s per image warm) is measured by the owner (L-3).

### X3 part 1: nodes and edges from Compose, Kubernetes and images
Read `docs/proposals/EXPANSION_A-D.md` §3.D and the X3 row, `docs/adr/0013-graph-paths-triage-history.md`, `0017-evidence-and-assurance.md`, `backend/riskgraph/modules/graph/attack.py`, `modules/context/iac.py` (`kubernetes_context`).
Build (closes G3: a repository with no `riskgraph.yaml` still gets a graph):
1. New node kinds: `container_image` (from the assets), `endpoint` only if the reachability extractor already yields routes (otherwise leave for X5), and workload/service nodes derived from Compose and Kubernetes when the manifest has none. Manifest still wins (precedence manifest > Kubernetes > Compose, unchanged).
2. Edge rules from §3.D with evidence and assurance per the table: EXPOSES (Kubernetes LoadBalancer/Ingress: inferred; Compose published port: inferred), RUNS_IMAGE (Compose or Kubernetes names the image: verified; a Dockerfile in the service path: inferred), RUNS_AS from the Kubernetes ServiceAccount (verified) or a name match (inferred), CAN_ACCESS from RBAC bindings (verified). Every edge needs evidence ids (declaration evidence from the IaC asset: kind `declaration` or `rbac_binding`, with the file); the builder already refuses an edge without evidence.
3. EXPLOIT onto a derived service from findings in its code path (`path_prefix`), and from image findings on its image (the finding's own tier; image packages have none, so `hypothesis` unless the finding is KEV or exploited in the wild, which stays `inferred` at most).
Acceptance (plan): a repository with Compose/Kubernetes and no manifest gets at least one inferred path (build a small fixture repo in the tests; NodeGoat itself is not available offline); a property test (Hypothesis): a random graph built **only from co-located findings with no edge rules yields 0 paths**; existing X1 tests unchanged.

---

## Day 2 — Tue 27 Oct: X3 part 2 + X4 part 1

### X3 part 2: assurance-aware paths
1. `/attack-paths` grouped by assurance (verified, inferred, hypothesis), then by score; each hypothesis path lists `missing_evidence[]` (the edge(s) at hypothesis level and the artifact that would prove them, e.g. "no manifest link proves this key authenticates as `api-role`"). Additive API change; keep the old fields.
2. The manifest link that makes a credential edge verified (the X1 follow-up): an **additive, optional** field on an identity, listing the exact secret locations or families it owns (design it in an ADR note inside ADR-0017's addendum or a new ADR 0019; keep strict validation and the existing meaning of `credentials:`). If you judge it is more than additive, flag it instead (FLAGS.md).
3. Property tests: hypothesis paths never change any score; assurance of a path is the minimum of its edges (random graphs).
4. Performance: build + search ≤ 2 s at 5k nodes / 20k edges with 10 sinks, k = 3, including function and endpoint nodes (extend the existing perf test).
Acceptance: all of the X3 row's exit criteria; the X0 evaluation re-run reports only intended differences.

### X4 part 1: tier-1 taint (own Semgrep rules) and the evidence contract
Read the X4 row and §3.A of the plan, `modules/scanners/semgrep/`, `modules/reachability/` (function spans from P8), `docs/adr/0015`, `0017`.
Build:
1. A taint **catalogue** (YAML, RiskGraph-authored, Apache-2.0, in the repo: sources, sinks, sanitizers per language for CWE 89, 78, 22, 502, 918, Python and JS) and Semgrep taint-mode rules generated from it. Do not copy anything from `semgrep-rules`.
2. A taint finding contract: `source_type = sast`, `analysis = intraprocedural` (tier 1), evidence kind `taint_flow` with ordered `steps` (≤ 50) from the Semgrep dataflow trace when present, assurance `inferred` (a rule applied to parsed code; never `verified` for tier 1).
3. Correlation: a tier-1 hit and an existing generic Semgrep finding at the same sink merge as one finding with two occurrences (the merge-key rules; corroboration K).
4. Tests on the 40-case synthetic suite structure of plan §6 (Python 20, JS 20): generate the cases as code in tests (intraprocedural, cross-function, cross-file, sanitized). The real Semgrep cannot run here: unit-test the rule **generation** (valid YAML, expected structure, every catalogue entry produces a rule) and the **parsing** of a hand-written Semgrep JSON sample with a dataflow trace; log running the rules against the suite with the real Semgrep as a local task (L-4).
Acceptance: catalogue + rule generator + parser tested; recall numbers are **not claimed** (UNVERIFIED until L-4).

---

## Day 3 — Wed 28 Oct: X4 part 2 (Joern)

Precondition: the owner's local spike has produced `docs/auto/spikes/joern/RESULT.md` and recorded fixtures under `backend/tests/fixtures/joern/` (L-2 in `LOCAL_TASKS.md`).
- If `RESULT.md` is missing or says `NO-GO`: **flag** (F-3-1), do not build the adapter, and spend the day on tier-1 hardening (more catalogue cases, merge tests) and on starting X5 part 1 early (Day 4's scope).
- If `GO`: build the Joern adapter per the plan: `ScannerAdapter` like the others (`command()`, `version_argv()`, `parse()` into findings plus `taint_flow` evidence with steps from the recorded Joern output), a `deep` profile that is **opt-in** with one slot, pinned by digest, the ADR-0014 hardening profile (no network, read-only source); parsing only (the container run is the owner's L-5). Correlate tier 1 + tier 2 flows ending at the same sink as one finding. Flow assurance: `verified` only when every step exists in the code graph as the spike's notes define, else `inferred`.
- Update ADR (new or amended) with the spike numbers (recall, precision, peak RAM, time) copied from `RESULT.md`.
Acceptance: parser golden tests on the recorded fixtures; correlation tests; `deep` off by default and a default scan unchanged (test); all earlier tests green.

---

## Day 4 — Thu 29 Oct: X5 part 1 (route inventory and guards)

Read the X5 row and §3.B of the plan, `modules/reachability/extract.py` (extractor `ts-imports.3`), `modules/context/manifest.py`.
Build:
1. Extractor `ts-imports.4`: collect route declarations, auth decorators/dependencies/middleware and route parameters for **Flask, FastAPI, Express** (Django/DRF deferred). Same sandboxed subprocess, size and file caps.
2. `modules/authz` (new): `route_inventory(extract) → Route[]`, a guard catalogue (YAML, extensible later by the manifest), guard detection with honest assurance: a catalogued guard is `inferred`, never `verified`; an unknown framework is reported as "unknown framework", never a false "no guard".
3. API: route inventory per scan, additive. Evidence kinds `route` and `auth_guard`.
Acceptance: route-inventory recall ≥ 0.95 on a labelled suite you write as test code (each framework: guarded, unguarded, inconsistent, custom guard, id param with and without an ownership check).

---

## Day 5 — Fri 30 Oct: X5 part 2 (authorization findings)

Build on Day 4:
1. Findings with `source_type = authz`: inconsistent guarding within a router, unguarded-sensitive routes, manifest policy diff (an additive optional `authz:` section in the manifest; strict validation; flag it if it is more than additive), and BOLA heuristic findings that are **always `hypothesis`** and never scored above Low.
2. Graph edges UNGUARDED (inferred) and BOLA_SUSPECT (hypothesis) with evidence; they obey the X1/X3 rules.
3. A "manual verification required" list in the API.
Acceptance (plan): inconsistency precision ≥ 0.8 on the labelled suite; **zero** BOLA findings above `hypothesis`; recall of the inventory unchanged; all earlier tests green.

---

## Day 6 — Sat 31 Oct: X6 (risk v2) + integration

Read the X6 row, `docs/adr/0011`, `0013`, `0017`, `0018`, `modules/risk/`, `docs/evaluation/BASELINE.md`.
Build model `v2`:
- factor tables for runtime EOL (replace the interim ones), container OS packages (R = 0.5, "not assessable"), taint (E by CWE and confidence) and authz (E for inferred unguarded; hypotheses never above Low);
- the **reduction property is kept**: with the new inputs absent, `v2` scores equal `v1-ctx.3` on every existing test (test it);
- scenarios F–H from plan §6 as fixtures (F: SSRF → metadata → identity; G: public image CVE on an internet service → DB; H: co-located findings with no relationship, **expected 0 paths**); monotonicity (Hypothesis) still holds;
- ADR 00NN for the model; `MODEL_VERSION` bumped; re-run the X0 evaluation and report every change against `BASELINE.md`.
Then an integration pass: run every suite, fix cross-phase breakage, write the six-day summary into `HANDOFF.md` and `todo1150.md`, list everything still open (flags, local tasks) in `docs/auto/FINAL_REPORT.md`.
Acceptance: the X6 row's exit criteria. Do not tune any weight to improve the X0 numbers (the baseline is frozen; plan §8).
