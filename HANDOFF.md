# HANDOFF: resume here (updated 2026-10-30, auto session day 5: X6 risk v2 built a day early (model `v2.1`, factor tables for image packages, taint, runtime EOL and authz; image packages scored in their services' context; scenarios F–H); next the day-6 integration pass, see docs/auto/SCHEDULE.md)

## Auto session day 5 (2026-10-30, cloud, branch `extended_phase_auto`)
- **Verdict COMPLETE.** Report: `docs/auto/DAY_5_REPORT.md`; plan: `DAY_5_PLAN.md`.
- **X6, a day early** (`PHASE_X6.md`, ADR-0024, no migration, model `v2.1`):
  - image packages: R = 0.5, "not assessable";
  - tier-1 taint: E by CWE class and rule confidence, never below the SAST row;
  - runtime EOL: E by time past the end of support, read from the feed snapshot (no date: the old 0.5);
  - authz: an inferred finding is scored by its own table, no longer capped; a BOLA hypothesis stays Low;
  - **an image package takes the exposure and privilege of the services that run its image.** The first scenario run showed that image findings had no context at all.
  - Reduction (without the new inputs, v2.1 = v1-ctx.3) and monotonicity are Hypothesis properties.
  - Scenarios F–H pass with labels written first. H has 0 paths.
- Verified:
  - lint/types clean; 648 unit; 84 db, 2 skipped; perf 4 passed;
  - migration round trip and `alembic check` clean;
  - the X0 re-run equals the day-4 run except for the model line; the pooled table equals `BASELINE.md`.
- **For the owner:**
  - new flag **F-5-1**: a weak hash next to an SSRF in an exposed service takes the path's effective impact and is Critical. The rule predates v2; the options and their X0 effect are in the flag;
  - F-1-1 now also holds scenario G's database end;
  - an inferred authz finding can now rank High or Critical (F-4-1 is about labelling them).


## Auto session day 4 (2026-10-29, cloud, branch `extended_phase_auto`)
- **Verdict COMPLETE.** Report: `docs/auto/DAY_4_REPORT.md`; plan: `DAY_4_PLAN.md`.
- **X5 part 2, a day early** (`PHASE_X5.md` part 2, ADR-0023, no migration, model `v1-ctx.4`):
  - extractor `ts-imports.5`: handler bodies (what a handler looks up, whether it checks an owner), JS call sites;
  - a passed-in Express app is bound through its call site (NodeGoat: 20/20 routes resolved);
  - manifest `authz: {guards, rules}`, optional and strict;
  - `authz` findings: inconsistent, unguarded-sensitive, policy, and BOLA (always a low hypothesis). They link the route evidence they rest on;
  - **every authz finding is capped at Low until X6** (uncapped, two entered the X0 top 10; that ranking is X6's call);
  - `GET /scans/{id}/authz/manual` (what a person must check);
  - UNGUARDED (inferred) and BOLA_SUSPECT (hypothesis) edges, stored **without a probability**, so no path or score changes.
  - Labelled suite: inconsistency 4/4, no false positive; unguarded-sensitive 3 TP and 2 FP (precision 0.6, F-4-2); BOLA 6 TP and 1 FP.
- Verified:
  - lint/types clean; 610 unit; 83 db, 2 skipped; perf 4 passed;
  - migration round trip and `alembic check` clean;
  - the X0 re-run's pooled table equals `BASELINE.md`, with authz findings outside the X0 set (F-4-1).
- **For the owner:**
  - new flags F-4-1 (authz findings in the evaluation) and F-4-2 (declaring public routes); F-1-1, F-1-2, F-2-1 and F-3-1 are still open;
  - `1fd675c` was pushed with one lint error (tests green), fixed in the next commit `fe25182`; the check script that let it through is fixed;
  - the kitchen sink now has 3 correct authz findings (pinned counts 29 → 32).


## Auto session day 3 (2026-10-28, cloud, branch `extended_phase_auto`)
- **Verdict COMPLETE.** Report: `docs/auto/DAY_3_REPORT.md`; plan: `DAY_3_PLAN.md`.
- **X4 part 2 not built:** the Joern spike (L-2) had not run, so there were no `RESULT.md` and no fixtures. Flag **F-3-1** (OPEN) has the resume steps for `GO` and `NO-GO`.
- **Tier-1 hardening** (`PHASE_X4.md` part 2): a taint hit now joins the generic finding whose multi-line call covers its line (bounded look-back, still linear).
- **X5 part 1, a day early** (`PHASE_X5.md`, ADR-0022, no migration):
  - extractor `ts-imports.4` records routes and every guard source for Flask, FastAPI and Express;
  - new `modules/authz`: a strict `guards.yaml` catalogue and a route inventory that resolves mounts across files;
  - status per route: guarded, custom, none_found, unresolved or unknown_framework. A catalogued guard is inferred, never verified;
  - routes stored as `route`/`auth_guard` evidence; `GET /scans/{id}/routes`; `summary.routes`;
  - labelled suite recall 30/31 = 0.968, every status as labelled;
  - OWASP NodeGoat (`c5cb68a`): all 20 routes found.
- Verified: lint/types clean; 528 unit; 80 db, 2 skipped; perf 4 passed; migration round trip and `alembic check` clean; the X0 re-run differs from `BASELINE.md` only by the differences recorded on day 1 (the pooled table is identical).
- **For the owner:**
  - F-3-1 (Joern spike), plus the open F-1-1, F-1-2, F-2-1 in `docs/auto/FLAGS.md`;
  - no new local tasks; L-7 now also covers `/scans/{id}/routes`.


## Auto session day 2 (2026-10-27, cloud, branch `extended_phase_auto`)
- **Verdict COMPLETE.** Report: `docs/auto/DAY_2_REPORT.md`; plan: `DAY_2_PLAN.md`.
- **X3 part 2** (`PHASE_X3.md` part 2, ADR-0020, no migration):
  - **bug found by the new property test:** hypothesis paths could lower other findings' scores, by crowding inferred paths out of the top 3 or by taking over an EXPLOIT edge;
  - I\* now comes from a search over the edges of at least inferred; hypotheses are only listed;
  - `/attack-paths` is grouped by assurance, then score, and every path has `missing_evidence[]`;
  - a manifest identity can declare `owns: [{file, line?, family?}]`, which makes that key's credential edge verified;
  - perf: build + search 0.63 s at 5k/20k.
- **X4 part 1** (`PHASE_X4.md`, ADR-0021, no migration):
  - RiskGraph's own taint catalogue, from which 10 Semgrep taint rules are generated (committed, drift-tested);
  - taint traces are kept as location-only steps;
  - a tier-1 hit is `taint_flow` evidence, inferred, and it merges with a generic finding at the same sink;
  - the 40-case suite and its scorer are built.
  - **Tier 1 is off by default** (F-2-1) until the rules have run on the real Semgrep (L-4).
- Verified: lint/types clean; 472 unit; 78 db, 2 skipped; perf 4 passed; migration round trip and `alembic check` clean; the X0 re-run differs from `BASELINE.md` only by the day-1 differences already recorded (the pooled table is identical).
- **For the owner:**
  - flags F-1-1, F-1-2 (day 1) and F-2-1 (tier 1 default) in `docs/auto/FLAGS.md`;
  - L-4 has exact steps;
  - **the Joern spike (L-2) is needed before day 3**, otherwise day 3 flags F-3-1 and moves to X5;
  - one commit (`ea5a710`) was pushed with a db test pinning the old order; it was fixed in the next commit (`eb26c3b`).


## Auto session day 1 (2026-10-26, cloud, branch `extended_phase_auto`)
- **Verdict COMPLETE.** Report: `docs/auto/DAY_1_REPORT.md`; plan: `DAY_1_PLAN.md`.
- **X2 part 2 (image scanning)** (`PHASE_X2.md` part 2, ADR-0018 amendment, migration `b8d3f1a6c2e9`):
  - a `scan_images` stage between collect and analyze runs `trivy image` on up to 5 allowed references (warnings only);
  - image packages become `sca` findings marked with the image, with n/a reachability and `image_package` evidence;
  - an end-of-support base OS becomes `runtime-eol:os:*`;
  - the SBOM has `image`, and `GET /scans/{id}/sbom` has `origin`;
  - an image finding is only marked fixed when its image is rescanned.
- **Bug fixed:** Trivy failed in every docker-runner scan since X2 part 1 (`TRIVY_CACHE_DIR` was not on the container env allow-list). Please confirm live (L-9).
- **X3 part 1** (`PHASE_X3.md`, ADR-0019):
  - without manifest services, the graph comes from Compose and Kubernetes: services, images, ServiceAccounts, RBAC sinks;
  - inferred exposure;
  - EXPLOIT is capped at inferred, and image findings are hypotheses unless they are in KEV;
  - manifest graphs are unchanged.
- Verified: lint/types clean; 421 unit; 77 db, 2 skipped; perf 2 passed; migration up/down/up and `alembic check` clean; X0 re-run byte-identical to the start of the day (pooled table = `BASELINE.md`).
- **For the owner:**
  - flags F-1-1 (data stores from Compose: NodeGoat needs it) and F-1-2 (CAN_ACCESS from RBAC), in `docs/auto/FLAGS.md`;
  - local tasks L-3, L-8, L-9 in `docs/auto/LOCAL_TASKS.md`;
  - the dev DB needs `make dev` for `b8d3f1a6c2e9`;
  - commit `d701718` (the day-1 plan) has the sandbox's default author; later commits use the run book's identity.


## Session 8, part 3: X2 part 1, runtime EOL and freshness (2026-10-25, local)
- **Owner decisions (2026-10-25), recorded in ADR-0018:** image package CVEs stay `sca` (marked with the image); image pulls only from a public registry allow-list (5 images, 2 GB each, never fail the scan); runtime EOL gets an interim score until X6.
- **Done** (`docs/phases/PHASE_X2.md`, migration `a7c2e9f4b1d6`):
  - new `modules/runtime`: image references with the allow-list, runtime declarations (exact pins only produce findings), and endoflife.date cycles refreshed daily by Beat into `runtime_eol`;
  - `runtime` findings come from a per-scan `riskgraph` producer run (no report; excluded from the final status);
  - `container_image` assets;
  - Trivy DB time and EOL fetch time as `data_as_of`, plus `summary.freshness`;
  - model `v1-ctx.3` (also covers X1's gate).
- Verified: `make lint` clean; 382 unit tests; 66 db tests, 2 skipped; migration round trip; `alembic check` clean; the X0 re-run differs only in C's key (X1).
- **Next: X2 part 2:** a `trivy image` and `syft` stage in the egress profile, a recorded image fixture, and overhead measured. It pulls public images (python:3.8-slim, node:14) once to record the fixtures.
- The dev DB needs `make dev` to apply `f3a9c1d7b2e8` and `a7c2e9f4b1d6`. Stop the test stack first (same ports). EOL findings appear after the first daily refresh (or run the `riskgraph.runtime.refresh_eol` task once).

## Session 8, part 2: X1 evidence and assurance (2026-10-25, local)
- **X1 done** (`docs/phases/PHASE_X1.md`, ADR-0017, migration `f3a9c1d7b2e8`). New `modules/evidence`. Every graph edge has an assurance level (verified, inferred or hypothesis) and evidence ids, and the builder refuses an edge without them. Findings have stored evidence (scanner matches and reachability). The API serves `evidence[]`, path `assurance`, and edge `assurance` and `evidence_ids`.
- **Intended score change:** credential-family AUTHENTICATES_AS edges are hypotheses and no longer raise I\*. On the X0 scenarios only C's AWS key changes (99.61 → 62.26, still Critical). The pooled metrics are unchanged, and `BASELINE.md` stays frozen.
- P12: path assurance is in the evidence pack; the prompt is now `explain.2` (cached explanations regenerate). Live check: validated in 18.2 s.
- Verified: `make lint` clean; 358 unit tests; 62 db tests, 2 skipped; migration up/down/up; `alembic check` no drift; `make test-llm` 2 passed (model unloaded afterwards).
- **Your dev DB is still at `e1b7d3a9c2f4`.** The next `make dev` applies `f3a9c1d7b2e8` and backfills assurance on the existing edges.
- Open for later phases: there is no way to make a credential link verified yet (the manifest only lists families; X3); RawRef points at the whole report; `runtime`/`authz` scoring is X6.

## Session 8 (2026-10-25, local)
- **X0 done** (`docs/phases/PHASE_X0.md`): `backend/evaluation/{run,metrics,baselines,report}.py`, `make eval-baseline` → `docs/evaluation/BASELINE.md` (byte-identical on rerun).
- Pooled baseline, 59 findings and 7 important: nDCG@10 M1 0.293, M2 0.162, M4 0.991 (CIs in the report). Construct bias and a low positive rate are written up as limits.
- `make eval-baseline` needs `make test-services` and empties `riskgraph_test` (it refuses any DB not named `*_test`).
- Verified: `make lint` clean; 322 unit tests; 57 db tests, 2 skipped. Committed locally, not pushed.
- **Explanation model lifecycle** (`infrastructure/scripts/llm.sh`, `PHASE_12.md` §L): `make dev` loads `qwen3:4b` (GPU+CPU, resident); `make down`/Ctrl-C unload it. Containers reach Ollama through `.data/ollama/ollama.sock` (needs `socat`), because `ufw` blocks container-to-host TCP. `make llm-status` shows it.
  - Verified: load/unload, the up-then-down race, `make test-llm`, and the **full stack** (`make dev-detached`): readyz ok, dev DB migrated to `e1b7d3a9c2f4`, the `api` container reaches the model through the socket (0.8 s), the `worker` sees the socket. Not yet done: a real scan and the Explanation panel in the UI.
  - **Gotcha (cost a failed first run):** the test stack (`make test-services`) and the dev stack both bind 15432/16379. If both are started, the dev `postgres`/`redis` containers come up *without a network*, and `migrate` fails with `failed to resolve host 'postgres'`. Fix: `docker compose -f docker-compose.test.yml down`, `make down`, `make dev-detached`. Run `make test-services` only while the dev stack is down.
  - `make down` and `make nuke` were broken from a fresh shell (Compose demanded `RISKGRAPH_HOST_DATA_DIR` even to stop); fixed with dummy values, and they now always unload the model.
- **Next: X1 contracts** (ADR-0017, `modules/evidence`, migration). Owner items unchanged (push, PR #2, dev DB migrate, P2 auth).


## Session 7 (2026-10-25, local)
- **Branch** `mvp-level2-integration`, all committed locally. **Not pushed** (owner approved local commits per phase only). PR #2 untouched.
- **Phases done, one chapter each (`docs/phases/PHASE_07.md` … `PHASE_12.md`):**
  - P7 (`08d5181`): Kubernetes Service/Ingress/RBAC per workload; RBAC privilege scored; `GET /scans/{id}/sbom`.
  - P8 (`bc34f75`): Semgrep findings mapped to the enclosing function (SAST L3 via the call graph). Semgrep `generic.secrets` are now secrets, so the old "secrets show unknown" bug is fixed. L3 in the UI.
  - P9 (`43c03e3`): graph invariants enforced (unknown-identity, repository node); `GET /scans/{id}/graph/reach` (recursive CTE); `to_networkx`.
  - P10 (`91d5219`): hop pre-filter. Yen was 11 s with 0 paths at 5k/20k; it is now 0.06 s. Scenario E; a brute-force property test.
  - P11 (`e9fa0f6`): `GET /risks`, `GET /risks/{id}`; scenarios A–E pinned; monotonicity and reduction properties.
  - P12 (`943be49`): AI explanations (ADR-0016, migration `e1b7d3a9c2f4`). Live with `qwen3:4b`: validated in 17.7 s; template fallback when the model is unreachable.
- **Verified at `943be49`:** ruff and mypy clean; 306 unit and 56 db passed (2 e2e skipped: no host scanners); `make test-llm` 2 passed; `alembic check` no drift; frontend lint, typecheck, 10 Vitest tests and build passed.
- **Expansion plan** `docs/proposals/EXPANSION_A-D.md`: approved by the owner. **Phases only, no timings** (owner's rule). Build X0 → X8 in order; items marked "deferred" stay deferred.
- **Not done / for the owner:**
  - Dev DB not migrated to `e1b7d3a9c2f4` (stack not running; `make dev` migrates).
  - ~~Containers reach the host's Ollama only if it listens on `172.17.0.1`~~: solved in session 8 with a socket (see Session 8).
  - P2 auth is still missing.
- **New commands:** `make test-llm` (real local model). `make test-db` now excludes `llm`.
- **In progress: expansion X0, part 1 committed** (baseline dataset and metrics). Exact state and next steps: **`todo1150.md`**.
  - Files so far: `backend/evaluation/{__init__,scenarios,record}.py` and a refactor of `backend/tests/fixtures/scanners/record.py` (`record_repo`, `clean_tmp`).
  - All five scenarios recorded (fixtures and intel snapshot committed). Next: label check, `run.py`, metrics, baselines.

---
## Session 6 (2026-10-23, local): containers, SBOM, NVD, L3 — UNCOMMITTED
- **Nothing from this session is committed or pushed.** Branch `mvp-level2-integration` is still at `8e8c4db` (housekeeping). Review, then commit in logical pieces.
- **Built and verified here:**
  - P3: `DockerRunner` with the blueprint §9.3 profile, socket proxy, slot cap, cancel, reaper. ADR-0014. Chapter `docs/phases/PHASE_03.md`.
  - P4: five pinned, checksum-verified scanner images plus `git-fetcher`; Syft adapter; fixtures re-recorded from the images. Chapter `PHASE_04.md`.
  - P5: SBOM (`sbom_components`), Trivy→Syft attachment. Chapter `PHASE_05.md`.
  - P7 (partly): NVD refresh by Beat; Kubernetes and Compose extraction; `GET /repositories/{id}/context`. No Terraform (stretch). Chapter `PHASE_07.md`.
  - P8 (partly): L3 for Python (call graph, `vulnerable_symbols.yaml`, blind-spot tests). ADR-0015. Chapter `PHASE_08.md`.
- **Verified:** unit 242+ tests, db 32+ tests, ruff and mypy clean. Live `make dev` NodeGoat scan through all five containers: COMPLETED, 124 findings, zero workspace residue.
- **Migrations applied to the dev DB:** `5c1e0a9d2f47`, `9a4d2c7e1b30`, `c4f0a7e2d913` (head).
- **Gotchas found this session (keep these):**
  - `/tmp` is a 7.8 GB tmpfs. Test temp trees used to fill it; `conftest` now removes them at exit.
  - Scanner containers write files as uid 65534. Cleanup needs `discard_workspace` (widen, then remove). Tools may tighten their own cache dirs to 0700, so the worker widens its own dirs first.
  - The egress network `riskgraph_egress` must exist before the stack starts; `make dev` creates it.
  - The Trivy image needs `ca-certificates` in its runtime stage, or the DB download fails TLS.
  - The reachability extractor has no scanner image, so it must always use the subprocess runner. Running it through the container runner made every reachability result `unknown` (regression test: `test_reachability_still_runs_when_scanners_are_containers`).
  - One active scan per repo and ref: a test that leaves a scan `SCANNING` makes later scans dedupe onto it. Close scans in tests.
- **Open issues, in priority order:**
  1. Semgrep's `generic.secrets` private-key rule is typed SAST, so its reachability is `unknown`, where secrets should be `n_a`.
  2. Frontend does not show the L3 tier yet.
  3. `GET /scans/{id}/sbom` endpoint is not written (data is in `summary.sbom`).
  4. Semgrep findings are not mapped to enclosing functions (blueprint §10.2).
  5. A db test for the context endpoint is missing.
  6. `docker/scanner-versions.env` pins Semgrep and Checkov from PyPI without hashes.
- **Decisions taken without asking (review):** NVD refreshed by Beat only, never on the scan path (ADR-0015). Fetcher runs as the worker uid (ADR-0014). Semgrep's pinned rule set changed one expected count (`test_merge.py` now expects three rules on one line).

---


## Session 5 (2026-10-22, local): integrate, fix CI, graph — current state
- **Branch:** `mvp-level2-integration` at `74b40f3`, pushed. It is `cloud-mvp-integration` (`1ccaa41`) plus `mvp-level2-extended` (`392e68f`, a fast-forward), then the fixes and the graphify commit. `main` is still at `8fa3a97`.
- **PR:** draft **#2** `mvp-level2-integration` → `main`. CI green on `74b40f3`: backend, frontend, security-self-scan, images. Mark ready and merge when you're happy. **PR #1** (`claude/great-mendel-b58dhj`) is superseded by #2 and still open; close it after #2 merges.
- **CI fixes (`d253adc`, `e708cbb`):**
  - `aquasecurity/trivy-action@0.28.0` no longer exists upstream; pinned to v0.36.0 by commit `ed142fd0…`. This was why the security and image jobs died at setup.
  - The image scan then found a **critical** advisory in `certifi 2026.7.22` (GHSA-6q48-6c7w-9gw2, emSign CA keys). Bumped to `2026.10.19`, which is two days old at the time.
  - `httpx2==2.13.1` added as a dev dependency so Starlette's TestClient stops warning about httpx. Its transitive `truststore` is held at `0.10.4`, which is my choice: 0.10.5 was under two weeks old and I didn't check with you before holding it back.
  - `make test-db`, `test-all` and `e2e` now read the database and Redis ports from `.env` (`15432`/`16379` here).
- **Verified here:** ruff, format and mypy clean; 192 unit tests passed; 32 db tests passed (2 e2e skipped: no scanners on the host); migration round trip; frontend lint, typecheck, 8 tests, build, npm audit 0.
- **Verified live (`make dev`, Docker):** all services healthy; migration at head `b7dac1b028da`; readyz OK. Live scan of OWASP/NodeGoat: COMPLETED, 124 findings (1 critical), reachability L0 4 / L1 3 / L2 37 / unknown 74. A rescan showed 0 new, 0 fixed, 124 existing, and the gate went from fail to pass after one finding was marked `accepted_risk`.
- **Not verified:** attack paths on a live scan. NodeGoat has no `riskgraph.yaml`, so its graph is empty. The DB tests cover the path logic. Scanning a repo with a manifest would close this.
- **Dev DB leftovers:** two NodeGoat scans and one `accepted_risk` finding (reason "integration test").
- **graphify:** `graphify-out/` built: 2021 nodes, 5827 edges, 91 communities. Committed in `74b40f3` with the `CLAUDE.md` section, `.claude/settings.json` hook-guards and `.gitattributes`. The graph was built by Claude subagents over the docs and the AST over code; the Gemini extraction was discarded as too sparse.
  - The git post-commit hook rebuilds the graph after every commit and leaves uncommitted changes in `graphify-out/`. How to handle this is still undecided (see Open items).
  - `.claude/settings.json` points at `/home/jojo/.local/bin/graphify`, which only exists on this machine.
- **Gotchas found this session:**
  - Dev and test compose both bind 15432/16379 from `.env`. Run one stack at a time; `make test-db` works while `make dev` is up.
  - Starlette 1.6.0 still emits one `anyio` deprecation warning. Starlette 1.7+ removes it.
- **Next:** Phase 2 auth (`docs/adr/0004-auth-model.md`); it gates hosted CI and webhooks.

## Open items (decide before Phase 2)
- Graphify post-commit hook: keep it and ignore its outputs (add `.pending`, `.sig` and the dated snapshot folder to `.gitignore`), or remove it with `graphify hook uninstall` and rebuild by hand with `graphify update .`.
- Commit the rebuilt `graphify-out/graph.json`, or leave it uncommitted. Cloud sessions only see it if it is committed.
- Move `.claude/settings.json` to `.claude/settings.local.json` if its machine-specific graphify path is a problem for cloud sessions.
- Mark PR #2 ready, merge to `main`, and close PR #1.
- `docs/TECH_STACK.md` dependency log is still not created (see the session 1 open items).

---

## Session 4 (2026-10-22, cloud): MVP level 2 extended, done
- Branch `mvp-level2-extended`, cut from `cloud-mvp-integration`. Chapter: `docs/phases/PHASE_MVP2_EXT.md`. Decisions: ADR-0012 (reachability L0–L2) and ADR-0013 (graph and attack paths, effective impact, triage, history, CI gate).
- **Added:**
  - tree-sitter reachability in an isolated subprocess (R factor, L0 ceiling), model `v1-ctx.2`;
  - per-scan security graph and Yen top-3 attack paths, with I* effective impact;
  - triage with `audit_logs`; new / existing / reopened / fixed; diff; repository trend;
  - gate endpoint and CLI;
  - UI: attack paths panel, Cytoscape graph (lazy), triage panel, repository page.
  - One migration: `b7dac1b028da`.
- **Verified here:** 192 unit, 32 db and 2 e2e tests with the real scanners; frontend gates; live scans of NodeGoat and terragoat plus the kitchen sink with a manifest; the CLI gate; Playwright screenshots. **Not verified:** `make dev` with Docker.
- **Next:** Phase 2 auth (it gates hosted CI and webhooks), Phase 3 DockerRunner, Phase 7 IaC topology (paths without a manifest), Phase 8 L3.

---
# Session 3 handoff (2026-10-21, session 3: MVP level 2)

## Session 3 (2026-10-21): run, debug, MVP level 2 (context-aware scoring), done
- Branch `cloud-mvp-integration` (main + the cloud MVP merge `3c44f97` + this work). Chapter: `docs/phases/PHASE_MVP2.md`. Decision: ADR-0011.
- **Level 2:** `riskgraph.yaml` manifest (strict, hardened) plus repository visibility give X/D/P/C per finding. Model `v1-ctx.1`, identical to `v1-cf.1` without context. Context panel in the UI; the drawer shows the factor origin.
- **Bugs fixed:** non-trivy scanners crashed on a non-root host because the pipeline created the Trivy cache dir for every scanner; `tsconfig.app.tsbuildinfo` was tracked.
- **Verified on the dev machine:** 165 unit + 24 db tests, frontend gate, `docker compose build` (incl. worker image with scanners). **Not yet run:** `make dev` with a live scan.
- **Next:** Phase 2 (auth) is still required before anything but localhost. Then Phase 7 proper (IaC/Compose/K8s extraction under the manifest, conflict flag for T-12) and Phase 8 (reachability, the last unknown factor R).

---
# Session 2 handoff (2026-10-21)

## Session 2 (2026-10-21): MVP vertical slice, done
- Branch `claude/great-mendel-b58dhj`. The owner asked for an MVP ahead of the roadmap: a GitHub URL goes in; Trivy, Semgrep, Checkov and Gitleaks run; reports are normalized and merged; findings are scored; a FastAPI + React UI shows the result. Full chapter: `docs/phases/PHASE_MVP.md`. Decisions: ADR-0009 (subprocess runner) and ADR-0010 (scope deviations, including **no auth**).
- Verified in a cloud container without Docker: 123 unit, 22 db and 1 e2e test (real scanners), plus a live Celery run on terragoat. **Not verified:** `make dev` with the new `worker` image target. Run it on the dev machine first.
- **Next:** Phase 2 (auth skeleton) on top of migration `fc3b3ff80221`, then Phase 3 (DockerRunner behind `ScannerRunner`, the ADR-0009 trigger).
- Host runs need scanners: `make scanner-tools` installs them into `~/.local/share/riskgraph-tools`.

---
# Session 1 handoff (2026-09-19)

## Where things stand
- **Blueprint complete** (`docs/blueprint/00–08`), **Phase 0 done** (`docs/PROJECT_SPEC.md`, `docs/THREAT_MODEL.md`, `docs/adr/0001–0008`, `docs/phases/PHASE_00.md`), **Phase 1 done and verified** (`docs/phases/PHASE_01.md`).
- Commits: `da286b2` (blueprint, Phase 0, Phase 1 code) and `1c2ac72` (Phase 1 chapter, HANDOFF.md, workdone.md, README port note). Working tree was clean at end of session.
- **Next step: `START PHASE 2`** — domain model, Alembic migrations for V1 tables, auth skeleton (users/roles/JWT/refresh/API keys), repositories module. Design: `docs/blueprint/02_DATA_AND_API.md` §16–17, ADR-0003/0004/0008.

## This machine (important, non-obvious)
- Other projects occupy the default ports (native Postgres on 5432, `hma-postgres` on 5433, `dna-stego-*` on 8000 and 5173, Supabase on 5432x). **Do not stop those containers.**
- RiskGraph therefore uses, via `.env` (git-ignored, already created with a generated dev secret):
  `POSTGRES_PORT=15432  REDIS_PORT=16379  API_PORT=18000  FRONTEND_PORT=15173`
- URLs: API http://127.0.0.1:18000/api/v1/healthz · Swagger http://127.0.0.1:18000/api/v1/docs · Dashboard http://127.0.0.1:15173
- The Compose stack (`riskgraph-*` containers) was left **running** at the end of the session. `make down` stops it; `make dev-detached` restarts it.
- Host toolchain verified: Python 3.13 (uv creates a 3.12.13 venv in `backend/.venv`), uv 0.11.28, Node 20.19.2, npm 9.2, Docker 29.6.2, Compose 2.26. RAM 15 GB (only ~3 GB free with everything running).

## Commands that are known to work
```bash
make dev-detached                       # full stack in background
docker compose ps                       # expect: postgres/redis/api/worker healthy, migrate Exited(0), beat/frontend Up
curl -s 127.0.0.1:18000/api/v1/readyz  # {"status":"ok","checks":{"database":"ok","redis":"ok"}}
cd backend && uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest -m "not db and not docker" -q
make test-db                            # reads .env ports; needs make dev or make test-services running
cd frontend && npm run lint && npm run typecheck && npm run build
docker compose exec api python -c "from riskgraph.entrypoints.worker import ping; print(ping.delay().get(timeout=20))"   # pong
```

## Gotchas already hit (so you don't hit them again)
1. Mounting `./backend:/app` shadows the image venv → `exit 127`. Compose mounts `riskgraph/`, `alembic/`, `alembic.ini`, `tests/` only. Keep it that way when adding folders (add a new mount line per new top-level backend folder).
2. `pyproject.toml` must not reference `../README.md` (hatchling).
3. `conftest.py` sets `RISKGRAPH_ENV=test`; unit tests that assert on `env` must pass it explicitly.
4. Frontend: TypeScript 7 is on npm but typescript-eslint 8.70 needs <6.1 → TS pinned `^5.9.3`. Bump dev deps by editing `package.json` and clean-installing, not with `npm install -D a@latest b@latest …` (ERESOLVE).
5. Worker/beat must not inherit the image HTTP healthcheck (already handled in Compose).
6. `ruff` on the host PATH is an ancient 0.0.291; always use `uv run ruff`.

## Open items (small, do at the start of Phase 2)
- Verify `.pre-commit-config.yaml` hook revs (`uvx pre-commit autoupdate`) and the GitHub Action versions in `.github/workflows/ci.yml` (`setup-uv@v5`, `trivy-action@0.28.0`, `gitleaks-action@v2`, `build-push-action@v6`) against current releases. They are BELIEVE, not verified.
- Push to a GitHub remote and watch CI go green once.
- `docs/TECH_STACK.md` (dependency log per kit doc 04) not yet created; `docs/blueprint/04_TECH_STACK.md` holds the decisions. Create it when Phase 2 adds its first dependencies (`pwdlib[argon2]`, `PyJWT`).

## Rules of engagement (from the brief and CLAUDE.md)
- Implement one phase per `START PHASE N`; each phase writes `docs/phases/PHASE_NN.md` with chapters A–S.
- Never re-decide an ADR; write a superseding one.
- Report with VERIFIED / CONFIDENT / BELIEVE / GUESS labels; paste real output.
