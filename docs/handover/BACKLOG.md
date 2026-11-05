# Backlog (handover, 2026-11-05)

Pick from the top of each section. Every item says what "done" means. Size is relative (S: one focused change, M: several modules or a migration, L: a phase of its own); there are no calendar estimates. Rules for any item:
- Read `CONTRIBUTING.md` first.
- A new decision gets an ADR.
- A phase gets a chapter in `docs/phases/`.
- An evaluation label is committed before its first run.

Legend for the source column: **X7/X8** = expansion plan (`docs/proposals/EXPANSION_A-D.md`), **P#** = blueprint roadmap (`docs/blueprint/06_ROADMAP.md`), **FAIL** = a measured X8 criterion that fails today, **New** = scope added at handover.

## 1. Before any deployment beyond localhost
| ID | Item | Source | Size | Done when |
|---|---|---|---|---|
| AUTH-1 | **P2 auth skeleton**: users, roles, JWT access and refresh, API keys; every router behind it (ADR-0004; data model in `docs/blueprint/02_DATA_AND_API.md` §16–17). It gates hosted CI and webhooks | P2 | L | Every endpoint except health and `docs` needs a principal; the role checks are tested; migration; `PHASE_02.md` |
| AUTH-2 | Auth hardening and security-controls verification against `docs/THREAT_MODEL.md` | P15 | M | Each threat-model control has a test or a written residual risk |
| DEP-1 | Deployment: production Compose, Caddy, backups, optional EC2 | P18 | L | `docs/blueprint/08_DEPLOYMENT.md` steps run from a clean host; restore tested once |

## 2. Finish the expansion
| ID | Item | Source | Size | Done when |
|---|---|---|---|---|
| X7-1 | **SARIF export with provenance**: `GET /scans/{id}/sarif`. Each result carries its evidence ids, assurance and producer versions; hypotheses become `note`-level results, never errors | X7 | M | Validates against the SARIF 2.1.0 schema; a hypothesis is never `error`; golden test |
| X7-2 | **Gate `--assurance-min`** on the CLI and the gate endpoint: ignore findings and paths below the given assurance | X7 | S | A gate with `--assurance-min inferred` ignores hypotheses (plan X7 test) |
| X7-3 | UI views: assurance badges, flow-step viewer (steps as plain text), route-inventory table, image/runtime panel, "paths to verify". The API already serves the data | X7, P13 | L | Playwright: flow steps render as text; a hypothesis is never styled as a finding |
| X8-1 | **C1, images**: a seeded CVE/EOL list and a frozen Trivy DB digest; `check_images()` in `evaluation/expansion.py` | X8 | M | C1 measured (run book §C) |
| X8-2 | **D1/D3, path truth**: per-edge ground truth for scenarios A–H, written first; path precision and assurance calibration | X8 | M | D1, D3 measured |
| X8-3 | **P2, ablations**: test-only switches −A/−B/−C/−D and an X0 replay per switch | X8 | M | The ablation table is in `EVALUATION_EXPANSION.md` |
| X8-4 | **O1, overhead**: real-scanner timing of the X0 repositories, at the X0 commit and at HEAD | X8 | S | p50 reported; deep profile reported separately |
| X8-5 | **P1 power**: scenarios where findings inside one repository differ in context (two services, exposed and internal parts), labels first | FAIL P1 | M | The paired test can reach p < 0.05; result reported as found |
| X8-6 | Realism: OWASP Juice Shop and one Python vulnerable app, with a blind-labelled subset | X8 | L | Labelled sets committed, metrics reported |
| TAINT-1 | **Allow-list lookups in tier 1**: read `lookup_sanitizers` in the Semgrep rule generator (a `pattern-sanitizers` entry with `metavariable-regex` on the receiver); regenerate `taint_rules.yaml`; re-run the real Semgrep suite | FAIL A3 | S | Tier-1 sanitized flags fall from 5/10; A3 re-measured |
| TAINT-2 | Tier 2 for JavaScript (`jssrc` frontend; the query already has JS sinks from the spike). The plan defers it (§5), but A1 fails without it: owner call | FAIL A1 | M | A1 re-measured; NodeGoat flows match its known `eval` sinks |
| TAINT-3 | Structural sanitizers for every class (today only lookups are structural; the rest match by name anywhere in an element, ADR-0025) | ADR-0025 | M | A hostile case `"…" + str(int(a)) + b` keeps `b` tainted |
| TAINT-4 | "Verified" tier 2: a flow is verified only when every step exists in the code graph (SCHEDULE day 3 rule) | X4 | M | Assurance test with a step that is missing from the graph |
| TAINT-5 | Owner decision, then build: a tier-2 E row in risk model v2 (ADR-0024 table), or keep the SAST row | ADR-0025 | S | ADR amendment; reduction and monotonicity properties still pass |

## 3. Follow-ups from earlier phases
| ID | Item | Source | Size |
|---|---|---|---|
| FU-1 | A probability for UNGUARDED and BOLA_SUSPECT edges, so endpoints can be on paths (today they are not traversable, ADR-0023) | X5 | M |
| FU-2 | Cross-file BOLA (ownership checks in a called service or repository function) | X5 | M |
| FU-3 | Django/DRF and GraphQL in the route inventory and guard catalogue | X5 | M |
| FU-4 | OSV cross-check of Trivy's advisories ("how often do they disagree?") | X8 | S |
| FU-5 | Private registries for image scans (credentials stay out of the worker env) | X2 | M |
| FU-6 | Choke-point metric (betweenness) and "cheapest edge to fix" | D | M |
| FU-7 | Cross-scan, organisation-wide graph: the ADR-0006 trigger for Apache AGE | D | L |
| FU-8 | Dynamic two-user tests for BOLA hypotheses (needs a running target and credentials) | B | L |
| FU-9 | CodeQL as a research oracle on open-source apps only (licence!) | X8 | M |
| FU-10 | `pre-commit-hooks` v5 → v6; Starlette ≥ 1.7 to drop the `anyio` deprecation warning | tooling | S |
| FU-11 | Test consolidation and security validation | P16 | M |
| FU-12 | GitHub Action and webhook integration with policy | P14 | L |
| FU-13 | Documentation, thesis, presentation, demo script | P19 | L |

## 4. New scope for collaborators (added at handover)
These go beyond the expansion plan. Each needs an ADR before code, because each one changes what RiskGraph is.

| ID | Idea | Why it fits | First step | Size |
|---|---|---|---|---|
| NEW-1 | **Java and Go** in reachability (tree-sitter grammars) and tier-2 taint (Joern `javasrc`, `gosrc`) | Most enterprise code; the catalogue shape already supports more languages | Extend `LANGUAGES` in `backend/riskgraph/modules/scanners/semgrep/taint.py` and the extractor; one framework each (Spring, net/http) | L |
| NEW-2 | **Terraform → cloud identity graph**: IAM roles, policies and S3/RDS from Terraform as identity, privilege and data-store nodes | Attack paths today stop at the manifest or Compose/K8s; cloud IAM is where privilege really lives | A `backend/riskgraph/modules/graph/topology.py` derivation from `backend/riskgraph/modules/context/iac.py` Terraform assets, with assurance `inferred` | L |
| NEW-3 | **Policy-as-code gate**: an OPA/Rego (or plain YAML) policy file evaluated on findings and paths in CI | Teams want "fail on new critical path to PII", not severity counts | A gate policy schema next to `riskgraph.yaml`; evaluate it in the existing gate endpoint | M |
| NEW-4 | **Ticketing**: open or update GitHub issues for new Critical/High findings, with the evidence pack as the body | Closes the loop from finding to fix | An outbound integration behind an allow-list, idempotent by merge key | M |
| NEW-5 | **VEX output** with the SBOM (CycloneDX VEX): "not affected" for L0/L1 packages, with the reachability evidence | Reachability is RiskGraph's edge; VEX is the standard way to ship it | Map reachability tiers to VEX states; ADR on what may claim "not affected" | M |
| NEW-6 | **Fix suggestions** in the evidence pack: the fixed version for SCA, the guard to add for authz (template first, model second) | The AI layer explains; a reviewed fix template is the next useful step, still deterministic | Extend `explain` with a template per category; the model only rephrases | M |
| NEW-7 | **Multi-repository view**: one organisation, many repositories, a risk trend per service | Needed by any real user; depends on AUTH-1 | Data model for organisations (ADR-0003 tenancy) | L |
| NEW-8 | **Live Kubernetes inventory** (read-only kubeconfig): compare the deployed state with the manifests | The graph can be wrong when the cluster drifts from Git | A read-only collector with its own threat-model section | L |

## Done in the handover session (for reference)
F-1-1, F-3-1, F-4-1, F-4-2, F-5-1, F-L-1 and F-L-2 are closed. L-5 is measured through the pipeline runner. See `STATE.md`.
