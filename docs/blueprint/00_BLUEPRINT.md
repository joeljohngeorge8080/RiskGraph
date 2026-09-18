# RiskGraph — Master Blueprint (v0.1, 2026-09-19)

> Context-Aware Security Risk Prioritization and Attack-Path Analysis Platform.
> Final-year B.Tech CSE project. Solo developer, 7–9 months, near-zero cloud budget.
>
> This folder is the pre-implementation blueprint. It is the reference every phase
> reads before writing code. Decisions here are frozen unless superseded by an ADR
> in `docs/adr/` (created in Phase 0).

| File | Sections of the brief it answers |
|---|---|
| `00_BLUEPRINT.md` (this file) | 1 Executive summary · 2 Problem · 3 Scope · 4 Non-goals · 5 Contribution · 28 Demo · 29 Risks · 30 MVP |
| `01_ARCHITECTURE.md` | 6–15: system, components, data flow, orchestration, normalization, context, graph, attack paths, risk engine, AI |
| `02_DATA_AND_API.md` | 16 Database · 17 API · 18 Frontend · 19 CI/CD |
| `03_THREAT_MODEL.md` | 20 Security threat model (STRIDE) |
| `04_TECH_STACK.md` | 21 Technology selection with alternatives |
| `05_REPO_STRUCTURE.md` | 22 Repository structure |
| `06_ROADMAP.md` | 23 Phase dependency graph · 24 Phase roadmap |
| `07_TESTING_AND_EVALUATION.md` | 25 Testing strategy · 26 Research evaluation |
| `08_DEPLOYMENT.md` | 27 Deployment architecture · NFRs · failure handling |

Evidence labels used throughout: **VERIFIED** (checked this session), **CONFIDENT**
(strong inference), **BELIEVE** (training memory, unchecked), **GUESS** (pattern).
Anything labelled BELIEVE about a tool's exact flags or output format must be
re-verified against the pinned tool version in the phase that uses it.

---

## 1. Executive summary

RiskGraph is a self-hosted platform that sits **above** open-source security
scanners. On a push, pull request, schedule or manual trigger it clones a
repository into an isolated workspace, runs Trivy, Semgrep, Gitleaks, Checkov and
Syft in locked-down containers, normalizes their outputs into one canonical
finding model, enriches findings with exploit likelihood (EPSS, CISA KEV), code
reachability (import/call-graph analysis), network exposure, identity privilege
and data sensitivity, projects everything into a security graph, searches that
graph for attack paths from the Internet to sensitive sinks, and scores each
finding with a deterministic, explainable contextual risk model. An LLM then
turns the structured evidence into a plain-language explanation. Results reach
developers through a React dashboard and a GitHub Actions check that can warn or
fail a pipeline on a configurable risk threshold.

The engineering thesis: **a finding's practical importance is a property of the
system it lives in, not of the CVE record.** The research thesis: contextual,
graph-based prioritization ranks practically important findings higher than
CVSS-only and CVSS+EPSS baselines, measured with Precision@K, nDCG@K and
analyst-effort metrics on controlled datasets.

What it is not: a scanner, a CVSS calculator, a CRUD dashboard, or an LLM wrapper.
AI never decides risk; it only narrates evidence produced by deterministic code.

## 2. Exact problem definition

A modern repository produces findings from five tool categories (SCA, SAST,
secrets, IaC, SBOM). Each tool has its own schema, severity vocabulary and
false-positive profile. Teams therefore face four concrete problems:

1. **Orchestration cost.** Each tool has to be installed, run, updated and its
   output parsed. In practice most get run rarely or not at all.
2. **Severity ≠ risk.** CVSS describes the vulnerability in isolation. It does not
   know whether the vulnerable code is reachable, whether the service is
   Internet-facing, what identity it runs as, or what data sits behind it.
   The result is alert fatigue: hundreds of "Critical" findings with no ordering
   that reflects real exposure.
3. **No correlation.** A medium-severity SSRF, an over-privileged IAM role and a
   PII database are three separate rows in three tools. Together they are one
   attack path. No open-source tool joins them.
4. **No explanation.** Even when a tool ranks a finding, developers get a severity
   label, not the reason the finding matters *here*.

RiskGraph's job is to solve exactly these four problems for a single
self-hosted organization, on commodity hardware, using only open-source
scanners and public vulnerability data.

**Motivating example (retained from the original spec):** Finding A is a
CVSS 9.8 CVE in a dependency the application never imports, on an internal
batch service. Finding B is a hard-coded cloud credential in an Internet-facing
frontend bundle, with no CVE at all. CVSS-only ordering puts A first and B
nowhere. RiskGraph must put B first and explain why.

## 3. Scope (what V1 delivers)

| Area | In scope for V1 |
|---|---|
| Triggers | GitHub push webhook, pull request webhook, cron schedule, manual API/dashboard trigger, GitHub Action (polling mode) |
| Scanners | Trivy (fs + image), Semgrep (bundled rule packs), Gitleaks, Checkov, Syft — each in an isolated container with limits |
| Languages for reachability | Python (function-level call graph); JavaScript/TypeScript (import-level in MVP, function-level stretch) |
| Context sources | NVD/CVSS, FIRST EPSS, CISA KEV; a `riskgraph.yaml` context manifest in the repo; extraction from Kubernetes manifests, Docker Compose and Terraform (exposure, identities, data stores) |
| Graph | Per-scan security graph persisted in PostgreSQL, analysed in-process with NetworkX |
| Attack paths | Internet → … → sensitive sink, likelihood-weighted shortest and top-k paths |
| Risk engine | Deterministic hybrid model, 0–100 score, four priority bands, per-factor evidence |
| AI explanation | Ollama (local) and Anthropic API adapters; schema-validated output; deterministic fallback |
| Dashboard | Overview, repositories, scans, findings list/detail, risk ranking, attack paths, graph view, SBOM, secrets, IaC, scan status, explanations (13 views; 9 in MVP, see §30) |
| CI/CD | Reusable GitHub Action, PR check + comment, configurable warn/fail policy |
| Security | JWT auth, RBAC (4 roles), API keys for CI, HMAC webhook verification, rate limiting, audit log, scanner sandboxing, secret redaction |
| Evaluation | Scenario dataset with constructed ground truth; two real vulnerable apps with blind expert labels; three ranking methods compared |
| Deployment | Docker Compose (dev + prod profile), Caddy TLS, optional single AWS EC2 VM, nightly backups |

## 4. Non-goals (stated so nobody expects them)

- **Not a scanner.** RiskGraph finds nothing by itself; it orchestrates and reasons.
- **Not multi-tenant SaaS.** One instance = one organization. No `org_id` on every
  table. (Retrofit cost is accepted and documented; see ADR in Phase 0.)
- **Not dynamic analysis.** No DAST, no runtime instrumentation, no exploit
  execution. Reachability is static and has documented blind spots.
- **Not zero-day detection.** Non-CVE findings are handled via rule severity; true
  zero-day discovery is out of scope for static analysis.
- **Not a cloud-account scanner.** Exposure/identity context comes from IaC and
  the manifest, not from live AWS/GCP/Azure APIs. (Live cloud graphing is what
  Wiz/Orca do; it needs credentials and budget we do not have.)
- **Not auto-remediation.** No PRs with fixes. The scanner's remediation text is
  surfaced; nothing is applied.
- **Not GitLab/Bitbucket.** GitHub only. The webhook module is the seam for others.
- **Not Java/Go/C reachability.** Unsupported languages get reachability = unknown.
- **Not an enterprise graph database.** See `04_TECH_STACK.md` for why Neo4j is rejected.

## 5. Novelty and technical contribution (honest version)

No single component of RiskGraph is new. The contribution is an **open,
reproducible, evaluated integration** of components that today exist only in
closed commercial products or as isolated pieces.

| Capability | DefectDojo | Dependency-Track | OWASP dep-scan | Snyk / Wiz / Orca | RiskGraph |
|---|---|---|---|---|---|
| Multi-scanner ingestion & dedup | ✅ | SBOM only | partial | ✅ | ✅ |
| Automated scanner orchestration (sandboxed) | ❌ (import only) | ❌ | CLI | ✅ (SaaS) | ✅ |
| EPSS / KEV enrichment | ✅ | ✅ | ✅ | ✅ | ✅ |
| Code reachability | ❌ | ❌ | partial (Java/Python) | ✅ (proprietary) | ✅ tiered, open |
| Exposure / identity / data context | ❌ | ❌ | ❌ | ✅ (live cloud) | ✅ (IaC + manifest) |
| Cross-domain security graph (code + infra + identity + data) | ❌ | ❌ | ❌ | ✅ | ✅ |
| Attack-path discovery | ❌ | ❌ | ❌ | ✅ | ✅ |
| Explainable, documented risk formula | ❌ | ❌ | partial | ❌ (opaque) | ✅ |
| Evaluation against CVSS baselines | — | — | — | — | ✅ |
| Open source, self-hosted, zero budget | ✅ | ✅ | ✅ | ❌ | ✅ |

Academic lineage to cite: attack graphs (MulVAL, Ou et al. 2005), EPSS (Jacobs
et al. 2021), SSVC (CISA), CVSS v3.1/v4.0 specifications, reachability analysis
literature (e.g. "Vulnerable dependency reachability" work behind tools like
Eclipse Steady). RiskGraph's positioning: a **lightweight attack-graph
system for the CI/CD context** that uses static context instead of live cloud
telemetry, and whose risk model is published and testable.

Specific contributions to defend in the thesis:

1. A canonical finding model plus fingerprinting scheme that dedups across five
   heterogeneous scanners without losing scanner-native data.
2. A tiered static-reachability method (L0–L3) with explicit confidence and
   documented blind spots, usable when no proprietary vulnerable-function database exists.
3. A security-graph schema unifying code, dependencies, infrastructure, identity
   and data nodes derived from IaC and a small manifest, and a likelihood-weighted
   attack-path search over it.
4. A hybrid risk model whose context-free case reduces provably to the CVSS+EPSS
   baseline, so every deviation from the baseline is attributable to a named factor.
5. An evaluation protocol with constructed ground truth and blind labels that
   avoids the circularity of using KEV both as a model input and as truth.

## 28. Final demonstration workflow (what the examiner sees, ~12 minutes)

1. **Login** as Security Engineer. Overview page shows two connected repositories.
2. **Connect** a third repository (the `datasets/attack_paths/scenario-e` repo).
   Show the `riskgraph.yaml` manifest declaring an Internet-facing API, an
   admin-ish IAM role and a PII database.
3. **Push a commit** to that repo (from a terminal). GitHub webhook fires; the
   Scans page shows the job moving PENDING → CLONING → SCANNING (five scanner
   cards update live) → ANALYZING → COMPLETED.
4. **Findings page**, sorted by CVSS: a 9.8 CVE in an unreachable dependency is on top.
5. **Risk ranking page**: the same list sorted by RiskGraph score. The SSRF
   finding on the Internet-facing endpoint is now on top; the 9.8 CVE is Low.
   Click the 9.8: factor panel shows "not imported (L0) · internal · limited identity".
6. **Finding detail** for the SSRF: CVSS, EPSS, reachability evidence (call
   chain from `POST /fetch` to `requests.get`), exposure source (K8s Ingress),
   identity, data sensitivity, risk score with the formula terms, remediation.
7. **Attack paths page**: Internet → `api` endpoint → SSRF → `api-role` →
   metadata credentials → `customers-db (PII)`. Path likelihood and sink impact shown.
8. **Graph page**: the path highlighted in the security graph.
9. **AI explanation**: click "Explain". Local model returns a validated
   explanation; each sentence cites an evidence id. Toggle the LLM off: the
   deterministic template explanation still renders.
10. **Pull request**: open a PR that removes the manifest's `auth: none`. The
    GitHub check posts a risk summary comment; policy `warn` passes, then switch
    policy to `fail` and show the check going red.
11. **Evaluation page / notebook**: Precision@5, nDCG@10 and analyst-effort for
    CVSS-only vs CVSS+EPSS vs RiskGraph across the scenario suite, with
    bootstrap confidence intervals.
12. **Kill Ollama and Redis** during a scan to show graceful degradation: scan
    resumes when Redis returns; explanations fall back to templates.

## 29. Project risks and mitigations

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R1 | Scope too large for one person in 7–9 months | High | Fatal | MVP cut in §30; stretch items flagged; phase time-boxes in `06_ROADMAP.md`; dashboard built last against a stable API |
| R2 | Reachability rabbit hole (call graphs are a PhD topic) | High | High | Tiered method: L1 import-level ships first (1 week), L3 function-level only for Python with a curated vulnerable-symbol map; documented blind spots are a *deliverable*, not a failure |
| R3 | Context data does not exist for real repos (no manifest, no IaC) | High | High | Manifest is first-class; IaC extraction covers K8s/Compose/Terraform; `unknown` is a legal value that the risk model handles explicitly |
| R4 | Risk weights look arbitrary to examiners | Medium | High | Equal weights by maximum-entropy argument, geometric/arithmetic split by conjunctive/disjunctive semantics, calibration + sensitivity analysis in Phase 17 |
| R5 | Evaluation circularity (KEV as input and truth) | Medium | High | Constructed ground truth in synthetic scenarios; KEV held out from the model during evaluation on real apps; blind labelling protocol |
| R6 | Scanner output formats change | Medium | Medium | Pin scanner image versions; parser fixtures recorded per version; parser contract tests |
| R7 | Docker socket on the worker is a root-equivalent hole | Medium | High | Socket proxy with allow-list, worker code controls all mounts, scanner containers get no socket; documented residual risk |
| R8 | GitHub cannot reach a laptop for webhooks/actions | High (demo) | Medium | Self-hosted GitHub runner for the demo; webhook via a tunnel only during demo; manual trigger path always works |
| R9 | LLM hallucination in explanations | Medium | Medium | Evidence-id citation validation, numeric cross-check, deterministic fallback; AI is off the critical path |
| R10 | Laptop resources (5 containers + Postgres + Redis + Ollama) | Medium | Medium | Scanner concurrency limit; Ollama optional; 7B model quantized; document minimum 16 GB RAM |
| R11 | Thesis writing squeezed at the end | High | High | Each phase's docs are thesis chapters; Phase 19 assembles, does not write from scratch |

## 30. Definition of the final MVP

The MVP is what must exist for the project to be **demonstrable and defensible**.
Everything else is stretch and is dropped first when time runs out.

**MVP (must):**
- Triggers: manual, GitHub push webhook, GitHub Action polling mode. (Schedule is trivial with Celery Beat; include.)
- All five scanners in sandboxed containers; partial success when one fails.
- Canonical findings with fingerprint dedup across scans and Trivy↔Syft correlation.
- Enrichment: CVSS, EPSS, KEV; manifest-based context; Kubernetes + Compose extraction.
- Reachability: L0/L1 (import-level) for Python and JS/TS; L2/L3 (call-graph) for Python.
- Security graph in Postgres + NetworkX; attack paths (best path per sink, top-3).
- Risk engine with factor evidence and priority bands.
- AI explanation with Ollama adapter, validation and fallback.
- Dashboard: Overview, Repositories, Scans + scan status, Findings, Finding detail, Risk ranking, Attack paths, Graph (basic), Explanations panel inside finding detail. (9 of 13 views.)
- Auth (JWT + refresh), RBAC, API keys, webhook HMAC, rate limiting, audit log.
- Tests: unit + parser fixtures + integration on Compose + security tests; CI green.
- Evaluation on the scenario suite with three methods and confidence intervals.
- Docker Compose prod profile with Caddy TLS; deployment guide.

**Stretch (in priority order):**
1. Terraform context extraction (Checkov output already gives resources; extraction of exposure/IAM is extra work).
2. Function-level reachability for JS/TS.
3. Dedicated SBOM, Secrets and IaC dashboard views (MVP shows them as filters on Findings).
4. Anthropic API adapter (adapter interface exists in MVP; only Ollama is wired).
5. Blind-labelled evaluation on two real vulnerable apps.
6. Prometheus + Grafana profile (metrics endpoint ships in MVP; dashboards are stretch).
7. AWS EC2 deployment with S3 backups.
8. Yen top-k attack paths beyond top-3; privilege-escalation-aware path constraints.
