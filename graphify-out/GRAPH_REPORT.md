# Graph Report - riskgraph  (2026-10-23)

## Corpus Check
- 240 files · ~111,035 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 21 file(s) not represented in the graph (top: (none) 12, .Dockerfile 2, .example 1)

## Summary
- 2456 nodes · 6830 edges · 141 communities (105 shown, 36 thin omitted)
- Extraction: 90% EXTRACTED · 10% INFERRED · 0% AMBIGUOUS · INFERRED: 705 edges (avg confidence: 0.91)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `5def368c`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- pipeline.py
- FindingsSection.tsx
- RunSpec
- context/service.py
- ScanWorkspace
- json
- graph/__init__.py
- Findings API and Vocabulary
- test_manifest.py
- Findings Persistence and History
- cli.py
- V1 Data Model Tables
- Severity
- Tech Choices and Threats
- Phase MVP — Scan, normalize, merge, prioritize (vertical slice)
- Scanner Isolation Threats
- conftest.py
- Graph and Reachability ADRs
- Dev Stack and CI Docs
- test_pipeline_db.py
- test_level2_ext_db.py
- Finding Drawer and Triage UI
- Frontend Shell and Routing
- ADR-0010 MVP vertical slice and deviations
- ScanDetailPage.tsx
- trivy/parser.py
- Deployment and Degradation
- Frontend Build Config
- Scans API Router
- PHASE 3: Scanner orchestration engine (hardened DockerRunner)
- Roadmap Phase Graph
- Domain Module Layout
- repositories/router.py
- _Resolver
- Evaluation and Invariants
- AttackPathsPanel.tsx
- docker_runner.py
- test_parsers.py
- Core Architecture ADRs
- db/__init__.py
- Triage and Audit Log
- types.ts
- iac.py
- dataclasses
- SourceType
- os
- TS App Config
- API Auth and Errors Design
- Architecture Scan Flow
- Phase 0 — Project Definition & Threat Model
- Auth and ID ADRs
- Graph API Router
- Spec and Manifest Docs
- test_workspace.py
- CI/CD and Database Design
- default_deps
- orchestration.py
- repositories/router.py
- Attack Graph Research
- Hybrid Risk and AI Explain
- Test Datasets
- TS Node Config
- _record
- Project Risks and Isolation
- Scan Creation and Rate Limits
- Health Endpoint Tests
- Blueprint Overview
- semgrep/parser.py
- UUIDv7 Generator
- test_runtime_db.py
- Graph Schema and Explainer
- Process Architecture
- Thesis and Finding Model
- scans/service.py
- Session 1 handoff (2026-09-19)
- Hosting ADR
- Scanner Installer
- test_docker_runner.py
- pipeline_support.py
- TS Root Config
- Test DB Init
- Evidence Labels
- SSRF-safe HTTP Client
- Backend Package
- test_config.py
- pytest
- health.py
- UUID
- ScanDetailPage.tsx
- vocabulary.py
- Phase 1 — Repository & Development Environment
- checkov/parser.py
- orchestration.py
- ScannerName
- storage.py
- PHASE 4: Scanner adapters (five hardened images)
- api.py
- context/router.py
- kitchen_sink.json
- RiskGraph — AI session entry point
- ADR-0015: L3 reachability by intraprocedural call graph; NVD refreshed by Beat
- test_reachability.py
- sqlalchemy
- level2.test.ts
- PHASE 8: Reachability (L0–L3)
- build-scanner-images.sh
- devDependencies
- redact.py
- test_api.py
- test_scan_state.py
- problems.py
- Scanner
- 20261023_0900_reachability_l3.py

## God Nodes (most connected - your core abstractions)
1. `Settings` - 118 edges
2. `ScannerName` - 86 edges
3. `SourceType` - 80 edges
4. `Severity` - 52 edges
5. `score()` - 38 edges
6. `session_scope()` - 38 edges
7. `ScanWorkspace` - 36 edges
8. `analyze()` - 35 edges
9. `RawFinding` - 33 edges
10. `Priority` - 32 edges

## Surprising Connections (you probably didn't know these)
- `Session 2 (2026-10-21): MVP vertical slice, done` --references--> `ScannerRunner`  [INFERRED]
  HANDOFF.md → backend/riskgraph/modules/scanners/runner.py
- `Verification` --references--> `test_analyze_is_idempotent_and_rescans_reuse_findings()`  [INFERRED]
  docs/phases/PHASE_05.md → backend/tests/test_pipeline_db.py
- `Verification` --references--> `clean_rule_id()`  [INFERRED]
  docs/phases/PHASE_04.md → backend/riskgraph/modules/scanners/semgrep/parser.py
- `Conventions` --references--> `Problem`  [INFERRED]
  CLAUDE.md → backend/riskgraph/shared/problems.py
- `Session 6 (2026-10-23, local): containers, SBOM, NVD, L3 — UNCOMMITTED` --references--> `DockerRunner`  [INFERRED]
  HANDOFF.md → backend/riskgraph/modules/scanners/docker_runner.py

## Import Cycles
- 3-file cycle: `backend/riskgraph/modules/risk/__init__.py -> backend/riskgraph/modules/risk/service.py -> backend/riskgraph/modules/risk/model.py -> backend/riskgraph/modules/risk/__init__.py`

## Hyperedges (group relationships)
- **Analyze stage: context, reachability, attack paths, two-pass scoring** — docs_phases_phase_mvp2_context_resolver, docs_phases_phase_mvp2_ext_reachability_tiers, docs_phases_phase_mvp2_ext_attack_graph, docs_phases_phase_mvp2_ext_two_pass_scoring [EXTRACTED 1.00]
- **Dev Compose stack services sharing the backend image** — docker_compose_migrate, docker_compose_api, docker_compose_worker, docker_compose_beat [EXTRACTED 1.00]
- **Five sandboxed scanner adapters** — docs_blueprint_01_architecture_trivy, docs_blueprint_01_architecture_semgrep, docs_blueprint_01_architecture_gitleaks, docs_blueprint_01_architecture_checkov, docs_blueprint_01_architecture_syft [EXTRACTED 1.00]
- **Evidence-bound LLM explanation with validation and fallback** — docs_blueprint_01_architecture_evidence_pack, docs_blueprint_01_architecture_llm_adapter, docs_blueprint_01_architecture_explanation_validator, docs_blueprint_01_architecture_template_explainer [EXTRACTED 1.00]
- **Production Compose stack** — docs_blueprint_08_deployment_caddy, docs_blueprint_08_deployment_api_service, docs_blueprint_08_deployment_worker_service, docs_blueprint_08_deployment_beat_service, docs_blueprint_08_deployment_redis_service, docs_blueprint_08_deployment_postgres_service, docs_blueprint_08_deployment_migrate_service, docs_blueprint_08_deployment_socket_proxy_service [EXTRACTED 1.00]
- **riskgraph.yaml context model (services, identities, data stores, criticality)** — docs_examples_riskgraph_services, docs_examples_riskgraph_identities, docs_examples_riskgraph_data_stores, docs_examples_riskgraph_criticality, readme_context_aware_scoring [EXTRACTED 1.00]
- **Per-scan analysis data (components, graph, reachability, attack paths, risk scores)** — docs_blueprint_02_data_and_api_table_scan_jobs, docs_blueprint_02_data_and_api_table_components, docs_blueprint_02_data_and_api_table_graph_nodes, docs_blueprint_02_data_and_api_table_graph_edges, docs_blueprint_02_data_and_api_table_reachability_results, docs_blueprint_02_data_and_api_table_attack_paths, docs_blueprint_02_data_and_api_table_risk_scores [EXTRACTED 1.00]
- **Scan pipeline: scanners -> normalization -> enrichment -> graph -> paths -> risk -> explain** — docs_blueprint_01_architecture_scanner_protocol, docs_blueprint_01_architecture_canonical_finding_model, docs_blueprint_01_architecture_context_enrichment, docs_blueprint_01_architecture_security_graph_schema, docs_blueprint_01_architecture_attack_graph_derivation, docs_blueprint_01_architecture_hybrid_risk_model, docs_blueprint_01_architecture_ai_explanation [EXTRACTED 1.00]
- **ScannerRunner seam implementations** — docs_adr_0009_subprocess_scanner_runner_scannerrunner_protocol, docs_adr_0009_subprocess_scanner_runner_subprocess_runner, docs_adr_0009_subprocess_scanner_runner_dockerrunner, docs_adr_0005_hosting_k8sjobrunner [EXTRACTED 1.00]
- **Risk score model evolution v1-cf.1 -> v1-ctx.1 -> v1-ctx.2 -> effective impact** — docs_adr_0010_mvp_scope_context_free_score_v1_cf_1, docs_adr_0011_manifest_context_scoring_v1_ctx_1, docs_adr_0012_reachability_tiers_mvp_v1_ctx_2, docs_adr_0013_graph_paths_triage_history_effective_impact [EXTRACTED 1.00]
- **Authentication and authorization controls** — docs_blueprint_02_data_and_api_auth_jwt_api_key, docs_blueprint_02_data_and_api_rbac, docs_blueprint_02_data_and_api_redis_rate_limiting, docs_blueprint_02_data_and_api_audit_in_transaction, docs_blueprint_03_threat_model_t09, docs_blueprint_03_threat_model_t10, docs_blueprint_03_threat_model_t19 [INFERRED 0.85]
- **Defenses against hostile repository content** — docs_phases_phase_00_hostile_repositories, docs_phases_phase_mvp_safe_resolve, docs_phases_phase_mvp_subprocess_runner, docs_phases_phase_mvp2_ext_extractor_isolation, docs_phases_phase_mvp2_riskgraph_manifest [INFERRED 0.85]
- **Untrusted repository input parsing defenses** — docs_adr_0011_manifest_context_scoring_manifest_hardening, docs_adr_0012_reachability_tiers_mvp_tree_sitter_extraction, docs_adr_0009_subprocess_scanner_runner_hardened_git_clone, docs_threat_model_safe_resolve, docs_threat_model_t_02 [INFERRED 0.85]
- **Risk model version lineage (v1-cf.1 → v1-ctx.1 → v1-ctx.2)** — docs_phases_phase_mvp_risk_model_v1_cf_1, docs_phases_phase_mvp2_risk_model_v1_ctx_1, docs_phases_phase_mvp2_ext_risk_model_v1_ctx_2 [INFERRED 0.95]

## Communities (141 total, 36 thin omitted)

### Community 0 - "pipeline.py"
Cohesion: 0.19
Nodes (21): get_scanner(), analyze(), _classify(), _container_fields(), discard_workspace(), _excerpt(), fail_scan(), fetcher_image() (+13 more)

### Community 1 - "FindingsSection.tsx"
Cohesion: 0.15
Nodes (17): FindingChange, FindingList, ReachabilityTier, ScannerName, CHANGES, FilterState, FindingFilters(), SCANNERS (+9 more)

### Community 2 - "RunSpec"
Cohesion: 0.11
Nodes (19): _kill_group(), _rlimits(), RunSpec, SubprocessRunner, _tail(), build_clone_argv(), _drop(), test_memory_limit_is_enforced() (+11 more)

### Community 3 - "context/service.py"
Cohesion: 0.10
Nodes (17): _date(), _decimal(), _decimal_score(), EpssScore, fetch_epss(), fetch_kev(), fetch_nvd(), _kev_index() (+9 more)

### Community 4 - "ScanWorkspace"
Cohesion: 0.18
Nodes (6): CloneResult, GitCloner, ScanWorkspace, test_readonly_then_cleanup(), test_safe_resolve_stays_inside_src(), test_snippet_hash_ignores_whitespace()

### Community 5 - "json"
Cohesion: 0.13
Nodes (12): CvssSubscores, _round1(), subscores(), IacResult, persist_assets(), _client(), test_cvss_rejects_v2_and_garbage(), test_cvss_subscores() (+4 more)

### Community 6 - "graph/__init__.py"
Cohesion: 0.25
Nodes (11): AttackPath, AttackPathFinding, GraphEdge, GraphNode, clear(), _dec(), list_paths(), load_graph() (+3 more)

### Community 7 - "Findings API and Vocabulary"
Cohesion: 0.11
Nodes (26): _diff_items(), _float(), get_finding(), list_findings(), path_out(), require_scan(), scan_diff(), scan_gate() (+18 more)

### Community 8 - "test_manifest.py"
Cohesion: 0.18
Nodes (16): load_manifest(), normalize_service_path(), parse_manifest(), _short(), test_alias_bomb_is_refused_before_expansion(), test_deep_nesting_is_refused_without_crashing(), test_documented_example_manifest_is_valid(), test_hostile_or_broken_documents_never_raise() (+8 more)

### Community 9 - "Findings Persistence and History"
Cohesion: 0.14
Nodes (16): apply_history(), diff_scans(), previous_scan_id(), ScanDiff, Finding, FindingOccurrence, ScanFinding, _base_query() (+8 more)

### Community 10 - "cli.py"
Cohesion: 0.13
Nodes (10): build_parser(), main(), markdown(), _out(), run_scan(), test_failed_scan_and_api_errors(), test_gate_failure_exit_code_and_escaping(), test_gate_pass_and_summary() (+2 more)

### Community 11 - "V1 Data Model Tables"
Cohesion: 0.08
Nodes (36): Cytoscape.js graph view, GET /attack-paths, GET /findings, GET /graph, GET /risks, GET /sbom, POST /findings/{id}/explain, GET /repositories/{id}/context (+28 more)

### Community 12 - "Severity"
Cohesion: 0.06
Nodes (62): FindingContext, Observed, Manifest, VulnIntel, analyze(), AttackAnalysis, _ds(), GraphFinding (+54 more)

### Community 13 - "Tech Choices and Threats"
Cohesion: 0.07
Nodes (26): GET /findings/{id} composite view, GET /graph/nodes/{id}/neighbors (recursive CTE), FindingDetailPage (tabs), Frontend Architecture (React 18 + TS + Vite), TanStack Query server state, container_spec.py (only mount builder), T-01 Scanner container escape, T-02 Attacker-influenced scanner output (traversal/XSS) (+18 more)

### Community 15 - "Phase MVP — Scan, normalize, merge, prioritize (vertical slice)"
Cohesion: 0.09
Nodes (21): Phase MVP — Scan, normalize, merge, prioritize (vertical slice), Phase MVP level 2 — context-aware scoring, ContextResolver (longest path-prefix service mapping), Phase MVP level 2 extended — reachability, attack paths, triage and history, Attack graph with Yen k=3 shortest paths, Effective impact I* (I_eff), L0 high-confidence ceiling (≤ Medium unless KEV), Reachability tiers L0/L1/L2 (R factor) (+13 more)

### Community 16 - "Scanner Isolation Threats"
Cohesion: 0.09
Nodes (25): ADR-0009 MVP runs scanners as subprocesses in the worker, DockerRunner (deferred to Phase 3), ScannerRunner protocol, SubprocessRunner, Trivy Redis lock, tree-sitter extraction (reachability/extract.py), RiskGraph Threat Model (living), A1 Findings, secrets metadata, risk scores (+17 more)

### Community 17 - "conftest.py"
Cohesion: 0.13
Nodes (9): dispose_engine(), get_engine(), _session_factory(), _alembic(), client(), db(), migrated_db(), settings() (+1 more)

### Community 18 - "Graph and Reachability ADRs"
Cohesion: 0.10
Nodes (23): ADR-0006 Graph storage and analysis, Apache AGE (rejected for now), Neo4j (rejected), NetworkX in-process analysis, Yen's k-shortest simple paths, ADR-0012 Reachability tiers L0-L2 in the MVP, Entry point detection, Import graph (graph.py) (+15 more)

### Community 19 - "Dev Stack and CI Docs"
Cohesion: 0.14
Nodes (17): CI Workflow (ci.yml), CI backend job (ruff, mypy, pytest unit + db), CI frontend job (npm lint, typecheck, build), CI images job (build + Trivy scan backend image), CI security-self-scan job (Gitleaks + Trivy fs), Pre-commit config (pre-commit-hooks, ruff, gitleaks), Dev Compose stack, api service (uvicorn create_app) (+9 more)

### Community 20 - "test_pipeline_db.py"
Cohesion: 0.17
Nodes (27): run_pipeline_inline(), clone(), collect(), finalize(), cas_scan(), runs_for(), session_scope(), test_real_scanners_end_to_end() (+19 more)

### Community 21 - "test_level2_ext_db.py"
Cohesion: 0.14
Nodes (14): Settings, FixtureRunner, test_prod_refuses_to_start_without_auth(), api(), _by_package(), _findings(), _scan(), test_attack_paths_and_effective_impact() (+6 more)

### Community 22 - "Finding Drawer and Triage UI"
Cohesion: 0.16
Nodes (25): FindingDetail, FindingListItem, FindingStatus, Priority, contextOrigin(), DrawerBody(), FACTOR_NAME, FactorRow() (+17 more)

### Community 23 - "Frontend Shell and Routing"
Cohesion: 0.17
Nodes (14): RFC-7807, API_BASE, ApiError, apiPatch(), handle(), Health, problemMessage(), Readiness (+6 more)

### Community 24 - "ADR-0010 MVP vertical slice and deviations"
Cohesion: 0.13
Nodes (18): ADR-0010 MVP vertical slice and deviations, Context-free score model v1-cf.1, Corroboration factor K, Cross-scanner merge keys (normalization/families.py), Threat intel: EPSS + CISA KEV, ADR-0011 Context-aware scoring from repository manifest, Context factors X, P, D, C with source/confidence, Longest path-prefix finding-to-service mapping (+10 more)

### Community 25 - "ScanDetailPage.tsx"
Cohesion: 0.22
Nodes (17): apiGet(), ScanContext, PriorityCounts(), RepositoryPage(), ContextPanel(), MANIFEST_TEXT, Value(), ScanDetailPage() (+9 more)

### Community 26 - "trivy/parser.py"
Cohesion: 0.15
Nodes (17): Location, normalize_path(), gitleaks_severity(), trivy_severity(), count(), _items(), parse(), clip() (+9 more)

### Community 27 - "Deployment and Degradation"
Cohesion: 0.10
Nodes (24): GET /healthz /readyz /metrics, T-20 LLM unavailability blocks scans, infrastructure/ (caddy, prometheus, socket-proxy, scripts), RiskGraph Deployment, NFRs, Failure Handling (section 27), api service (uvicorn), Nightly pg_dump backups (restore rehearsed), beat service, caddy service (only published port :443) (+16 more)

### Community 28 - "Frontend Build Config"
Cohesion: 0.07
Nodes (27): dependencies, cytoscape, react, react-dom, react-router-dom, @tanstack/react-query, name, private (+19 more)

### Community 29 - "Scans API Router"
Cohesion: 0.14
Nodes (11): cancel_scan(), create_scan(), download_report(), get_scan(), list_scans(), to_out(), RepositoryOut, ScanCreate (+3 more)

### Community 30 - "PHASE 3: Scanner orchestration engine (hardened DockerRunner)"
Cohesion: 0.13
Nodes (14): A. Objective, B. Why, F. Folder structure, G. Database, H. API, I. Algorithms, J. Implementation notes, K. Commands (+6 more)

### Community 31 - "Roadmap Phase Graph"
Cohesion: 0.16
Nodes (22): RiskGraph Phase Dependency Graph and Roadmap (sections 23-24), Critical path P0->P1->P2->P3->P4->P5->P7->P8->P9->P10->P11->P13->P17->P19, Phase 0: Project definition & threat model, Phase 1: Repository & dev environment, Phase 2: Domain model, DB, auth skeleton, Phase 3: Scanner orchestration engine, Phase 4: Scanner adapters, Phase 5: Normalization, correlation, SBOM (+14 more)

### Community 32 - "Domain Module Layout"
Cohesion: 0.15
Nodes (21): RiskGraph Repository Structure (section 22), backend/tests (fixtures, integration, security, e2e), backend/riskgraph/entrypoints (api, worker, cli), modules/attack_paths, modules/audit, modules/auth, modules/context (nvd, epss, kev, extractors), modules/dashboard (+13 more)

### Community 33 - "repositories/router.py"
Cohesion: 0.20
Nodes (12): clone_url_for(), get_or_create(), InvalidRef, InvalidRepositoryUrl, parse_github_url(), validate_ref(), UnprocessableEntity, test_accepts_branch_and_tag_names() (+4 more)

### Community 35 - "Evaluation and Invariants"
Cohesion: 0.10
Nodes (19): RiskGraph Security Threat Model (section 20), Attack surfaces S1-S12, Scanner isolation profile, Protected assets A1-A7, STRIDE per element, Threat actors T1-T6, evaluation/, RiskGraph Testing Strategy and Research Evaluation (sections 25-26) (+11 more)

### Community 36 - "AttackPathsPanel.tsx"
Cohesion: 0.24
Nodes (11): AttackPath, GraphData, ScanSummary, AttackPathsPanel(), GraphView, KIND_COLOR, kindOf(), COLORS (+3 more)

### Community 37 - "docker_runner.py"
Cohesion: 0.12
Nodes (13): _Containers, DockerClient, DockerRunner, _Images, make_removable(), _printable(), _write_capped(), RunResult (+5 more)

### Community 38 - "test_parsers.py"
Cohesion: 0.21
Nodes (10): ScannerName, fixture_path(), load(), test_canvas_shape_and_queues(), test_checkov_shapes_and_resources(), test_counts_match_parsed_findings(), test_gitleaks_uses_redacted_fields_only(), test_hostile_paths_are_neutralised() (+2 more)

### Community 39 - "Core Architecture ADRs"
Cohesion: 0.11
Nodes (20): ADR-0001 Modular monolith with API and worker roles, api process role (FastAPI), import-linter contract, Services per pipeline stage (rejected), worker process role (Celery + beat), ADR-0002 Stack, Caddy, Celery 5 (+12 more)

### Community 40 - "db/__init__.py"
Cohesion: 0.10
Nodes (15): downgrade(), upgrade(), upgrade(), Asset, Vulnerability, ReachabilityResult, persist_verdict(), Repository (+7 more)

### Community 41 - "Triage and Audit Log"
Cohesion: 0.16
Nodes (8): AuditLog, history(), record(), evaluate_gate(), GatePolicy, GateResult, InvalidTriage, set_status()

### Community 42 - "types.ts"
Cohesion: 0.11
Nodes (22): AttackPathEdge, FindingLocation, ManifestStatus, Occurrence, PackageInfo, RepositoryDetail, RepositorySummary, RiskFactor (+14 more)

### Community 43 - "iac.py"
Cohesion: 0.07
Nodes (33): _clean_file(), ContextResolver, _code_dir(), _compose(), _d(), extract(), IacAsset, _k8s() (+25 more)

### Community 44 - "dataclasses"
Cohesion: 0.10
Nodes (11): _structure_problem(), find_l3(), Path3, _qualify(), build(), ModuleGraph, _python_module_index(), _python_roots() (+3 more)

### Community 45 - "SourceType"
Cohesion: 0.16
Nodes (16): RawFinding, fingerprint(), stable_hash(), _build(), merge(), MergedFinding, _overlap_clusters(), _graph_label() (+8 more)

### Community 46 - "os"
Cohesion: 0.18
Nodes (4): Cloner, git_env(), _force_writable(), widen_own_directories()

### Community 47 - "TS App Config"
Cohesion: 0.11
Nodes (17): compilerOptions, baseUrl, isolatedModules, jsx, lib, module, moduleResolution, noEmit (+9 more)

### Community 48 - "API Auth and Errors Design"
Cohesion: 0.13
Nodes (15): API Architecture (FastAPI /api/v1), Audit log written in same transaction, Auth: JWT bearer + X-API-Key + rotating refresh tokens, Cursor-based pagination for findings, Problem schema (RFC 7807), RBAC roles (admin, security_engineer, developer, viewer), RFC 7807 Problem errors, RiskFactorOut schema (+7 more)

### Community 49 - "Architecture Scan Flow"
Cohesion: 0.14
Nodes (15): Beat Process (Celery Beat), Checkov, Context Enrichment (precedence: override > manifest > IaC > unknown), Cross-scanner Correlation (Trivy-Syft purl, Gitleaks-identity, Checkov-assets, Semgrep-functions), Entry Point Detection (FastAPI/Flask/Django/Express/...), Gitleaks, IaC Extractors (Kubernetes, Docker Compose, Terraform), Reachability Tiers L0-L3 (+7 more)

### Community 50 - "Phase 0 — Project Definition & Threat Model"
Cohesion: 0.25
Nodes (4): Phase 0 — Project Definition & Threat Model, STRIDE Threat Model (T-01…T-20), Success Criteria S1–S8, HMAC secret redaction and report scrubbing

### Community 51 - "Auth and ID ADRs"
Cohesion: 0.13
Nodes (12): ADR-0003 UUID v7 ids, single tenant, deletion policy, ADR-0004 Authentication and authorization model, Scoped API keys for CI, argon2id password hashing (pwdlib), 15-min JWT access tokens (HS256), RBAC roles (admin/security_engineer/developer/viewer), Rotating refresh tokens with reuse detection, CI gate (GET /scans/{id}/gate + CLI) (+4 more)

### Community 52 - "Graph API Router"
Cohesion: 0.27
Nodes (6): attack_paths(), GraphEdgeOut, GraphNodeOut, GraphOut, scan_graph(), get_session()

### Community 53 - "Spec and Manifest Docs"
Cohesion: 0.18
Nodes (12): riskgraph.yaml v1 manifest example, Manifest criticality, Manifest data_stores (kind, sensitivity), Manifest identities (privilege, can_access, credentials), Manifest services (path, exposure, auth, runs_as, connects_to), RiskGraph Project Specification (Phase 0), Assumptions A1-A6 (single-tenant, hostile repos, manifest context), Research question: contextual graph prioritization vs CVSS / CVSS+EPSS (+4 more)

### Community 54 - "test_workspace.py"
Cohesion: 0.22
Nodes (5): WorkspaceError, test_measure_enforces_limits(), test_report_path_is_fixed(), test_workspace_requires_uuid(), ws()

### Community 55 - "CI/CD and Database Design"
Cohesion: 0.17
Nodes (10): RiskGraph Data, API, Frontend, CI/CD (sections 16-19), Alembic migrations (reversible, migrate service), CI/CD Architecture, POST /webhooks/github, Beat retention job (keep last 20 scans), RiskGraph's own CI pipeline (ci.yml), webhook_deliveries table (idempotency), Path A: GitHub webhook integration (+2 more)

### Community 56 - "default_deps"
Cohesion: 0.11
Nodes (9): SlotLimiter, SlotTimeoutError, refresh_trivy_db_task(), build_runner(), default_deps(), _kev_cache(), redis_scanner_lock(), reap_task() (+1 more)

### Community 57 - "orchestration.py"
Cohesion: 0.29
Nodes (4): build_canvas(), enqueue(), enqueue_kill(), _sig()

### Community 58 - "repositories/router.py"
Cohesion: 0.22
Nodes (7): get_repository(), list_repositories(), _point(), RepositoryDetail, RepositorySummary, _summary(), TrendPoint

### Community 59 - "Attack Graph Research"
Cohesion: 0.20
Nodes (10): Comparison: DefectDojo, Dependency-Track, OWASP dep-scan, Snyk/Wiz/Orca, CVSS v3.1/v4.0 specifications, Vulnerable dependency reachability (Eclipse Steady), EPSS (Jacobs et al. 2021), MulVAL attack graphs (Ou et al. 2005), Novelty: open reproducible evaluated integration, Attack-Graph Derivation (exploit, credential, control edges; w=-ln p), Dijkstra best path per (source, sink) (+2 more)

### Community 60 - "Hybrid Risk and AI Explain"
Cohesion: 0.22
Nodes (11): SSVC (CISA), AI Explanation Architecture, Attack-Path Coupling (effective impact I_eff), EvidencePack (Pydantic), Hybrid Risk Model (geomean likelihood x mean impact + overrides), Impact Factors T, D, P, C, Risk Model Versioning (model_version per score row), Path Scoring (100 * P(path) * I(sink)) (+3 more)

### Community 61 - "Test Datasets"
Cohesion: 0.18
Nodes (11): EvidencePack (LLM input), T-11 Prompt injection into AI explanation, datasets/, Scenario A: high CVSS unreachable, Scenario B: moderate reachable exposed, Scenario C: exposed credential, Scenario D: internal limited, Scenario E: attack path (SSRF) (+3 more)

### Community 62 - "TS Node Config"
Cohesion: 0.18
Nodes (10): compilerOptions, composite, module, moduleResolution, noEmit, skipLibCheck, strict, target (+2 more)

### Community 63 - "_record"
Cohesion: 0.19
Nodes (9): container_fields(), scanner_image(), main(), _make_removable_later(), _open_for_scanner_uid(), _record(), _recording_runner(), _trim_trivy() (+1 more)

### Community 64 - "Project Risks and Isolation"
Cohesion: 0.20
Nodes (9): MVP Definition and Stretch List, Non-goals (not a scanner, not multi-tenant, no DAST, no live cloud, GitHub only), Project Risks R1-R11, V1 Scope, shared/docker/container_spec.py (only place mounts are built), docker-socket-proxy, git-fetcher clone container, LLM Adapter Protocol (Ollama, Anthropic, Null) (+1 more)

### Community 65 - "Scan Creation and Rate Limits"
Cohesion: 0.20
Nodes (10): POST /scans, Path B: riskgraph-action GitHub Action, Redis token bucket rate limiting, ScanCreate schema, T-03 Command injection via ref/repo/commit, T-13 Resource exhaustion, T-17 CI token leakage in Action, Own Redis token bucket middleware (+2 more)

### Community 66 - "Health Endpoint Tests"
Cohesion: 0.29
Nodes (5): test_healthz_reports_version(), test_readyz_ok_with_real_services(), test_readyz_reports_503_when_dependencies_down(), test_request_id_is_echoed_or_generated(), test_unknown_route_is_problem_json()

### Community 67 - "Blueprint Overview"
Cohesion: 0.22
Nodes (6): RiskGraph Master Blueprint v0.1, Motivating Example (unreachable CVSS 9.8 vs exposed credential), Problem Definition (orchestration cost, severity != risk, no correlation, no explanation), RiskGraph Platform, RiskGraph Architecture (sections 6-15), Worked Examples Scenarios A-E

### Community 68 - "semgrep/parser.py"
Cohesion: 0.28
Nodes (7): cwe_ids(), sast_category(), semgrep_severity(), clean_rule_id(), count(), parse(), _results()

### Community 69 - "UUIDv7 Generator"
Cohesion: 0.39
Nodes (3): uuid7(), test_uuid7_is_time_ordered_and_unique(), test_uuid7_version_and_variant()

### Community 70 - "test_runtime_db.py"
Cohesion: 0.16
Nodes (11): reap(), ReapResult, api(), _ContainerOnlyRunner, _create(), kills(), test_a_finished_scan_cannot_be_cancelled(), test_a_healthy_running_scan_is_left_alone() (+3 more)

### Community 71 - "Graph Schema and Explainer"
Cohesion: 0.25
Nodes (8): Final Demonstration Workflow (12 steps), Explanation Validator (evidence ids, numbers, URLs), Graph Builder Invariants, NetworkX DiGraph, riskgraph.yaml Manifest Schema v1, Security Graph Schema (node and edge kinds), TemplateExplainer (deterministic fallback), Yen's k-shortest simple paths (top-3)

### Community 72 - "Process Architecture"
Cohesion: 0.29
Nodes (8): API Process (FastAPI), Celery Canvas (clone -> chord(scanners) -> analyze -> finalize), Frontend (React + TS via Caddy), GitHub Action CI/CD Feedback (polling), PostgreSQL (system of record), Redis (broker, result backend, rate limits, scanner slots), scan_jobs / scanner_runs State Machines, Worker Process (Celery)

### Community 73 - "Thesis and Finding Model"
Cohesion: 0.29
Nodes (4): Evaluation Protocol (constructed ground truth, blind labels, KEV held out), Five Thesis Contributions, Canonical Finding Model (Finding + ScanFinding), Finding Fingerprinting (per source type)

### Community 74 - "scans/service.py"
Cohesion: 0.20
Nodes (10): ScanJob, cancel_scan(), create_scan(), get_scan(), list_scans(), report_file(), ScanView, start_scan() (+2 more)

### Community 75 - "Session 1 handoff (2026-09-19)"
Cohesion: 0.12
Nodes (16): Commands that are known to work, Gotchas already hit (so you don't hit them again), HANDOFF: resume here (updated 2026-10-23, session 6: P3, P4, P5, P7, P8), Open items (decide before Phase 2), Open items (small, do at the start of Phase 2), Rules of engagement (from the brief and CLAUDE.md), Session 1 handoff (2026-09-19), Session 2 (2026-10-21): MVP vertical slice, done (+8 more)

### Community 76 - "Hosting ADR"
Cohesion: 0.33
Nodes (5): ADR-0005 Hosting and deployment, docker-socket-proxy, K8sJobRunner (future), container_spec.py mount builder, T-08 Docker socket proxy abuse

### Community 77 - "Scanner Installer"
Cohesion: 0.50
Nodes (4): fetch_verified(), install-scanners.sh script, UV_TOOL_BIN_DIR, UV_TOOL_DIR

### Community 78 - "test_docker_runner.py"
Cohesion: 0.14
Nodes (14): PathRoot, FakeClient, FakeContainer, FakeContainers, FakeImages, _runner(), _spec(), test_a_hung_container_is_killed_at_the_timeout() (+6 more)

### Community 79 - "pipeline_support.py"
Cohesion: 0.17
Nodes (3): CloneError, real_settings(), workspace_exists()

### Community 91 - "test_config.py"
Cohesion: 0.25
Nodes (6): _base(), test_bad_redis_url_rejected(), test_missing_required_fails(), test_non_psycopg_database_url_rejected(), test_short_secret_rejected(), test_valid_settings_parse()

### Community 92 - "pytest"
Cohesion: 0.18
Nodes (22): build_create_kwargs(), _check_env(), _checked_path(), ContainerSpecError, Limits, Mount, scanner_mounts(), _kwargs() (+14 more)

### Community 93 - "health.py"
Cohesion: 0.18
Nodes (5): check_database(), Health, healthz(), Readiness, readyz()

### Community 94 - "UUID"
Cohesion: 0.06
Nodes (39): parse_nvd_cvss(), clear(), SbomComponent, attach_findings(), canonical_purl(), clear(), _ecosystem(), list_components() (+31 more)

### Community 95 - "ScanDetailPage.tsx"
Cohesion: 0.21
Nodes (13): apiPost(), App(), HealthDot(), HomePage(), RepositoryRoute(), ScanRoute(), EXAMPLES, NewScanForm() (+5 more)

### Community 96 - "vocabulary.py"
Cohesion: 0.19
Nodes (5): run_extractor(), ScannerRunner, _open_cache_to_scanners(), refresh_argv(), refresh_trivy_db()

### Community 97 - "Phase 1 — Repository & Development Environment"
Cohesion: 0.25
Nodes (4): Phase 1 — Repository & Development Environment, Docker Compose dev stack (postgres, redis, migrate, api, worker, beat, frontend), healthz / readyz endpoints, RFC 7807 problem+json errors

### Community 98 - "checkov/parser.py"
Cohesion: 0.13
Nodes (14): iac_family(), iac_topic(), IacFamily, normalize_check_id(), secret_family(), checkov_severity(), _blocks(), count() (+6 more)

### Community 99 - "orchestration.py"
Cohesion: 0.10
Nodes (9): _bind_task_context(), _clear_task_context(), _configure_worker_logging(), ping(), create_celery(), get_celery_app(), get_settings(), check_redis() (+1 more)

### Community 100 - "ScannerName"
Cohesion: 0.07
Nodes (9): Command, ParseContext, ScanPaths, CheckovScanner, GitleaksScanner, drop_keys(), SemgrepScanner, SyftScanner (+1 more)

### Community 101 - "storage.py"
Cohesion: 0.32
Nodes (6): read_json_capped(), read_report(), report_path(), report_relpath(), ReportTooLargeError, write_report()

### Community 102 - "PHASE 4: Scanner adapters (five hardened images)"
Cohesion: 0.25
Nodes (7): Built, Decisions, Known differences from the host-run MVP, Not done, Objective, PHASE 4: Scanner adapters (five hardened images), Verification

### Community 103 - "api.py"
Cohesion: 0.13
Nodes (5): create_app(), configure_logging(), get_logger(), RequestIdMiddleware, X-Request-ID middleware

### Community 104 - "context/router.py"
Cohesion: 0.43
Nodes (4): AssetOut, ContextOut, repository_context(), list_assets()

### Community 105 - "kitchen_sink.json"
Cohesion: 0.13
Nodes (14): bomFormat, bom-ref, name, type, components, metadata, component, timestamp (+6 more)

### Community 106 - "RiskGraph — AI session entry point"
Cohesion: 0.29
Nodes (6): Commands, Conventions, Current state, Dependencies, graphify, RiskGraph — AI session entry point

### Community 107 - "ADR-0015: L3 reachability by intraprocedural call graph; NVD refreshed by Beat"
Cohesion: 0.29
Nodes (6): ADR-0015: L3 reachability by intraprocedural call graph; NVD refreshed by Beat, Consequences, Context, Decision, L3, NVD

### Community 108 - "test_reachability.py"
Cohesion: 0.05
Nodes (49): load_symbols(), SymbolEntry, _dotted(), extract(), _js(), main(), _package_json(), _parsers() (+41 more)

### Community 109 - "sqlalchemy"
Cohesion: 0.31
Nodes (5): upgrade(), downgrade(), _in_list(), _replace_check(), upgrade()

### Community 110 - "level2.test.ts"
Cohesion: 0.33
Nodes (3): TrendPoint, buildQuery(), vitest

### Community 111 - "PHASE 8: Reachability (L0–L3)"
Cohesion: 0.40
Nodes (4): Built, Not done (blueprint §11.3, §10.2), PHASE 8: Reachability (L0–L3), Verification

### Community 116 - "devDependencies"
Cohesion: 0.17
Nodes (12): devDependencies, eslint, @eslint/js, eslint-plugin-react-hooks, @types/node, @types/react, @types/react-dom, typescript (+4 more)

### Community 118 - "redact.py"
Cohesion: 0.19
Nodes (10): derive_key(), mask(), scrub(), _scrub(), secret_hmac(), test_gitleaks_redaction_removes_every_raw_field(), test_hmac_is_keyed_and_deterministic(), test_mask_never_shows_short_secrets() (+2 more)

### Community 123 - "test_api.py"
Cohesion: 0.28
Nodes (11): api(), _completed_scan(), enqueued(), test_concurrency_cap(), test_create_scan_enqueues_and_dedups(), test_create_scan_rejects_bad_input(), test_findings_sort_filter_and_detail(), test_get_and_list_scans() (+3 more)

### Community 124 - "test_scan_state.py"
Cohesion: 0.15
Nodes (15): active_scan(), cas_run(), count_active(), get_run(), check_run(), check_scan(), final_status(), InvalidTransitionError (+7 more)

### Community 128 - "problems.py"
Cohesion: 0.12
Nodes (13): TooManyActiveScans, Conflict, Forbidden, Problem, problem_response(), register_problem_handlers(), _http(), _problem() (+5 more)

### Community 132 - "20261023_0900_reachability_l3.py"
Cohesion: 0.83
Nodes (3): _check(), downgrade(), upgrade()

## Knowledge Gaps
- **102 isolated node(s):** `Docker Compose dev stack (postgres, redis, migrate, api, worker, beat, frontend)`, `GET /scans/{id}/events (SSE)`, `Finding fingerprint uq(repository_id, fingerprint)`, `TanStack Query server state`, `T-06 Plaintext secret storage` (+97 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 719 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **36 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Phase 1 — Repository & Development Environment` connect `Phase 1 — Repository & Development Environment` to `Domain Module Layout`, `api.py`, `Core Architecture ADRs`, `Phase 0 — Project Definition & Threat Model`, `Auth and ID ADRs`?**
  _High betweenness centrality (0.143) - this node is a cross-community bridge._
- **Are the 19 inferred relationships involving `Settings` (e.g. with `Scanner` and `CheckovScanner`) actually correct?**
  _`Settings` has 19 INFERRED edges - model-reasoned connections that need verification._
- **What connects `Docker Compose dev stack (postgres, redis, migrate, api, worker, beat, frontend)`, `GET /scans/{id}/events (SSE)`, `Finding fingerprint uq(repository_id, fingerprint)` to the rest of the system?**
  _102 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `RunSpec` be split into smaller, more focused modules?**
  _Cohesion score 0.11025641025641025 - nodes in this community are weakly interconnected._
- **Why does `RiskGraph Repository Structure (section 22)` connect `Domain Module Layout` to `Scan Creation and Rate Limits`, `Phase 1 — Repository & Development Environment`, `Evaluation and Invariants`, `Tech Choices and Threats`, `API Auth and Errors Design`, `CI/CD and Database Design`, `Deployment and Degradation`, `Test Datasets`?**
  _High betweenness centrality (0.104) - this node is a cross-community bridge._
- **Are the 43 inferred relationships involving `ScannerName` (e.g. with `list_findings()` and `OccurrenceOut`) actually correct?**
  _`ScannerName` has 43 INFERRED edges - model-reasoned connections that need verification._
- **Should `context/service.py` be split into smaller, more focused modules?**
  _Cohesion score 0.10299003322259136 - nodes in this community are weakly interconnected._