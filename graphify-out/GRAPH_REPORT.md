# Graph Report - riskgraph  (2026-10-22)

## Corpus Check
- 212 files · ~94,157 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 14 file(s) not represented in the graph (top: (none) 5, .Dockerfile 2, .example 1)

## Summary
- 2021 nodes · 5827 edges · 91 communities (76 shown, 15 thin omitted)
- Extraction: 88% EXTRACTED · 12% INFERRED · 0% AMBIGUOUS · INFERRED: 698 edges (avg confidence: 0.92)
- Token cost: 439,201 input · 0 output

## Community Hubs (Navigation)
- Scan Pipeline Orchestration
- Scanner Output Normalization
- Reachability Analysis
- Threat Intel Enrichment
- Scan Workspace Storage
- Scanner Adapter Contracts
- ORM Base and Graph Service
- Findings API and Vocabulary
- Manifest Parsing
- Findings Persistence and History
- Subprocess Scanner Runner
- V1 Data Model Tables
- Risk Model Tests
- Tech Choices and Threats
- API App Factory
- MVP Phase Chapters
- Scanner Isolation Threats
- Real-Scanner Test Harness
- Graph and Reachability ADRs
- Dev Stack and CI Docs
- Settings and Health Checks
- DB Session and Fixtures
- Finding Drawer and Triage UI
- Frontend Shell and Routing
- Context Scoring ADRs
- Scan List and Badges UI
- Celery Canvas
- Deployment and Degradation
- Frontend Build Config
- Scans API Router
- Attack Path Search
- Roadmap Phase Graph
- Domain Module Layout
- Repository URL Validation
- Config and Git Cloner
- Evaluation and Invariants
- Scan Detail and Graph UI
- Repositories API
- Secret Redaction
- Core Architecture ADRs
- Findings Filters UI
- Triage and Audit Log
- Frontend Types and Trends
- Context Resolver
- Level 2 DB Tests
- Risk Scoring Service
- API Integration Tests
- TS App Config
- API Auth and Errors Design
- Architecture Scan Flow
- Phase 0-1 Foundations
- Auth and ID ADRs
- Graph API Router
- Spec and Manifest Docs
- Problem Error Types
- CI/CD and Database Design
- Frontend Dev Dependencies
- Risk Factor Math
- Problem Handlers
- Attack Graph Research
- Hybrid Risk and AI Explain
- Test Datasets
- TS Node Config
- Scanner Protocol
- Project Risks and Isolation
- Scan Creation and Rate Limits
- Health Endpoint Tests
- Blueprint Overview
- Alembic Migrations
- UUIDv7 Generator
- Environment Resolver Tests
- Graph Schema and Explainer
- Process Architecture
- Thesis and Finding Model
- npm Scripts
- Celery Smoke Task
- Hosting ADR
- Scanner Installer
- CI Gate Policy
- TS Root Config
- Test DB Init
- Evidence Labels
- SSRF-safe HTTP Client
- Backend Package

## God Nodes (most connected - your core abstractions)
1. `Settings` - 102 edges
2. `ScannerName` - 92 edges
3. `SourceType` - 92 edges
4. `Severity` - 54 edges
5. `ScanStatus` - 47 edges
6. `analyze()` - 42 edges
7. `RawFinding` - 41 edges
8. `score()` - 39 edges
9. `session_scope()` - 37 edges
10. `ScanWorkspace` - 35 edges

## Surprising Connections (you probably didn't know these)
- `Untrusted input rules (no string subprocess, workspace-confined paths, no logging evidence/secrets)` --semantically_similar_to--> `Untrusted by default (sandboxed execution, tree-sitter parsing)`  [INFERRED] [semantically similar]
  CLAUDE.md → docs/PROJECT_SPEC.md
- `CI backend job (ruff, mypy, pytest unit + db)` --semantically_similar_to--> `Test services Compose (postgres + redis)`  [INFERRED] [semantically similar]
  .github/workflows/ci.yml → docker-compose.test.yml
- `CI security-self-scan job (Gitleaks + Trivy fs)` --semantically_similar_to--> `Pre-commit config (pre-commit-hooks, ruff, gitleaks)`  [INFERRED] [semantically similar]
  .github/workflows/ci.yml → .pre-commit-config.yaml
- `Session 1: Blueprint, Phase 0 and Phase 1` --conceptually_related_to--> `trivy-action pinned by commit (v0.36.0)`  [INFERRED]
  HANDOFF.md → .github/workflows/ci.yml
- `MVP has no authentication: localhost only` --conceptually_related_to--> `ADR-0010 MVP vertical slice and deviations`  [INFERRED]
  README.md → docs/adr/0010-mvp-scope.md

## Import Cycles
- 3-file cycle: `backend/riskgraph/modules/risk/__init__.py -> backend/riskgraph/modules/risk/service.py -> backend/riskgraph/modules/risk/model.py -> backend/riskgraph/modules/risk/__init__.py`

## Hyperedges (group relationships)
- **Dev Compose stack services sharing the backend image** — docker_compose_migrate, docker_compose_api, docker_compose_worker, docker_compose_beat [EXTRACTED 1.00]
- **riskgraph.yaml context model (services, identities, data stores, criticality)** — docs_examples_riskgraph_services, docs_examples_riskgraph_identities, docs_examples_riskgraph_data_stores, docs_examples_riskgraph_criticality, readme_context_aware_scoring [EXTRACTED 1.00]
- **MVP level 2 extended features (ADR-0012/0013)** — readme_reachability, readme_attack_paths, readme_triage_history, readme_ci_gate_cli, handoff_session_4_mvp2_extended [INFERRED 0.85]
- **Risk score model evolution v1-cf.1 -> v1-ctx.1 -> v1-ctx.2 -> effective impact** — docs_adr_0010_mvp_scope_context_free_score_v1_cf_1, docs_adr_0011_manifest_context_scoring_v1_ctx_1, docs_adr_0012_reachability_tiers_mvp_v1_ctx_2, docs_adr_0013_graph_paths_triage_history_effective_impact [EXTRACTED 1.00]
- **ScannerRunner seam implementations** — docs_adr_0009_subprocess_scanner_runner_scannerrunner_protocol, docs_adr_0009_subprocess_scanner_runner_subprocess_runner, docs_adr_0009_subprocess_scanner_runner_dockerrunner, docs_adr_0005_hosting_k8sjobrunner [EXTRACTED 1.00]
- **Untrusted repository input parsing defenses** — docs_adr_0011_manifest_context_scoring_manifest_hardening, docs_adr_0012_reachability_tiers_mvp_tree_sitter_extraction, docs_adr_0009_subprocess_scanner_runner_hardened_git_clone, docs_threat_model_safe_resolve, docs_threat_model_t_02 [INFERRED 0.85]
- **Scan pipeline: scanners -> normalization -> enrichment -> graph -> paths -> risk -> explain** — docs_blueprint_01_architecture_scanner_protocol, docs_blueprint_01_architecture_canonical_finding_model, docs_blueprint_01_architecture_context_enrichment, docs_blueprint_01_architecture_security_graph_schema, docs_blueprint_01_architecture_attack_graph_derivation, docs_blueprint_01_architecture_hybrid_risk_model, docs_blueprint_01_architecture_ai_explanation [EXTRACTED 1.00]
- **Five sandboxed scanner adapters** — docs_blueprint_01_architecture_trivy, docs_blueprint_01_architecture_semgrep, docs_blueprint_01_architecture_gitleaks, docs_blueprint_01_architecture_checkov, docs_blueprint_01_architecture_syft [EXTRACTED 1.00]
- **Evidence-bound LLM explanation with validation and fallback** — docs_blueprint_01_architecture_evidence_pack, docs_blueprint_01_architecture_llm_adapter, docs_blueprint_01_architecture_explanation_validator, docs_blueprint_01_architecture_template_explainer [EXTRACTED 1.00]
- **Per-scan analysis data (components, graph, reachability, attack paths, risk scores)** — docs_blueprint_02_data_and_api_table_scan_jobs, docs_blueprint_02_data_and_api_table_components, docs_blueprint_02_data_and_api_table_graph_nodes, docs_blueprint_02_data_and_api_table_graph_edges, docs_blueprint_02_data_and_api_table_reachability_results, docs_blueprint_02_data_and_api_table_attack_paths, docs_blueprint_02_data_and_api_table_risk_scores [EXTRACTED 1.00]
- **Authentication and authorization controls** — docs_blueprint_02_data_and_api_auth_jwt_api_key, docs_blueprint_02_data_and_api_rbac, docs_blueprint_02_data_and_api_redis_rate_limiting, docs_blueprint_02_data_and_api_audit_in_transaction, docs_blueprint_03_threat_model_t09, docs_blueprint_03_threat_model_t10, docs_blueprint_03_threat_model_t19 [INFERRED 0.85]
- **Production Compose stack** — docs_blueprint_08_deployment_caddy, docs_blueprint_08_deployment_api_service, docs_blueprint_08_deployment_worker_service, docs_blueprint_08_deployment_beat_service, docs_blueprint_08_deployment_redis_service, docs_blueprint_08_deployment_postgres_service, docs_blueprint_08_deployment_migrate_service, docs_blueprint_08_deployment_socket_proxy_service [EXTRACTED 1.00]
- **Risk model version lineage (v1-cf.1 → v1-ctx.1 → v1-ctx.2)** — docs_phases_phase_mvp_risk_model_v1_cf_1, docs_phases_phase_mvp2_risk_model_v1_ctx_1, docs_phases_phase_mvp2_ext_risk_model_v1_ctx_2 [INFERRED 0.95]
- **Analyze stage: context, reachability, attack paths, two-pass scoring** — docs_phases_phase_mvp2_context_resolver, docs_phases_phase_mvp2_ext_reachability_tiers, docs_phases_phase_mvp2_ext_attack_graph, docs_phases_phase_mvp2_ext_two_pass_scoring [EXTRACTED 1.00]
- **Defenses against hostile repository content** — docs_phases_phase_00_hostile_repositories, docs_phases_phase_mvp_safe_resolve, docs_phases_phase_mvp_subprocess_runner, docs_phases_phase_mvp2_ext_extractor_isolation, docs_phases_phase_mvp2_riskgraph_manifest [INFERRED 0.85]

## Communities (91 total, 15 thin omitted)

### Community 0 - "Scan Pipeline Orchestration"
Cohesion: 0.07
Nodes (75): get_scanner(), CloneError, Cloner, ScanJob, ScannerRun, run_pipeline_inline(), analyze(), _classify() (+67 more)

### Community 1 - "Scanner Output Normalization"
Cohesion: 0.05
Nodes (59): Location, RawFinding, cwe_ids(), sast_category(), iac_family(), iac_topic(), IacFamily, normalize_check_id() (+51 more)

### Community 2 - "Reachability Analysis"
Cohesion: 0.06
Nodes (41): extract(), _js(), main(), _package_json(), _parsers(), _python(), _string_value(), _text() (+33 more)

### Community 3 - "Threat Intel Enrichment"
Cohesion: 0.05
Nodes (31): build_parser(), main(), markdown(), _out(), run_scan(), CvssSubscores, _round1(), subscores() (+23 more)

### Community 4 - "Scan Workspace Storage"
Cohesion: 0.08
Nodes (18): CloneResult, git_env(), read_json_capped(), read_report(), report_path(), report_relpath(), ReportTooLargeError, write_report() (+10 more)

### Community 5 - "Scanner Adapter Contracts"
Cohesion: 0.09
Nodes (9): Command, ParseContext, ScanPaths, CheckovScanner, GitleaksScanner, drop_keys(), SemgrepScanner, TrivyScanner (+1 more)

### Community 6 - "ORM Base and Graph Service"
Cohesion: 0.10
Nodes (17): Vulnerability, AttackAnalysis, AttackPath, AttackPathFinding, GraphEdge, GraphNode, clear(), _dec() (+9 more)

### Community 7 - "Findings API and Vocabulary"
Cohesion: 0.11
Nodes (26): _diff_items(), _float(), get_finding(), list_findings(), path_out(), scan_diff(), scan_gate(), triage_finding() (+18 more)

### Community 8 - "Manifest Parsing"
Cohesion: 0.08
Nodes (23): DataStoreDecl, IdentityDecl, load_manifest(), Manifest, ManifestResult, normalize_service_path(), parse_manifest(), _Resolver (+15 more)

### Community 9 - "Findings Persistence and History"
Cohesion: 0.13
Nodes (19): apply_history(), diff_scans(), previous_scan_id(), ScanDiff, Finding, FindingOccurrence, ScanFinding, _base_query() (+11 more)

### Community 10 - "Subprocess Scanner Runner"
Cohesion: 0.11
Nodes (22): _rlimits(), RunSpec, SubprocessRunner, _tail(), build_clone_argv(), build(), main(), _trim_trivy() (+14 more)

### Community 11 - "V1 Data Model Tables"
Cohesion: 0.08
Nodes (36): Cytoscape.js graph view, GET /attack-paths, GET /findings, GET /graph, GET /risks, GET /sbom, POST /findings/{id}/explain, GET /repositories/{id}/context (+28 more)

### Community 12 - "Risk Model Tests"
Cohesion: 0.22
Nodes (30): FindingContext, priority_for(), score(), ScoreInput, Severity, SourceType, _obs(), _reach() (+22 more)

### Community 13 - "Tech Choices and Threats"
Cohesion: 0.07
Nodes (26): GET /findings/{id} composite view, GET /graph/nodes/{id}/neighbors (recursive CTE), FindingDetailPage (tabs), Frontend Architecture (React 18 + TS + Vite), TanStack Query server state, container_spec.py (only mount builder), T-01 Scanner container escape, T-02 Attacker-influenced scanner output (traversal/XSS) (+18 more)

### Community 14 - "API App Factory"
Cohesion: 0.09
Nodes (8): create_app(), report_file(), start_scan(), configure_logging(), get_logger(), RequestIdMiddleware, test_prod_refuses_to_start_without_auth(), X-Request-ID middleware

### Community 15 - "MVP Phase Chapters"
Cohesion: 0.09
Nodes (22): Phase MVP — Scan, normalize, merge, prioritize (vertical slice), Phase MVP level 2 — context-aware scoring, ContextResolver (longest path-prefix service mapping), Phase MVP level 2 extended — reachability, attack paths, triage and history, Attack graph with Yen k=3 shortest paths, CI gate endpoint and CLI, Effective impact I* (I_eff), L0 high-confidence ceiling (≤ Medium unless KEV) (+14 more)

### Community 16 - "Scanner Isolation Threats"
Cohesion: 0.10
Nodes (24): ADR-0009 MVP runs scanners as subprocesses in the worker, DockerRunner (deferred to Phase 3), ScannerRunner protocol, SubprocessRunner, Trivy Redis lock, RiskGraph Threat Model (living), A1 Findings, secrets metadata, risk scores, A3 Credentials (DB, Redis, JWT key, webhook secrets, LLM key) (+16 more)

### Community 17 - "Real-Scanner Test Harness"
Cohesion: 0.09
Nodes (6): _kill_group(), no_lock(), redis_scanner_lock(), real_settings(), _fake_private_key(), workspace_exists()

### Community 18 - "Graph and Reachability ADRs"
Cohesion: 0.09
Nodes (25): ADR-0006 Graph storage and analysis, Apache AGE (rejected for now), Neo4j (rejected), NetworkX in-process analysis, Yen's k-shortest simple paths, ADR-0012 Reachability tiers L0-L2 in the MVP, Entry point detection, Import graph (graph.py) (+17 more)

### Community 19 - "Dev Stack and CI Docs"
Cohesion: 0.10
Nodes (22): CI Workflow (ci.yml), CI backend job (ruff, mypy, pytest unit + db), CI frontend job (npm lint, typecheck, build), CI images job (build + Trivy scan backend image), CI security-self-scan job (Gitleaks + Trivy fs), Pre-commit config (pre-commit-hooks, ruff, gitleaks), CLAUDE.md AI session entry point, Phase chapter A-S template (docs/phases/PHASE_NN.md) (+14 more)

### Community 20 - "Settings and Health Checks"
Cohesion: 0.11
Nodes (7): get_settings(), Health, healthz(), Readiness, readyz(), check_redis(), get_redis()

### Community 21 - "DB Session and Fixtures"
Cohesion: 0.13
Nodes (11): check_database(), dispose_engine(), get_engine(), get_session(), _session_factory(), _alembic(), client(), db() (+3 more)

### Community 22 - "Finding Drawer and Triage UI"
Cohesion: 0.16
Nodes (25): FindingDetail, FindingListItem, FindingStatus, Priority, contextOrigin(), DrawerBody(), FACTOR_NAME, FactorRow() (+17 more)

### Community 23 - "Frontend Shell and Routing"
Cohesion: 0.12
Nodes (22): RFC-7807, API_BASE, ApiError, apiPatch(), apiPost(), handle(), Health, problemMessage() (+14 more)

### Community 24 - "Context Scoring ADRs"
Cohesion: 0.10
Nodes (23): ADR-0010 MVP vertical slice and deviations, Context-free score model v1-cf.1, Corroboration factor K, Cross-scanner merge keys (normalization/families.py), Threat intel: EPSS + CISA KEV, ADR-0011 Context-aware scoring from repository manifest, Context factors X, P, D, C with source/confidence, Longest path-prefix finding-to-service mapping (+15 more)

### Community 25 - "Scan List and Badges UI"
Cohesion: 0.17
Nodes (20): reportUrl(), RunStatus, ScanList, ScanStatus, Severity, PriorityCounts(), ScanList(), ROLE (+12 more)

### Community 26 - "Celery Canvas"
Cohesion: 0.13
Nodes (9): _bind_task_context(), _clear_task_context(), _configure_worker_logging(), build_canvas(), enqueue(), _sig(), create_celery(), get_celery_app() (+1 more)

### Community 27 - "Deployment and Degradation"
Cohesion: 0.10
Nodes (24): GET /healthz /readyz /metrics, T-20 LLM unavailability blocks scans, infrastructure/ (caddy, prometheus, socket-proxy, scripts), RiskGraph Deployment, NFRs, Failure Handling (section 27), api service (uvicorn), Nightly pg_dump backups (restore rehearsed), beat service, caddy service (only published port :443) (+16 more)

### Community 28 - "Frontend Build Config"
Cohesion: 0.09
Nodes (21): dependencies, cytoscape, react, react-dom, react-router-dom, @tanstack/react-query, name, private (+13 more)

### Community 29 - "Scans API Router"
Cohesion: 0.14
Nodes (10): create_scan(), download_report(), get_scan(), list_scans(), to_out(), RepositoryOut, ScanCreate, ScanList (+2 more)

### Community 30 - "Attack Path Search"
Cohesion: 0.16
Nodes (15): analyze(), _ds(), GraphFinding, _idn(), _path(), PathResult, _search(), _svc() (+7 more)

### Community 31 - "Roadmap Phase Graph"
Cohesion: 0.16
Nodes (22): RiskGraph Phase Dependency Graph and Roadmap (sections 23-24), Critical path P0->P1->P2->P3->P4->P5->P7->P8->P9->P10->P11->P13->P17->P19, Phase 0: Project definition & threat model, Phase 1: Repository & dev environment, Phase 2: Domain model, DB, auth skeleton, Phase 3: Scanner orchestration engine, Phase 4: Scanner adapters, Phase 5: Normalization, correlation, SBOM (+14 more)

### Community 32 - "Domain Module Layout"
Cohesion: 0.15
Nodes (21): RiskGraph Repository Structure (section 22), backend/tests (fixtures, integration, security, e2e), backend/riskgraph/entrypoints (api, worker, cli), modules/attack_paths, modules/audit, modules/auth, modules/context (nvd, epss, kev, extractors), modules/dashboard (+13 more)

### Community 33 - "Repository URL Validation"
Cohesion: 0.20
Nodes (12): clone_url_for(), get_or_create(), InvalidRef, InvalidRepositoryUrl, parse_github_url(), validate_ref(), UnprocessableEntity, test_accepts_branch_and_tag_names() (+4 more)

### Community 34 - "Config and Git Cloner"
Cohesion: 0.15
Nodes (8): GitCloner, Settings, _base(), test_bad_redis_url_rejected(), test_missing_required_fails(), test_non_psycopg_database_url_rejected(), test_short_secret_rejected(), test_valid_settings_parse()

### Community 35 - "Evaluation and Invariants"
Cohesion: 0.10
Nodes (19): RiskGraph Security Threat Model (section 20), Attack surfaces S1-S12, Scanner isolation profile, Protected assets A1-A7, STRIDE per element, Threat actors T1-T6, evaluation/, RiskGraph Testing Strategy and Research Evaluation (sections 25-26) (+11 more)

### Community 36 - "Scan Detail and Graph UI"
Cohesion: 0.19
Nodes (18): apiGet(), AttackPath, ScanContext, AttackPathsPanel(), GraphView, KIND_COLOR, kindOf(), ContextPanel() (+10 more)

### Community 37 - "Repositories API"
Cohesion: 0.19
Nodes (8): Repository, get_repository(), list_repositories(), _point(), RepositoryDetail, RepositorySummary, _summary(), TrendPoint

### Community 38 - "Secret Redaction"
Cohesion: 0.18
Nodes (10): derive_key(), mask(), scrub(), _scrub(), secret_hmac(), test_gitleaks_redaction_removes_every_raw_field(), test_hmac_is_keyed_and_deterministic(), test_mask_never_shows_short_secrets() (+2 more)

### Community 39 - "Core Architecture ADRs"
Cohesion: 0.11
Nodes (20): ADR-0001 Modular monolith with API and worker roles, api process role (FastAPI), import-linter contract, Services per pipeline stage (rejected), worker process role (Celery + beat), ADR-0002 Stack, Caddy, Celery 5 (+12 more)

### Community 40 - "Findings Filters UI"
Cohesion: 0.14
Nodes (19): FindingChange, FindingList, ReachabilityTier, ScannerName, FindingDrawer(), CHANGES, FilterState, FindingFilters() (+11 more)

### Community 41 - "Triage and Audit Log"
Cohesion: 0.19
Nodes (6): AuditLog, history(), record(), InvalidTriage, set_status(), NotFound

### Community 42 - "Frontend Types and Trends"
Cohesion: 0.11
Nodes (17): AttackPathEdge, FindingLocation, GraphData, ManifestStatus, Occurrence, PackageInfo, RepositoryDetail, RepositorySummary (+9 more)

### Community 43 - "Context Resolver"
Cohesion: 0.21
Nodes (5): _clean_file(), ContextResolver, Observed, ServiceDecl, test_secret_in_public_repo_is_internet_exposed_without_manifest()

### Community 44 - "Level 2 DB Tests"
Cohesion: 0.25
Nodes (13): RunResult, FixtureRunner, api(), _by_package(), _findings(), _scan(), test_attack_paths_and_effective_impact(), test_gate() (+5 more)

### Community 45 - "Risk Scoring Service"
Cohesion: 0.22
Nodes (8): VulnIntel, EffectiveImpact, ScoreResult, RiskFactor, input_for(), persist_score(), rescore(), score_finding()

### Community 46 - "API Integration Tests"
Cohesion: 0.25
Nodes (10): api(), _completed_scan(), enqueued(), test_concurrency_cap(), test_create_scan_enqueues_and_dedups(), test_create_scan_rejects_bad_input(), test_findings_sort_filter_and_detail(), test_get_and_list_scans() (+2 more)

### Community 47 - "TS App Config"
Cohesion: 0.11
Nodes (17): compilerOptions, baseUrl, isolatedModules, jsx, lib, module, moduleResolution, noEmit (+9 more)

### Community 48 - "API Auth and Errors Design"
Cohesion: 0.13
Nodes (15): API Architecture (FastAPI /api/v1), Audit log written in same transaction, Auth: JWT bearer + X-API-Key + rotating refresh tokens, Cursor-based pagination for findings, Problem schema (RFC 7807), RBAC roles (admin, security_engineer, developer, viewer), RFC 7807 Problem errors, RiskFactorOut schema (+7 more)

### Community 49 - "Architecture Scan Flow"
Cohesion: 0.14
Nodes (15): Beat Process (Celery Beat), Checkov, Context Enrichment (precedence: override > manifest > IaC > unknown), Cross-scanner Correlation (Trivy-Syft purl, Gitleaks-identity, Checkov-assets, Semgrep-functions), Entry Point Detection (FastAPI/Flask/Django/Express/...), Gitleaks, IaC Extractors (Kubernetes, Docker Compose, Terraform), Reachability Tiers L0-L3 (+7 more)

### Community 50 - "Phase 0-1 Foundations"
Cohesion: 0.13
Nodes (8): Phase 0 — Project Definition & Threat Model, STRIDE Threat Model (T-01…T-20), Success Criteria S1–S8, Phase 1 — Repository & Development Environment, Docker Compose dev stack (postgres, redis, migrate, api, worker, beat, frontend), healthz / readyz endpoints, RFC 7807 problem+json errors, HMAC secret redaction and report scrubbing

### Community 51 - "Auth and ID ADRs"
Cohesion: 0.13
Nodes (12): ADR-0003 UUID v7 ids, single tenant, deletion policy, ADR-0004 Authentication and authorization model, Scoped API keys for CI, argon2id password hashing (pwdlib), 15-min JWT access tokens (HS256), RBAC roles (admin/security_engineer/developer/viewer), Rotating refresh tokens with reuse detection, CI gate (GET /scans/{id}/gate + CLI) (+4 more)

### Community 52 - "Graph API Router"
Cohesion: 0.26
Nodes (6): require_scan(), attack_paths(), GraphEdgeOut, GraphNodeOut, GraphOut, scan_graph()

### Community 53 - "Spec and Manifest Docs"
Cohesion: 0.20
Nodes (12): riskgraph.yaml v1 manifest example, Manifest criticality, Manifest data_stores (kind, sensitivity), Manifest identities (privilege, can_access, credentials), Manifest services (path, exposure, auth, runs_as, connects_to), RiskGraph Project Specification (Phase 0), Assumptions A1-A6 (single-tenant, hostile repos, manifest context), Research question: contextual graph prioritization vs CVSS / CVSS+EPSS (+4 more)

### Community 54 - "Problem Error Types"
Cohesion: 0.22
Nodes (7): TooManyActiveScans, Conflict, Forbidden, Problem, ServiceUnavailable, TooManyRequests, Unauthorized

### Community 55 - "CI/CD and Database Design"
Cohesion: 0.17
Nodes (10): RiskGraph Data, API, Frontend, CI/CD (sections 16-19), Alembic migrations (reversible, migrate service), CI/CD Architecture, POST /webhooks/github, Beat retention job (keep last 20 scans), RiskGraph's own CI pipeline (ci.yml), webhook_deliveries table (idempotency), Path A: GitHub webhook integration (+2 more)

### Community 56 - "Frontend Dev Dependencies"
Cohesion: 0.17
Nodes (12): devDependencies, eslint, @eslint/js, eslint-plugin-react-hooks, @types/node, @types/react, @types/react-dom, typescript (+4 more)

### Community 57 - "Risk Factor Math"
Cohesion: 0.33
Nodes (7): _clamp(), _context_factor(), epss_to_e(), _exploitability(), Factor, _reachability_factor(), _technical_impact()

### Community 58 - "Problem Handlers"
Cohesion: 0.24
Nodes (6): problem_response(), register_problem_handlers(), _http(), _problem(), _unhandled(), _validation()

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

### Community 64 - "Project Risks and Isolation"
Cohesion: 0.20
Nodes (9): MVP Definition and Stretch List, Non-goals (not a scanner, not multi-tenant, no DAST, no live cloud, GitHub only), Project Risks R1-R11, V1 Scope, shared/docker/container_spec.py (only place mounts are built), docker-socket-proxy, git-fetcher clone container, LLM Adapter Protocol (Ollama, Anthropic, Null) (+1 more)

### Community 65 - "Scan Creation and Rate Limits"
Cohesion: 0.20
Nodes (10): POST /scans, Path B: riskgraph-action GitHub Action, Redis token bucket rate limiting, ScanCreate schema, T-03 Command injection via ref/repo/commit, T-13 Resource exhaustion, T-17 CI token leakage in Action, Own Redis token bucket middleware (+2 more)

### Community 66 - "Health Endpoint Tests"
Cohesion: 0.33
Nodes (5): test_healthz_reports_version(), test_readyz_ok_with_real_services(), test_readyz_reports_503_when_dependencies_down(), test_request_id_is_echoed_or_generated(), test_unknown_route_is_problem_json()

### Community 67 - "Blueprint Overview"
Cohesion: 0.22
Nodes (6): RiskGraph Master Blueprint v0.1, Motivating Example (unreachable CVSS 9.8 vs exposed credential), Problem Definition (orchestration cost, severity != risk, no correlation, no explanation), RiskGraph Platform, RiskGraph Architecture (sections 6-15), Worked Examples Scenarios A-E

### Community 68 - "Alembic Migrations"
Cohesion: 0.39
Nodes (3): downgrade(), upgrade(), upgrade()

### Community 69 - "UUIDv7 Generator"
Cohesion: 0.39
Nodes (3): uuid7(), test_uuid7_is_time_ordered_and_unique(), test_uuid7_version_and_variant()

### Community 70 - "Environment Resolver Tests"
Cohesion: 0.46
Nodes (7): _resolver(), test_data_sensitivity_stops_after_two_hops(), test_data_sensitivity_two_hops_prefers_most_sensitive(), test_exposure_labels(), test_longest_path_prefix_wins(), test_secret_keeps_service_impact_context(), test_summary_counts_findings_per_service()

### Community 71 - "Graph Schema and Explainer"
Cohesion: 0.25
Nodes (8): Final Demonstration Workflow (12 steps), Explanation Validator (evidence ids, numbers, URLs), Graph Builder Invariants, NetworkX DiGraph, riskgraph.yaml Manifest Schema v1, Security Graph Schema (node and edge kinds), TemplateExplainer (deterministic fallback), Yen's k-shortest simple paths (top-3)

### Community 72 - "Process Architecture"
Cohesion: 0.29
Nodes (8): API Process (FastAPI), Celery Canvas (clone -> chord(scanners) -> analyze -> finalize), Frontend (React + TS via Caddy), GitHub Action CI/CD Feedback (polling), PostgreSQL (system of record), Redis (broker, result backend, rate limits, scanner slots), scan_jobs / scanner_runs State Machines, Worker Process (Celery)

### Community 73 - "Thesis and Finding Model"
Cohesion: 0.29
Nodes (4): Evaluation Protocol (constructed ground truth, blind labels, KEV held out), Five Thesis Contributions, Canonical Finding Model (Finding + ScanFinding), Finding Fingerprinting (per source type)

### Community 74 - "npm Scripts"
Cohesion: 0.29
Nodes (7): scripts, build, dev, lint, preview, test, typecheck

### Community 76 - "Hosting ADR"
Cohesion: 0.33
Nodes (5): ADR-0005 Hosting and deployment, docker-socket-proxy, K8sJobRunner (future), container_spec.py mount builder, T-08 Docker socket proxy abuse

### Community 77 - "Scanner Installer"
Cohesion: 0.50
Nodes (4): fetch_verified(), install-scanners.sh script, UV_TOOL_BIN_DIR, UV_TOOL_DIR

## Knowledge Gaps
- **102 isolated node(s):** `riskgraph`, `@types/node`, `@types/react`, `@types/react-dom`, `eslint` (+97 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 541 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **15 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Phase 1 — Repository & Development Environment` connect `Phase 0-1 Foundations` to `Domain Module Layout`, `Auth and ID ADRs`, `API App Factory`, `Core Architecture ADRs`?**
  _High betweenness centrality (0.152) - this node is a cross-community bridge._
- **Are the 55 inferred relationships involving `Settings` (e.g. with `create_app()` and `refresh_intel()`) actually correct?**
  _`Settings` has 55 INFERRED edges - model-reasoned connections that need verification._
- **What connects `riskgraph`, `@types/node`, `@types/react` to the rest of the system?**
  _102 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Scan Pipeline Orchestration` be split into smaller, more focused modules?**
  _Cohesion score 0.06611694152923538 - nodes in this community are weakly interconnected._
- **Why does `RiskGraph Repository Structure (section 22)` connect `Domain Module Layout` to `Scan Creation and Rate Limits`, `Evaluation and Invariants`, `Tech Choices and Threats`, `API Auth and Errors Design`, `Phase 0-1 Foundations`, `CI/CD and Database Design`, `Deployment and Degradation`, `Test Datasets`?**
  _High betweenness centrality (0.111) - this node is a cross-community bridge._
- **Are the 55 inferred relationships involving `ScannerName` (e.g. with `FindingOccurrence` and `list_findings()`) actually correct?**
  _`ScannerName` has 55 INFERRED edges - model-reasoned connections that need verification._
- **Should `Scanner Output Normalization` be split into smaller, more focused modules?**
  _Cohesion score 0.05157493942540672 - nodes in this community are weakly interconnected._