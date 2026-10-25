# Graph Report - riskgraph  (2026-10-25)

## Corpus Check
- 324 files · ~166,787 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 22 file(s) not represented in the graph (top: (none) 12, .Dockerfile 2, .example 1)

## Summary
- 3088 nodes · 9093 edges · 163 communities (146 shown, 17 thin omitted)
- Extraction: 89% EXTRACTED · 11% INFERRED · 0% AMBIGUOUS · INFERRED: 960 edges (avg confidence: 0.94)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `299d419c`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- pipeline.py
- FindingsSection.tsx
- RunSpec
- make_evidence
- ScanWorkspace
- RiskGraph expansion A–D: architecture decision and phased plan
- to_networkx
- findings/router.py
- context/__init__.py
- findings/service.py
- cli.py
- feeds.py
- SourceType
- redact.py
- PHASE MVP level 2: context-aware scoring
- PHASE MVP — Scan, normalize, merge, prioritize (vertical slice)
- run.py
- RunStatus
- ADR-0006: Graph storage and analysis
- Dev Stack and CI Docs
- test_pipeline_db.py
- Settings
- Finding Drawer and Triage UI
- Frontend Shell and Routing
- 0013-graph-paths-triage-history.md
- App.tsx
- trivy/parser.py
- RiskGraph — Deployment, NFRs, Failure Handling (section 27)
- Frontend Build Config
- explain/service.py
- PHASE 3: Scanner orchestration engine (hardened DockerRunner)
- PHASE MVP level 2, extended: reachability, attack paths, triage and history
- 05_REPO_STRUCTURE.md
- repositories/router.py
- test_explain.py
- RiskGraph — Security Threat Model (section 20)
- AttackPathsPanel.tsx
- docker_runner.py
- scans/tasks.py
- adr/README.md
- graph/__init__.py
- dataclasses
- types.ts
- re
- list_findings
- config.py
- test_explain_db.py
- TS App Config
- PHASE 0 — Project Definition & Threat Model
- json
- PHASE 1 — Repository & Development Environment
- ADR-0003: UUID v7 ids, single tenant, deletion policy
- graph/router.py
- ADR-0011: Context-aware scoring from the repository manifest (MVP level 2)
- test_callgraph.py
- test_evaluation.py
- test_docker_runner.py
- api.py
- evidence/__init__.py
- test_context.py
- RiskGraph — Master Blueprint (v0.1, 2026-09-19)
- test_runtime_db.py
- TS Node Config
- scanners/record.py
- ADR-0001: Modular monolith with API and worker roles
- report.py
- ContextResolver
- 14. Risk-engine architecture
- test_iac.py
- risk/router.py
- analyze
- Handoff (short summary)
- reachability/service.py
- RawFinding
- test_environment.py
- Session 1 handoff (2026-09-19)
- ADR-0004: Authentication and authorization model
- Scanner Installer
- parse_manifest
- llm.sh
- TS Root Config
- Test DB Init
- ADR-0007: Celery + Redis for background work
- PHASE X0: baseline dataset and metrics (expansion plan)
- Backend Package
- format.ts
- pytest
- RiskGraph
- components
- iac.py
- collections_abc
- ADR-0008: Synchronous SQLAlchemy sessions
- baselines.py
- ScannerName
- vocabulary.py
- scan_sbom
- PHASE 4: Scanner adapters (five hardened images)
- Work done — session 1 (2026-09-19)
- scans/router.py
- kitchen_sink.json
- repositories/router.py
- ADR-0015: L3 reachability by intraprocedural call graph; NVD refreshed by Beat
- tiers.py
- scans/service.py
- generate.py
- PHASE 8: Reachability (L0–L3)
- context/service.py
- build-scanner-images.sh
- ADR-0009: MVP runs scanners as subprocesses in the worker
- A_high_cvss_unreachable/syft/1.54.1/report.json
- extract.py
- findings/service.py
- metrics.py
- 20261022_1200_containers_sbom_assets.py
- TECH_STACK.md
- B_moderate_reachable_exposed/syft/1.54.1/report.json
- D_internal_limited/syft/1.54.1/report.json
- test_api.py
- E_attack_path/syft/1.54.1/report.json
- C_exposed_credential/syft/1.54.1/report.json
- pipeline_support.py
- PHASE 11: Contextual risk engine (scenarios, properties, GET /risks)
- build_canvas
- audit/service.py
- _ollama
- PHASE X1: evidence and assurance contracts (expansion plan)
- 20261023_0900_reachability_l3.py
- gitleaks/parser.py
- PHASE 12: AI explanation (evidence-grounded, validated, cached)
- OllamaAdapter
- 26. Research evaluation methodology
- test_health.py
- Scanner
- test_graph_db.py
- RiskGraph — AI session entry point
- test_risks_db.py
- average_precision
- test_reachability.py
- context/router.py
- RiskGraph baseline (expansion phase X0)
- typing
- contract.py
- feeds.py
- .source
- RiskGraph — Architecture (sections 6–15)
- ADR-0002: Stack
- explain/router.py
- PHASE 10: Attack-path engine (scenario E, performance budget)
- ADR-0010: MVP vertical slice and its deviations from the blueprint
- ADR-0012: Reachability tiers L0–L2 in the MVP (import graph, no call graph)
- test_search_matches_brute_force_top_k
- 13. Attack-path architecture
- 9. Scanner orchestration architecture
- ADR-0016: Evidence-grounded explanations with a local model and a template fallback
- Settings

## God Nodes (most connected - your core abstractions)
1. `Settings` - 155 edges
2. `SourceType` - 124 edges
3. `ScannerName` - 115 edges
4. `session_scope()` - 73 edges
5. `ScanStatus` - 72 edges
6. `Severity` - 63 edges
7. `RawFinding` - 52 edges
8. `analyze()` - 51 edges
9. `analyze()` - 47 edges
10. `score()` - 46 edges

## Surprising Connections (you probably didn't know these)
- `Decision` --references--> `create_app()`  [INFERRED]
  docs/adr/0010-mvp-scope.md → backend/riskgraph/entrypoints/api.py
- `Session 7 additions (2026-10-25)` --references--> `kubernetes_context()`  [INFERRED]
  docs/phases/PHASE_07.md → backend/riskgraph/modules/context/iac.py
- `8. Main risks, scope traps and decisions to finalize early` --references--> `Assurance`  [INFERRED]
  docs/proposals/EXPANSION_A-D.md → backend/riskgraph/modules/evidence/contract.py
- `Consequences` --references--> `RawRef`  [INFERRED]
  docs/adr/0017-evidence-and-assurance.md → backend/riskgraph/modules/evidence/contract.py
- `B. Built` --references--> `risk_out()`  [INFERRED]
  docs/phases/PHASE_11.md → backend/riskgraph/modules/findings/router.py

## Import Cycles
- 3-file cycle: `backend/riskgraph/modules/risk/__init__.py -> backend/riskgraph/modules/risk/service.py -> backend/riskgraph/modules/risk/model.py -> backend/riskgraph/modules/risk/__init__.py`

## Hyperedges (group relationships)
- **Dev Compose stack services sharing the backend image** — docker_compose_migrate, docker_compose_api, docker_compose_worker, docker_compose_beat [EXTRACTED 1.00]
- **riskgraph.yaml context model (services, identities, data stores, criticality)** — docs_examples_riskgraph_services, docs_examples_riskgraph_identities, docs_examples_riskgraph_data_stores, docs_examples_riskgraph_criticality, readme_context_aware_scoring [EXTRACTED 1.00]

## Communities (163 total, 17 thin omitted)

### Community 0 - "pipeline.py"
Cohesion: 0.07
Nodes (44): IacResult, SbomComponent, attach_findings(), canonical_purl(), clear(), _ecosystem(), list_components(), PackageSeen (+36 more)

### Community 1 - "FindingsSection.tsx"
Cohesion: 0.13
Nodes (21): apiGet(), FindingChange, FindingList, ReachabilityTier, ScannerName, FindingDrawer(), CHANGES, FilterState (+13 more)

### Community 2 - "RunSpec"
Cohesion: 0.17
Nodes (16): _rlimits(), SubprocessRunner, _tail(), build_clone_argv(), test_memory_limit_is_enforced(), test_self_python_is_the_only_path_alias(), runner(), _spec() (+8 more)

### Community 3 - "make_evidence"
Cohesion: 0.12
Nodes (17): Assurance, FlowStep, make_evidence(), min_assurance(), RawRef, declared(), _ev(), test_a_relationship_needs_evidence() (+9 more)

### Community 4 - "ScanWorkspace"
Cohesion: 0.10
Nodes (14): CloneError, Cloner, CloneResult, git_env(), GitCloner, ScanWorkspace, WorkspaceError, test_measure_enforces_limits() (+6 more)

### Community 5 - "RiskGraph expansion A–D: architecture decision and phased plan"
Cohesion: 0.10
Nodes (17): 1.1 Existing functionality (VERIFIED by reading the code at `08d5181`), 1.2 Gaps that matter for A–D, 1. Audit: what exists, and where A–D plug in, 2.1 Options compared, 2.2 Graph storage (re-evaluated, not assumed), 2.3 Recommended architecture, 2. Architecture: options and the decision, 3. Technical designs (+9 more)

### Community 6 - "to_networkx"
Cohesion: 0.07
Nodes (21): _EdgeRow, _NodeRow, to_networkx(), test_to_networkx_keeps_the_most_probable_parallel_edge(), _attack_graph(), Row, _rows(), test_loader_builds_5k_nodes_20k_edges_under_one_second() (+13 more)

### Community 7 - "findings/router.py"
Cohesion: 0.16
Nodes (23): _diff_items(), _float(), get_finding(), path_out(), risk_out(), AttackPathOut, AuditOut, DiffItem (+15 more)

### Community 8 - "context/__init__.py"
Cohesion: 0.13
Nodes (7): DataStoreDecl, IdentityDecl, normalize_service_path(), _Resolver, _short(), _Strict, _structure_problem()

### Community 9 - "findings/service.py"
Cohesion: 0.15
Nodes (11): apply_history(), diff_scans(), previous_scan_id(), ScanDiff, Finding, evaluate_gate(), GatePolicy, GateResult (+3 more)

### Community 10 - "cli.py"
Cohesion: 0.14
Nodes (9): build_parser(), main(), markdown(), _out(), run_scan(), test_failed_scan_and_api_errors(), test_gate_failure_exit_code_and_escaping(), test_gate_pass_and_summary() (+1 more)

### Community 11 - "feeds.py"
Cohesion: 0.15
Nodes (13): fetch_nvd(), NvdCvss, parse_nvd_cvss(), _nvd(), test_falls_back_to_v30_then_v40(), test_malformed_responses_yield_none_not_exceptions(), test_prefers_v31_primary_over_other_entries(), Built (+5 more)

### Community 12 - "SourceType"
Cohesion: 0.08
Nodes (63): FindingContext, Observed, VulnIntel, _clamp(), _context_factor(), EffectiveImpact, epss_to_e(), _exploitability() (+55 more)

### Community 13 - "redact.py"
Cohesion: 0.25
Nodes (8): derive_key(), mask(), secret_hmac(), test_gitleaks_redaction_removes_every_raw_field(), test_hmac_is_keyed_and_deterministic(), test_mask_never_shows_short_secrets(), test_scrub_removes_secrets_from_any_report(), test_snippet_fields_are_dropped()

### Community 14 - "PHASE MVP level 2: context-aware scoring"
Cohesion: 0.11
Nodes (17): A. Objective, B. Why, C. Architecture, D. Components, H. API, I. Algorithms, J. Implementation, K. Commands (+9 more)

### Community 15 - "PHASE MVP — Scan, normalize, merge, prioritize (vertical slice)"
Cohesion: 0.11
Nodes (18): A. Objective, B. Why, C. Architecture, D. Components, E. Technical decisions, F. Folder structure, G. Database, I. Algorithms (+10 more)

### Community 16 - "run.py"
Cohesion: 0.16
Nodes (9): collect(), _environment(), EvaluationError, _guard(), _report(), _reset_db(), _scan(), Scenario (+1 more)

### Community 17 - "RunStatus"
Cohesion: 0.18
Nodes (15): active_scan(), cas_run(), cas_scan(), count_active(), get_run(), check_run(), check_scan(), final_status() (+7 more)

### Community 18 - "ADR-0006: Graph storage and analysis"
Cohesion: 0.22
Nodes (8): ADR-0006: Graph storage and analysis, Alternatives considered, Apache AGE (Postgres extension) — rejected for now, Consequences, Context, Decision, igraph instead of NetworkX — rejected, Neo4j Community — rejected

### Community 19 - "Dev Stack and CI Docs"
Cohesion: 0.16
Nodes (16): CI Workflow (ci.yml), CI backend job (ruff, mypy, pytest unit + db), CI frontend job (npm lint, typecheck, build), CI images job (build + Trivy scan backend image), CI security-self-scan job (Gitleaks + Trivy fs), Pre-commit config (pre-commit-hooks, ruff, gitleaks), Dev Compose stack, api service (uvicorn create_app) (+8 more)

### Community 20 - "test_pipeline_db.py"
Cohesion: 0.14
Nodes (37): FindingFilters, run_pipeline_inline(), clone(), collect(), finalize(), runs_for(), create_scan(), session_scope() (+29 more)

### Community 21 - "Settings"
Cohesion: 0.12
Nodes (19): FixtureRunner, api(), _count(), test_every_edge_and_finding_rests_on_stored_evidence(), test_hypothesis_paths_never_raise_a_score(), test_the_api_serves_evidence_and_assurance(), test_the_migration_backfill_matches_the_builder(), api() (+11 more)

### Community 22 - "Finding Drawer and Triage UI"
Cohesion: 0.13
Nodes (28): apiPost(), Explanation, FindingDetail, FindingListItem, FindingStatus, TrendPoint, ExplanationPanel(), contextOrigin() (+20 more)

### Community 23 - "Frontend Shell and Routing"
Cohesion: 0.27
Nodes (8): RFC-7807, API_BASE, ApiError, apiPatch(), handle(), Health, problemMessage(), Readiness

### Community 24 - "0013-graph-paths-triage-history.md"
Cohesion: 0.25
Nodes (8): ADR-0013: Per-scan attack paths with effective impact; triage, history and the CI gate, Alternatives considered, CI gate, Consequences, Context, Decision, Graph and attack paths, Triage and history

### Community 25 - "App.tsx"
Cohesion: 0.19
Nodes (13): Scan, App(), HealthDot(), HomePage(), RepositoryRoute(), ScanRoute(), EXAMPLES, NewScanForm() (+5 more)

### Community 26 - "trivy/parser.py"
Cohesion: 0.11
Nodes (27): cwe_ids(), sast_category(), iac_family(), iac_topic(), IacFamily, normalize_path(), checkov_severity(), semgrep_severity() (+19 more)

### Community 27 - "RiskGraph — Deployment, NFRs, Failure Handling (section 27)"
Cohesion: 0.40
Nodes (4): 27.1 Deployment architecture, 27.2 Non-functional requirements (measurable targets), 27.3 Failure handling (graceful degradation table), RiskGraph — Deployment, NFRs, Failure Handling (section 27)

### Community 28 - "Frontend Build Config"
Cohesion: 0.05
Nodes (39): dependencies, cytoscape, react, react-dom, react-router-dom, @tanstack/react-query, devDependencies, eslint (+31 more)

### Community 29 - "explain/service.py"
Cohesion: 0.15
Nodes (16): clip_lines(), factor_evidence(), FactorEv, FindingEv, _Frozen, PathEv, ScoreEv, SnippetEv (+8 more)

### Community 30 - "PHASE 3: Scanner orchestration engine (hardened DockerRunner)"
Cohesion: 0.13
Nodes (14): A. Objective, B. Why, F. Folder structure, G. Database, H. API, I. Algorithms, J. Implementation notes, K. Commands (+6 more)

### Community 31 - "PHASE MVP level 2, extended: reachability, attack paths, triage and history"
Cohesion: 0.11
Nodes (18): A. Objective, B. Why, C. Architecture, D. Components, E. Technical decisions, F. Folder structure, H. API, I. Algorithms (+10 more)

### Community 33 - "repositories/router.py"
Cohesion: 0.20
Nodes (12): clone_url_for(), get_or_create(), InvalidRef, InvalidRepositoryUrl, parse_github_url(), validate_ref(), UnprocessableEntity, test_accepts_branch_and_tag_names() (+4 more)

### Community 34 - "test_explain.py"
Cohesion: 0.18
Nodes (23): NullAdapter, Reason, generate(), explain(), validate(), _draft(), _pack(), test_a_grounded_draft_passes() (+15 more)

### Community 35 - "RiskGraph — Security Threat Model (section 20)"
Cohesion: 0.38
Nodes (6): Actors, Assets (what we protect), Attack surfaces, RiskGraph — Security Threat Model (section 20), Security invariants (tested in Phase 15/16), Threats and mitigations

### Community 36 - "AttackPathsPanel.tsx"
Cohesion: 0.24
Nodes (11): AttackPath, GraphData, ScanSummary, AttackPathsPanel(), GraphView, KIND_COLOR, kindOf(), COLORS (+3 more)

### Community 37 - "docker_runner.py"
Cohesion: 0.09
Nodes (9): _Containers, DockerClient, _Images, _printable(), _write_capped(), SlotLimiter, SlotTimeoutError, build_runner() (+1 more)

### Community 38 - "scans/tasks.py"
Cohesion: 0.19
Nodes (12): refresh_trivy_db_task(), default_deps(), fetcher_image(), redis_scanner_lock(), analyze_task(), clone_task(), collect_task(), finalize_task() (+4 more)

### Community 39 - "adr/README.md"
Cohesion: 0.18
Nodes (8): ADR-0005: Hosting and deployment, Alternatives considered, Consequences, Decision, ADR-0014: Scanners run as hardened containers (DockerRunner), with pinned images, Consequences, Context, Architecture Decision Records

### Community 40 - "graph/__init__.py"
Cohesion: 0.22
Nodes (13): AttackPath, AttackPathFinding, GraphEdge, GraphNode, clear(), _dec(), list_paths(), load_graph() (+5 more)

### Community 41 - "dataclasses"
Cohesion: 0.16
Nodes (12): _bfs(), chain_to(), find_l3(), Path3, _qualify(), reachable_functions(), _resolve(), _python_module_index() (+4 more)

### Community 42 - "types.ts"
Cohesion: 0.10
Nodes (21): AttackPathEdge, FindingLocation, KubeWorkload, ManifestStatus, Occurrence, PackageInfo, Priority, RepositoryDetail (+13 more)

### Community 43 - "re"
Cohesion: 0.21
Nodes (6): import_names(), python_import_names(), used_without_import(), test_package_names(), _pins(), test_every_adapter_image_tag_matches_the_pinned_version()

### Community 44 - "list_findings"
Cohesion: 0.19
Nodes (5): list_findings(), require_scan(), scan_diff(), scan_gate(), triage_finding()

### Community 45 - "config.py"
Cohesion: 0.08
Nodes (10): _bind_task_context(), _clear_task_context(), _configure_worker_logging(), ping(), refresh_feeds_task(), create_celery(), get_celery_app(), get_settings() (+2 more)

### Community 46 - "test_explain_db.py"
Cohesion: 0.26
Nodes (11): api(), _critical(), _grounded_reply(), sid(), test_a_grounded_model_answer_is_validated_and_stored(), test_an_injected_answer_is_rejected_and_never_stored(), test_explanation_not_found_cases(), test_refresh_replaces_a_fallback_once_the_model_is_back() (+3 more)

### Community 47 - "TS App Config"
Cohesion: 0.11
Nodes (17): compilerOptions, baseUrl, isolatedModules, jsx, lib, module, moduleResolution, noEmit (+9 more)

### Community 48 - "PHASE 0 — Project Definition & Threat Model"
Cohesion: 0.04
Nodes (41): 17.1 Cross-cutting, 17.2 Endpoints (V1), 17.3 Representative schemas, 17. API architecture, 18. Frontend architecture, 19.1 Two integration paths, 19.2 Policy (from `riskgraph.yaml` `policy:` or repository settings; action input overrides), 19.3 RiskGraph's own CI (`.github/workflows/ci.yml`) (+33 more)

### Community 49 - "json"
Cohesion: 0.17
Nodes (7): _cves(), _freeze_intel(), record(), _target(), _seed_intel(), fetch_kev(), OutboundClient

### Community 50 - "PHASE 1 — Repository & Development Environment"
Cohesion: 0.10
Nodes (20): A. Objective, B. Why, C. Architecture, D. Components, E. Technical decisions, F. Folder structure, G. Database, H. API (+12 more)

### Community 51 - "ADR-0003: UUID v7 ids, single tenant, deletion policy"
Cohesion: 0.25
Nodes (7): ADR-0003: UUID v7 ids, single tenant, deletion policy, Alternatives considered, bigint serial ids — rejected, Consequences, Context, Decision, Multi-tenant from day one — rejected

### Community 52 - "graph/router.py"
Cohesion: 0.13
Nodes (11): attack_paths(), _edges_out(), graph_reach(), GraphEdgeOut, GraphNodeOut, GraphOut, ReachNodeOut, ReachOut (+3 more)

### Community 53 - "ADR-0011: Context-aware scoring from the repository manifest (MVP level 2)"
Cohesion: 0.27
Nodes (9): ADR-0011: Context-aware scoring from the repository manifest (MVP level 2), Alternatives considered, Consequences, Context, riskgraph.yaml v1 manifest example, Manifest criticality, Manifest data_stores (kind, sensitivity), Manifest identities (privilege, can_access, credentials) (+1 more)

### Community 54 - "test_callgraph.py"
Cohesion: 0.18
Nodes (20): load_symbols(), SymbolEntry, _classifier(), _l3(), _project(), test_a_call_through_another_module_function_is_l3(), test_a_direct_call_from_a_route_is_l3(), test_a_from_import_is_resolved() (+12 more)

### Community 55 - "test_evaluation.py"
Cohesion: 0.18
Nodes (10): rank(), effort_at(), recall_at(), _F, test_effort_to_ninety_percent_recall(), test_m1_uses_cvss_then_severity_equivalent_then_fingerprint(), test_m2_multiplies_by_the_epss_transform_and_treats_missing_epss_as_neutral(), test_m4_ranks_like_the_product_priority_first() (+2 more)

### Community 56 - "test_docker_runner.py"
Cohesion: 0.14
Nodes (14): PathRoot, FakeClient, FakeContainer, FakeContainers, FakeImages, _runner(), _spec(), test_a_hung_container_is_killed_at_the_timeout() (+6 more)

### Community 57 - "api.py"
Cohesion: 0.07
Nodes (9): create_app(), Health, healthz(), Readiness, readyz(), configure_logging(), get_logger(), RequestIdMiddleware (+1 more)

### Community 58 - "evidence/__init__.py"
Cohesion: 0.28
Nodes (12): Evidence, EdgeEvidence, EvidenceRow, FindingEvidence, clear(), evidence_for_edges(), evidence_for_finding(), link_edge() (+4 more)

### Community 59 - "test_context.py"
Cohesion: 0.19
Nodes (8): _client(), test_cvss_rejects_v2_and_garbage(), test_cvss_subscores(), test_epss_batches_and_parses(), handler(), test_kev_falls_back_to_mirror(), test_outbound_caps_body_size(), test_outbound_refuses_redirects_and_foreign_hosts()

### Community 60 - "RiskGraph — Master Blueprint (v0.1, 2026-09-19)"
Cohesion: 0.20
Nodes (9): 1. Executive summary, 28. Final demonstration workflow (what the examiner sees, ~12 minutes), 29. Project risks and mitigations, 2. Exact problem definition, 30. Definition of the final MVP, 3. Scope (what V1 delivers), 4. Non-goals (stated so nobody expects them), 5. Novelty and technical contribution (honest version) (+1 more)

### Community 61 - "test_runtime_db.py"
Cohesion: 0.19
Nodes (12): ScanJob, ScannerRun, reap(), ReapResult, api(), _create(), kills(), test_a_finished_scan_cannot_be_cancelled() (+4 more)

### Community 62 - "TS Node Config"
Cohesion: 0.13
Nodes (12): manifests(), inputs(), compilerOptions, composite, module, moduleResolution, noEmit, skipLibCheck (+4 more)

### Community 63 - "scanners/record.py"
Cohesion: 0.10
Nodes (24): DockerRunner, make_removable(), scrub(), _scrub(), RunResult, RunSpec, ScannerRunner, refresh_trivy_db() (+16 more)

### Community 64 - "ADR-0001: Modular monolith with API and worker roles"
Cohesion: 0.22
Nodes (8): ADR-0001: Modular monolith with API and worker roles, Alternatives considered, Compliance, Consequences, Context, Decision, Services per pipeline stage — rejected, Single flat package (no module boundaries) — rejected

### Community 65 - "report.py"
Cohesion: 0.25
Nodes (9): _cell(), findings_csv(), _fmt(), _labels(), main(), render(), _statistic(), _versions() (+1 more)

### Community 66 - "ContextResolver"
Cohesion: 0.15
Nodes (6): _clean_file(), ContextResolver, KubeContext, ManifestResult, ServiceDecl, test_secret_in_public_repo_is_internet_exposed_without_manifest()

### Community 67 - "14. Risk-engine architecture"
Cohesion: 0.25
Nodes (8): 14.1 Model comparison, 14.2 Definitions, 14.3 Reduction to a context-free model (the property that makes the model defensible), 14.4 Attack-path coupling ("effective impact"), 14.5 Rule overrides (explainable, listed in output as `overrides[]`), 14.6 Worked examples (scenarios A–E from the brief), 14.7 Sensitivity, calibration, limitations, 14. Risk-engine architecture

### Community 68 - "test_iac.py"
Cohesion: 0.30
Nodes (16): extract(), _rel(), _walk(), _repo(), test_alias_bombs_are_refused_before_parsing(), test_compose_build_context_cannot_escape_the_repository(), test_compose_exposure_reaches_findings_under_its_build_context(), test_compose_publishes_only_non_loopback_ports() (+8 more)

### Community 69 - "risk/router.py"
Cohesion: 0.14
Nodes (8): ranked(), score_of(), _latest_scan(), list_risks(), risk_detail(), RiskDetailOut, RiskListOut, _scan_id()

### Community 70 - "analyze"
Cohesion: 0.08
Nodes (42): Manifest, Relationship, analyze(), edge(), exploit_edge(), AttackAnalysis, _ds(), exploit_assurance() (+34 more)

### Community 71 - "Handoff (short summary)"
Cohesion: 0.33
Nodes (5): Before the next session, Commands, Handoff (short summary), State, Verified (at commit `943be49`)

### Community 72 - "reachability/service.py"
Cohesion: 0.26
Nodes (5): ReachabilityResult, clear(), persist_verdict(), ReachabilityRun, run_extractor()

### Community 73 - "RawFinding"
Cohesion: 0.11
Nodes (25): Location, RawFinding, fingerprint(), stable_hash(), _build(), merge(), MergedFinding, _overlap_clusters() (+17 more)

### Community 74 - "test_environment.py"
Cohesion: 0.46
Nodes (7): _resolver(), test_data_sensitivity_stops_after_two_hops(), test_data_sensitivity_two_hops_prefers_most_sensitive(), test_exposure_labels(), test_longest_path_prefix_wins(), test_secret_keeps_service_impact_context(), test_summary_counts_findings_per_service()

### Community 75 - "Session 1 handoff (2026-09-19)"
Cohesion: 0.11
Nodes (18): Commands that are known to work, Gotchas already hit (so you don't hit them again), HANDOFF: resume here (updated 2026-10-25, session 8: X0 and X1 done; next X2, see todo1150.md), Open items (decide before Phase 2), Open items (small, do at the start of Phase 2), Rules of engagement (from the brief and CLAUDE.md), Session 1 handoff (2026-09-19), Session 2 (2026-10-21): MVP vertical slice, done (+10 more)

### Community 76 - "ADR-0004: Authentication and authorization model"
Cohesion: 0.25
Nodes (7): ADR-0004: Authentication and authorization model, Alternatives considered, Consequences, Context, Decision, GitHub OAuth — deferred (stretch), Server-side sessions — rejected

### Community 77 - "Scanner Installer"
Cohesion: 0.50
Nodes (4): fetch_verified(), install-scanners.sh script, UV_TOOL_BIN_DIR, UV_TOOL_DIR

### Community 78 - "parse_manifest"
Cohesion: 0.22
Nodes (14): load_manifest(), parse_manifest(), test_alias_bomb_is_refused_before_expansion(), test_deep_nesting_is_refused_without_crashing(), test_documented_example_manifest_is_valid(), test_hostile_or_broken_documents_never_raise(), test_load_absent_valid_and_yml_fallback(), test_load_refuses_oversized_and_non_utf8() (+6 more)

### Community 79 - "llm.sh"
Cohesion: 0.38
Nodes (12): cancel_preload(), down(), loaded(), ollama_up(), say(), setting(), llm.sh script, socket_forward() (+4 more)

### Community 87 - "ADR-0007: Celery + Redis for background work"
Cohesion: 0.25
Nodes (7): ADR-0007: Celery + Redis for background work, Alternatives considered, arq / Dramatiq — rejected, Consequences, Context, Decision, Postgres job table + worker loop — rejected

### Community 88 - "PHASE X0: baseline dataset and metrics (expansion plan)"
Cohesion: 0.12
Nodes (13): A. Objective, B. Why, C. Architecture, D. Components, Deviations from the plan, E. Technical decisions, G. Database, H. API (+5 more)

### Community 91 - "format.ts"
Cohesion: 0.17
Nodes (23): reportUrl(), RunStatus, ScanStatus, Severity, PriorityCounts(), RepositoryPage(), ScanDetailPage(), STAGES (+15 more)

### Community 92 - "pytest"
Cohesion: 0.13
Nodes (24): build_create_kwargs(), _check_env(), _checked_path(), container_fields(), ContainerSpecError, Limits, Mount, scanner_image() (+16 more)

### Community 93 - "RiskGraph"
Cohesion: 0.25
Nodes (7): Context-aware scoring, Develop, Documentation, Quickstart, RiskGraph, Run without Docker, Triage, history and the CI gate

### Community 94 - "components"
Cohesion: 0.15
Nodes (16): components(), count(), _ecosystem(), _location(), _text(), test_syft_components_are_deduplicated_and_capped_text(), test_syft_tolerates_garbage(), 16.1 Principles (+8 more)

### Community 95 - "iac.py"
Cohesion: 0.25
Nodes (11): _code_dir(), _compose(), _d(), IacAsset, _ingress_backends(), _k8s(), kubernetes_context(), _l() (+3 more)

### Community 96 - "collections_abc"
Cohesion: 0.09
Nodes (15): check_database(), dispose_engine(), get_engine(), get_session(), _session_factory(), _alembic(), client(), db() (+7 more)

### Community 97 - "ADR-0008: Synchronous SQLAlchemy sessions"
Cohesion: 0.29
Nodes (6): ADR-0008: Synchronous SQLAlchemy sessions, Alternatives considered, Async SQLAlchemy (asyncpg) — rejected, Consequences, Context, Decision

### Community 98 - "baselines.py"
Cohesion: 0.30
Nodes (5): cvss_equivalent(), m1_key(), m2_key(), m4_key(), Rankable

### Community 99 - "ScannerName"
Cohesion: 0.12
Nodes (25): normalize_check_id(), secret_family(), clean_rule_id(), semgrep_secret_family(), ScannerName, fixture_path(), load(), parse_all() (+17 more)

### Community 100 - "vocabulary.py"
Cohesion: 0.06
Nodes (9): Command, ParseContext, ScanPaths, CheckovScanner, GitleaksScanner, drop_keys(), SemgrepScanner, SyftScanner (+1 more)

### Community 101 - "scan_sbom"
Cohesion: 0.19
Nodes (3): ComponentOut, SbomOut, scan_sbom()

### Community 102 - "PHASE 4: Scanner adapters (five hardened images)"
Cohesion: 0.29
Nodes (6): Built, Decisions, Known differences from the host-run MVP, Not done, Objective, PHASE 4: Scanner adapters (five hardened images)

### Community 103 - "Work done — session 1 (2026-09-19)"
Cohesion: 0.15
Nodes (12): 1. Orientation, 2. Blueprint (`docs/blueprint/`, 9 files, ~18.8k words), 3. Phase 0 (docs), 4. Phase 1 (code) — see `docs/phases/PHASE_01.md` for the full chapter, 5. Commit, 6. After the commit (uncommitted at time of writing), Problems hit and fixed, Problems hit and fixed during Phase 1 (+4 more)

### Community 104 - "scans/router.py"
Cohesion: 0.16
Nodes (11): cancel_scan(), create_scan(), download_report(), get_scan(), list_scans(), to_out(), RepositoryOut, ScanCreate (+3 more)

### Community 105 - "kitchen_sink.json"
Cohesion: 0.13
Nodes (14): bomFormat, bom-ref, name, type, components, metadata, component, timestamp (+6 more)

### Community 106 - "repositories/router.py"
Cohesion: 0.22
Nodes (8): Repository, get_repository(), list_repositories(), _point(), RepositoryDetail, RepositorySummary, _summary(), TrendPoint

### Community 107 - "ADR-0015: L3 reachability by intraprocedural call graph; NVD refreshed by Beat"
Cohesion: 0.29
Nodes (6): ADR-0015: L3 reachability by intraprocedural call graph; NVD refreshed by Beat, Consequences, Context, Decision, L3, NVD

### Community 108 - "tiers.py"
Cohesion: 0.16
Nodes (3): enclosing_function(), ModuleGraph, TierClassifier

### Community 109 - "scans/service.py"
Cohesion: 0.10
Nodes (21): cancel_scan(), get_scan(), list_scans(), report_file(), ScanView, start_scan(), TooManyActiveScans, _view() (+13 more)

### Community 110 - "generate.py"
Cohesion: 0.10
Nodes (11): ExplanationDraft, json_schema(), EvidencePack, norm(), spellings(), _parse(), user_message(), _phrase() (+3 more)

### Community 111 - "PHASE 8: Reachability (L0–L3)"
Cohesion: 0.33
Nodes (5): Built, Not done (out of the blueprint's P8 scope), PHASE 8: Reachability (L0–L3), Verification, Verification (session 7)

### Community 112 - "context/service.py"
Cohesion: 0.16
Nodes (11): CvssSubscores, _round1(), subscores(), Asset, Vulnerability, _fresh(), list_assets(), _load_kev() (+3 more)

### Community 114 - "ADR-0009: MVP runs scanners as subprocesses in the worker"
Cohesion: 0.33
Nodes (5): ADR-0009: MVP runs scanners as subprocesses in the worker, Alternatives considered, Blueprint DockerRunner now (§9.3): deferred, bubblewrap / `unshare --net` around each subprocess: deferred, Context

### Community 115 - "A_high_cvss_unreachable/syft/1.54.1/report.json"
Cohesion: 0.13
Nodes (14): bomFormat, bom-ref, name, type, components, metadata, component, timestamp (+6 more)

### Community 116 - "extract.py"
Cohesion: 0.26
Nodes (12): _dotted(), extract(), _js(), main(), _package_json(), _parsers(), _python(), _python_calls() (+4 more)

### Community 117 - "findings/service.py"
Cohesion: 0.16
Nodes (13): FindingOccurrence, ScanFinding, _base_query(), clear_scan(), _escape_like(), _evidence(), FindingDetail, get_finding_detail() (+5 more)

### Community 118 - "metrics.py"
Cohesion: 0.21
Nodes (6): bootstrap(), _dcg(), Estimate, ndcg_at(), _percentile(), test_percentile_interpolates_like_numpy()

### Community 119 - "20261022_1200_containers_sbom_assets.py"
Cohesion: 0.17
Nodes (9): upgrade(), downgrade(), _in_list(), _replace_check(), upgrade(), upgrade(), downgrade(), _source_check() (+1 more)

### Community 121 - "B_moderate_reachable_exposed/syft/1.54.1/report.json"
Cohesion: 0.13
Nodes (14): bomFormat, bom-ref, name, type, components, metadata, component, timestamp (+6 more)

### Community 122 - "D_internal_limited/syft/1.54.1/report.json"
Cohesion: 0.13
Nodes (14): bomFormat, bom-ref, name, type, components, metadata, component, timestamp (+6 more)

### Community 123 - "test_api.py"
Cohesion: 0.27
Nodes (10): api(), _completed_scan(), enqueued(), test_concurrency_cap(), test_create_scan_enqueues_and_dedups(), test_create_scan_rejects_bad_input(), test_findings_sort_filter_and_detail(), test_get_and_list_scans() (+2 more)

### Community 124 - "E_attack_path/syft/1.54.1/report.json"
Cohesion: 0.13
Nodes (14): bomFormat, bom-ref, name, type, components, metadata, component, timestamp (+6 more)

### Community 125 - "C_exposed_credential/syft/1.54.1/report.json"
Cohesion: 0.14
Nodes (13): bomFormat, bom-ref, name, type, metadata, component, timestamp, tools (+5 more)

### Community 126 - "pipeline_support.py"
Cohesion: 0.08
Nodes (7): LabelRule, _kill_group(), _open_cache_to_scanners(), refresh_argv(), _force_writable(), widen_own_directories(), _drop()

### Community 127 - "PHASE 11: Contextual risk engine (scenarios, properties, GET /risks)"
Cohesion: 0.29
Nodes (6): A. Objective, B. Built, M. Testing, Not done, O. Validation, PHASE 11: Contextual risk engine (scenarios, properties, GET /risks)

### Community 128 - "build_canvas"
Cohesion: 0.25
Nodes (5): build_canvas(), enqueue(), enqueue_kill(), _sig(), test_canvas_shape_and_queues()

### Community 129 - "audit/service.py"
Cohesion: 0.38
Nodes (3): AuditLog, history(), record()

### Community 130 - "_ollama"
Cohesion: 0.22
Nodes (7): _ollama(), test_ollama_connection_errors_are_adapter_errors(), test_ollama_failures_are_adapter_errors(), test_ollama_keep_alive_is_sent_as_a_number_when_it_is_one(), test_ollama_request_shape_and_reply(), handler(), test_ollama_url_must_be_http()

### Community 131 - "PHASE X1: evidence and assurance contracts (expansion plan)"
Cohesion: 0.09
Nodes (18): ADR-0017: One evidence and assurance contract; no edge without evidence, Consequences, Context, Decision, Rejected, H. API, A. Objective, B. Why (+10 more)

### Community 132 - "20261023_0900_reachability_l3.py"
Cohesion: 0.83
Nodes (3): _check(), downgrade(), upgrade()

### Community 133 - "gitleaks/parser.py"
Cohesion: 0.33
Nodes (4): gitleaks_severity(), count(), _items(), parse()

### Community 134 - "PHASE 12: AI explanation (evidence-grounded, validated, cached)"
Cohesion: 0.15
Nodes (13): A. Objective, B. Why, C. Architecture, D. Components, E. Technical decisions, G. Database, H. API, L. Configuration (+5 more)

### Community 135 - "OllamaAdapter"
Cohesion: 0.09
Nodes (8): AdapterError, LlmAdapter, OllamaAdapter, Outcome, test_real_model_explains_a_critical_finding_and_the_result_is_cached(), test_unreachable_model_falls_back_to_the_template(), test_ollama_over_a_unix_socket(), test_ollama_socket_that_is_missing_is_an_adapter_error()

### Community 136 - "26. Research evaluation methodology"
Cohesion: 0.17
Nodes (11): 25.1 Layers and markers, 25.2 Test datasets (`datasets/`), 25. Testing strategy, 26.1 Question and hypotheses, 26.2 Methods compared, 26.3 Ground truth, 26.4 Metrics, 26.5 Statistics (+3 more)

### Community 137 - "test_health.py"
Cohesion: 0.33
Nodes (5): test_healthz_reports_version(), test_readyz_ok_with_real_services(), test_readyz_reports_503_when_dependencies_down(), test_request_id_is_echoed_or_generated(), test_unknown_route_is_problem_json()

### Community 139 - "test_graph_db.py"
Cohesion: 0.19
Nodes (8): build(), _fake_private_key(), api(), _reach(), test_depth_bounds_the_walk(), test_downstream_from_the_internet_and_nothing_upstream(), test_unknown_node_scan_and_bad_params(), test_what_can_reach_the_pii_store()

### Community 140 - "RiskGraph — AI session entry point"
Cohesion: 0.29
Nodes (6): Commands, Conventions, Current state, Dependencies, graphify, RiskGraph — AI session entry point

### Community 141 - "test_risks_db.py"
Cohesion: 0.29
Nodes (5): api(), test_risk_detail_lists_factors_and_the_reasons_off_baseline(), test_risks_are_ranked_by_score_and_match_the_findings(), test_risks_parameter_errors(), test_triaged_noise_leaves_the_ranking_but_stays_retrievable()

### Community 142 - "average_precision"
Cohesion: 0.29
Nodes (5): average_precision(), precision_at(), test_average_precision_by_hand(), test_bootstrap_is_seeded_and_reports_undefined_draws(), test_precision_divides_by_k_even_past_the_end()

### Community 144 - "test_reachability.py"
Cohesion: 0.21
Nodes (15): build(), _resolve_python(), _classifier(), extracted(), test_extractor_runs_isolated_through_the_runner(), test_hostile_inputs_do_not_break_extraction(), test_indirect_dependencies_inherit_from_direct_parents(), test_js_imports_entries_and_skips() (+7 more)

### Community 145 - "context/router.py"
Cohesion: 0.33
Nodes (3): AssetOut, ContextOut, repository_context()

### Community 146 - "RiskGraph baseline (expansion phase X0)"
Cohesion: 0.29
Nodes (6): Dataset, Per scenario, Pooled ranking (primary), Reading these numbers, RiskGraph baseline (expansion phase X0), Top 10 of the pooled ranking

### Community 147 - "typing"
Cohesion: 0.11
Nodes (8): downgrade(), upgrade(), upgrade(), AiExplanation, Base, str_enum(), TimestampMixin, UUIDPrimaryKeyMixin

### Community 149 - "feeds.py"
Cohesion: 0.24
Nodes (7): _date(), _decimal(), _decimal_score(), EpssScore, fetch_epss(), _kev_index(), OutboundError

### Community 150 - ".source"
Cohesion: 0.25
Nodes (7): Decision, 11.1 Manifest schema (`riskgraph.yaml`, v1), 11.2 Factors produced (all with `source` and `confidence`), 11.3 Reachability tiers (the honest design), 11. Context enrichment architecture, G. Database, R. Common failure modes

### Community 151 - "RiskGraph — Architecture (sections 6–15)"
Cohesion: 0.18
Nodes (10): 10.1 Canonical model, 10.2 Fingerprinting (dedup within and across scans), 10.3 Severity mapping, 10. Finding normalization architecture, 12. Security graph schema, 15. AI explanation architecture, 6. Complete system architecture, 7. Component architecture (+2 more)

### Community 152 - "ADR-0002: Stack"
Cohesion: 0.33
Nodes (5): ADR-0002: Stack, Alternatives considered, Consequences, Context, Decision

### Community 153 - "explain/router.py"
Cohesion: 0.23
Nodes (6): create_explanation(), EvidenceRef, ExplanationOut, get_explanation(), _out(), ReasonOut

### Community 154 - "PHASE 10: Attack-path engine (scenario E, performance budget)"
Cohesion: 0.29
Nodes (6): A. Objective, B. Defect found and fixed, M. Testing, Not done, O. Validation, PHASE 10: Attack-path engine (scenario E, performance budget)

### Community 155 - "ADR-0010: MVP vertical slice and its deviations from the blueprint"
Cohesion: 0.33
Nodes (5): ADR-0010: MVP vertical slice and its deviations from the blueprint, Consequences, Context, Decision, Example RiskGraph gate GitHub workflow (self-hosted)

### Community 156 - "ADR-0012: Reachability tiers L0–L2 in the MVP (import graph, no call graph)"
Cohesion: 0.33
Nodes (5): ADR-0012: Reachability tiers L0–L2 in the MVP (import graph, no call graph), Alternatives considered, Consequences, Context, Decision

### Community 158 - "13. Attack-path architecture"
Cohesion: 0.40
Nodes (4): 13.1 Attack-graph derivation, 13.2 Algorithm choice, 13.3 Path scoring and output, 13. Attack-path architecture

### Community 159 - "9. Scanner orchestration architecture"
Cohesion: 0.50
Nodes (4): 9.1 Job model and state machines, 9.2 Celery canvas, 9.4 Scanner adapter interface, 9. Scanner orchestration architecture

### Community 164 - "ADR-0016: Evidence-grounded explanations with a local model and a template fallback"
Cohesion: 0.33
Nodes (5): ADR-0016: Evidence-grounded explanations with a local model and a template fallback, Alternatives considered, Consequences, Context, Decision

### Community 169 - "Settings"
Cohesion: 0.14
Nodes (8): Settings, workspace_exists(), _base(), test_bad_redis_url_rejected(), test_missing_required_fails(), test_non_psycopg_database_url_rejected(), test_short_secret_rejected(), test_valid_settings_parse()

## Knowledge Gaps
- **14 isolated node(s):** `riskgraph`, `@types/node`, `@types/react`, `@types/react-dom`, `eslint` (+9 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 1107 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **17 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `AdapterError` connect `OllamaAdapter` to `test_explain.py`, `PHASE 12: AI explanation (evidence-grounded, validated, cached)`, `generate.py`, `_ollama`?**
  _High betweenness centrality (0.104) - this node is a cross-community bridge._
- **Are the 91 inferred relationships involving `Settings` (e.g. with `_environment()` and `_guard()`) actually correct?**
  _`Settings` has 91 INFERRED edges - model-reasoned connections that need verification._
- **What connects `riskgraph`, `@types/node`, `@types/react` to the rest of the system?**
  _14 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `pipeline.py` be split into smaller, more focused modules?**
  _Cohesion score 0.07229832572298325 - nodes in this community are weakly interconnected._
- **Why does `M. Testing` connect `PHASE 12: AI explanation (evidence-grounded, validated, cached)` to `OllamaAdapter`?**
  _High betweenness centrality (0.103) - this node is a cross-community bridge._
- **Are the 86 inferred relationships involving `SourceType` (e.g. with `ContextResolver` and `Finding`) actually correct?**
  _`SourceType` has 86 INFERRED edges - model-reasoned connections that need verification._
- **Should `FindingsSection.tsx` be split into smaller, more focused modules?**
  _Cohesion score 0.13438735177865613 - nodes in this community are weakly interconnected._