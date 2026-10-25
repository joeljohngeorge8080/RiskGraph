# Graph Report - riskgraph  (2026-10-25)

## Corpus Check
- 273 files · ~135,762 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 21 file(s) not represented in the graph (top: (none) 12, .Dockerfile 2, .example 1)

## Summary
- 2716 nodes · 8020 edges · 146 communities (129 shown, 17 thin omitted)
- Extraction: 90% EXTRACTED · 10% INFERRED · 0% AMBIGUOUS · INFERRED: 835 edges (avg confidence: 0.94)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `943be497`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- pipeline.py
- FindingsSection.tsx
- RunSpec
- context/service.py
- ScanWorkspace
- RiskGraph expansion A–D: architecture decision and phased plan
- attack.py
- Findings API and Vocabulary
- manifest.py
- findings/service.py
- cli.py
- pipeline_support.py
- SourceType
- modules/scanners/__init__.py
- PHASE MVP level 2: context-aware scoring
- PHASE MVP — Scan, normalize, merge, prioritize (vertical slice)
- RiskGraph — Project Specification (Phase 0, v1.0, 2026-09-19)
- scans/service.py
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
- test_parsers.py
- adr/README.md
- Base
- dataclasses
- types.ts
- runner.py
- attack.py
- UUID
- test_explain_db.py
- TS App Config
- PHASE 0 — Project Definition & Threat Model
- 26. Research evaluation methodology
- PHASE 1 — Repository & Development Environment
- ADR-0003: UUID v7 ids, single tenant, deletion policy
- graph/router.py
- ADR-0011: Context-aware scoring from the repository manifest (MVP level 2)
- test_callgraph.py
- RiskGraph — Data, API, Frontend, CI/CD (sections 16–19)
- test_docker_runner.py
- api.py
- Scanner
- test_risks_db.py
- RiskGraph — Master Blueprint (v0.1, 2026-09-19)
- context/router.py
- TS Node Config
- record.py
- ADR-0001: Modular monolith with API and worker roles
- RiskGraph — Threat Model (living document; v0.1 from blueprint 03, 2026-09-19)
- ContextResolver
- RiskGraph — Architecture (sections 6–15)
- test_iac.py
- risk/router.py
- analyze
- Handoff
- Work done — session 1 (2026-09-19)
- .source
- test_environment.py
- Session 1 handoff (2026-09-19)
- ADR-0004: Authentication and authorization model
- Scanner Installer
- parse_manifest
- kitchen_sink.py
- TS Root Config
- Test DB Init
- ADR-0007: Celery + Redis for background work
- 14. Risk-engine architecture
- Backend Package
- format.ts
- pytest
- RiskGraph
- sbom/service.py
- iac.py
- kitchen_sink.py
- ADR-0008: Synchronous SQLAlchemy sessions
- re
- json
- ScannerName
- semgrep/parser.py
- PHASE 4: Scanner adapters (five hardened images)
- health.py
- scans/router.py
- kitchen_sink.json
- gitleaks/parser.py
- ADR-0015: L3 reachability by intraprocedural call graph; NVD refreshed by Beat
- tiers.py
- sqlalchemy
- ExplanationDraft
- PHASE 8: Reachability (L0–L3)
- context/service.py
- build-scanner-images.sh
- ADR-0009: MVP runs scanners as subprocesses in the worker
- Problems hit and fixed
- extract.py
- ADR-0012: Reachability tiers L0–L2 in the MVP (import graph, no call graph)
- 13. Attack-path architecture
- 9. Scanner orchestration architecture
- TECH_STACK.md
- test_api.py
- ScanStatus
- PHASE 11: Contextual risk engine (scenarios, properties, GET /risks)
- reachability/service.py
- 20261023_0900_reachability_l3.py
- PHASE 12: AI explanation (evidence-grounded, validated, cached)
- conftest.py
- OllamaAdapter
- RiskGraph — AI session entry point
- EvidencePack
- test_reachability.py
- uuid7.py
- typing
- normalization/__init__.py
- checkov/parser.py
- explain/router.py
- PHASE 10: Attack-path engine (scenario E, performance budget)
- reach
- test_health.py
- audit/models.py
- sbom/router.py
- problem_response
- worker.py
- ADR-0016: Evidence-grounded explanations with a local model and a template fallback

## God Nodes (most connected - your core abstractions)
1. `Settings` - 142 edges
2. `SourceType` - 113 edges
3. `ScannerName` - 105 edges
4. `ScanStatus` - 68 edges
5. `session_scope()` - 64 edges
6. `Severity` - 58 edges
7. `score()` - 47 edges
8. `analyze()` - 46 edges
9. `Priority` - 45 edges
10. `RawFinding` - 43 edges

## Surprising Connections (you probably didn't know these)
- `Decision` --references--> `create_app()`  [INFERRED]
  docs/adr/0010-mvp-scope.md → backend/riskgraph/entrypoints/api.py
- `Session 7 additions (2026-10-25)` --references--> `kubernetes_context()`  [INFERRED]
  docs/phases/PHASE_07.md → backend/riskgraph/modules/context/iac.py
- `Session 7 (2026-10-25, local)` --references--> `kubernetes_context()`  [INFERRED]
  HANDOFF.md → backend/riskgraph/modules/context/iac.py
- `E. Technical decisions` --references--> `ScanPaths`  [INFERRED]
  docs/phases/PHASE_MVP.md → backend/riskgraph/modules/scanners/base.py
- `2.1 Options compared` --references--> `DockerRunner`  [INFERRED]
  docs/proposals/EXPANSION_A-D.md → backend/riskgraph/modules/scanners/docker_runner.py

## Import Cycles
- 3-file cycle: `backend/riskgraph/modules/risk/__init__.py -> backend/riskgraph/modules/risk/service.py -> backend/riskgraph/modules/risk/model.py -> backend/riskgraph/modules/risk/__init__.py`

## Hyperedges (group relationships)
- **Dev Compose stack services sharing the backend image** — docker_compose_migrate, docker_compose_api, docker_compose_worker, docker_compose_beat [EXTRACTED 1.00]
- **riskgraph.yaml context model (services, identities, data stores, criticality)** — docs_examples_riskgraph_services, docs_examples_riskgraph_identities, docs_examples_riskgraph_data_stores, docs_examples_riskgraph_criticality, readme_context_aware_scoring [EXTRACTED 1.00]

## Communities (146 total, 17 thin omitted)

### Community 0 - "pipeline.py"
Cohesion: 0.12
Nodes (35): IacResult, get_scanner(), analyze(), _classify(), clone(), collect(), _container_fields(), discard_workspace() (+27 more)

### Community 1 - "FindingsSection.tsx"
Cohesion: 0.13
Nodes (21): apiGet(), FindingChange, FindingList, ReachabilityTier, ScannerName, FindingDrawer(), CHANGES, FilterState (+13 more)

### Community 2 - "RunSpec"
Cohesion: 0.20
Nodes (16): RunSpec, SubprocessRunner, _tail(), build_clone_argv(), test_memory_limit_is_enforced(), test_self_python_is_the_only_path_alias(), runner(), _spec() (+8 more)

### Community 3 - "context/service.py"
Cohesion: 0.10
Nodes (18): _date(), _decimal(), _decimal_score(), EpssScore, fetch_epss(), fetch_kev(), fetch_nvd(), _kev_index() (+10 more)

### Community 4 - "ScanWorkspace"
Cohesion: 0.11
Nodes (13): Cloner, CloneResult, git_env(), GitCloner, ScanWorkspace, WorkspaceError, test_measure_enforces_limits(), test_readonly_then_cleanup() (+5 more)

### Community 5 - "RiskGraph expansion A–D: architecture decision and phased plan"
Cohesion: 0.11
Nodes (18): 1.1 Existing functionality (VERIFIED by reading the code at `08d5181`), 1.2 Gaps that matter for A–D, 1. Audit: what exists, and where A–D plug in, 2.1 Options compared, 2.2 Graph storage (re-evaluated, not assumed), 2.3 Recommended architecture, 2.4 Module boundaries and interfaces, 2. Architecture: options and the decision (+10 more)

### Community 6 - "attack.py"
Cohesion: 0.14
Nodes (5): _EdgeRow, _NodeRow, to_networkx(), test_to_networkx_keeps_the_most_probable_parallel_edge(), M. Testing

### Community 7 - "Findings API and Vocabulary"
Cohesion: 0.14
Nodes (22): _float(), get_finding(), list_findings(), path_out(), scan_diff(), scan_gate(), triage_finding(), AttackPathOut (+14 more)

### Community 8 - "manifest.py"
Cohesion: 0.14
Nodes (6): DataStoreDecl, IdentityDecl, _Resolver, _short(), _Strict, _structure_problem()

### Community 9 - "findings/service.py"
Cohesion: 0.11
Nodes (22): apply_history(), diff_scans(), previous_scan_id(), ScanDiff, Finding, FindingOccurrence, ScanFinding, _base_query() (+14 more)

### Community 10 - "cli.py"
Cohesion: 0.14
Nodes (9): build_parser(), main(), markdown(), _out(), run_scan(), test_failed_scan_and_api_errors(), test_gate_failure_exit_code_and_escaping(), test_gate_pass_and_summary() (+1 more)

### Community 11 - "pipeline_support.py"
Cohesion: 0.09
Nodes (16): CloneError, no_lock(), _drop(), fixture_path(), api(), _scan(), test_context_endpoint_404s_without_a_finished_scan(), test_context_endpoint_returns_assets_and_kubernetes_privilege() (+8 more)

### Community 12 - "SourceType"
Cohesion: 0.07
Nodes (64): FindingContext, VulnIntel, _clamp(), _context_factor(), EffectiveImpact, epss_to_e(), _exploitability(), Factor (+56 more)

### Community 13 - "modules/scanners/__init__.py"
Cohesion: 0.20
Nodes (10): derive_key(), mask(), scrub(), _scrub(), secret_hmac(), test_gitleaks_redaction_removes_every_raw_field(), test_hmac_is_keyed_and_deterministic(), test_mask_never_shows_short_secrets() (+2 more)

### Community 14 - "PHASE MVP level 2: context-aware scoring"
Cohesion: 0.11
Nodes (18): A. Objective, B. Why, C. Architecture, D. Components, F. Folder structure, H. API, I. Algorithms, J. Implementation (+10 more)

### Community 15 - "PHASE MVP — Scan, normalize, merge, prioritize (vertical slice)"
Cohesion: 0.11
Nodes (18): A. Objective, B. Why, C. Architecture, D. Components, E. Technical decisions, F. Folder structure, G. Database, I. Algorithms (+10 more)

### Community 16 - "RiskGraph — Project Specification (Phase 0, v1.0, 2026-09-19)"
Cohesion: 0.20
Nodes (7): 1. Problem statement, 2. Scope, 3. Assumptions, 4. Research question, 5. Success criteria (project level), 6. Architecture principles, RiskGraph — Project Specification (Phase 0, v1.0, 2026-09-19)

### Community 17 - "scans/service.py"
Cohesion: 0.10
Nodes (29): ScanJob, ScannerRun, reap(), ReapResult, active_scan(), cas_run(), count_active(), get_run() (+21 more)

### Community 18 - "ADR-0006: Graph storage and analysis"
Cohesion: 0.22
Nodes (8): ADR-0006: Graph storage and analysis, Alternatives considered, Apache AGE (Postgres extension) — rejected for now, Consequences, Context, Decision, igraph instead of NetworkX — rejected, Neo4j Community — rejected

### Community 19 - "Dev Stack and CI Docs"
Cohesion: 0.16
Nodes (16): CI Workflow (ci.yml), CI backend job (ruff, mypy, pytest unit + db), CI frontend job (npm lint, typecheck, build), CI images job (build + Trivy scan backend image), CI security-self-scan job (Gitleaks + Trivy fs), Pre-commit config (pre-commit-hooks, ruff, gitleaks), Dev Compose stack, api service (uvicorn create_app) (+8 more)

### Community 20 - "test_pipeline_db.py"
Cohesion: 0.15
Nodes (24): run_pipeline_inline(), session_scope(), criticals(), _ollama_up(), real_settings(), test_real_scanners_end_to_end(), test_real_scanners_with_manifest_reachability_paths_and_history(), scan() (+16 more)

### Community 21 - "Settings"
Cohesion: 0.12
Nodes (16): RunResult, Settings, FixtureRunner, workspace_exists(), api(), _by_package(), _findings(), _scan() (+8 more)

### Community 22 - "Finding Drawer and Triage UI"
Cohesion: 0.13
Nodes (28): apiPost(), Explanation, FindingDetail, FindingListItem, FindingStatus, TrendPoint, ExplanationPanel(), contextOrigin() (+20 more)

### Community 23 - "Frontend Shell and Routing"
Cohesion: 0.27
Nodes (8): RFC-7807, API_BASE, ApiError, apiPatch(), handle(), Health, problemMessage(), Readiness

### Community 24 - "0013-graph-paths-triage-history.md"
Cohesion: 0.14
Nodes (13): ADR-0010: MVP vertical slice and its deviations from the blueprint, Consequences, Context, Decision, ADR-0013: Per-scan attack paths with effective impact; triage, history and the CI gate, Alternatives considered, CI gate, Consequences (+5 more)

### Community 25 - "App.tsx"
Cohesion: 0.19
Nodes (13): Scan, App(), HealthDot(), HomePage(), RepositoryRoute(), ScanRoute(), EXAMPLES, NewScanForm() (+5 more)

### Community 26 - "trivy/parser.py"
Cohesion: 0.23
Nodes (12): RawFinding, trivy_severity(), clip(), count(), dependency_graph(), _list(), _misconfig(), parse() (+4 more)

### Community 27 - "RiskGraph — Deployment, NFRs, Failure Handling (section 27)"
Cohesion: 0.40
Nodes (4): 27.1 Deployment architecture, 27.2 Non-functional requirements (measurable targets), 27.3 Failure handling (graceful degradation table), RiskGraph — Deployment, NFRs, Failure Handling (section 27)

### Community 28 - "Frontend Build Config"
Cohesion: 0.05
Nodes (39): dependencies, cytoscape, react, react-dom, react-router-dom, @tanstack/react-query, devDependencies, eslint (+31 more)

### Community 29 - "explain/service.py"
Cohesion: 0.21
Nodes (12): clip_lines(), factor_evidence(), FactorEv, FindingEv, _Frozen, norm(), PathEv, ScoreEv (+4 more)

### Community 30 - "PHASE 3: Scanner orchestration engine (hardened DockerRunner)"
Cohesion: 0.13
Nodes (14): A. Objective, B. Why, F. Folder structure, G. Database, H. API, I. Algorithms, J. Implementation notes, K. Commands (+6 more)

### Community 31 - "PHASE MVP level 2, extended: reachability, attack paths, triage and history"
Cohesion: 0.11
Nodes (18): A. Objective, B. Why, C. Architecture, D. Components, E. Technical decisions, F. Folder structure, H. API, I. Algorithms (+10 more)

### Community 33 - "repositories/router.py"
Cohesion: 0.10
Nodes (20): Repository, get_repository(), list_repositories(), _point(), RepositoryDetail, RepositorySummary, _summary(), TrendPoint (+12 more)

### Community 34 - "test_explain.py"
Cohesion: 0.17
Nodes (26): Reason, generate(), validate(), _draft(), _ollama(), _pack(), test_a_grounded_draft_passes(), test_a_url_that_is_in_the_evidence_may_be_repeated_but_not_trusted_alone() (+18 more)

### Community 35 - "RiskGraph — Security Threat Model (section 20)"
Cohesion: 0.38
Nodes (6): Actors, Assets (what we protect), Attack surfaces, RiskGraph — Security Threat Model (section 20), Security invariants (tested in Phase 15/16), Threats and mitigations

### Community 36 - "AttackPathsPanel.tsx"
Cohesion: 0.24
Nodes (11): AttackPath, GraphData, ScanSummary, AttackPathsPanel(), GraphView, KIND_COLOR, kindOf(), COLORS (+3 more)

### Community 37 - "docker_runner.py"
Cohesion: 0.07
Nodes (17): _Containers, DockerClient, DockerRunner, _Images, make_removable(), PathRoot, _printable(), _write_capped() (+9 more)

### Community 38 - "test_parsers.py"
Cohesion: 0.30
Nodes (9): ScannerName, load(), test_checkov_shapes_and_resources(), test_counts_match_parsed_findings(), test_gitleaks_uses_redacted_fields_only(), test_hostile_paths_are_neutralised(), test_semgrep_rule_ids_and_categories(), test_semgrep_secret_rules_are_secrets_not_sast() (+1 more)

### Community 39 - "adr/README.md"
Cohesion: 0.15
Nodes (10): ADR-0002: Stack, Alternatives considered, Consequences, Context, Decision, ADR-0005: Hosting and deployment, Alternatives considered, Consequences (+2 more)

### Community 40 - "Base"
Cohesion: 0.31
Nodes (11): AttackPath, AttackPathFinding, GraphEdge, GraphNode, clear(), _dec(), list_paths(), load_graph() (+3 more)

### Community 41 - "dataclasses"
Cohesion: 0.13
Nodes (12): _bfs(), chain_to(), enclosing_function(), find_l3(), Path3, _qualify(), reachable_functions(), _resolve() (+4 more)

### Community 42 - "types.ts"
Cohesion: 0.10
Nodes (21): AttackPathEdge, FindingLocation, KubeWorkload, ManifestStatus, Occurrence, PackageInfo, Priority, RepositoryDetail (+13 more)

### Community 43 - "runner.py"
Cohesion: 0.12
Nodes (7): _kill_group(), _rlimits(), _open_cache_to_scanners(), refresh_argv(), refresh_trivy_db(), _force_writable(), widen_own_directories()

### Community 44 - "attack.py"
Cohesion: 0.15
Nodes (9): Manifest, AttackAnalysis, _ds(), _idn(), _path(), PathResult, _search(), _svc() (+1 more)

### Community 45 - "UUID"
Cohesion: 0.08
Nodes (22): refresh_trivy_db_task(), build_canvas(), enqueue(), enqueue_kill(), _sig(), default_deps(), fetcher_image(), _kev_cache() (+14 more)

### Community 46 - "test_explain_db.py"
Cohesion: 0.21
Nodes (11): NullAdapter, api(), _critical(), _grounded_reply(), test_a_grounded_model_answer_is_validated_and_stored(), test_an_injected_answer_is_rejected_and_never_stored(), test_explanation_not_found_cases(), test_refresh_replaces_a_fallback_once_the_model_is_back() (+3 more)

### Community 47 - "TS App Config"
Cohesion: 0.11
Nodes (17): compilerOptions, baseUrl, isolatedModules, jsx, lib, module, moduleResolution, noEmit (+9 more)

### Community 48 - "PHASE 0 — Project Definition & Threat Model"
Cohesion: 0.13
Nodes (15): A. Objective, B. Why, C. Architecture, D. Components, E. Technical decisions, F. Folder structure, G. Database · H. API · I. Algorithms · J. Implementation · K. Commands · L. Configuration, M. Testing (+7 more)

### Community 49 - "26. Research evaluation methodology"
Cohesion: 0.17
Nodes (11): 25.1 Layers and markers, 25.2 Test datasets (`datasets/`), 25. Testing strategy, 26.1 Question and hypotheses, 26.2 Methods compared, 26.3 Ground truth, 26.4 Metrics, 26.5 Statistics (+3 more)

### Community 50 - "PHASE 1 — Repository & Development Environment"
Cohesion: 0.10
Nodes (20): A. Objective, B. Why, C. Architecture, D. Components, E. Technical decisions, F. Folder structure, G. Database, H. API (+12 more)

### Community 51 - "ADR-0003: UUID v7 ids, single tenant, deletion policy"
Cohesion: 0.25
Nodes (7): ADR-0003: UUID v7 ids, single tenant, deletion policy, Alternatives considered, bigint serial ids — rejected, Consequences, Context, Decision, Multi-tenant from day one — rejected

### Community 52 - "graph/router.py"
Cohesion: 0.14
Nodes (11): attack_paths(), _edge_out(), graph_reach(), GraphEdgeOut, GraphNodeOut, GraphOut, ReachNodeOut, ReachOut (+3 more)

### Community 53 - "ADR-0011: Context-aware scoring from the repository manifest (MVP level 2)"
Cohesion: 0.27
Nodes (9): ADR-0011: Context-aware scoring from the repository manifest (MVP level 2), Alternatives considered, Consequences, Context, riskgraph.yaml v1 manifest example, Manifest criticality, Manifest data_stores (kind, sensitivity), Manifest identities (privilege, can_access, credentials) (+1 more)

### Community 54 - "test_callgraph.py"
Cohesion: 0.18
Nodes (20): load_symbols(), SymbolEntry, _classifier(), _l3(), _project(), test_a_call_through_another_module_function_is_l3(), test_a_direct_call_from_a_route_is_l3(), test_a_from_import_is_resolved() (+12 more)

### Community 55 - "RiskGraph — Data, API, Frontend, CI/CD (sections 16–19)"
Cohesion: 0.18
Nodes (10): 17.1 Cross-cutting, 17.2 Endpoints (V1), 17.3 Representative schemas, 17. API architecture, 18. Frontend architecture, 19.1 Two integration paths, 19.2 Policy (from `riskgraph.yaml` `policy:` or repository settings; action input overrides), 19.3 RiskGraph's own CI (`.github/workflows/ci.yml`) (+2 more)

### Community 56 - "test_docker_runner.py"
Cohesion: 0.16
Nodes (13): FakeClient, FakeContainer, FakeContainers, FakeImages, _runner(), _spec(), test_a_hung_container_is_killed_at_the_timeout(), test_a_missing_image_is_a_failure_not_an_exception() (+5 more)

### Community 57 - "api.py"
Cohesion: 0.14
Nodes (4): create_app(), configure_logging(), get_logger(), RequestIdMiddleware

### Community 59 - "test_risks_db.py"
Cohesion: 0.33
Nodes (6): api(), scan(), test_risk_detail_lists_factors_and_the_reasons_off_baseline(), test_risks_are_ranked_by_score_and_match_the_findings(), test_risks_parameter_errors(), test_triaged_noise_leaves_the_ranking_but_stays_retrievable()

### Community 60 - "RiskGraph — Master Blueprint (v0.1, 2026-09-19)"
Cohesion: 0.20
Nodes (9): 1. Executive summary, 28. Final demonstration workflow (what the examiner sees, ~12 minutes), 29. Project risks and mitigations, 2. Exact problem definition, 30. Definition of the final MVP, 3. Scope (what V1 delivers), 4. Non-goals (stated so nobody expects them), 5. Novelty and technical contribution (honest version) (+1 more)

### Community 61 - "context/router.py"
Cohesion: 0.33
Nodes (3): AssetOut, ContextOut, repository_context()

### Community 62 - "TS Node Config"
Cohesion: 0.13
Nodes (12): manifests(), inputs(), compilerOptions, composite, module, moduleResolution, noEmit, skipLibCheck (+4 more)

### Community 63 - "record.py"
Cohesion: 0.14
Nodes (11): container_fields(), scanner_image(), ScannerRunner, main(), _make_removable_later(), _open_for_scanner_uid(), _record(), _recording_runner() (+3 more)

### Community 64 - "ADR-0001: Modular monolith with API and worker roles"
Cohesion: 0.22
Nodes (8): ADR-0001: Modular monolith with API and worker roles, Alternatives considered, Compliance, Consequences, Context, Decision, Services per pipeline stage — rejected, Single flat package (no module boundaries) — rejected

### Community 65 - "RiskGraph — Threat Model (living document; v0.1 from blueprint 03, 2026-09-19)"
Cohesion: 0.22
Nodes (9): Actors, Assets (what we protect), Attack surfaces, MVP level 2 extended note (2026-10-22), MVP level 2 note (2026-10-21): manifest context, MVP note (2026-10-21), RiskGraph — Threat Model (living document; v0.1 from blueprint 03, 2026-09-19), Security invariants (tested in Phase 15/16) (+1 more)

### Community 66 - "ContextResolver"
Cohesion: 0.16
Nodes (7): _clean_file(), ContextResolver, Observed, KubeContext, ServiceDecl, test_secret_in_public_repo_is_internet_exposed_without_manifest(), o()

### Community 67 - "RiskGraph — Architecture (sections 6–15)"
Cohesion: 0.18
Nodes (10): 10.1 Canonical model, 10.2 Fingerprinting (dedup within and across scans), 10.3 Severity mapping, 10. Finding normalization architecture, 12. Security graph schema, 15. AI explanation architecture, 6. Complete system architecture, 7. Component architecture (+2 more)

### Community 68 - "test_iac.py"
Cohesion: 0.27
Nodes (17): extract(), kubernetes_context(), _selects(), ManifestResult, _repo(), test_alias_bombs_are_refused_before_parsing(), test_compose_build_context_cannot_escape_the_repository(), test_compose_exposure_reaches_findings_under_its_build_context() (+9 more)

### Community 69 - "risk/router.py"
Cohesion: 0.18
Nodes (9): RiskScoreOut, _latest_scan(), list_risks(), risk_detail(), RiskDetailOut, RiskItemOut, RiskListOut, _scan_id() (+1 more)

### Community 70 - "analyze"
Cohesion: 0.18
Nodes (18): analyze(), GraphFinding, invariant_violations(), _manifest(), test_control_only_paths_are_not_attacks(), test_effective_impact_uses_the_rest_of_the_chain(), test_k_paths_per_sink_and_hop_limit(), test_kitchen_sink_manifest_is_valid_and_links_aws_keys() (+10 more)

### Community 71 - "Handoff"
Cohesion: 0.22
Nodes (8): Before the next session, Commands, Gotchas, Handoff, Not done, State, Verified, What works

### Community 72 - "Work done — session 1 (2026-09-19)"
Cohesion: 0.22
Nodes (9): 1. Orientation, 2. Blueprint (`docs/blueprint/`, 9 files, ~18.8k words), 3. Phase 0 (docs), 4. Phase 1 (code) — see `docs/phases/PHASE_01.md` for the full chapter, 5. Commit, 6. After the commit (uncommitted at time of writing), Problems hit and fixed during Phase 1, Verified results (+1 more)

### Community 73 - ".source"
Cohesion: 0.25
Nodes (7): Decision, 11.1 Manifest schema (`riskgraph.yaml`, v1), 11.2 Factors produced (all with `source` and `confidence`), 11.3 Reachability tiers (the honest design), 11. Context enrichment architecture, G. Database, R. Common failure modes

### Community 74 - "test_environment.py"
Cohesion: 0.46
Nodes (7): _resolver(), test_data_sensitivity_stops_after_two_hops(), test_data_sensitivity_two_hops_prefers_most_sensitive(), test_exposure_labels(), test_longest_path_prefix_wins(), test_secret_keeps_service_impact_context(), test_summary_counts_findings_per_service()

### Community 75 - "Session 1 handoff (2026-09-19)"
Cohesion: 0.12
Nodes (16): Commands that are known to work, Gotchas already hit (so you don't hit them again), HANDOFF: resume here (updated 2026-10-25, session 7: P7 finished; expansion A–D proposed), Open items (decide before Phase 2), Open items (small, do at the start of Phase 2), Rules of engagement (from the brief and CLAUDE.md), Session 1 handoff (2026-09-19), Session 2 (2026-10-21): MVP vertical slice, done (+8 more)

### Community 76 - "ADR-0004: Authentication and authorization model"
Cohesion: 0.25
Nodes (7): ADR-0004: Authentication and authorization model, Alternatives considered, Consequences, Context, Decision, GitHub OAuth — deferred (stretch), Server-side sessions — rejected

### Community 77 - "Scanner Installer"
Cohesion: 0.50
Nodes (4): fetch_verified(), install-scanners.sh script, UV_TOOL_BIN_DIR, UV_TOOL_DIR

### Community 78 - "parse_manifest"
Cohesion: 0.19
Nodes (15): load_manifest(), normalize_service_path(), parse_manifest(), test_alias_bomb_is_refused_before_expansion(), test_deep_nesting_is_refused_without_crashing(), test_documented_example_manifest_is_valid(), test_hostile_or_broken_documents_never_raise(), test_load_absent_valid_and_yml_fallback() (+7 more)

### Community 79 - "kitchen_sink.py"
Cohesion: 0.36
Nodes (5): _attack_graph(), Row, _rows(), test_loader_builds_5k_nodes_20k_edges_under_one_second(), test_yen_top3_for_10_sinks_on_5k_20k_under_two_seconds()

### Community 87 - "ADR-0007: Celery + Redis for background work"
Cohesion: 0.25
Nodes (7): ADR-0007: Celery + Redis for background work, Alternatives considered, arq / Dramatiq — rejected, Consequences, Context, Decision, Postgres job table + worker loop — rejected

### Community 88 - "14. Risk-engine architecture"
Cohesion: 0.25
Nodes (8): 14.1 Model comparison, 14.2 Definitions, 14.3 Reduction to a context-free model (the property that makes the model defensible), 14.4 Attack-path coupling ("effective impact"), 14.5 Rule overrides (explainable, listed in output as `overrides[]`), 14.6 Worked examples (scenarios A–E from the brief), 14.7 Sensitivity, calibration, limitations, 14. Risk-engine architecture

### Community 91 - "format.ts"
Cohesion: 0.17
Nodes (23): reportUrl(), RunStatus, ScanStatus, Severity, PriorityCounts(), RepositoryPage(), ScanDetailPage(), STAGES (+15 more)

### Community 92 - "pytest"
Cohesion: 0.15
Nodes (22): build_create_kwargs(), _check_env(), _checked_path(), ContainerSpecError, Limits, Mount, scanner_mounts(), _kwargs() (+14 more)

### Community 93 - "RiskGraph"
Cohesion: 0.25
Nodes (7): Context-aware scoring, Develop, Documentation, Quickstart, RiskGraph, Run without Docker, Triage, history and the CI gate

### Community 94 - "sbom/service.py"
Cohesion: 0.06
Nodes (42): parse_nvd_cvss(), SbomComponent, attach_findings(), canonical_purl(), clear(), _ecosystem(), list_components(), PackageSeen (+34 more)

### Community 95 - "iac.py"
Cohesion: 0.21
Nodes (12): _code_dir(), _compose(), _d(), IacAsset, _ingress_backends(), _k8s(), _l(), _labels() (+4 more)

### Community 97 - "ADR-0008: Synchronous SQLAlchemy sessions"
Cohesion: 0.29
Nodes (6): ADR-0008: Synchronous SQLAlchemy sessions, Alternatives considered, Async SQLAlchemy (asyncpg) — rejected, Consequences, Context, Decision

### Community 99 - "json"
Cohesion: 0.14
Nodes (4): AdapterError, LlmAdapter, Outcome, _parse()

### Community 100 - "ScannerName"
Cohesion: 0.07
Nodes (10): Command, ParseContext, ScanPaths, CheckovScanner, GitleaksScanner, drop_keys(), SemgrepScanner, SyftScanner (+2 more)

### Community 101 - "semgrep/parser.py"
Cohesion: 0.16
Nodes (10): cwe_ids(), sast_category(), iac_topic(), semgrep_severity(), clean_rule_id(), count(), parse(), _results() (+2 more)

### Community 102 - "PHASE 4: Scanner adapters (five hardened images)"
Cohesion: 0.29
Nodes (6): Built, Decisions, Known differences from the host-run MVP, Not done, Objective, PHASE 4: Scanner adapters (five hardened images)

### Community 103 - "health.py"
Cohesion: 0.16
Nodes (6): check_database(), Health, healthz(), Readiness, readyz(), check_redis()

### Community 104 - "scans/router.py"
Cohesion: 0.17
Nodes (11): cancel_scan(), create_scan(), download_report(), get_scan(), list_scans(), to_out(), RepositoryOut, ScanCreate (+3 more)

### Community 105 - "kitchen_sink.json"
Cohesion: 0.13
Nodes (14): bomFormat, bom-ref, name, type, components, metadata, component, timestamp (+6 more)

### Community 106 - "gitleaks/parser.py"
Cohesion: 0.33
Nodes (4): gitleaks_severity(), count(), _items(), parse()

### Community 107 - "ADR-0015: L3 reachability by intraprocedural call graph; NVD refreshed by Beat"
Cohesion: 0.29
Nodes (6): ADR-0015: L3 reachability by intraprocedural call graph; NVD refreshed by Beat, Consequences, Context, Decision, L3, NVD

### Community 108 - "tiers.py"
Cohesion: 0.17
Nodes (7): import_names(), python_import_names(), used_without_import(), _scope(), TierClassifier, Verdict, test_package_names()

### Community 109 - "sqlalchemy"
Cohesion: 0.16
Nodes (8): downgrade(), upgrade(), upgrade(), downgrade(), _in_list(), _replace_check(), upgrade(), upgrade()

### Community 110 - "ExplanationDraft"
Cohesion: 0.17
Nodes (7): ExplanationDraft, json_schema(), explain(), _phrase(), _steps(), _texts(), _words()

### Community 111 - "PHASE 8: Reachability (L0–L3)"
Cohesion: 0.33
Nodes (5): Built, Not done (out of the blueprint's P8 scope), PHASE 8: Reachability (L0–L3), Verification, Verification (session 7)

### Community 112 - "context/service.py"
Cohesion: 0.12
Nodes (13): CvssSubscores, _round1(), subscores(), Asset, Vulnerability, _fresh(), list_assets(), _load_kev() (+5 more)

### Community 114 - "ADR-0009: MVP runs scanners as subprocesses in the worker"
Cohesion: 0.29
Nodes (6): ADR-0009: MVP runs scanners as subprocesses in the worker, Alternatives considered, Blueprint DockerRunner now (§9.3): deferred, bubblewrap / `unshare --net` around each subprocess: deferred, Consequences, Context

### Community 115 - "Problems hit and fixed"
Cohesion: 0.29
Nodes (6): Problems hit and fixed, Problems hit and fixed, What was built, What was built, Work done: session 2 (2026-10-21): MVP vertical slice, Work done: session 4 (2026-10-22): MVP level 2 extended

### Community 116 - "extract.py"
Cohesion: 0.26
Nodes (12): _dotted(), extract(), _js(), main(), _package_json(), _parsers(), _python(), _python_calls() (+4 more)

### Community 117 - "ADR-0012: Reachability tiers L0–L2 in the MVP (import graph, no call graph)"
Cohesion: 0.33
Nodes (5): ADR-0012: Reachability tiers L0–L2 in the MVP (import graph, no call graph), Alternatives considered, Consequences, Context, Decision

### Community 118 - "13. Attack-path architecture"
Cohesion: 0.40
Nodes (4): 13.1 Attack-graph derivation, 13.2 Algorithm choice, 13.3 Path scoring and output, 13. Attack-path architecture

### Community 119 - "9. Scanner orchestration architecture"
Cohesion: 0.40
Nodes (5): 9.1 Job model and state machines, 9.2 Celery canvas, 9.3 Isolation profile for scanner containers, 9.4 Scanner adapter interface, 9. Scanner orchestration architecture

### Community 123 - "test_api.py"
Cohesion: 0.25
Nodes (11): api(), _completed_scan(), enqueued(), test_concurrency_cap(), test_create_scan_enqueues_and_dedups(), test_create_scan_rejects_bad_input(), test_findings_sort_filter_and_detail(), test_get_and_list_scans() (+3 more)

### Community 124 - "ScanStatus"
Cohesion: 0.28
Nodes (11): check_run(), check_scan(), final_status(), InvalidTransitionError, RunStatus, ScanStatus, test_every_active_state_can_fail(), test_final_status() (+3 more)

### Community 127 - "PHASE 11: Contextual risk engine (scenarios, properties, GET /risks)"
Cohesion: 0.17
Nodes (8): _diff_items(), risk_out(), A. Objective, B. Built, M. Testing, Not done, O. Validation, PHASE 11: Contextual risk engine (scenarios, properties, GET /risks)

### Community 130 - "reachability/service.py"
Cohesion: 0.26
Nodes (5): ReachabilityResult, clear(), persist_verdict(), ReachabilityRun, run_extractor()

### Community 132 - "20261023_0900_reachability_l3.py"
Cohesion: 0.83
Nodes (3): _check(), downgrade(), upgrade()

### Community 134 - "PHASE 12: AI explanation (evidence-grounded, validated, cached)"
Cohesion: 0.15
Nodes (13): A. Objective, B. Why, C. Architecture, D. Components, E. Technical decisions, G. Database, H. API, L. Configuration (+5 more)

### Community 135 - "conftest.py"
Cohesion: 0.16
Nodes (9): dispose_engine(), get_engine(), _session_factory(), _alembic(), client(), db(), migrated_db(), settings() (+1 more)

### Community 136 - "OllamaAdapter"
Cohesion: 0.15
Nodes (10): OllamaAdapter, AiExplanation, adapter_from_settings(), cached(), explain(), _store(), top_critical(), explain_top_findings_task() (+2 more)

### Community 140 - "RiskGraph — AI session entry point"
Cohesion: 0.29
Nodes (6): Commands, Conventions, Current state, Dependencies, graphify, RiskGraph — AI session entry point

### Community 144 - "test_reachability.py"
Cohesion: 0.22
Nodes (16): build(), _resolve_python(), ReachabilityTier, _classifier(), extracted(), test_extractor_runs_isolated_through_the_runner(), test_hostile_inputs_do_not_break_extraction(), test_indirect_dependencies_inherit_from_direct_parents() (+8 more)

### Community 145 - "uuid7.py"
Cohesion: 0.39
Nodes (3): uuid7(), test_uuid7_is_time_ordered_and_unique(), test_uuid7_version_and_variant()

### Community 147 - "typing"
Cohesion: 0.10
Nodes (9): upgrade(), RiskFactor, RiskScore, ranked(), score_of(), Base, str_enum(), TimestampMixin (+1 more)

### Community 148 - "normalization/__init__.py"
Cohesion: 0.10
Nodes (20): Location, iac_family(), normalize_check_id(), secret_family(), fingerprint(), stable_hash(), _build(), merge() (+12 more)

### Community 150 - "checkov/parser.py"
Cohesion: 0.29
Nodes (7): IacFamily, checkov_severity(), _blocks(), count(), _failed(), parse(), _resource()

### Community 153 - "explain/router.py"
Cohesion: 0.19
Nodes (7): create_explanation(), EvidenceRef, ExplanationOut, get_explanation(), _out(), ReasonOut, require_scan()

### Community 154 - "PHASE 10: Attack-path engine (scenario E, performance budget)"
Cohesion: 0.29
Nodes (6): A. Objective, B. Defect found and fixed, M. Testing, Not done, O. Validation, PHASE 10: Attack-path engine (scenario E, performance budget)

### Community 156 - "reach"
Cohesion: 0.18
Nodes (8): GraphInvariantError, reach(), A. Objective, B. Built, C. Decisions taken here, Not done, O. Validation, PHASE 9: Security graph (invariants, neighbourhood queries, loader)

### Community 157 - "test_health.py"
Cohesion: 0.25
Nodes (5): test_healthz_reports_version(), test_readyz_ok_with_real_services(), test_readyz_reports_503_when_dependencies_down(), test_request_id_is_echoed_or_generated(), test_unknown_route_is_problem_json()

### Community 158 - "audit/models.py"
Cohesion: 0.38
Nodes (3): AuditLog, history(), record()

### Community 160 - "sbom/router.py"
Cohesion: 0.15
Nodes (4): ComponentOut, SbomOut, scan_sbom(), get_session()

### Community 161 - "problem_response"
Cohesion: 0.14
Nodes (9): Forbidden, Problem, problem_response(), register_problem_handlers(), _http(), _problem(), _unhandled(), _validation() (+1 more)

### Community 163 - "worker.py"
Cohesion: 0.19
Nodes (4): _bind_task_context(), _clear_task_context(), _configure_worker_logging(), ping()

### Community 164 - "ADR-0016: Evidence-grounded explanations with a local model and a template fallback"
Cohesion: 0.33
Nodes (5): ADR-0016: Evidence-grounded explanations with a local model and a template fallback, Alternatives considered, Consequences, Context, Decision

## Knowledge Gaps
- **14 isolated node(s):** `riskgraph`, `@types/node`, `@types/react`, `@types/react-dom`, `eslint` (+9 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 962 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **17 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `AdapterError` connect `json` to `test_explain.py`, `PHASE 12: AI explanation (evidence-grounded, validated, cached)`?**
  _High betweenness centrality (0.083) - this node is a cross-community bridge._
- **Are the 80 inferred relationships involving `Settings` (e.g. with `create_app()` and `nvd_refresh()`) actually correct?**
  _`Settings` has 80 INFERRED edges - model-reasoned connections that need verification._
- **What connects `riskgraph`, `@types/node`, `@types/react` to the rest of the system?**
  _14 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `pipeline.py` be split into smaller, more focused modules?**
  _Cohesion score 0.11990950226244344 - nodes in this community are weakly interconnected._
- **Why does `M. Testing` connect `PHASE 12: AI explanation (evidence-grounded, validated, cached)` to `json`?**
  _High betweenness centrality (0.082) - this node is a cross-community bridge._
- **Are the 78 inferred relationships involving `SourceType` (e.g. with `ContextResolver` and `Finding`) actually correct?**
  _`SourceType` has 78 INFERRED edges - model-reasoned connections that need verification._
- **Should `FindingsSection.tsx` be split into smaller, more focused modules?**
  _Cohesion score 0.13438735177865613 - nodes in this community are weakly interconnected._