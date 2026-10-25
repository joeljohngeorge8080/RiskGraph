# Graph Report - riskgraph  (2026-10-25)

## Corpus Check
- 312 files · ~158,445 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 22 file(s) not represented in the graph (top: (none) 12, .Dockerfile 2, .example 1)

## Summary
- 2955 nodes · 8507 edges · 173 communities (139 shown, 34 thin omitted)
- Extraction: 90% EXTRACTED · 10% INFERRED · 0% AMBIGUOUS · INFERRED: 875 edges (avg confidence: 0.94)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `e165f144`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- pipeline.py
- FindingsSection.tsx
- RunSpec
- dataclasses
- ScanWorkspace
- RiskGraph expansion A–D: architecture decision and phased plan
- time
- Findings API and Vocabulary
- context/__init__.py
- findings/service.py
- cli.py
- feeds.py
- SourceType
- redact.py
- PHASE MVP level 2: context-aware scoring
- PHASE MVP — Scan, normalize, merge, prioritize (vertical slice)
- run.py
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
- graph/__init__.py
- dataclasses
- types.ts
- re
- context/router.py
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
- Scanner
- EvidencePack
- RiskGraph — Master Blueprint (v0.1, 2026-09-19)
- test_runtime_db.py
- TS Node Config
- get_settings
- ADR-0001: Modular monolith with API and worker roles
- report.py
- ContextResolver
- 14. Risk-engine architecture
- test_iac.py
- risk/router.py
- analyze
- Handoff (short summary)
- reachability/service.py
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
- devDependencies
- ADR-0008: Synchronous SQLAlchemy sessions
- baselines.py
- json
- typing
- semgrep/parser.py
- PHASE 4: Scanner adapters (five hardened images)
- health.py
- scans/router.py
- kitchen_sink.json
- repositories/router.py
- ADR-0015: L3 reachability by intraprocedural call graph; NVD refreshed by Beat
- tiers.py
- sqlalchemy
- pydantic
- PHASE 8: Reachability (L0–L3)
- context/service.py
- build-scanner-images.sh
- ADR-0009: MVP runs scanners as subprocesses in the worker
- A_high_cvss_unreachable/syft/1.54.1/report.json
- extract.py
- ADR-0010: MVP vertical slice and its deviations from the blueprint
- metrics.py
- docker_runner.py
- TECH_STACK.md
- B_moderate_reachable_exposed/syft/1.54.1/report.json
- D_internal_limited/syft/1.54.1/report.json
- test_api.py
- E_attack_path/syft/1.54.1/report.json
- C_exposed_credential/syft/1.54.1/report.json
- storage.py
- PHASE 11: Contextual risk engine (scenarios, properties, GET /risks)
- to_networkx
- SemgrepScanner
- _ollama
- OutboundClient
- 20261023_0900_reachability_l3.py
- registry.py
- PHASE 12: AI explanation (evidence-grounded, validated, cached)
- OllamaAdapter
- 26. Research evaluation methodology
- SyftScanner
- PHASE 7: Context enrichment (NVD, EPSS, KEV, manifest, Kubernetes and Compose)
- test_graph_db.py
- RiskGraph — AI session entry point
- TrivyScanner
- CheckovScanner
- test_reachability.py
- uuid7.py
- RiskGraph baseline (expansion phase X0)
- typing
- normalization/__init__.py
- ADR-0002: Stack
- .source
- RiskGraph — Architecture (sections 6–15)
- TODO (saved 2026-10-25, session 7): where work stopped and what is next
- explain/router.py
- PHASE 10: Attack-path engine (scenario E, performance budget)
- scenarios.py
- ADR-0012: Reachability tiers L0–L2 in the MVP (import graph, no call graph)
- test_scenario_build_is_byte_identical
- 13. Attack-path architecture
- 9. Scanner orchestration architecture
- sbom/service.py
- 10. Finding normalization architecture
- ping
- ADR-0016: Evidence-grounded explanations with a local model and a template fallback

## God Nodes (most connected - your core abstractions)
1. `Settings` - 148 edges
2. `SourceType` - 113 edges
3. `ScannerName` - 110 edges
4. `ScanStatus` - 70 edges
5. `session_scope()` - 67 edges
6. `Severity` - 58 edges
7. `analyze()` - 46 edges
8. `score()` - 46 edges
9. `Priority` - 44 edges
10. `run_pipeline_inline()` - 44 edges

## Surprising Connections (you probably didn't know these)
- `Session 2 (2026-10-21): MVP vertical slice, done` --references--> `ScannerRunner`  [INFERRED]
  HANDOFF.md → backend/riskgraph/modules/scanners/runner.py
- `Done and committed (session 7)` --references--> `to_networkx()`  [INFERRED]
  todo1150.md → backend/riskgraph/modules/graph/attack.py
- `E. Technical decisions` --references--> `ScanPaths`  [INFERRED]
  docs/phases/PHASE_MVP.md → backend/riskgraph/modules/scanners/base.py
- `Conventions` --references--> `Problem`  [INFERRED]
  CLAUDE.md → backend/riskgraph/shared/problems.py
- `Problems hit and fixed during Phase 1` --references--> `Problem`  [INFERRED]
  workdone.md → backend/riskgraph/shared/problems.py

## Import Cycles
- 3-file cycle: `backend/riskgraph/modules/risk/__init__.py -> backend/riskgraph/modules/risk/service.py -> backend/riskgraph/modules/risk/model.py -> backend/riskgraph/modules/risk/__init__.py`

## Hyperedges (group relationships)
- **Dev Compose stack services sharing the backend image** — docker_compose_migrate, docker_compose_api, docker_compose_worker, docker_compose_beat [EXTRACTED 1.00]
- **riskgraph.yaml context model (services, identities, data stores, criticality)** — docs_examples_riskgraph_services, docs_examples_riskgraph_identities, docs_examples_riskgraph_data_stores, docs_examples_riskgraph_criticality, readme_context_aware_scoring [EXTRACTED 1.00]

## Communities (173 total, 34 thin omitted)

### Community 0 - "pipeline.py"
Cohesion: 0.17
Nodes (24): IacResult, load_manifest(), ManifestResult, get_scanner(), analyze(), _classify(), clone(), _container_fields() (+16 more)

### Community 1 - "FindingsSection.tsx"
Cohesion: 0.27
Nodes (12): apiGet(), FindingList, FindingDrawer(), FilterState, FindingFilters(), toggle(), FindingsSection(), fromParams() (+4 more)

### Community 2 - "RunSpec"
Cohesion: 0.14
Nodes (18): RunResult, RunSpec, SubprocessRunner, _tail(), build_clone_argv(), _drop(), test_memory_limit_is_enforced(), test_self_python_is_the_only_path_alias() (+10 more)

### Community 3 - "dataclasses"
Cohesion: 0.13
Nodes (13): _clamp(), _context_factor(), EffectiveImpact, epss_to_e(), _exploitability(), Factor, _reachability_factor(), ScoreResult (+5 more)

### Community 4 - "ScanWorkspace"
Cohesion: 0.10
Nodes (14): CloneError, Cloner, CloneResult, git_env(), GitCloner, ScanWorkspace, WorkspaceError, test_measure_enforces_limits() (+6 more)

### Community 5 - "RiskGraph expansion A–D: architecture decision and phased plan"
Cohesion: 0.11
Nodes (18): 1.1 Existing functionality (VERIFIED by reading the code at `08d5181`), 1. Audit: what exists, and where A–D plug in, 2.1 Options compared, 2.2 Graph storage (re-evaluated, not assumed), 2.3 Recommended architecture, 2.4 Module boundaries and interfaces, 2. Architecture: options and the decision, 3. Technical designs (+10 more)

### Community 6 - "time"
Cohesion: 0.17
Nodes (10): AttackAnalysis, _path(), PathResult, _search(), test_search_matches_brute_force_top_k(), _attack_graph(), Row, _rows() (+2 more)

### Community 7 - "Findings API and Vocabulary"
Cohesion: 0.11
Nodes (26): _diff_items(), _float(), get_finding(), list_findings(), path_out(), require_scan(), risk_out(), scan_diff() (+18 more)

### Community 8 - "context/__init__.py"
Cohesion: 0.11
Nodes (8): DataStoreDecl, IdentityDecl, Manifest, normalize_service_path(), _Resolver, _short(), _Strict, _structure_problem()

### Community 9 - "findings/service.py"
Cohesion: 0.11
Nodes (22): apply_history(), diff_scans(), previous_scan_id(), ScanDiff, Finding, FindingOccurrence, ScanFinding, _base_query() (+14 more)

### Community 10 - "cli.py"
Cohesion: 0.13
Nodes (9): build_parser(), main(), markdown(), _out(), run_scan(), test_failed_scan_and_api_errors(), test_gate_failure_exit_code_and_escaping(), test_gate_pass_and_summary() (+1 more)

### Community 11 - "feeds.py"
Cohesion: 0.18
Nodes (12): _date(), _decimal(), _decimal_score(), fetch_nvd(), _kev_index(), NvdCvss, parse_nvd_cvss(), _nvd() (+4 more)

### Community 12 - "SourceType"
Cohesion: 0.13
Nodes (46): FindingContext, Observed, priority_for(), score(), ScoreInput, Priority, Severity, SourceType (+38 more)

### Community 13 - "redact.py"
Cohesion: 0.22
Nodes (10): derive_key(), mask(), scrub(), _scrub(), secret_hmac(), test_gitleaks_redaction_removes_every_raw_field(), test_hmac_is_keyed_and_deterministic(), test_mask_never_shows_short_secrets() (+2 more)

### Community 14 - "PHASE MVP level 2: context-aware scoring"
Cohesion: 0.11
Nodes (17): A. Objective, B. Why, C. Architecture, D. Components, H. API, I. Algorithms, J. Implementation, K. Commands (+9 more)

### Community 15 - "PHASE MVP — Scan, normalize, merge, prioritize (vertical slice)"
Cohesion: 0.10
Nodes (19): A. Objective, B. Why, C. Architecture, D. Components, E. Technical decisions, F. Folder structure, G. Database, H. API (+11 more)

### Community 16 - "run.py"
Cohesion: 0.06
Nodes (27): collect(), _environment(), EvaluationError, _guard(), _report(), _reset_db(), _scan(), _seed_intel() (+19 more)

### Community 17 - "scans/service.py"
Cohesion: 0.09
Nodes (38): ScanJob, ScannerRun, collect(), fail_scan(), finalize(), reap(), ReapResult, active_scan() (+30 more)

### Community 18 - "ADR-0006: Graph storage and analysis"
Cohesion: 0.22
Nodes (8): ADR-0006: Graph storage and analysis, Alternatives considered, Apache AGE (Postgres extension) — rejected for now, Consequences, Context, Decision, igraph instead of NetworkX — rejected, Neo4j Community — rejected

### Community 19 - "Dev Stack and CI Docs"
Cohesion: 0.16
Nodes (16): CI Workflow (ci.yml), CI backend job (ruff, mypy, pytest unit + db), CI frontend job (npm lint, typecheck, build), CI images job (build + Trivy scan backend image), CI security-self-scan job (Gitleaks + Trivy fs), Pre-commit config (pre-commit-hooks, ruff, gitleaks), Dev Compose stack, api service (uvicorn create_app) (+8 more)

### Community 20 - "test_pipeline_db.py"
Cohesion: 0.10
Nodes (28): FindingFilters, run_pipeline_inline(), no_lock(), session_scope(), criticals(), _ollama_up(), real_settings(), test_real_scanners_end_to_end() (+20 more)

### Community 21 - "Settings"
Cohesion: 0.11
Nodes (20): Settings, FixtureRunner, _base(), test_bad_redis_url_rejected(), test_missing_required_fails(), test_non_psycopg_database_url_rejected(), test_short_secret_rejected(), test_valid_settings_parse() (+12 more)

### Community 22 - "Finding Drawer and Triage UI"
Cohesion: 0.15
Nodes (25): FindingDetail, FindingStatus, Priority, ReachabilityTier, TrendPoint, ExplanationPanel(), contextOrigin(), DrawerBody() (+17 more)

### Community 23 - "Frontend Shell and Routing"
Cohesion: 0.16
Nodes (15): RFC-7807, API_BASE, ApiError, apiPatch(), apiPost(), handle(), Health, problemMessage() (+7 more)

### Community 24 - "0013-graph-paths-triage-history.md"
Cohesion: 0.25
Nodes (8): ADR-0013: Per-scan attack paths with effective impact; triage, history and the CI gate, Alternatives considered, CI gate, Consequences, Context, Decision, Graph and attack paths, Triage and history

### Community 25 - "App.tsx"
Cohesion: 0.18
Nodes (17): ScanList, App(), HealthDot(), HomePage(), RepositoryRoute(), ScanRoute(), PriorityCounts(), RepositoryPage() (+9 more)

### Community 26 - "trivy/parser.py"
Cohesion: 0.10
Nodes (32): Location, iac_family(), iac_topic(), IacFamily, normalize_check_id(), secret_family(), normalize_path(), checkov_severity() (+24 more)

### Community 27 - "RiskGraph — Deployment, NFRs, Failure Handling (section 27)"
Cohesion: 0.40
Nodes (4): 27.1 Deployment architecture, 27.2 Non-functional requirements (measurable targets), 27.3 Failure handling (graceful degradation table), RiskGraph — Deployment, NFRs, Failure Handling (section 27)

### Community 28 - "Frontend Build Config"
Cohesion: 0.07
Nodes (27): dependencies, cytoscape, react, react-dom, react-router-dom, @tanstack/react-query, name, private (+19 more)

### Community 29 - "explain/service.py"
Cohesion: 0.20
Nodes (14): clip_lines(), factor_evidence(), FactorEv, FindingEv, _Frozen, PathEv, ScoreEv, SnippetEv (+6 more)

### Community 30 - "PHASE 3: Scanner orchestration engine (hardened DockerRunner)"
Cohesion: 0.13
Nodes (14): A. Objective, B. Why, F. Folder structure, G. Database, H. API, I. Algorithms, J. Implementation notes, K. Commands (+6 more)

### Community 31 - "PHASE MVP level 2, extended: reachability, attack paths, triage and history"
Cohesion: 0.11
Nodes (18): A. Objective, B. Why, C. Architecture, D. Components, E. Technical decisions, F. Folder structure, H. API, I. Algorithms (+10 more)

### Community 33 - "repositories/router.py"
Cohesion: 0.13
Nodes (15): clone_url_for(), get_or_create(), InvalidRef, InvalidRepositoryUrl, parse_github_url(), validate_ref(), Forbidden, Problem (+7 more)

### Community 34 - "test_explain.py"
Cohesion: 0.19
Nodes (18): NullAdapter, validate(), _draft(), _pack(), test_a_grounded_draft_passes(), test_a_url_that_is_in_the_evidence_may_be_repeated_but_not_trusted_alone(), test_a_valid_first_answer_is_used(), test_digest_is_stable_and_changes_with_the_evidence() (+10 more)

### Community 35 - "RiskGraph — Security Threat Model (section 20)"
Cohesion: 0.38
Nodes (6): Actors, Assets (what we protect), Attack surfaces, RiskGraph — Security Threat Model (section 20), Security invariants (tested in Phase 15/16), Threats and mitigations

### Community 36 - "AttackPathsPanel.tsx"
Cohesion: 0.23
Nodes (12): AttackPath, GraphData, ScanSummary, AttackPathsPanel(), GraphView, KIND_COLOR, kindOf(), COLORS (+4 more)

### Community 37 - "docker_runner.py"
Cohesion: 0.09
Nodes (8): _Containers, DockerClient, _Images, _printable(), _write_capped(), SlotLimiter, SlotTimeoutError, test_the_slot_limiter_caps_concurrent_containers()

### Community 38 - "test_parsers.py"
Cohesion: 0.22
Nodes (10): ScannerName, fixture_path(), load(), test_checkov_shapes_and_resources(), test_counts_match_parsed_findings(), test_gitleaks_uses_redacted_fields_only(), test_hostile_paths_are_neutralised(), test_semgrep_rule_ids_and_categories() (+2 more)

### Community 39 - "adr/README.md"
Cohesion: 0.29
Nodes (5): ADR-0005: Hosting and deployment, Alternatives considered, Consequences, Decision, Architecture Decision Records

### Community 40 - "graph/__init__.py"
Cohesion: 0.24
Nodes (12): AttackPath, AttackPathFinding, GraphEdge, GraphNode, clear(), _dec(), list_paths(), load_graph() (+4 more)

### Community 41 - "dataclasses"
Cohesion: 0.11
Nodes (16): _bfs(), chain_to(), enclosing_function(), find_l3(), Path3, _qualify(), reachable_functions(), _resolve() (+8 more)

### Community 42 - "types.ts"
Cohesion: 0.11
Nodes (18): AttackPathEdge, FindingChange, FindingListItem, FindingLocation, KubeWorkload, ManifestStatus, Occurrence, PackageInfo (+10 more)

### Community 43 - "re"
Cohesion: 0.21
Nodes (6): import_names(), python_import_names(), used_without_import(), test_package_names(), _pins(), test_every_adapter_image_tag_matches_the_pinned_version()

### Community 44 - "context/router.py"
Cohesion: 0.19
Nodes (5): AssetOut, ContextOut, repository_context(), get_session(), _session_factory()

### Community 45 - "config.py"
Cohesion: 0.08
Nodes (21): _bind_task_context(), _clear_task_context(), _configure_worker_logging(), build_canvas(), enqueue(), enqueue_kill(), _sig(), default_deps() (+13 more)

### Community 46 - "test_explain_db.py"
Cohesion: 0.19
Nodes (13): top_critical(), explain_top_findings_task(), api(), _critical(), _grounded_reply(), sid(), test_a_grounded_model_answer_is_validated_and_stored(), test_an_injected_answer_is_rejected_and_never_stored() (+5 more)

### Community 47 - "TS App Config"
Cohesion: 0.11
Nodes (17): compilerOptions, baseUrl, isolatedModules, jsx, lib, module, moduleResolution, noEmit (+9 more)

### Community 48 - "PHASE 0 — Project Definition & Threat Model"
Cohesion: 0.04
Nodes (41): 17.1 Cross-cutting, 17.2 Endpoints (V1), 17.3 Representative schemas, 17. API architecture, 18. Frontend architecture, 19.1 Two integration paths, 19.2 Policy (from `riskgraph.yaml` `policy:` or repository settings; action input overrides), 19.3 RiskGraph's own CI (`.github/workflows/ci.yml`) (+33 more)

### Community 49 - "json"
Cohesion: 0.14
Nodes (13): _cves(), _freeze_intel(), record(), _target(), fetch_epss(), fetch_kev(), OutboundError, _client() (+5 more)

### Community 50 - "PHASE 1 — Repository & Development Environment"
Cohesion: 0.10
Nodes (19): A. Objective, B. Why, C. Architecture, D. Components, E. Technical decisions, F. Folder structure, G. Database, H. API (+11 more)

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

### Community 55 - "test_evaluation.py"
Cohesion: 0.23
Nodes (9): rank(), effort_at(), recall_at(), _F, test_effort_to_ninety_percent_recall(), test_m1_uses_cvss_then_severity_equivalent_then_fingerprint(), test_m2_multiplies_by_the_epss_transform_and_treats_missing_epss_as_neutral(), test_m4_ranks_like_the_product_priority_first() (+1 more)

### Community 56 - "test_docker_runner.py"
Cohesion: 0.14
Nodes (14): PathRoot, FakeClient, FakeContainer, FakeContainers, FakeImages, _runner(), _spec(), test_a_hung_container_is_killed_at_the_timeout() (+6 more)

### Community 57 - "api.py"
Cohesion: 0.09
Nodes (10): create_app(), configure_logging(), get_logger(), RequestIdMiddleware, test_prod_refuses_to_start_without_auth(), api(), _scan(), test_context_endpoint_404s_without_a_finished_scan() (+2 more)

### Community 59 - "EvidencePack"
Cohesion: 0.21
Nodes (4): EvidencePack, norm(), spellings(), user_message()

### Community 60 - "RiskGraph — Master Blueprint (v0.1, 2026-09-19)"
Cohesion: 0.20
Nodes (9): 1. Executive summary, 28. Final demonstration workflow (what the examiner sees, ~12 minutes), 29. Project risks and mitigations, 2. Exact problem definition, 30. Definition of the final MVP, 3. Scope (what V1 delivers), 4. Non-goals (stated so nobody expects them), 5. Novelty and technical contribution (honest version) (+1 more)

### Community 61 - "test_runtime_db.py"
Cohesion: 0.31
Nodes (8): api(), _create(), kills(), test_a_finished_scan_cannot_be_cancelled(), test_a_healthy_running_scan_is_left_alone(), test_cancel_asks_the_worker_to_kill_containers(), test_cancel_stops_the_scan_and_its_pending_runs(), test_the_reaper_times_out_dead_runs_and_fails_stale_scans()

### Community 62 - "TS Node Config"
Cohesion: 0.13
Nodes (12): manifests(), inputs(), compilerOptions, composite, module, moduleResolution, noEmit, skipLibCheck (+4 more)

### Community 63 - "get_settings"
Cohesion: 0.09
Nodes (22): run_extractor(), DockerRunner, make_removable(), ScannerRunner, build_runner(), clean_tmp(), main(), _make_removable_later() (+14 more)

### Community 64 - "ADR-0001: Modular monolith with API and worker roles"
Cohesion: 0.22
Nodes (8): ADR-0001: Modular monolith with API and worker roles, Alternatives considered, Compliance, Consequences, Context, Decision, Services per pipeline stage — rejected, Single flat package (no module boundaries) — rejected

### Community 65 - "report.py"
Cohesion: 0.22
Nodes (10): ndcg_at(), _cell(), findings_csv(), _fmt(), _labels(), main(), render(), _statistic() (+2 more)

### Community 66 - "ContextResolver"
Cohesion: 0.16
Nodes (5): _clean_file(), ContextResolver, KubeContext, ServiceDecl, test_secret_in_public_repo_is_internet_exposed_without_manifest()

### Community 67 - "14. Risk-engine architecture"
Cohesion: 0.25
Nodes (8): 14.1 Model comparison, 14.2 Definitions, 14.3 Reduction to a context-free model (the property that makes the model defensible), 14.4 Attack-path coupling ("effective impact"), 14.5 Rule overrides (explainable, listed in output as `overrides[]`), 14.6 Worked examples (scenarios A–E from the brief), 14.7 Sensitivity, calibration, limitations, 14. Risk-engine architecture

### Community 68 - "test_iac.py"
Cohesion: 0.30
Nodes (16): extract(), _rel(), _walk(), _repo(), test_alias_bombs_are_refused_before_parsing(), test_compose_build_context_cannot_escape_the_repository(), test_compose_exposure_reaches_findings_under_its_build_context(), test_compose_publishes_only_non_loopback_ports() (+8 more)

### Community 69 - "risk/router.py"
Cohesion: 0.13
Nodes (10): RiskScore, ranked(), score_of(), _latest_scan(), list_risks(), risk_detail(), RiskDetailOut, RiskItemOut (+2 more)

### Community 70 - "analyze"
Cohesion: 0.13
Nodes (22): analyze(), _ds(), GraphFinding, GraphInvariantError, _idn(), invariant_violations(), _svc(), _manifest() (+14 more)

### Community 71 - "Handoff (short summary)"
Cohesion: 0.33
Nodes (5): Before the next session, Commands, Handoff (short summary), State, Verified (at commit `943be49`)

### Community 72 - "reachability/service.py"
Cohesion: 0.28
Nodes (4): ReachabilityResult, clear(), persist_verdict(), ReachabilityRun

### Community 74 - "test_environment.py"
Cohesion: 0.46
Nodes (7): _resolver(), test_data_sensitivity_stops_after_two_hops(), test_data_sensitivity_two_hops_prefers_most_sensitive(), test_exposure_labels(), test_longest_path_prefix_wins(), test_secret_keeps_service_impact_context(), test_summary_counts_findings_per_service()

### Community 75 - "Session 1 handoff (2026-09-19)"
Cohesion: 0.12
Nodes (16): Commands that are known to work, Gotchas already hit (so you don't hit them again), HANDOFF: resume here (updated 2026-10-25, session 8: X0 done; next X1, see todo1150.md), Open items (decide before Phase 2), Open items (small, do at the start of Phase 2), Rules of engagement (from the brief and CLAUDE.md), Session 1 handoff (2026-09-19), Session 2 (2026-10-21): MVP vertical slice, done (+8 more)

### Community 76 - "ADR-0004: Authentication and authorization model"
Cohesion: 0.25
Nodes (7): ADR-0004: Authentication and authorization model, Alternatives considered, Consequences, Context, Decision, GitHub OAuth — deferred (stretch), Server-side sessions — rejected

### Community 77 - "Scanner Installer"
Cohesion: 0.50
Nodes (4): fetch_verified(), install-scanners.sh script, UV_TOOL_BIN_DIR, UV_TOOL_DIR

### Community 78 - "parse_manifest"
Cohesion: 0.23
Nodes (13): parse_manifest(), test_alias_bomb_is_refused_before_expansion(), test_deep_nesting_is_refused_without_crashing(), test_documented_example_manifest_is_valid(), test_hostile_or_broken_documents_never_raise(), test_load_absent_valid_and_yml_fallback(), test_load_refuses_oversized_and_non_utf8(), test_service_paths() (+5 more)

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
Cohesion: 0.12
Nodes (26): reportUrl(), RunStatus, ScanContext, ScanStatus, CHANGES, SCANNERS, STATUSES, TIERS (+18 more)

### Community 92 - "pytest"
Cohesion: 0.13
Nodes (24): build_create_kwargs(), _check_env(), _checked_path(), container_fields(), ContainerSpecError, Limits, Mount, scanner_image() (+16 more)

### Community 93 - "RiskGraph"
Cohesion: 0.25
Nodes (7): Context-aware scoring, Develop, Documentation, Quickstart, RiskGraph, Run without Docker, Triage, history and the CI gate

### Community 94 - "components"
Cohesion: 0.16
Nodes (15): components(), count(), _ecosystem(), _location(), _text(), test_syft_components_are_deduplicated_and_capped_text(), 16.1 Principles, 16.2 ER diagram (V1) (+7 more)

### Community 95 - "iac.py"
Cohesion: 0.23
Nodes (11): _code_dir(), _compose(), _d(), IacAsset, _ingress_backends(), _k8s(), kubernetes_context(), _l() (+3 more)

### Community 96 - "devDependencies"
Cohesion: 0.17
Nodes (12): devDependencies, eslint, @eslint/js, eslint-plugin-react-hooks, @types/node, @types/react, @types/react-dom, typescript (+4 more)

### Community 97 - "ADR-0008: Synchronous SQLAlchemy sessions"
Cohesion: 0.29
Nodes (6): ADR-0008: Synchronous SQLAlchemy sessions, Alternatives considered, Async SQLAlchemy (asyncpg) — rejected, Consequences, Context, Decision

### Community 98 - "baselines.py"
Cohesion: 0.30
Nodes (5): cvss_equivalent(), m1_key(), m2_key(), m4_key(), Rankable

### Community 99 - "json"
Cohesion: 0.16
Nodes (7): AdapterError, LlmAdapter, json_schema(), generate(), Outcome, _parse(), test_an_unavailable_model_falls_back_without_retrying()

### Community 100 - "typing"
Cohesion: 0.20
Nodes (4): Command, ParseContext, ScanPaths, Decision

### Community 101 - "semgrep/parser.py"
Cohesion: 0.17
Nodes (12): cwe_ids(), sast_category(), semgrep_severity(), clean_rule_id(), count(), parse(), _results(), semgrep_secret_family() (+4 more)

### Community 102 - "PHASE 4: Scanner adapters (five hardened images)"
Cohesion: 0.29
Nodes (6): Built, Decisions, Known differences from the host-run MVP, Not done, Objective, PHASE 4: Scanner adapters (five hardened images)

### Community 103 - "health.py"
Cohesion: 0.05
Nodes (28): Health, healthz(), Readiness, readyz(), problem_response(), register_problem_handlers(), _http(), _problem() (+20 more)

### Community 104 - "scans/router.py"
Cohesion: 0.17
Nodes (11): cancel_scan(), create_scan(), download_report(), get_scan(), list_scans(), to_out(), RepositoryOut, ScanCreate (+3 more)

### Community 105 - "kitchen_sink.json"
Cohesion: 0.13
Nodes (14): bomFormat, bom-ref, name, type, components, metadata, component, timestamp (+6 more)

### Community 106 - "repositories/router.py"
Cohesion: 0.20
Nodes (7): get_repository(), list_repositories(), _point(), RepositoryDetail, RepositorySummary, _summary(), TrendPoint

### Community 107 - "ADR-0015: L3 reachability by intraprocedural call graph; NVD refreshed by Beat"
Cohesion: 0.29
Nodes (6): ADR-0015: L3 reachability by intraprocedural call graph; NVD refreshed by Beat, Consequences, Context, Decision, L3, NVD

### Community 109 - "sqlalchemy"
Cohesion: 0.21
Nodes (6): upgrade(), downgrade(), _in_list(), _replace_check(), upgrade(), upgrade()

### Community 110 - "pydantic"
Cohesion: 0.22
Nodes (7): ExplanationDraft, Reason, explain(), _phrase(), _steps(), _texts(), _words()

### Community 111 - "PHASE 8: Reachability (L0–L3)"
Cohesion: 0.33
Nodes (5): Built, Not done (out of the blueprint's P8 scope), PHASE 8: Reachability (L0–L3), Verification, Verification (session 7)

### Community 112 - "context/service.py"
Cohesion: 0.13
Nodes (14): CvssSubscores, _round1(), subscores(), EpssScore, Asset, _fresh(), list_assets(), _load_kev() (+6 more)

### Community 114 - "ADR-0009: MVP runs scanners as subprocesses in the worker"
Cohesion: 0.29
Nodes (6): ADR-0009: MVP runs scanners as subprocesses in the worker, Alternatives considered, Blueprint DockerRunner now (§9.3): deferred, bubblewrap / `unshare --net` around each subprocess: deferred, Consequences, Context

### Community 115 - "A_high_cvss_unreachable/syft/1.54.1/report.json"
Cohesion: 0.13
Nodes (14): bomFormat, bom-ref, name, type, components, metadata, component, timestamp (+6 more)

### Community 116 - "extract.py"
Cohesion: 0.26
Nodes (12): _dotted(), extract(), _js(), main(), _package_json(), _parsers(), _python(), _python_calls() (+4 more)

### Community 117 - "ADR-0010: MVP vertical slice and its deviations from the blueprint"
Cohesion: 0.33
Nodes (5): ADR-0010: MVP vertical slice and its deviations from the blueprint, Consequences, Context, Decision, Example RiskGraph gate GitHub workflow (self-hosted)

### Community 118 - "metrics.py"
Cohesion: 0.15
Nodes (10): average_precision(), bootstrap(), _dcg(), Estimate, _percentile(), precision_at(), test_average_precision_by_hand(), test_bootstrap_is_seeded_and_reports_undefined_draws() (+2 more)

### Community 119 - "docker_runner.py"
Cohesion: 0.10
Nodes (9): _kill_group(), _rlimits(), refresh_trivy_db_task(), _open_cache_to_scanners(), refresh_argv(), refresh_trivy_db(), redis_scanner_lock(), _force_writable() (+1 more)

### Community 121 - "B_moderate_reachable_exposed/syft/1.54.1/report.json"
Cohesion: 0.13
Nodes (14): bomFormat, bom-ref, name, type, components, metadata, component, timestamp (+6 more)

### Community 122 - "D_internal_limited/syft/1.54.1/report.json"
Cohesion: 0.13
Nodes (14): bomFormat, bom-ref, name, type, components, metadata, component, timestamp (+6 more)

### Community 123 - "test_api.py"
Cohesion: 0.25
Nodes (11): api(), _completed_scan(), enqueued(), test_concurrency_cap(), test_create_scan_enqueues_and_dedups(), test_create_scan_rejects_bad_input(), test_findings_sort_filter_and_detail(), test_get_and_list_scans() (+3 more)

### Community 124 - "E_attack_path/syft/1.54.1/report.json"
Cohesion: 0.13
Nodes (14): bomFormat, bom-ref, name, type, components, metadata, component, timestamp (+6 more)

### Community 125 - "C_exposed_credential/syft/1.54.1/report.json"
Cohesion: 0.14
Nodes (13): bomFormat, bom-ref, name, type, metadata, component, timestamp, tools (+5 more)

### Community 126 - "storage.py"
Cohesion: 0.30
Nodes (6): read_json_capped(), read_report(), report_path(), report_relpath(), ReportTooLargeError, write_report()

### Community 127 - "PHASE 11: Contextual risk engine (scenarios, properties, GET /risks)"
Cohesion: 0.29
Nodes (6): A. Objective, B. Built, M. Testing, Not done, O. Validation, PHASE 11: Contextual risk engine (scenarios, properties, GET /risks)

### Community 128 - "to_networkx"
Cohesion: 0.10
Nodes (12): _EdgeRow, _NodeRow, to_networkx(), test_to_networkx_keeps_the_most_probable_parallel_edge(), A. Objective, B. Built, C. Decisions taken here, M. Testing (+4 more)

### Community 130 - "_ollama"
Cohesion: 0.22
Nodes (7): _ollama(), test_ollama_connection_errors_are_adapter_errors(), test_ollama_failures_are_adapter_errors(), test_ollama_keep_alive_is_sent_as_a_number_when_it_is_one(), test_ollama_request_shape_and_reply(), handler(), test_ollama_url_must_be_http()

### Community 132 - "20261023_0900_reachability_l3.py"
Cohesion: 0.83
Nodes (3): _check(), downgrade(), upgrade()

### Community 134 - "PHASE 12: AI explanation (evidence-grounded, validated, cached)"
Cohesion: 0.15
Nodes (13): A. Objective, B. Why, C. Architecture, D. Components, E. Technical decisions, G. Database, H. API, L. Configuration (+5 more)

### Community 135 - "OllamaAdapter"
Cohesion: 0.13
Nodes (6): OllamaAdapter, adapter_from_settings(), test_real_model_explains_a_critical_finding_and_the_result_is_cached(), test_unreachable_model_falls_back_to_the_template(), test_ollama_over_a_unix_socket(), test_ollama_socket_that_is_missing_is_an_adapter_error()

### Community 136 - "26. Research evaluation methodology"
Cohesion: 0.17
Nodes (11): 25.1 Layers and markers, 25.2 Test datasets (`datasets/`), 25. Testing strategy, 26.1 Question and hypotheses, 26.2 Methods compared, 26.3 Ground truth, 26.4 Metrics, 26.5 Statistics (+3 more)

### Community 138 - "PHASE 7: Context enrichment (NVD, EPSS, KEV, manifest, Kubernetes and Compose)"
Cohesion: 0.29
Nodes (6): Built, Not done, PHASE 7: Context enrichment (NVD, EPSS, KEV, manifest, Kubernetes and Compose), Session 7 additions (2026-10-25), Verification, Verification (session 7)

### Community 139 - "test_graph_db.py"
Cohesion: 0.36
Nodes (7): api(), _reach(), sid(), test_depth_bounds_the_walk(), test_downstream_from_the_internet_and_nothing_upstream(), test_unknown_node_scan_and_bad_params(), test_what_can_reach_the_pii_store()

### Community 140 - "RiskGraph — AI session entry point"
Cohesion: 0.29
Nodes (6): Commands, Conventions, Current state, Dependencies, graphify, RiskGraph — AI session entry point

### Community 144 - "test_reachability.py"
Cohesion: 0.26
Nodes (14): ReachabilityTier, _classifier(), extracted(), test_extractor_runs_isolated_through_the_runner(), test_hostile_inputs_do_not_break_extraction(), test_indirect_dependencies_inherit_from_direct_parents(), test_js_imports_entries_and_skips(), test_module_graph_resolution() (+6 more)

### Community 145 - "uuid7.py"
Cohesion: 0.48
Nodes (3): uuid7(), test_uuid7_is_time_ordered_and_unique(), test_uuid7_version_and_variant()

### Community 146 - "RiskGraph baseline (expansion phase X0)"
Cohesion: 0.29
Nodes (6): Dataset, Per scenario, Pooled ranking (primary), Reading these numbers, RiskGraph baseline (expansion phase X0), Top 10 of the pooled ranking

### Community 147 - "typing"
Cohesion: 0.10
Nodes (12): downgrade(), upgrade(), upgrade(), AuditLog, history(), record(), Vulnerability, Repository (+4 more)

### Community 148 - "normalization/__init__.py"
Cohesion: 0.17
Nodes (12): RawFinding, fingerprint(), stable_hash(), _build(), merge(), MergedFinding, _overlap_clusters(), _graph_label() (+4 more)

### Community 149 - "ADR-0002: Stack"
Cohesion: 0.33
Nodes (5): ADR-0002: Stack, Alternatives considered, Consequences, Context, Decision

### Community 150 - ".source"
Cohesion: 0.25
Nodes (7): Decision, 11.1 Manifest schema (`riskgraph.yaml`, v1), 11.2 Factors produced (all with `source` and `confidence`), 11.3 Reachability tiers (the honest design), 11. Context enrichment architecture, G. Database, R. Common failure modes

### Community 151 - "RiskGraph — Architecture (sections 6–15)"
Cohesion: 0.29
Nodes (6): 12. Security graph schema, 15. AI explanation architecture, 6. Complete system architecture, 7. Component architecture, 8. Data flow for one scan, RiskGraph — Architecture (sections 6–15)

### Community 152 - "TODO (saved 2026-10-25, session 7): where work stopped and what is next"
Cohesion: 0.33
Nodes (5): Done and committed (session 7), Done: expansion phase X0 (baseline dataset and metrics), Next: X1, then in order (expansion plan §4; "deferred" items stay deferred), Open items for the owner, TODO (saved 2026-10-25, session 7): where work stopped and what is next

### Community 153 - "explain/router.py"
Cohesion: 0.23
Nodes (6): create_explanation(), EvidenceRef, ExplanationOut, get_explanation(), _out(), ReasonOut

### Community 154 - "PHASE 10: Attack-path engine (scenario E, performance budget)"
Cohesion: 0.29
Nodes (6): A. Objective, B. Defect found and fixed, M. Testing, Not done, O. Validation, PHASE 10: Attack-path engine (scenario E, performance budget)

### Community 156 - "ADR-0012: Reachability tiers L0–L2 in the MVP (import graph, no call graph)"
Cohesion: 0.33
Nodes (5): ADR-0012: Reachability tiers L0–L2 in the MVP (import graph, no call graph), Alternatives considered, Consequences, Context, Decision

### Community 158 - "13. Attack-path architecture"
Cohesion: 0.40
Nodes (4): 13.1 Attack-graph derivation, 13.2 Algorithm choice, 13.3 Path scoring and output, 13. Attack-path architecture

### Community 159 - "9. Scanner orchestration architecture"
Cohesion: 0.40
Nodes (5): 9.1 Job model and state machines, 9.2 Celery canvas, 9.3 Isolation profile for scanner containers, 9.4 Scanner adapter interface, 9. Scanner orchestration architecture

### Community 160 - "sbom/service.py"
Cohesion: 0.09
Nodes (19): SbomComponent, ComponentOut, SbomOut, scan_sbom(), attach_findings(), canonical_purl(), clear(), _ecosystem() (+11 more)

### Community 162 - "10. Finding normalization architecture"
Cohesion: 0.50
Nodes (4): 10.1 Canonical model, 10.2 Fingerprinting (dedup within and across scans), 10.3 Severity mapping, 10. Finding normalization architecture

### Community 164 - "ADR-0016: Evidence-grounded explanations with a local model and a template fallback"
Cohesion: 0.33
Nodes (5): ADR-0016: Evidence-grounded explanations with a local model and a template fallback, Alternatives considered, Consequences, Context, Decision

## Knowledge Gaps
- **14 isolated node(s):** `Manifest criticality`, `Pre-commit config (pre-commit-hooks, ruff, gitleaks)`, `postgres service (16-alpine)`, `redis service (7-alpine, password)`, `Frontend index.html (mounts /src/main.tsx)` (+9 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 1081 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **34 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `AdapterError` connect `json` to `test_explain.py`, `_ollama`, `PHASE 12: AI explanation (evidence-grounded, validated, cached)`, `OllamaAdapter`?**
  _High betweenness centrality (0.115) - this node is a cross-community bridge._
- **Are the 85 inferred relationships involving `Settings` (e.g. with `_environment()` and `_guard()`) actually correct?**
  _`Settings` has 85 INFERRED edges - model-reasoned connections that need verification._
- **What connects `Manifest criticality`, `Pre-commit config (pre-commit-hooks, ruff, gitleaks)`, `postgres service (16-alpine)` to the rest of the system?**
  _14 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `RunSpec` be split into smaller, more focused modules?**
  _Cohesion score 0.1408199643493761 - nodes in this community are weakly interconnected._
- **Why does `M. Testing` connect `PHASE 12: AI explanation (evidence-grounded, validated, cached)` to `json`?**
  _High betweenness centrality (0.114) - this node is a cross-community bridge._
- **Are the 78 inferred relationships involving `SourceType` (e.g. with `ContextResolver` and `Finding`) actually correct?**
  _`SourceType` has 78 INFERRED edges - model-reasoned connections that need verification._
- **Should `dataclasses` be split into smaller, more focused modules?**
  _Cohesion score 0.13333333333333333 - nodes in this community are weakly interconnected._