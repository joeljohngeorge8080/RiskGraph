# Graph Report - riskgraph  (2026-11-05)

## Corpus Check
- 452 files · ~301,739 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 46 file(s) not represented in the graph (top: .tsv 21, (none) 13, .Dockerfile 2)

## Summary
- 4489 nodes · 13096 edges · 268 communities (214 shown, 54 thin omitted)
- Extraction: 89% EXTRACTED · 11% INFERRED · 0% AMBIGUOUS · INFERRED: 1456 edges (avg confidence: 0.93)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `9fffd526`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- HANDOFF: resume here (updated 2026-11-05, handover to collaborators)
- FindingsSection.tsx
- RunSpec
- evidence/__init__.py
- ScanWorkspace
- RiskGraph expansion A–D: architecture decision and phased plan
- manifest.py
- findings/router.py
- test_graph_perf.py
- test_joern.py
- cli.py
- runtime/__init__.py
- graph/router.py
- inventory.py
- PHASE MVP level 2: context-aware scoring
- OutboundClient
- test_docker_runner.py
- test_parsers.py
- ADR-0006: Graph storage and analysis
- Dev Stack and CI Docs
- session_scope
- test_evidence_db.py
- Finding Drawer and Triage UI
- Frontend Shell and Routing
- 0013-graph-paths-triage-history.md
- App.tsx
- test_runtime_db.py
- RiskGraph — Deployment, NFRs, Failure Handling (section 27)
- Frontend Build Config
- explain/service.py
- PHASE 3: Scanner orchestration engine (hardened DockerRunner)
- PHASE MVP level 2, extended: reachability, attack paths, triage and history
- 05_REPO_STRUCTURE.md
- json
- test_explain.py
- RiskGraph — Security Threat Model (section 20)
- AttackPathsPanel.tsx
- docker_runner.py
- authz.py
- adr/README.md
- graph/__init__.py
- reachability/service.py
- types.ts
- SourceType
- baselines.py
- repositories/service.py
- test_explain_db.py
- TS App Config
- risk/__init__.py
- RawFinding
- PHASE 1 — Repository & Development Environment
- ADR-0003: UUID v7 ids, single tenant, deletion policy
- scanners/record.py
- Part 2: authorization findings (2026-10-29)
- test_callgraph.py
- images/record.py
- trivy/parser.py
- config.py
- findings/service.py
- ScanStatus
- RiskGraph — Master Blueprint (v0.1, 2026-09-19)
- 20261022_1200_containers_sbom_assets.py
- TS Node Config
- semgrep/parser.py
- ADR-0001: Modular monolith with API and worker roles
- config.py
- taint.py
- components
- ContextResolver
- GraphFinding
- _manifest
- Handoff (short summary)
- typing
- test_runtime_eol_db.py
- test_topology_graph.py
- iac.py
- ADR-0004: Authentication and authorization model
- Scanner Installer
- extract
- llm.sh
- TS Root Config
- Test DB Init
- ADR-0007: Celery + Redis for background work
- PHASE X0: baseline dataset and metrics (expansion plan)
- Backend Package
- format.ts
- test_containers.py
- RiskGraph
- OllamaAdapter
- pipeline.py
- Observed
- ADR-0008: Synchronous SQLAlchemy sessions
- Unattended run book (branch `extended_phase_auto`)
- Severity
- modules/scanners/__init__.py
- sbom/service.py
- parse_ref
- context/__init__.py
- scans/router.py
- kitchen_sink.json
- ExplanationDraft
- ADR-0015: L3 reachability by intraprocedural call graph; NVD refreshed by Beat
- test_taint_tier1.py
- modules/scanners/__init__.py
- storage.py
- Location
- risk/router.py
- build-scanner-images.sh
- devDependencies
- A_high_cvss_unreachable/syft/1.54.1/report.json
- routes.py
- test_evidence.py
- explain/router.py
- repositories/router.py
- _ImageResults
- B_moderate_reachable_exposed/syft/1.54.1/report.json
- D_internal_limited/syft/1.54.1/report.json
- re
- E_attack_path/syft/1.54.1/report.json
- C_exposed_credential/syft/1.54.1/report.json
- test_risk_scenarios_v2.py
- PHASE 11: Contextual risk engine (scenarios, properties, GET /risks)
- PHASE X2: runtime and image intelligence (expansion plan)
- make_evidence
- TierClassifier
- callgraph.py
- 20261023_0900_reachability_l3.py
- authz/service.py
- PHASE 12: AI explanation (evidence-grounded, validated, cached)
- ReachabilityTier
- EvidencePack
- test_image_scan_db.py
- TODO (saved 2026-10-25, session 7; updated 2026-10-31, auto day 6): where work stopped and what is next
- Work done — session 1 (2026-09-19)
- ADR-0025: Tier-2 taint with Joern, in an opt-in `deep` scan profile
- guards.py
- test_taint_suite.py
- test_reachability.py
- RiskGraph — Data, API, Frontend, CI/CD (sections 16–19)
- RiskGraph baseline (expansion phase X0)
- test_authz_analysis.py
- Evaluation run book (X8)
- analysis.py
- Schedule: X2 part 2, X3, X4, X5, X6 over six days
- RiskGraph — Architecture (sections 6–15)
- test_authz_inventory.py
- HANDOFF: resume here (updated 2026-11-03, session 9 local: L-2…L-9 run, nine flags answered, F-1-1 built; remaining work below)
- PHASE 10: Attack-path engine (scenario E, performance budget)
- attack.py
- ADR-0012: Reachability tiers L0–L2 in the MVP (import graph, no call graph)
- ADR-0011: Context-aware scoring from the repository manifest (MVP level 2)
- readyz
- Joern spike (X4.0)
- PHASE MVP — Scan, normalize, merge, prioritize (vertical slice)
- topology.py
- AttackAnalysis
- ADR-0018: Runtime and image intelligence: EOL from a stored feed, image scans behind an allow-list
- problems.py
- RiskGraph — AI session entry point
- PHASE X3: the assured graph (expansion plan)
- PHASE X1: evidence and assurance contracts (expansion plan)
- test_route_extract.py
- json
- PHASE 7: Context enrichment (NVD, EPSS, KEV, manifest, Kubernetes and Compose)
- report.py
- extract
- Day 3 report (Wed 2026-10-28): X4 part 2 gated; tier-1 hardening and X5 part 1
- PHASE X4: deep code analysis (expansion plan)
- PHASE 0 — Project Definition & Threat Model
- report.py
- field_validator
- test_authz_findings_suite.py
- db
- Day 6 plan (Sat 2026-10-31): integration pass
- finding_evidence
- Day 4 report (Thu 2026-10-29): X5 part 2, authorization findings
- Day 6 report (Sat 2026-10-31): integration pass
- Part 3 (2026-11-05): the Joern adapter (F-3-1 answered (a), ADR-0025)
- ADR-0023: Authorization findings, the manifest `authz:` section, an interim score, and non-traversable authz edges
- 20261105_0900_joern_scanner.py
- Day 1 plan (Mon 2026-10-26): X2 part 2 + X3 part 1
- generate.py
- ADR-0021: Tier-1 taint rules from one RiskGraph catalogue; the taint evidence contract
- Day 2 report (Tue 2026-10-27): X3 part 2 + X4 part 1
- PHASE 8: Reachability (L0–L3)
- scan_images
- Files read and nearest analogs
- ADR-0016: Evidence-grounded explanations with a local model and a template fallback
- DockerRunner
- risk/service.py
- test_authz_suite.py
- RiskGraph — Project Specification (Phase 0, v1.0, 2026-09-19)
- Day 2 plan (Tue 2026-10-27): X3 part 2 + X4 part 1
- Scanner
- graph.py
- RiskGraph — Phase Dependency Graph and Roadmap (sections 23–24)
- EVALUATION_EXPANSION.md
- sbom/router.py
- gitleaks/parser.py
- Entries
- ADR-0019: A graph from Compose and Kubernetes when the manifest declares no services
- RiskGraph — Threat Model (living document; v0.1 from blueprint 03, 2026-09-19)
- .http
- uuid7.py
- logging.py
- test_environment.py
- Day 3 plan (Wed 2026-10-28): X4 part 2 is gated, so tier-1 hardening and X5 part 1 early
- worker.py
- ADR-0009: MVP runs scanners as subprocesses in the worker
- Authorization evaluation (scenario I, F-4-1)
- PHASE X6: risk v2 (expansion plan)
- 14. Risk-engine architecture
- PHASE 4: Scanner adapters (five hardened images)
- 26. Research evaluation methodology
- test_health.py
- context/router.py
- images/record.py
- Day 5 report (Fri 2026-10-30): X6, risk v2
- Day 5 plan (Fri 2026-10-30): X6, risk v2
- Where RiskGraph stands (handover, 2026-11-05)
- Backlog (handover, 2026-11-05)
- 16. Database architecture
- What was built
- PHASE 5: Normalization, correlation and SBOM
- ADR-0014: Scanners run as hardened containers (DockerRunner), with pinned images

## God Nodes (most connected - your core abstractions)
1. `Settings` - 205 edges
2. `SourceType` - 180 edges
3. `ScannerName` - 157 edges
4. `Severity` - 101 edges
5. `session_scope()` - 99 edges
6. `ScanStatus` - 89 edges
7. `analyze()` - 75 edges
8. `RawFinding` - 68 edges
9. `score()` - 63 edges
10. `ScoreInput` - 62 edges

## Surprising Connections (you probably didn't know these)
- `Conventions` --references--> `Problem`  [INFERRED]
  CLAUDE.md → backend/riskgraph/shared/problems.py
- `Session 2 (2026-10-21): MVP vertical slice, done` --references--> `ScannerRunner`  [INFERRED]
  docs/handover/HISTORY.md → backend/riskgraph/modules/scanners/runner.py
- `E. Technical decisions` --references--> `ScanPaths`  [INFERRED]
  docs/phases/PHASE_MVP.md → backend/riskgraph/modules/scanners/base.py
- `Consequences` --references--> `RawRef`  [INFERRED]
  docs/adr/0017-evidence-and-assurance.md → backend/riskgraph/modules/evidence/contract.py
- `Decision` --references--> `FlowStep`  [INFERRED]
  docs/adr/0021-tier1-taint-catalogue.md → backend/riskgraph/modules/evidence/contract.py

## Import Cycles
- 3-file cycle: `backend/riskgraph/modules/risk/__init__.py -> backend/riskgraph/modules/risk/service.py -> backend/riskgraph/modules/risk/model.py -> backend/riskgraph/modules/risk/__init__.py`

## Hyperedges (group relationships)
- **Dev Compose stack services sharing the backend image** — docker_compose_migrate, docker_compose_api, docker_compose_worker, docker_compose_beat [EXTRACTED 1.00]
- **riskgraph.yaml context model (services, identities, data stores, criticality)** — docs_examples_riskgraph_services, docs_examples_riskgraph_identities, docs_examples_riskgraph_data_stores, docs_examples_riskgraph_criticality, readme_context_aware_scoring [EXTRACTED 1.00]

## Communities (268 total, 54 thin omitted)

### Community 1 - "FindingsSection.tsx"
Cohesion: 0.15
Nodes (19): apiGet(), FindingChange, FindingList, ReachabilityTier, ScannerName, FindingDrawer(), CHANGES, FilterState (+11 more)

### Community 2 - "RunSpec"
Cohesion: 0.22
Nodes (14): RunSpec, SubprocessRunner, _tail(), test_memory_limit_is_enforced(), test_self_python_is_the_only_path_alias(), runner(), _spec(), test_environment_is_an_allow_list() (+6 more)

### Community 3 - "evidence/__init__.py"
Cohesion: 0.30
Nodes (10): EdgeEvidence, EvidenceRow, FindingEvidence, clear(), evidence_for_edges(), evidence_for_finding(), link_edge(), link_finding() (+2 more)

### Community 4 - "ScanWorkspace"
Cohesion: 0.08
Nodes (21): build_clone_argv(), CloneError, Cloner, CloneResult, git_env(), GitCloner, _excerpt(), _scan_one_image() (+13 more)

### Community 5 - "RiskGraph expansion A–D: architecture decision and phased plan"
Cohesion: 0.10
Nodes (19): Assurance, 1.1 Existing functionality (VERIFIED by reading the code at `08d5181`), 1. Audit: what exists, and where A–D plug in, 2.1 Options compared, 2.2 Graph storage (re-evaluated, not assumed), 2.3 Recommended architecture, 2.4 Module boundaries and interfaces, 2. Architecture: options and the decision (+11 more)

### Community 6 - "manifest.py"
Cohesion: 0.17
Nodes (17): load_manifest(), parse_manifest(), test_hostile_or_odd_links_are_rejected(), test_alias_bomb_is_refused_before_expansion(), test_authz_public_patterns_are_normalized_and_deduplicated(), test_deep_nesting_is_refused_without_crashing(), test_documented_example_manifest_is_valid(), test_hostile_or_broken_documents_never_raise() (+9 more)

### Community 7 - "findings/router.py"
Cohesion: 0.10
Nodes (29): _diff_items(), _float(), get_finding(), list_findings(), path_out(), require_scan(), risk_out(), scan_diff() (+21 more)

### Community 8 - "test_graph_perf.py"
Cohesion: 0.27
Nodes (7): _attack_graph(), Row, _rows(), test_build_and_search_a_5k_node_20k_edge_manifest_graph_under_two_seconds(), test_loader_builds_5k_nodes_20k_edges_under_one_second(), test_search_with_function_endpoint_nodes_and_hypotheses_under_two_seconds(), test_yen_top3_for_10_sinks_on_5k_20k_under_two_seconds()

### Community 9 - "test_joern.py"
Cohesion: 0.10
Nodes (18): _flow(), _golden(), _Lock, _Redis, test_a_malformed_report_gives_no_finding_and_no_error(), test_a_path_outside_the_checkout_is_normalized_like_every_scanner_path(), test_a_tier2_member_is_inferred_interprocedural_taint_flow_evidence(), test_an_allow_list_lookup_sanitizes_and_a_constant_beside_the_flow_does_not() (+10 more)

### Community 10 - "cli.py"
Cohesion: 0.10
Nodes (14): build_parser(), main(), markdown(), _out(), run_scan(), test_failed_scan_and_api_errors(), test_gate_failure_exit_code_and_escaping(), test_gate_pass_and_summary() (+6 more)

### Community 11 - "runtime/__init__.py"
Cohesion: 0.12
Nodes (24): declarations(), _files(), _first_line(), _from_file(), _from_images(), _read(), RuntimeDecl, _date() (+16 more)

### Community 12 - "graph/router.py"
Cohesion: 0.13
Nodes (10): attack_paths(), _edges_out(), graph_reach(), GraphEdgeOut, GraphNodeOut, GraphOut, ReachNodeOut, ReachOut (+2 more)

### Community 13 - "inventory.py"
Cohesion: 0.09
Nodes (37): _bind(), _bound(), _by_import(), _classify(), _collect_calls(), _collect_mounts(), _collect_receivers(), _deps_as() (+29 more)

### Community 14 - "PHASE MVP level 2: context-aware scoring"
Cohesion: 0.11
Nodes (17): A. Objective, B. Why, C. Architecture, D. Components, H. API, I. Algorithms, J. Implementation, K. Commands (+9 more)

### Community 15 - "OutboundClient"
Cohesion: 0.13
Nodes (8): refresh_feeds_task(), RuntimeEol, load_feeds(), refresh_eol(), store_cycles(), refresh_eol_task(), OutboundClient, test_beat_refresh_stores_cycles_and_keeps_old_data_on_failure()

### Community 16 - "test_docker_runner.py"
Cohesion: 0.14
Nodes (14): PathRoot, FakeClient, FakeContainer, FakeContainers, FakeImages, _runner(), _spec(), test_a_hung_container_is_killed_at_the_timeout() (+6 more)

### Community 17 - "test_parsers.py"
Cohesion: 0.14
Nodes (15): get_scanner(), clean_rule_id(), semgrep_secret_family(), _container_fields(), ScannerName, fixture_path(), load(), test_the_joern_adapter_is_registered_and_parses_the_kitchen_sink() (+7 more)

### Community 18 - "ADR-0006: Graph storage and analysis"
Cohesion: 0.22
Nodes (8): ADR-0006: Graph storage and analysis, Alternatives considered, Apache AGE (Postgres extension) — rejected for now, Consequences, Context, Decision, igraph instead of NetworkX — rejected, Neo4j Community — rejected

### Community 19 - "Dev Stack and CI Docs"
Cohesion: 0.16
Nodes (16): CI Workflow (ci.yml), CI backend job (ruff, mypy, pytest unit + db), CI frontend job (npm lint, typecheck, build), CI images job (build + Trivy scan backend image), CI security-self-scan job (Gitleaks + Trivy fs), Pre-commit config (pre-commit-hooks, ruff, gitleaks), Dev Compose stack, api service (uvicorn create_app) (+8 more)

### Community 20 - "session_scope"
Cohesion: 0.13
Nodes (28): _scan(), Scenario, FindingFilters, run_pipeline_inline(), real_settings(), test_real_scanners_with_manifest_reachability_paths_and_history(), scan(), LocalDirCloner (+20 more)

### Community 21 - "test_evidence_db.py"
Cohesion: 0.14
Nodes (18): api(), _count(), test_attack_paths_are_grouped_by_assurance_and_name_what_is_missing(), test_every_edge_and_finding_rests_on_stored_evidence(), test_hypothesis_paths_never_raise_a_score(), test_the_api_serves_evidence_and_assurance(), test_the_migration_backfill_matches_the_builder(), api() (+10 more)

### Community 22 - "Finding Drawer and Triage UI"
Cohesion: 0.14
Nodes (27): apiPost(), Explanation, FindingDetail, FindingListItem, FindingStatus, TrendPoint, ExplanationPanel(), contextOrigin() (+19 more)

### Community 23 - "Frontend Shell and Routing"
Cohesion: 0.27
Nodes (8): RFC-7807, API_BASE, ApiError, apiPatch(), handle(), Health, problemMessage(), Readiness

### Community 24 - "0013-graph-paths-triage-history.md"
Cohesion: 0.14
Nodes (13): ADR-0010: MVP vertical slice and its deviations from the blueprint, Consequences, Context, Decision, ADR-0013: Per-scan attack paths with effective impact; triage, history and the CI gate, Alternatives considered, CI gate, Consequences (+5 more)

### Community 25 - "App.tsx"
Cohesion: 0.16
Nodes (17): Scan, App(), HealthDot(), HomePage(), RepositoryRoute(), ScanRoute(), PriorityCounts(), RepositoryPage() (+9 more)

### Community 26 - "test_runtime_db.py"
Cohesion: 0.22
Nodes (10): ScanJob, api(), _create(), kills(), test_a_finished_scan_cannot_be_cancelled(), test_a_healthy_running_scan_is_left_alone(), test_cancel_asks_the_worker_to_kill_containers(), test_cancel_stops_the_scan_and_its_pending_runs() (+2 more)

### Community 27 - "RiskGraph — Deployment, NFRs, Failure Handling (section 27)"
Cohesion: 0.40
Nodes (4): 27.1 Deployment architecture, 27.2 Non-functional requirements (measurable targets), 27.3 Failure handling (graceful degradation table), RiskGraph — Deployment, NFRs, Failure Handling (section 27)

### Community 28 - "Frontend Build Config"
Cohesion: 0.07
Nodes (27): dependencies, cytoscape, react, react-dom, react-router-dom, @tanstack/react-query, name, private (+19 more)

### Community 29 - "explain/service.py"
Cohesion: 0.19
Nodes (14): clip_lines(), factor_evidence(), FactorEv, FindingEv, _Frozen, PathEv, ScoreEv, SnippetEv (+6 more)

### Community 30 - "PHASE 3: Scanner orchestration engine (hardened DockerRunner)"
Cohesion: 0.13
Nodes (14): A. Objective, B. Why, F. Folder structure, G. Database, H. API, I. Algorithms, J. Implementation notes, K. Commands (+6 more)

### Community 31 - "PHASE MVP level 2, extended: reachability, attack paths, triage and history"
Cohesion: 0.11
Nodes (18): A. Objective, B. Why, C. Architecture, D. Components, E. Technical decisions, F. Folder structure, H. API, I. Algorithms (+10 more)

### Community 33 - "json"
Cohesion: 0.16
Nodes (18): check_authz(), check_paths(), check_prioritization(), check_taint(), check_unmeasured(), Criterion, evaluate(), main() (+10 more)

### Community 34 - "test_explain.py"
Cohesion: 0.11
Nodes (28): NullAdapter, Reason, validate(), _draft(), _ollama(), _pack(), test_a_grounded_draft_passes(), test_a_url_that_is_in_the_evidence_may_be_repeated_but_not_trusted_alone() (+20 more)

### Community 35 - "RiskGraph — Security Threat Model (section 20)"
Cohesion: 0.38
Nodes (6): Actors, Assets (what we protect), Attack surfaces, RiskGraph — Security Threat Model (section 20), Security invariants (tested in Phase 15/16), Threats and mitigations

### Community 36 - "AttackPathsPanel.tsx"
Cohesion: 0.24
Nodes (11): AttackPath, GraphData, ScanSummary, AttackPathsPanel(), GraphView, KIND_COLOR, kindOf(), COLORS (+3 more)

### Community 37 - "docker_runner.py"
Cohesion: 0.09
Nodes (8): _Containers, DockerClient, _Images, _printable(), _write_capped(), SlotLimiter, SlotTimeoutError, test_the_slot_limiter_caps_concurrent_containers()

### Community 38 - "authz.py"
Cohesion: 0.12
Nodes (14): by_score(), by_severity(), _fmt(), main(), rank_metrics(), _ratio(), report(), Result (+6 more)

### Community 39 - "adr/README.md"
Cohesion: 0.09
Nodes (17): ADR-0002: Stack, Alternatives considered, Consequences, Context, Decision, ADR-0005: Hosting and deployment, Alternatives considered, Consequences (+9 more)

### Community 40 - "graph/__init__.py"
Cohesion: 0.15
Nodes (19): AttackPath, AttackPathFinding, GraphEdge, GraphNode, clear(), _dec(), list_paths(), load_graph() (+11 more)

### Community 41 - "reachability/service.py"
Cohesion: 0.26
Nodes (5): ReachabilityResult, clear(), persist_verdict(), ReachabilityRun, run_extractor()

### Community 42 - "types.ts"
Cohesion: 0.11
Nodes (19): AttackPathEdge, FindingLocation, KubeWorkload, ManifestStatus, Occurrence, PackageInfo, RepositoryDetail, RepositorySummary (+11 more)

### Community 43 - "SourceType"
Cohesion: 0.15
Nodes (43): FindingContext, priority_for(), score(), ScoreInput, Priority, SourceType, test_k_paths_per_sink_and_hop_limit(), test_ndcg_by_hand() (+35 more)

### Community 44 - "baselines.py"
Cohesion: 0.30
Nodes (5): cvss_equivalent(), m1_key(), m2_key(), m4_key(), Rankable

### Community 45 - "repositories/service.py"
Cohesion: 0.17
Nodes (14): Repository, clone_url_for(), get_or_create(), InvalidRef, InvalidRepositoryUrl, parse_github_url(), validate_ref(), TimestampMixin (+6 more)

### Community 46 - "test_explain_db.py"
Cohesion: 0.09
Nodes (34): explain_top_findings_task(), Settings, workspace_exists(), api(), _completed_scan(), enqueued(), test_a_deep_scan_runs_joern_too(), test_concurrency_cap() (+26 more)

### Community 47 - "TS App Config"
Cohesion: 0.11
Nodes (17): compilerOptions, baseUrl, isolatedModules, jsx, lib, module, moduleResolution, noEmit (+9 more)

### Community 48 - "risk/__init__.py"
Cohesion: 0.23
Nodes (10): _clamp(), _context_factor(), _eol_exploitability(), epss_to_e(), _exploitability(), Factor, _reachability_factor(), _taint_exploitability() (+2 more)

### Community 49 - "RawFinding"
Cohesion: 0.12
Nodes (17): issue_findings(), RawFinding, fingerprint(), stable_hash(), parse_all(), _legacy_sca_fingerprint(), _legacy_sca_merge_key(), report() (+9 more)

### Community 50 - "PHASE 1 — Repository & Development Environment"
Cohesion: 0.10
Nodes (19): A. Objective, B. Why, C. Architecture, D. Components, E. Technical decisions, F. Folder structure, G. Database, H. API (+11 more)

### Community 51 - "ADR-0003: UUID v7 ids, single tenant, deletion policy"
Cohesion: 0.25
Nodes (7): ADR-0003: UUID v7 ids, single tenant, deletion policy, Alternatives considered, bigint serial ids — rejected, Consequences, Context, Decision, Multi-tenant from day one — rejected

### Community 52 - "scanners/record.py"
Cohesion: 0.11
Nodes (17): container_fields(), scanner_image(), ScannerRunner, _open_cache_to_scanners(), refresh_argv(), refresh_trivy_db(), clean_tmp(), main() (+9 more)

### Community 53 - "Part 2: authorization findings (2026-10-29)"
Cohesion: 0.09
Nodes (22): A. Objective, A. Objective, B. Why, B. Why, C. Architecture, C. Architecture, E. Technical decisions, E. Technical decisions (+14 more)

### Community 54 - "test_callgraph.py"
Cohesion: 0.18
Nodes (20): load_symbols(), SymbolEntry, _classifier(), _l3(), _project(), test_a_call_through_another_module_function_is_l3(), test_a_direct_call_from_a_route_is_l3(), test_a_from_import_is_resolved() (+12 more)

### Community 55 - "images/record.py"
Cohesion: 0.11
Nodes (7): LabelRule, _kill_group(), _rlimits(), F-4-1: How should the evaluation count authorization findings?, main(), peak_bytes(), run_case()

### Community 56 - "trivy/parser.py"
Cohesion: 0.22
Nodes (16): trivy_severity(), clip(), count(), dependency_graph(), _dict(), ImagePackage, ImageReport, _list() (+8 more)

### Community 57 - "config.py"
Cohesion: 0.09
Nodes (20): build_canvas(), enqueue(), enqueue_kill(), _sig(), default_deps(), fetcher_image(), image_stage_time_limit_s(), analyze_task() (+12 more)

### Community 58 - "findings/service.py"
Cohesion: 0.11
Nodes (21): apply_history(), diff_scans(), previous_scan_id(), ScanDiff, Finding, FindingOccurrence, ScanFinding, _base_query() (+13 more)

### Community 59 - "ScanStatus"
Cohesion: 0.08
Nodes (44): ScannerRun, _classify(), clone(), collect(), finalize(), run_scanner(), reap(), ReapResult (+36 more)

### Community 60 - "RiskGraph — Master Blueprint (v0.1, 2026-09-19)"
Cohesion: 0.20
Nodes (9): 1. Executive summary, 28. Final demonstration workflow (what the examiner sees, ~12 minutes), 29. Project risks and mitigations, 2. Exact problem definition, 30. Definition of the final MVP, 3. Scope (what V1 delivers), 4. Non-goals (stated so nobody expects them), 5. Novelty and technical contribution (honest version) (+1 more)

### Community 61 - "20261022_1200_containers_sbom_assets.py"
Cohesion: 0.17
Nodes (9): upgrade(), downgrade(), _in_list(), _replace_check(), upgrade(), upgrade(), downgrade(), _source_check() (+1 more)

### Community 62 - "TS Node Config"
Cohesion: 0.20
Nodes (9): compilerOptions, module, moduleResolution, noEmit, skipLibCheck, strict, target, types (+1 more)

### Community 63 - "semgrep/parser.py"
Cohesion: 0.11
Nodes (20): cwe_ids(), sast_category(), normalize_path(), semgrep_severity(), _classes(), clean(), count(), _loc() (+12 more)

### Community 64 - "ADR-0001: Modular monolith with API and worker roles"
Cohesion: 0.22
Nodes (8): ADR-0001: Modular monolith with API and worker roles, Alternatives considered, Compliance, Consequences, Context, Decision, Services per pipeline stage — rejected, Single flat package (no module boundaries) — rejected

### Community 65 - "config.py"
Cohesion: 0.05
Nodes (32): _environment(), EvaluationError, _guard(), _report(), _reset_db(), create_app(), get_settings(), check_database() (+24 more)

### Community 66 - "taint.py"
Cohesion: 0.15
Nodes (21): build_rules(), Catalogue, CatalogueError, _ident(), _keys(), LanguageRules, load_catalogue(), _lookups() (+13 more)

### Community 67 - "components"
Cohesion: 0.22
Nodes (12): parse_nvd_cvss(), components(), count(), _ecosystem(), _location(), _text(), _nvd(), test_falls_back_to_v30_then_v40() (+4 more)

### Community 68 - "ContextResolver"
Cohesion: 0.17
Nodes (5): _clean_file(), ContextResolver, KubeContext, ServiceDecl, test_secret_in_public_repo_is_internet_exposed_without_manifest()

### Community 69 - "GraphFinding"
Cohesion: 0.15
Nodes (20): GraphFinding, manifests(), _aws_key(), mixed_findings(), _random_findings(), scenarios(), _sqli(), test_a_hypothesis_or_non_foothold_finding_never_takes_effective_impact() (+12 more)

### Community 70 - "_manifest"
Cohesion: 0.10
Nodes (36): analyze(), GraphInvariantError, invariant_violations(), _manifest(), test_control_only_paths_are_not_attacks(), test_effective_impact_uses_the_rest_of_the_chain(), test_kitchen_sink_manifest_is_valid_and_links_aws_keys(), test_no_manifest_means_no_paths_but_credentials_are_nodes() (+28 more)

### Community 71 - "Handoff (short summary)"
Cohesion: 0.33
Nodes (5): Before the next session, Commands, Handoff (short summary), State, Verified (at commit `943be49`)

### Community 72 - "typing"
Cohesion: 0.08
Nodes (16): downgrade(), upgrade(), upgrade(), _check(), downgrade(), upgrade(), upgrade(), AuditLog (+8 more)

### Community 73 - "test_runtime_eol_db.py"
Cohesion: 0.09
Nodes (18): no_lock(), criticals(), _ollama_up(), build(), _fake_private_key(), _drop(), api(), _reach() (+10 more)

### Community 74 - "test_topology_graph.py"
Cohesion: 0.23
Nodes (27): _code(), _compose_only(), _env_connections(), _image(), _kind(), _repo(), test_a_compose_database_is_an_assumed_sink_and_gives_an_inferred_path(), test_a_manifest_that_declares_services_still_wins_over_compose_databases() (+19 more)

### Community 75 - "iac.py"
Cohesion: 0.30
Nodes (9): _code_dir(), _compose(), _d(), _ingress_backends(), _k8s(), _l(), _labels(), _selects() (+1 more)

### Community 76 - "ADR-0004: Authentication and authorization model"
Cohesion: 0.25
Nodes (7): ADR-0004: Authentication and authorization model, Alternatives considered, Consequences, Context, Decision, GitHub OAuth — deferred (stretch), Server-side sessions — rejected

### Community 77 - "Scanner Installer"
Cohesion: 0.50
Nodes (4): fetch_verified(), install-scanners.sh script, UV_TOOL_BIN_DIR, UV_TOOL_DIR

### Community 78 - "extract"
Cohesion: 0.19
Nodes (11): _walk(), extract(), _js(), main(), _package_json(), _parsers(), _python(), _python_calls() (+3 more)

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
Cohesion: 0.15
Nodes (24): reportUrl(), Priority, RunStatus, ScanStatus, Severity, ScanDetailPage(), STAGES, ROLE (+16 more)

### Community 92 - "test_containers.py"
Cohesion: 0.13
Nodes (25): build_create_kwargs(), _check_env(), _checked_path(), ContainerSpecError, Limits, Mount, scanner_mounts(), _kwargs() (+17 more)

### Community 93 - "RiskGraph"
Cohesion: 0.25
Nodes (7): Context-aware scoring, Develop, Documentation, Quickstart, RiskGraph, Run without Docker, Triage, history and the CI gate

### Community 94 - "OllamaAdapter"
Cohesion: 0.15
Nodes (5): OllamaAdapter, test_real_model_explains_a_critical_finding_and_the_result_is_cached(), test_unreachable_model_falls_back_to_the_template(), test_ollama_over_a_unix_socket(), test_ollama_socket_that_is_missing_is_an_adapter_error()

### Community 95 - "pipeline.py"
Cohesion: 0.15
Nodes (24): IacResult, analyze(), _authz(), fail_scan(), _iac(), _image_entry(), _image_results(), _kev_cache() (+16 more)

### Community 96 - "Observed"
Cohesion: 0.16
Nodes (13): Observed, _build(), _ctx(), o(), _fields(), _reach(), test_context_free_score_is_a_function_of_vulnerability_data_only(), test_raising_any_factor_never_lowers_risk() (+5 more)

### Community 97 - "ADR-0008: Synchronous SQLAlchemy sessions"
Cohesion: 0.29
Nodes (6): ADR-0008: Synchronous SQLAlchemy sessions, Alternatives considered, Async SQLAlchemy (asyncpg) — rejected, Consequences, Context, Decision

### Community 98 - "Unattended run book (branch `extended_phase_auto`)"
Cohesion: 0.15
Nodes (12): 0. Start of every run, 1. Cloud environment (verified by a probe on 2026-10-25), 2.1 PLAN: before any code edit, 2.2 WORK, 2.3 TEST: before the day is closed, 2. The three stages, in this order, 3. Flags: what needs the owner, 4. Commits (this repository's `/commit` rules) (+4 more)

### Community 99 - "Severity"
Cohesion: 0.13
Nodes (20): os_eol_finding(), Severity, settings(), test_os_end_of_life_finding_shape(), test_trivy_covers_all_three_scanners(), _eol(), _raw(), test_a_tier1_flow_takes_e_from_the_taint_table() (+12 more)

### Community 100 - "modules/scanners/__init__.py"
Cohesion: 0.06
Nodes (11): Command, ParseContext, ScanPaths, CheckovScanner, GitleaksScanner, JoernScanner, drop_keys(), SyftScanner (+3 more)

### Community 101 - "sbom/service.py"
Cohesion: 0.17
Nodes (12): SbomComponent, attach_findings(), canonical_purl(), clear(), _ecosystem(), list_components(), PackageSeen, page_components() (+4 more)

### Community 102 - "parse_ref"
Cohesion: 0.16
Nodes (17): IacAsset, dockerfile_refs(), _dockerfiles(), _iac_refs(), image_refs(), ImageRef, _instructions(), parse_ref() (+9 more)

### Community 103 - "context/__init__.py"
Cohesion: 0.09
Nodes (25): CvssSubscores, _round1(), subscores(), _date(), _decimal(), _decimal_score(), EpssScore, fetch_epss() (+17 more)

### Community 104 - "scans/router.py"
Cohesion: 0.17
Nodes (11): cancel_scan(), create_scan(), download_report(), get_scan(), list_scans(), to_out(), RepositoryOut, ScanCreate (+3 more)

### Community 105 - "kitchen_sink.json"
Cohesion: 0.13
Nodes (14): bomFormat, bom-ref, name, type, components, metadata, component, timestamp (+6 more)

### Community 106 - "ExplanationDraft"
Cohesion: 0.21
Nodes (6): ExplanationDraft, explain(), _phrase(), _steps(), _texts(), _words()

### Community 107 - "ADR-0015: L3 reachability by intraprocedural call graph; NVD refreshed by Beat"
Cohesion: 0.29
Nodes (6): ADR-0015: L3 reachability by intraprocedural call graph; NVD refreshed by Beat, Consequences, Context, Decision, L3, NVD

### Community 108 - "test_taint_tier1.py"
Cohesion: 0.11
Nodes (24): SemgrepScanner, _hit(), _parsed(), _sample(), test_a_broken_catalogue_is_refused(), test_a_long_trace_is_capped_and_keeps_its_sink(), test_a_malformed_trace_gives_no_steps_and_no_error(), test_a_tier1_hit_alone_keeps_its_own_key() (+16 more)

### Community 109 - "modules/scanners/__init__.py"
Cohesion: 0.20
Nodes (10): derive_key(), mask(), scrub(), _scrub(), secret_hmac(), test_gitleaks_redaction_removes_every_raw_field(), test_hmac_is_keyed_and_deterministic(), test_mask_never_shows_short_secrets() (+2 more)

### Community 110 - "storage.py"
Cohesion: 0.34
Nodes (12): _image_path(), read_image_index(), read_image_report(), read_json_capped(), read_report(), report_path(), report_relpath(), ReportTooLargeError (+4 more)

### Community 111 - "Location"
Cohesion: 0.12
Nodes (19): Location, secret_family(), _build(), merge(), _overlap_clusters(), test_one_record_per_scanner_that_reported_it(), test_runtime_eol_evidence_is_dated_by_its_feed(), test_secrets_never_carry_the_secret() (+11 more)

### Community 112 - "risk/router.py"
Cohesion: 0.13
Nodes (11): RiskScore, ranked(), score_of(), _latest_scan(), list_risks(), risk_detail(), RiskDetailOut, RiskItemOut (+3 more)

### Community 114 - "devDependencies"
Cohesion: 0.17
Nodes (12): devDependencies, eslint, @eslint/js, eslint-plugin-react-hooks, @types/node, @types/react, @types/react-dom, typescript (+4 more)

### Community 115 - "A_high_cvss_unreachable/syft/1.54.1/report.json"
Cohesion: 0.13
Nodes (14): bomFormat, bom-ref, name, type, components, metadata, component, timestamp (+6 more)

### Community 116 - "routes.py"
Cohesion: 0.17
Nodes (27): _args(), _body(), _callee(), _decorator_name(), _depends_in(), _id_used(), _js_arg(), _js_call() (+19 more)

### Community 117 - "test_evidence.py"
Cohesion: 0.16
Nodes (14): FlowStep, min_assurance(), RawRef, Relationship, _ev(), test_a_relationship_needs_evidence(), test_assurance_orders_verified_over_inferred_over_hypothesis(), test_confidence_and_kind_are_validated() (+6 more)

### Community 118 - "explain/router.py"
Cohesion: 0.21
Nodes (7): create_explanation(), EvidenceRef, ExplanationOut, get_explanation(), _out(), ReasonOut, adapter_from_settings()

### Community 119 - "repositories/router.py"
Cohesion: 0.22
Nodes (7): get_repository(), list_repositories(), _point(), RepositoryDetail, RepositorySummary, _summary(), TrendPoint

### Community 121 - "B_moderate_reachable_exposed/syft/1.54.1/report.json"
Cohesion: 0.13
Nodes (14): bomFormat, bom-ref, name, type, components, metadata, component, timestamp (+6 more)

### Community 122 - "D_internal_limited/syft/1.54.1/report.json"
Cohesion: 0.13
Nodes (14): bomFormat, bom-ref, name, type, components, metadata, component, timestamp (+6 more)

### Community 123 - "re"
Cohesion: 0.09
Nodes (18): iac_family(), iac_topic(), IacFamily, normalize_check_id(), checkov_severity(), _blocks(), count(), _failed() (+10 more)

### Community 124 - "E_attack_path/syft/1.54.1/report.json"
Cohesion: 0.13
Nodes (14): bomFormat, bom-ref, name, type, components, metadata, component, timestamp (+6 more)

### Community 125 - "C_exposed_credential/syft/1.54.1/report.json"
Cohesion: 0.14
Nodes (13): bomFormat, bom-ref, name, type, metadata, component, timestamp, tools (+5 more)

### Community 126 - "test_risk_scenarios_v2.py"
Cohesion: 0.23
Nodes (13): _assured(), Case, _g_cases(), _g_repo(), _reach(), Run, _run(), test_f_ssrf_flow_reaches_the_admin_identity_and_the_metadata() (+5 more)

### Community 127 - "PHASE 11: Contextual risk engine (scenarios, properties, GET /risks)"
Cohesion: 0.29
Nodes (6): A. Objective, B. Built, M. Testing, Not done, O. Validation, PHASE 11: Contextual risk engine (scenarios, properties, GET /risks)

### Community 128 - "PHASE X2: runtime and image intelligence (expansion plan)"
Cohesion: 0.10
Nodes (20): A. Objective, B. Why, C. Architecture, C. Architecture (part 1), D. Components, E. Technical decisions, E. Technical decisions, G. Database (+12 more)

### Community 129 - "make_evidence"
Cohesion: 0.15
Nodes (10): Evidence, _fact(), _facts(), make_evidence(), declared(), ADR-0017: One evidence and assurance contract; no edge without evidence, Consequences, Context (+2 more)

### Community 131 - "callgraph.py"
Cohesion: 0.16
Nodes (10): _bfs(), chain_to(), enclosing_function(), find_l3(), Path3, _qualify(), reachable_functions(), _resolve() (+2 more)

### Community 132 - "20261023_0900_reachability_l3.py"
Cohesion: 0.83
Nodes (3): _check(), downgrade(), upgrade()

### Community 133 - "authz/service.py"
Cohesion: 0.13
Nodes (8): scan_manual_checks(), scan_routes(), ManualCheckOut, ManualChecksOut, RouteOut, RoutesOut, list_routes(), manual_checks()

### Community 134 - "PHASE 12: AI explanation (evidence-grounded, validated, cached)"
Cohesion: 0.15
Nodes (13): A. Objective, B. Why, C. Architecture, D. Components, E. Technical decisions, G. Database, H. API, L. Configuration (+5 more)

### Community 135 - "ReachabilityTier"
Cohesion: 0.49
Nodes (9): Verdict, ReachabilityTier, _evidence(), _sca(), test_a_scanner_match_is_verified_and_points_at_its_raw_report(), test_no_reachability_evidence_when_there_is_no_claim(), test_odd_verdict_evidence_is_dropped_not_fatal(), test_reachability_evidence_follows_the_tier() (+1 more)

### Community 136 - "EvidencePack"
Cohesion: 0.21
Nodes (4): EvidencePack, norm(), spellings(), user_message()

### Community 137 - "test_image_scan_db.py"
Cohesion: 0.12
Nodes (21): RunResult, session_scope(), FixtureRunner, api(), _build(), _image_findings(), _scan(), _summary() (+13 more)

### Community 138 - "TODO (saved 2026-10-25, session 7; updated 2026-10-31, auto day 6): where work stopped and what is next"
Cohesion: 0.15
Nodes (12): Done (auto day 1, 2026-10-26, branch `extended_phase_auto`): X2 part 2 and X3 part 1, Done (auto day 2, 2026-10-27, branch `extended_phase_auto`): X3 part 2 and X4 part 1, Done (auto day 3, 2026-10-28, branch `extended_phase_auto`): tier-1 hardening and X5 part 1, Done (auto day 4, 2026-10-29, branch `extended_phase_auto`): X5 part 2, Done (auto day 5, 2026-10-30, branch `extended_phase_auto`): X6 risk v2, Done (auto day 6, 2026-10-31, branch `extended_phase_auto`): integration pass, Done: expansion phase X0 (baseline dataset and metrics), Done: expansion phase X1 (evidence and assurance contracts) (+4 more)

### Community 139 - "Work done — session 1 (2026-09-19)"
Cohesion: 0.22
Nodes (9): 1. Orientation, 2. Blueprint (`docs/blueprint/`, 9 files, ~18.8k words), 3. Phase 0 (docs), 4. Phase 1 (code) — see `docs/phases/PHASE_01.md` for the full chapter, 5. Commit, 6. After the commit (uncommitted at time of writing), Problems hit and fixed during Phase 1, Verified results (+1 more)

### Community 140 - "ADR-0025: Tier-2 taint with Joern, in an opt-in `deep` scan profile"
Cohesion: 0.29
Nodes (6): ADR-0025: Tier-2 taint with Joern, in an opt-in `deep` scan profile, Consequences, Context, Decision, Numbers (measured 2026-11-05, Joern 4.0.671, the adapter's exact command, ADR-0014 profile), Rejected

### Community 142 - "guards.py"
Cohesion: 0.15
Nodes (6): CatalogueError, Framework, GuardEntry, parse(), _strs(), D. Components

### Community 143 - "test_taint_suite.py"
Cohesion: 0.12
Nodes (20): Case, cases(), _javascript(), main(), _python(), render(), Score, score() (+12 more)

### Community 144 - "test_reachability.py"
Cohesion: 0.18
Nodes (17): import_names(), python_import_names(), used_without_import(), _classifier(), extracted(), test_extractor_runs_isolated_through_the_runner(), test_hostile_inputs_do_not_break_extraction(), test_indirect_dependencies_inherit_from_direct_parents() (+9 more)

### Community 145 - "RiskGraph — Data, API, Frontend, CI/CD (sections 16–19)"
Cohesion: 0.18
Nodes (10): 17.1 Cross-cutting, 17.2 Endpoints (V1), 17.3 Representative schemas, 17. API architecture, 18. Frontend architecture, 19.1 Two integration paths, 19.2 Policy (from `riskgraph.yaml` `policy:` or repository settings; action input overrides), 19.3 RiskGraph's own CI (`.github/workflows/ci.yml`) (+2 more)

### Community 146 - "RiskGraph baseline (expansion phase X0)"
Cohesion: 0.29
Nodes (6): Dataset, Per scenario, Pooled ranking (primary), Reading these numbers, RiskGraph baseline (expansion phase X0), Top 10 of the pooled ranking

### Community 147 - "test_authz_analysis.py"
Cohesion: 0.12
Nodes (26): AuthzRule, _route(), _rules(), test_a_guarded_read_and_an_unguarded_write_is_inconsistent_even_as_a_pair(), test_a_minority_of_guarded_siblings_is_not_inconsistent(), test_a_policy_rule_still_applies_to_a_declared_public_route(), test_a_public_list_next_to_a_guarded_detail_read_is_inconsistent(), test_a_public_list_next_to_guarded_writes_is_not_inconsistent() (+18 more)

### Community 148 - "Evaluation run book (X8)"
Cohesion: 0.20
Nodes (9): A: taint, B: authorization, Deep profile on the full stack (UNVERIFIED), Evaluation run book (X8), P1: prioritization, Re-recording the inputs, Rules (from §6 and the blueprint), What exists today (generated 2026-11-05) (+1 more)

### Community 149 - "analysis.py"
Cohesion: 0.11
Nodes (20): analyze(), AuthzIssue, AuthzResult, _bola(), _inconsistent(), _names(), _policy(), resource() (+12 more)

### Community 150 - "Schedule: X2 part 2, X3, X4, X5, X6 over six days"
Cohesion: 0.17
Nodes (11): Day 1 — Mon 26 Oct: X2 part 2 + X3 part 1, Day 2 — Tue 27 Oct: X3 part 2 + X4 part 1, Day 3 — Wed 28 Oct: X4 part 2 (Joern), Day 4 — Thu 29 Oct: X5 part 1 (route inventory and guards), Day 5 — Fri 30 Oct: X5 part 2 (authorization findings), Day 6 — Sat 31 Oct: X6 (risk v2) + integration, Schedule: X2 part 2, X3, X4, X5, X6 over six days, X2 part 2: scan the images the repository names (+3 more)

### Community 151 - "RiskGraph — Architecture (sections 6–15)"
Cohesion: 0.10
Nodes (18): 10.1 Canonical model, 10.2 Fingerprinting (dedup within and across scans), 10.3 Severity mapping, 10. Finding normalization architecture, 11.1 Manifest schema (`riskgraph.yaml`, v1), 11.2 Factors produced (all with `source` and `confidence`), 11.3 Reachability tiers (the honest design), 11. Context enrichment architecture (+10 more)

### Community 152 - "test_authz_inventory.py"
Cohesion: 0.14
Nodes (26): summary(), _at(), _inventory(), _route_doc(), test_a_broken_catalogue_is_refused(), test_a_call_that_passes_no_receiver_binds_nothing(), test_a_mount_cycle_ends(), test_a_repository_inferred_framework_gives_inferred_route_evidence() (+18 more)

### Community 153 - "HANDOFF: resume here (updated 2026-11-03, session 9 local: L-2…L-9 run, nine flags answered, F-1-1 built; remaining work below)"
Cohesion: 0.08
Nodes (25): Auto session day 1 (2026-10-26, cloud, branch `extended_phase_auto`), Auto session day 2 (2026-10-27, cloud, branch `extended_phase_auto`), Auto session day 3 (2026-10-28, cloud, branch `extended_phase_auto`), Auto session day 4 (2026-10-29, cloud, branch `extended_phase_auto`), Auto session day 5 (2026-10-30, cloud, branch `extended_phase_auto`), Auto session day 6 (2026-10-31, cloud, branch `extended_phase_auto`), Commands that are known to work, Gotchas already hit (so you don't hit them again) (+17 more)

### Community 154 - "PHASE 10: Attack-path engine (scenario E, performance budget)"
Cohesion: 0.29
Nodes (6): A. Objective, B. Defect found and fixed, M. Testing, Not done, O. Validation, PHASE 10: Attack-path engine (scenario E, performance budget)

### Community 155 - "attack.py"
Cohesion: 0.09
Nodes (23): edge(), exploit_edge(), node(), stated(), Assured, assured_alternative(), _authz_edges(), _derive() (+15 more)

### Community 156 - "ADR-0012: Reachability tiers L0–L2 in the MVP (import graph, no call graph)"
Cohesion: 0.33
Nodes (5): ADR-0012: Reachability tiers L0–L2 in the MVP (import graph, no call graph), Alternatives considered, Consequences, Context, Decision

### Community 157 - "ADR-0011: Context-aware scoring from the repository manifest (MVP level 2)"
Cohesion: 0.24
Nodes (10): ADR-0011: Context-aware scoring from the repository manifest (MVP level 2), Alternatives considered, Consequences, Context, Decision, riskgraph.yaml v1 manifest example, Manifest criticality, Manifest data_stores (kind, sensitivity) (+2 more)

### Community 158 - "readyz"
Cohesion: 0.15
Nodes (6): Health, healthz(), Readiness, readyz(), check_redis(), get_redis()

### Community 159 - "Joern spike (X4.0)"
Cohesion: 0.25
Nodes (7): Fixtures, Joern spike (X4.0), Limits and honest caveats, Numbers, Reproduce, What the adapter (X4 part 2) can now build on, What was run

### Community 160 - "PHASE MVP — Scan, normalize, merge, prioritize (vertical slice)"
Cohesion: 0.10
Nodes (21): order(), test_issues_become_authz_findings_anchored_on_the_route_not_the_line(), findings(), G. Database, A. Objective, B. Why, C. Architecture, D. Components (+13 more)

### Community 161 - "topology.py"
Cohesion: 0.16
Nodes (12): _canonical(), _compose_services(), Declared, _default_dockerfile(), derive(), DerivedService, _dockerfile_base(), ServiceImage (+4 more)

### Community 162 - "AttackAnalysis"
Cohesion: 0.08
Nodes (14): _Resolver, assured_view(), AttackAnalysis, _EdgeRow, _k_best(), _NodeRow, _path(), PathResult (+6 more)

### Community 163 - "ADR-0018: Runtime and image intelligence: EOL from a stored feed, image scans behind an allow-list"
Cohesion: 0.33
Nodes (5): ADR-0018: Runtime and image intelligence: EOL from a stored feed, image scans behind an allow-list, Consequences, Context, Decision, Rejected

### Community 164 - "problems.py"
Cohesion: 0.14
Nodes (9): Forbidden, Problem, problem_response(), register_problem_handlers(), _http(), _problem(), _unhandled(), _validation() (+1 more)

### Community 165 - "RiskGraph — AI session entry point"
Cohesion: 0.25
Nodes (7): Commands, Conventions, Dependencies, graphify (optional), How to work here, Read first, RiskGraph: AI session entry point

### Community 166 - "PHASE X3: the assured graph (expansion plan)"
Cohesion: 0.11
Nodes (18): A. Objective, B. Why, C. Architecture (part 1), C. Architecture (part 2), Deviations from the plan, flagged, E. Technical decisions, E. Technical decisions (part 2), G. Database (+10 more)

### Community 167 - "PHASE X1: evidence and assurance contracts (expansion plan)"
Cohesion: 0.17
Nodes (11): A. Objective, B. Why, C. Architecture, Deviations and notes, E. Technical decisions, G. Database, H. API, L. Configuration (+3 more)

### Community 168 - "test_route_extract.py"
Cohesion: 0.32
Nodes (14): _http(), _route(), test_a_huge_handler_body_is_cut_off_and_still_described(), test_express_handler_bodies_inline_named_and_unknown(), test_express_routes_chains_uses_bindings_and_exports(), test_fastapi_dependencies_in_every_place(), test_fastapi_ownership_through_a_dependency_and_an_attribute_named_like_the_id(), test_files_without_routes_have_no_http_key() (+6 more)

### Community 169 - "json"
Cohesion: 0.17
Nodes (8): _cves(), _freeze_intel(), record(), _target(), _seed_intel(), _report(), test_each_image_report_has_os_and_language_results(), test_fixed_versions_and_the_end_of_support_flag_are_covered()

### Community 170 - "PHASE 7: Context enrichment (NVD, EPSS, KEV, manifest, Kubernetes and Compose)"
Cohesion: 0.29
Nodes (6): Built, Not done, PHASE 7: Context enrichment (NVD, EPSS, KEV, manifest, Kubernetes and Compose), Session 7 additions (2026-10-25), Verification, Verification (session 7)

### Community 171 - "report.py"
Cohesion: 0.09
Nodes (22): rank(), ndcg(), average_precision(), bootstrap(), _dcg(), effort_at(), Estimate, ndcg_at() (+14 more)

### Community 172 - "extract"
Cohesion: 0.26
Nodes (17): extract(), kubernetes_context(), _rel(), ManifestResult, _repo(), test_alias_bombs_are_refused_before_parsing(), test_compose_build_context_cannot_escape_the_repository(), test_compose_exposure_reaches_findings_under_its_build_context() (+9 more)

### Community 173 - "Day 3 report (Wed 2026-10-28): X4 part 2 gated; tier-1 hardening and X5 part 1"
Cohesion: 0.15
Nodes (11): Day 3 report (Wed 2026-10-28): X4 part 2 gated; tier-1 hardening and X5 part 1, Evaluation (X0), For Day 4 (Thu 29 Oct), New flags and local tasks, Per plan step, Precondition check (VERIFIED), Self-attack, Test output (run after the last code commit, `4aed1eb`) (+3 more)

### Community 174 - "PHASE X4: deep code analysis (expansion plan)"
Cohesion: 0.18
Nodes (10): B. Why, C. Architecture, E. Technical decisions, G. Database, H. API, L. Configuration, M. Testing, O. Validation (+2 more)

### Community 175 - "PHASE 0 — Project Definition & Threat Model"
Cohesion: 0.13
Nodes (15): A. Objective, B. Why, C. Architecture, D. Components, E. Technical decisions, F. Folder structure, G. Database · H. API · I. Algorithms · J. Implementation · K. Commands · L. Configuration, M. Testing (+7 more)

### Community 176 - "report.py"
Cohesion: 0.18
Nodes (11): _cell(), findings_csv(), _fmt(), _labels(), main(), render(), _statistic(), _versions() (+3 more)

### Community 177 - "field_validator"
Cohesion: 0.07
Nodes (12): DataStoreDecl, IdentityDecl, Manifest, normalize_service_path(), route_matches(), _route_pattern(), SecretLink, _segments() (+4 more)

### Community 179 - "test_authz_findings_suite.py"
Cohesion: 0.28
Nodes (9): _labels(), _run(), _score(), test_declared_public_routes_lift_unguarded_sensitive_precision(), test_every_route_of_the_suite_is_labelled_and_found(), test_inconsistency_precision_meets_the_target(), test_no_bola_finding_is_more_than_a_low_hypothesis(), test_policy_and_bola_match_the_labels() (+1 more)

### Community 180 - "db"
Cohesion: 0.11
Nodes (15): db(), Adding a scanner (the Joern adapter is the latest worked example), Commits and branches, Contributing to RiskGraph, Decisions and docs, Evaluation, Never (a change that breaks one of these is not mergeable), Shape of the code (+7 more)

### Community 181 - "Day 6 plan (Sat 2026-10-31): integration pass"
Cohesion: 0.20
Nodes (9): Acceptance, Cross-phase breakage found while reading (before any edit), Day 6 plan (Sat 2026-10-31): integration pass, Out of scope today, Risks and decisions, Start state (before any edit), Steps, The task (+1 more)

### Community 182 - "finding_evidence"
Cohesion: 0.36
Nodes (5): finding_evidence(), _match(), _parse_time(), _plain(), _reachability()

### Community 183 - "Day 4 report (Thu 2026-10-29): X5 part 2, authorization findings"
Cohesion: 0.22
Nodes (8): Day 4 report (Thu 2026-10-29): X5 part 2, authorization findings, Evaluation (X0), three runs, For Day 5 (Fri 30 Oct), New flags and local tasks, Per plan step, Self-attack, Test output (after the last code commit, `8996a79`), UNVERIFIED (needs the owner's machine)

### Community 184 - "Day 6 report (Sat 2026-10-31): integration pass"
Cohesion: 0.22
Nodes (8): Day 6 report (Sat 2026-10-31): integration pass, Evaluation (X0), New flags and local tasks, Note on commit identity, Per plan step, Self-attack, Test output (after the last code commit, `43842f1`), UNVERIFIED (needs the owner's machine)

### Community 185 - "Part 3 (2026-11-05): the Joern adapter (F-3-1 answered (a), ADR-0025)"
Cohesion: 0.12
Nodes (13): refresh_trivy_db_task(), redis_scanner_lock(), A. Objective, C. Architecture, D. Components, E. Technical decisions, G. Database, H. API (+5 more)

### Community 186 - "ADR-0023: Authorization findings, the manifest `authz:` section, an interim score, and non-traversable authz edges"
Cohesion: 0.33
Nodes (5): ADR-0023: Authorization findings, the manifest `authz:` section, an interim score, and non-traversable authz edges, Consequences, Context, Decision, Rejected

### Community 187 - "20261105_0900_joern_scanner.py"
Cohesion: 0.83
Nodes (3): _check(), downgrade(), upgrade()

### Community 188 - "Day 1 plan (Mon 2026-10-26): X2 part 2 + X3 part 1"
Cohesion: 0.29
Nodes (6): Close, Day 1 plan (Mon 2026-10-26): X2 part 2 + X3 part 1, Read, Risks and decisions, X2 part 2: scan the images the repository names, X3 part 1: a graph without a manifest

### Community 189 - "generate.py"
Cohesion: 0.16
Nodes (7): AdapterError, LlmAdapter, json_schema(), generate(), Outcome, _parse(), test_an_unavailable_model_falls_back_without_retrying()

### Community 191 - "ADR-0021: Tier-1 taint rules from one RiskGraph catalogue; the taint evidence contract"
Cohesion: 0.33
Nodes (5): ADR-0021: Tier-1 taint rules from one RiskGraph catalogue; the taint evidence contract, Consequences, Context, Decision, Rejected

### Community 192 - "Day 2 report (Tue 2026-10-27): X3 part 2 + X4 part 1"
Cohesion: 0.13
Nodes (16): taint_family(), _is_taint(), _join_taint_hits(), join(), taint_only(), _span_end(), Day 2 report (Tue 2026-10-27): X3 part 2 + X4 part 1, Evaluation (X0) (+8 more)

### Community 194 - "PHASE 8: Reachability (L0–L3)"
Cohesion: 0.33
Nodes (5): Built, Not done (out of the blueprint's P8 scope), PHASE 8: Reachability (L0–L3), Verification, Verification (session 7)

### Community 199 - "scan_images"
Cohesion: 0.10
Nodes (17): image_stage_budget_s(), scan_images(), Day 1 report (Mon 2026-10-26): X2 part 2 + X3 part 1, Evaluation (X0), For Day 2, New flags and local tasks, Per plan step, Self-attack (+9 more)

### Community 202 - "Files read and nearest analogs"
Cohesion: 0.29
Nodes (6): Acceptance (plan X5 row, §3.B, §6; SCHEDULE day 5), Day 4 plan (Thu 2026-10-29): X5 part 2, authorization findings, Files read and nearest analogs, Out of scope today, Risks and decisions, The task

### Community 204 - "ADR-0016: Evidence-grounded explanations with a local model and a template fallback"
Cohesion: 0.33
Nodes (5): ADR-0016: Evidence-grounded explanations with a local model and a template fallback, Alternatives considered, Consequences, Context, Decision

### Community 205 - "DockerRunner"
Cohesion: 0.11
Nodes (16): DockerRunner, make_removable(), build_runner(), discard_workspace(), widen_own_directories(), Decision, 9.1 Job model and state machines, 9.2 Celery canvas (+8 more)

### Community 210 - "risk/service.py"
Cohesion: 0.11
Nodes (14): fill_unknown(), MergedFinding, EffectiveImpact, ScoreResult, _eol_age(), input_for(), persist_score(), rescore() (+6 more)

### Community 213 - "test_authz_suite.py"
Cohesion: 0.42
Nodes (6): _found(), test_guard_status_and_parameters_match_the_labels(), test_no_route_is_ever_called_unguarded_without_a_resolved_mount(), test_route_inventory_recall_on_the_labelled_suite(), test_the_class_based_view_is_found_without_a_handler_name(), _write()

### Community 214 - "RiskGraph — Project Specification (Phase 0, v1.0, 2026-09-19)"
Cohesion: 0.20
Nodes (7): 1. Problem statement, 2. Scope, 3. Assumptions, 4. Research question, 5. Success criteria (project level), 6. Architecture principles, RiskGraph — Project Specification (Phase 0, v1.0, 2026-09-19)

### Community 215 - "Day 2 plan (Tue 2026-10-27): X3 part 2 + X4 part 1"
Cohesion: 0.22
Nodes (8): edges(), Close, Day 2 plan (Tue 2026-10-27): X3 part 2 + X4 part 1, Found while reading (it decides step 3), Read, Risks and decisions, X3 part 2: assurance-aware paths, X4 part 1: tier-1 taint rules and the evidence contract

### Community 222 - "graph.py"
Cohesion: 0.24
Nodes (7): build(), python_module_index(), _python_module_index(), _python_roots(), _resolve_js(), _resolve_python(), _scope()

### Community 225 - "RiskGraph — Phase Dependency Graph and Roadmap (sections 23–24)"
Cohesion: 0.50
Nodes (3): 23. Phase dependency graph, 24. Detailed roadmap (37 working weeks ≈ 8.5 months, plus 3 weeks buffer), RiskGraph — Phase Dependency Graph and Roadmap (sections 23–24)

### Community 236 - "sbom/router.py"
Cohesion: 0.19
Nodes (3): ComponentOut, SbomOut, scan_sbom()

### Community 237 - "gitleaks/parser.py"
Cohesion: 0.33
Nodes (4): gitleaks_severity(), count(), _items(), parse()

### Community 238 - "Entries"
Cohesion: 0.22
Nodes (8): Entries, F-1-1: Data stores from Compose (which images, which sensitivity), F-1-2: CAN_ACCESS from RBAC bindings has no target, F-2-1: Turn the tier-1 taint rules on by default?, F-3-1: Joern spike not run, so no Joern adapter, F-L-2: The explanation prompt does not validate on real findings, Flags: things that need the owner, Template

### Community 239 - "ADR-0019: A graph from Compose and Kubernetes when the manifest declares no services"
Cohesion: 0.33
Nodes (5): ADR-0019: A graph from Compose and Kubernetes when the manifest declares no services, Consequences, Context, Decision, Rejected

### Community 240 - "RiskGraph — Threat Model (living document; v0.1 from blueprint 03, 2026-09-19)"
Cohesion: 0.25
Nodes (8): Actors, Assets (what we protect), Attack surfaces, MVP level 2 extended note (2026-10-22), MVP level 2 note (2026-10-21): manifest context, MVP note (2026-10-21), RiskGraph — Threat Model (living document; v0.1 from blueprint 03, 2026-09-19), Security invariants (tested in Phase 15/16)

### Community 245 - ".http"
Cohesion: 0.40
Nodes (4): ADR-0022: Route inventory and guard detection; stored as evidence; honest guard status, Consequences, Context, Rejected

### Community 246 - "uuid7.py"
Cohesion: 0.39
Nodes (3): uuid7(), test_uuid7_is_time_ordered_and_unique(), test_uuid7_version_and_variant()

### Community 248 - "test_environment.py"
Cohesion: 0.46
Nodes (7): _resolver(), test_data_sensitivity_stops_after_two_hops(), test_data_sensitivity_two_hops_prefers_most_sensitive(), test_exposure_labels(), test_longest_path_prefix_wins(), test_secret_keeps_service_impact_context(), test_summary_counts_findings_per_service()

### Community 249 - "Day 3 plan (Wed 2026-10-28): X4 part 2 is gated, so tier-1 hardening and X5 part 1 early"
Cohesion: 0.29
Nodes (6): Acceptance (from the plan's X5 row and SCHEDULE day 4), Day 3 plan (Wed 2026-10-28): X4 part 2 is gated, so tier-1 hardening and X5 part 1 early, Out of scope today, Risks and decisions, Steps (each with the test that proves it), The task

### Community 250 - "worker.py"
Cohesion: 0.19
Nodes (4): _bind_task_context(), _clear_task_context(), _configure_worker_logging(), ping()

### Community 251 - "ADR-0009: MVP runs scanners as subprocesses in the worker"
Cohesion: 0.29
Nodes (6): ADR-0009: MVP runs scanners as subprocesses in the worker, Alternatives considered, Blueprint DockerRunner now (§9.3): deferred, bubblewrap / `unshare --net` around each subprocess: deferred, Consequences, Context

### Community 252 - "Authorization evaluation (scenario I, F-4-1)"
Cohesion: 0.33
Nodes (5): Authorization evaluation (scenario I, F-4-1), Detection: (route, rule) pairs against the expected issues, Findings, by RiskGraph score, Prioritization: routes by their best finding, against the routes to fix first, Reading it

### Community 253 - "PHASE X6: risk v2 (expansion plan)"
Cohesion: 0.15
Nodes (12): A. Objective, B. Why, C. Architecture, E. Technical decisions, G. Database, H. API, L. Configuration, M. Testing (+4 more)

### Community 254 - "14. Risk-engine architecture"
Cohesion: 0.25
Nodes (8): 14.1 Model comparison, 14.2 Definitions, 14.3 Reduction to a context-free model (the property that makes the model defensible), 14.4 Attack-path coupling ("effective impact"), 14.5 Rule overrides (explainable, listed in output as `overrides[]`), 14.6 Worked examples (scenarios A–E from the brief), 14.7 Sensitivity, calibration, limitations, 14. Risk-engine architecture

### Community 255 - "PHASE 4: Scanner adapters (five hardened images)"
Cohesion: 0.29
Nodes (6): Built, Decisions, Known differences from the host-run MVP, Not done, Objective, PHASE 4: Scanner adapters (five hardened images)

### Community 256 - "26. Research evaluation methodology"
Cohesion: 0.17
Nodes (11): 25.1 Layers and markers, 25.2 Test datasets (`datasets/`), 25. Testing strategy, 26.1 Question and hypotheses, 26.2 Methods compared, 26.3 Ground truth, 26.4 Metrics, 26.5 Statistics (+3 more)

### Community 257 - "test_health.py"
Cohesion: 0.25
Nodes (5): test_healthz_reports_version(), test_readyz_ok_with_real_services(), test_readyz_reports_503_when_dependencies_down(), test_request_id_is_echoed_or_generated(), test_unknown_route_is_problem_json()

### Community 258 - "context/router.py"
Cohesion: 0.33
Nodes (3): AssetOut, ContextOut, repository_context()

### Community 259 - "images/record.py"
Cohesion: 0.31
Nodes (4): _docker(), record(), slug(), _trim_trivy()

### Community 260 - "Day 5 report (Fri 2026-10-30): X6, risk v2"
Cohesion: 0.22
Nodes (8): Day 5 report (Fri 2026-10-30): X6, risk v2, Evaluation (X0), For Day 6 (Sat 31 Oct), New flags and local tasks, Per plan step, Self-attack, Test output (after the last code commit, `c6e0649`), UNVERIFIED (needs the owner's machine)

### Community 261 - "Day 5 plan (Fri 2026-10-30): X6, risk v2"
Cohesion: 0.25
Nodes (7): Acceptance (plan X6 row, §6; SCHEDULE day 6), Day 5 plan (Fri 2026-10-30): X6, risk v2, Labels for F–H (written before any scoring run; not changed afterwards), Out of scope today, Risks and decisions, Steps, The task

### Community 262 - "Where RiskGraph stands (handover, 2026-11-05)"
Cohesion: 0.25
Nodes (7): Done in the handover session (2026-11-05), Evaluation today (`docs/evaluation/EVALUATION_EXPANSION.md`), Machine notes (the previous owner's machine; yours will differ), Owner items (decide; not engineering tasks), Verified at handover, What is built, Where RiskGraph stands (handover, 2026-11-05)

### Community 263 - "Backlog (handover, 2026-11-05)"
Cohesion: 0.29
Nodes (6): 1. Before any deployment beyond localhost, 2. Finish the expansion, 3. Follow-ups from earlier phases, 4. New scope for collaborators (added at handover), Backlog (handover, 2026-11-05), Done in the handover session (for reference)

### Community 264 - "16. Database architecture"
Cohesion: 0.33
Nodes (6): 16.1 Principles, 16.2 ER diagram (V1), 16.3 Table definitions (V1), 16.4 Deferred from the brief (and why), 16.5 Growth and retention, 16. Database architecture

### Community 265 - "What was built"
Cohesion: 0.33
Nodes (5): Problems hit and fixed, What was built, What was built, Work done: session 2 (2026-10-21): MVP vertical slice, Work done: session 4 (2026-10-22): MVP level 2 extended

### Community 266 - "PHASE 5: Normalization, correlation and SBOM"
Cohesion: 0.40
Nodes (4): Not done, Objective, PHASE 5: Normalization, correlation and SBOM, Verification

### Community 267 - "ADR-0014: Scanners run as hardened containers (DockerRunner), with pinned images"
Cohesion: 0.50
Nodes (3): ADR-0014: Scanners run as hardened containers (DockerRunner), with pinned images, Consequences, Context

## Knowledge Gaps
- **14 isolated node(s):** `Manifest criticality`, `Pre-commit config (pre-commit-hooks, ruff, gitleaks)`, `postgres service (16-alpine)`, `redis service (7-alpine, password)`, `Frontend index.html (mounts /src/main.tsx)` (+9 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 1630 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **54 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `AdapterError` connect `generate.py` to `test_explain.py`, `PHASE 12: AI explanation (evidence-grounded, validated, cached)`, `OllamaAdapter`?**
  _High betweenness centrality (0.080) - this node is a cross-community bridge._
- **Are the 122 inferred relationships involving `Settings` (e.g. with `_environment()` and `_guard()`) actually correct?**
  _`Settings` has 122 INFERRED edges - model-reasoned connections that need verification._
- **What connects `Manifest criticality`, `Pre-commit config (pre-commit-hooks, ruff, gitleaks)`, `postgres service (16-alpine)` to the rest of the system?**
  _14 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `ScanWorkspace` be split into smaller, more focused modules?**
  _Cohesion score 0.0780399274047187 - nodes in this community are weakly interconnected._
- **Why does `M. Testing` connect `PHASE 12: AI explanation (evidence-grounded, validated, cached)` to `generate.py`?**
  _High betweenness centrality (0.080) - this node is a cross-community bridge._
- **Are the 121 inferred relationships involving `SourceType` (e.g. with `issue_findings()` and `manual_checks()`) actually correct?**
  _`SourceType` has 121 INFERRED edges - model-reasoned connections that need verification._
- **Should `RiskGraph expansion A–D: architecture decision and phased plan` be split into smaller, more focused modules?**
  _Cohesion score 0.09523809523809523 - nodes in this community are weakly interconnected._