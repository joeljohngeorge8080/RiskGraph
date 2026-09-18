# RiskGraph — Phase Dependency Graph and Roadmap (sections 23–24)

## 23. Phase dependency graph

The brief's 20 phases are kept (numbering preserved so "START PHASE N" is
unambiguous) with three structural corrections:

1. **Auth skeleton moves early.** Phase 2 ships users/roles/JWT/API keys in
   their minimal form; Phase 15 hardens. Shipping 14 phases of an
   unauthenticated security product and bolting auth on last is how
   authorization checks get forgotten in service code.
2. **Phase 6 (SBOM) is folded into Phase 5.** Syft is one more adapter and one
   `components` table; a separate phase is ceremony.
3. **Phase 16 (testing) is continuous.** Every phase has a Testing chapter;
   Phase 16 becomes a one-week consolidation + security validation sprint.

```
 P0 Definition & threat model
  │
 P1 Dev environment ─────────────────────────────────────────────┐
  │                                                              │
 P2 Domain model + DB + auth skeleton                            │
  │                                                              │
 P3 Orchestration engine (runner, canvas, states, isolation)     │
  │                                                              │
 P4 Scanner adapters ×5 (trivy, semgrep, gitleaks, checkov, syft)│
  │                                                              │
 P5 Normalization + correlation + SBOM (absorbs P6)              │
  │            ╲                                                 │
  │             ╲                                                │
 P7 Context enrichment (NVD/EPSS/KEV, manifest, K8s/Compose)     │
  │            ╲                                                 │
 P8 Reachability (L0/L1 both langs → L2/L3 Python)               │
  │                                                              │
 P9 Security graph (builder, loader, queries)                    │
  │                                                              │
 P10 Attack paths ──────┐                                        │
  │                     │                                        │
 P11 Risk engine ◀──────┘  (needs paths for effective impact)    │
  │        ╲                                                     │
  │         ╲───────▶ P12 AI explanation (needs risk factors)    │
  │                                                              │
 P13 Dashboard  (needs a frozen API from P2–P12)                 │
  │                                                              │
 P14 GitHub Action + webhook + policy (needs risk + scans API)   │
  │                                                              │
 P15 Auth hardening + security controls verification ◀──── P0 threat model
  │
 P16 Test consolidation + security validation
  │
 P17 Research evaluation (needs P11 + datasets from P4/P8)
  │
 P18 Deployment (Compose prod, Caddy, backups, optional EC2) ◀── P1
  │
 P19 Documentation, thesis, presentation, demo script
```

Critical path: P0→P1→P2→P3→P4→P5→P7→P8→P9→P10→P11→P13→P17→P19.
P12, P14, P15, P18 can each interleave with the dashboard when a
context-switch is welcome.

## 24. Detailed roadmap (37 working weeks ≈ 8.5 months, plus 3 weeks buffer)

| Phase | Name | Weeks | MVP? | Working increment (Definition of Done headline) | Key deliverables |
|---|---|---|---|---|---|
| 0 | Project definition & threat model | 1 | ✅ | `docs/` has spec, threat model, 6 ADRs, success criteria; nothing to run | `PROJECT_SPEC.md`, `THREAT_MODEL.md`, `adr/0001–0006`, research question + metrics fixed |
| 1 | Repository & dev environment | 1 | ✅ | `make dev` starts postgres, redis, api, worker, beat, frontend; `GET /healthz` and `/readyz` green; CI runs lint + unit tests | Compose, uv project, ruff/mypy, pre-commit, structlog, Settings, frontend skeleton, CI workflow |
| 2 | Domain model, DB, auth skeleton | 2 | ✅ | Alembic migrations create all V1 tables; `POST /auth/login` works; RBAC dependency exists; repositories CRUD | ERD, models, migrations, users/roles/JWT/API keys (minimal), repositories module |
| 3 | Scanner orchestration engine | 2 | ✅ | `POST /scans` → clone in fetcher container → a dummy scanner container runs under the full isolation profile → state machine reaches COMPLETED; cancel works; partial failure handled | DockerRunner, container_spec, socket proxy, canvas, states, timeouts, retries, slot semaphore, reaper |
| 4 | Scanner adapters | 3 | ✅ | All five scanners run on the kitchen-sink dataset and produce parsed RawFindings; fixtures recorded per version | 5 hardened images, adapters, parsers, fixture tests, secret redaction in Gitleaks parser |
| 5 | Normalization, correlation, SBOM | 2 | ✅ | `GET /findings` returns canonical findings; re-scanning the same commit creates zero new findings; Trivy CVEs attach to Syft components; fixed-detection works | fingerprints, severity mapping, dedup, correlation, components table, `GET /sbom` |
| 6 | (merged into 5) | 0 | — | — | — |
| 7 | Context enrichment | 2 | ✅ | Findings carry CVSS/EPSS/KEV; manifest parsed with provenance; K8s + Compose extraction produce assets; Terraform extraction (stretch) | NVD/EPSS/KEV clients + Beat refresh, manifest schema, extractors, `GET /repositories/{id}/context` |
| 8 | Reachability engine | 3 | ✅ (L0–L1 both languages, L2–L3 Python) | Each SCA/SAST finding has a tier with evidence and confidence; blind-spot tests document what is *not* detected | tree-sitter parsers, import graph, entry points, Python call graph, vulnerable_symbols.yaml, subprocess sandboxing |
| 9 | Security graph | 2 | ✅ | `graph_nodes/edges` built per scan; invariants tested; `GET /graph` and neighbour queries work; NetworkX loader < 1 s at 5 k nodes | schema, builder, loader, recursive-CTE queries |
| 10 | Attack-path engine | 2 | ✅ | Scenario E produces the expected path with evidence; Dijkstra + Yen top-3; performance budget met | derive, search, score, `GET /attack-paths` |
| 11 | Contextual risk engine | 2 | ✅ | Scenario A–E fixture scores match §14.6; monotonicity property tests; context-free reduction test; `GET /risks` | factors, model v1, thresholds, overrides, effective impact, model_version |
| 12 | AI explanation | 1 | ✅ (Ollama) | Explanation generated for a Critical finding, validated, cached; validator golden tests; fallback verified by killing Ollama | adapter protocol, Ollama adapter, prompt, validator, template fallback; Anthropic adapter (stretch) |
| 13 | React dashboard | 4 | ✅ (9 views) | Demo walk-through §28 steps 1–9 possible in the UI; Playwright smoke passes | Overview, Repos, Scans (live), Findings, Detail, Risk ranking, Attack paths, Graph, Explanation panel; SBOM/Secrets/IaC/Explanations list views (stretch) |
| 14 | GitHub / CI-CD integration | 2 | ✅ | Webhook creates scans with verified signatures; Action posts summary + PR comment; policy modes enforce | `action/`, webhook module, policy evaluation, self-hosted runner demo doc |
| 15 | Auth & security hardening | 2 | ✅ | Every threat T-01…T-20 has a mitigation ticked with a test or a documented residual; authz matrix test passes; rate limits, audit, headers verified | refresh rotation, reuse detection, rate limiter, audit coverage, redaction audit, CSP, `/docs` gating |
| 16 | Test consolidation & security validation | 1 | ✅ | Coverage report; malicious-repo dataset run end-to-end without escape/leak; performance numbers recorded against NFRs | `TEST_REPORT.md` |
| 17 | Research evaluation | 2 | ✅ | Three methods compared on scenario suite with CIs; ablations; weight sensitivity; (stretch) blind-labelled real apps | `evaluation/` code, results, charts, `EVALUATION_REPORT.md` |
| 18 | Deployment & DevOps | 1 | ✅ (local VM) / stretch (EC2) | Prod Compose with Caddy TLS on a VM; backup + restore rehearsed; deploy + rollback workflow | prod compose, Caddyfile, scripts, `DEPLOYMENT.md`, observability profile (stretch) |
| 19 | Documentation & final project | 2 | ✅ | README, architecture doc, API doc, DB doc, security model, test + eval reports, user + deployment guides, thesis, slides, demo script | `docs/thesis/`, presentation, recorded demo |
| — | Buffer | 3 | — | absorbs overrun on P8, P13, P17 (the three most likely to slip) | — |

**Total: 37 weeks + 3 buffer = 40 weeks (≈ 9.2 months).** This is the
full scope and it overruns the 9-month ceiling by about a week before any
buffer is used; the plan therefore *assumes* at least two stretch items are
dropped. If the calendar is 7 months (30 weeks): drop in order → Terraform extraction, JS/TS call graph,
stretch dashboard views, Anthropic adapter, real-app blind evaluation, EC2,
Grafana. The MVP in `00_BLUEPRINT.md` §30 stays intact at 30 weeks only if
the dashboard is held to 3 weeks and Phase 8 to L0–L2.

Per-phase chapter template (A–S from the brief) is produced when a phase
starts; each phase writes `docs/phases/PHASE_NN.md` as its own chapter, so
Phase 19 assembles rather than authors.
