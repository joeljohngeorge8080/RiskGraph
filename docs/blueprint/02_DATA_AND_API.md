# RiskGraph — Data, API, Frontend, CI/CD (sections 16–19)

## 16. Database architecture

### 16.1 Principles

- PostgreSQL 16 is the single system of record. No second store.
- UUID v7 primary keys (time-ordered, index-friendly; generated in the app).
- `created_at`/`updated_at` UTC `timestamptz` on every table.
- Soft delete only where the audit trail needs it (repositories); hard delete elsewhere.
- Single-tenant: no `organization_id` (ADR-0003 in Phase 0). `organizations` and
  `projects` from the brief are **deferred**: a self-hosted instance *is* the org.
- JSONB for scanner-native payloads and factor evidence; typed columns for anything queried or joined.
- All schema changes via Alembic migrations; models never create tables.

### 16.2 ER diagram (V1)

```
users ──< refresh_tokens
users ──< api_keys
users ──< audit_logs

repositories ──< scan_jobs ──< scanner_runs
repositories ──< findings ──< scan_findings >── scan_jobs
repositories ──< assets  (service | endpoint | identity | credential | data_store | network_zone | container_image)
repositories ──< repository_context (parsed manifest + extracted context, per scan)

findings >── vulnerabilities (cve cache)          [nullable]
findings >── components (sbom, per scan)          [nullable]
findings >── assets                               [nullable]
findings ──< reachability_results (per scan)
findings ──< risk_scores ──< risk_factors
findings ──< ai_explanations

scan_jobs ──< components ──< component_dependencies (parent, child)
scan_jobs ──< graph_nodes ──< graph_edges
scan_jobs ──< attack_paths ──< attack_path_findings >── findings

webhook_deliveries (idempotency)
```

### 16.3 Table definitions (V1)

Notation: `pk`, `fk→`, `uq`, `idx`. Types are Postgres.

**users** — id pk · email citext uq · password_hash text (argon2id) · role enum(admin, security_engineer, developer, viewer) · is_active bool · last_login_at · created_at/updated_at

**refresh_tokens** — id pk · user_id fk→users (cascade) · token_hash text uq (sha256 of opaque token) · expires_at · revoked_at · replaced_by_id fk→self (rotation chain) · idx(user_id, expires_at)

**api_keys** — id pk · user_id fk→users · name text · key_hash text uq · prefix char(8) (display) · scopes text[] (e.g. `scans:write`, `scans:read`) · expires_at · last_used_at · revoked_at

**repositories** — id pk · name text · clone_url text · provider enum(github) · external_id text (GitHub repo id) · default_branch text · visibility enum(public, private) · enabled_scanners text[] · policy jsonb (CI policy) · webhook_secret_ref text (name of env/secret, not the value) · deleted_at · uq(provider, external_id) · idx(name)

**scan_jobs** — id pk · repository_id fk→repositories · commit_sha char(40) · ref text · trigger enum(manual, push, pull_request, schedule, action) · trigger_meta jsonb (PR number, sender, delivery id) · status enum (§9.1) · status_reason text · requested_by_user_id fk→users null · cancel_requested_at · started_at · finished_at · summary jsonb (counts by priority, max risk; cached at finalize) · risk_model_version text · created_at · **uq partial** (repository_id, commit_sha) WHERE status IN ('PENDING','QUEUED','CLONING','SCANNING','ANALYZING') · idx(repository_id, created_at desc) · idx(status)

**scanner_runs** — id pk · scan_job_id fk→scan_jobs (cascade) · scanner enum · scanner_version text · status enum (§9.1) · exit_code int · started_at · finished_at · duration_ms int · output_path text · output_sha256 char(64) · output_bytes bigint · error_excerpt text (≤ 4 KB, redacted) · container_id text · uq(scan_job_id, scanner)

**vulnerabilities** — id text pk (CVE-…/GHSA-…) · description text · cvss_version text · cvss_base numeric(3,1) · cvss_vector text · cvss_exploitability numeric(3,1) · cvss_impact numeric(3,1) · epss numeric(6,5) · epss_percentile numeric(6,5) · epss_date date · kev bool · kev_added date · cwe_ids text[] · fetched_at · idx(kev) · idx(epss desc)

**components** — id pk · scan_job_id fk→scan_jobs (cascade) · purl text · name · version · ecosystem text · scope enum(runtime, dev, unknown) · locations text[] (manifest files) · discovered_by enum(syft, trivy) · uq(scan_job_id, purl) · idx(scan_job_id, name)

**component_dependencies** — parent_id fk→components · child_id fk→components · pk(parent_id, child_id)

**assets** — id pk · repository_id fk→repositories · kind enum(service, endpoint, identity, credential, data_store, network_zone, container_image) · name text · attributes jsonb (exposure, auth, privilege, sensitivity, path, language, criticality, …) · source enum(manifest, k8s, compose, terraform, reachability, gitleaks, override) · source_ref text (file:line or manifest key) · uq(repository_id, kind, name)

**repository_context** — id pk · scan_job_id fk uq · manifest_raw jsonb · manifest_valid bool · manifest_errors jsonb · extracted jsonb (per-source extraction with provenance) · created_at

**findings** — as §10.1: id pk · repository_id fk · fingerprint char(64) · source_type enum · scanner enum · scanner_rule_id text · vulnerability_id fk→vulnerabilities null · component_id fk→components null (latest) · asset_id fk→assets null · title · description · category enum · cwe_ids text[] · scanner_severity text · severity enum · location jsonb · evidence jsonb · remediation text · status enum · status_reason text · status_changed_by fk→users null · first_seen_scan_id fk · last_seen_scan_id fk · first_seen_at · last_seen_at · raw jsonb · **uq(repository_id, fingerprint)** · idx(repository_id, status) · idx(vulnerability_id) · idx(source_type) · GIN(location) only if needed (measure first)

**scan_findings** — scan_job_id fk (cascade) · finding_id fk · scanner_run_id fk · location jsonb (snapshot) · pk(scan_job_id, finding_id)

**reachability_results** — id pk · scan_job_id fk (cascade) · finding_id fk · tier enum(L0, L1, L2, L3, unknown, n_a) · confidence enum(high, medium, low) · evidence jsonb (import chain / call chain, entry point, vulnerable symbol) · language text · analyzer_version text · uq(scan_job_id, finding_id)

**graph_nodes** — id pk · scan_job_id fk (cascade) · kind enum (§12) · ref_table text · ref_id uuid null · label text · properties jsonb · uq(scan_job_id, kind, ref_table, ref_id) · idx(scan_job_id, kind)

**graph_edges** — id pk · scan_job_id fk (cascade) · src_id fk→graph_nodes · dst_id fk→graph_nodes · kind enum (§12) · probability numeric(5,4) null (attack-graph edges) · evidence jsonb · uq(scan_job_id, src_id, dst_id, kind) · idx(scan_job_id, src_id) · idx(scan_job_id, dst_id)

**attack_paths** — id pk · scan_job_id fk (cascade) · source_node_id fk · sink_node_id fk · node_ids uuid[] (ordered) · hops smallint · probability numeric(6,5) · sink_impact numeric(4,3) · score numeric(5,2) · rank_for_sink smallint · evidence jsonb · idx(scan_job_id, score desc)

**attack_path_findings** — attack_path_id fk (cascade) · finding_id fk · hop_index smallint · pk(attack_path_id, finding_id)

**risk_scores** — id pk · scan_job_id fk (cascade) · finding_id fk · model_version text · likelihood numeric(5,4) · impact numeric(5,4) · effective_impact numeric(5,4) · score numeric(5,2) · priority enum(critical, high, medium, low) · overrides jsonb · computed_at · uq(scan_job_id, finding_id) · idx(scan_job_id, score desc) · idx(finding_id)

**risk_factors** — id pk · risk_score_id fk (cascade) · group enum(likelihood, impact) · name text (E, X, R, T, D, P, C) · value numeric(5,4) · raw_value text (e.g. "epss=0.05", "L3") · source text · confidence text · evidence jsonb · applicable bool

**ai_explanations** — id pk · finding_id fk · risk_score_id fk · evidence_hash char(64) · provider text · model text · status enum(generated, fallback, failed) · content jsonb (validated draft) · validation_errors jsonb · latency_ms int · created_at · uq(risk_score_id, evidence_hash)

**audit_logs** — id pk · actor_user_id fk null · actor_api_key_id fk null · action text (`finding.status_changed`, `repository.created`, `scan.cancelled`, `auth.login_failed`, …) · target_type text · target_id uuid · details jsonb (redacted) · ip inet · created_at · idx(created_at desc) · idx(target_type, target_id)

**webhook_deliveries** — delivery_id text pk (`X-GitHub-Delivery`) · event text · repository_id fk null · scan_job_id fk null · received_at · outcome text

### 16.4 Deferred from the brief (and why)

| Entity | Decision |
|---|---|
| organizations, projects | single-tenant; "project" = repository |
| secrets, identities, permissions, network_assets, data_assets | folded into `assets.kind` + `attributes` (one table, one graph loader; typed columns can be split out later by migration when a kind grows its own queries) |
| packages, sbom_components | one `components` table |
| remediation_actions | out of scope (no auto-remediation); `findings.status` + audit covers triage |
| scan_jobs.summary as separate table | cached JSON is enough |

### 16.5 Growth and retention

Per scan, expect ~10³ findings, ~10³–10⁴ components, ~10³–10⁴ graph rows.
Per-scan tables (`components`, `graph_*`, `reachability_results`,
`risk_scores`, `attack_paths`) are cascade-deleted by a Beat retention job
(keep last N=20 scans per repository plus any scan referenced by an open
finding's `first_seen`). `findings` persist. Raw output files follow the same
retention. Migration strategy: Alembic autogenerate + hand review; every
migration reversible; migrations run by a one-shot `migrate` service in
Compose before `api`/`worker` start.

## 17. API architecture

FastAPI, versioned under `/api/v1`. OpenAPI is the API documentation; Swagger
UI is the primary interface until the dashboard exists (Phase 13).

### 17.1 Cross-cutting

| Concern | Decision |
|---|---|
| Auth | `Authorization: Bearer <jwt>` (15 min access) or `X-API-Key` (CI). Refresh via `POST /auth/refresh` with rotating opaque refresh token (30 days, stored hashed, reuse detection revokes the chain) |
| RBAC | `require_role(...)` dependency. admin: everything · security_engineer: manage repos, triage findings, run/cancel scans, explanations · developer: run scans on repos, read all, change finding status to false_positive with reason · viewer: read only. API keys carry scopes ≤ owner's role |
| Validation | Pydantic v2 request models, `extra="forbid"`, bounded lengths, enums; path ids are UUIDs |
| Errors | RFC 7807 `application/problem+json`: `{type, title, status, detail, instance, errors?[]}`; no stack traces; correlation id header `X-Request-ID` |
| Pagination | cursor-based for findings (`?cursor=&limit≤200`), offset for small lists; sort allow-list |
| Rate limiting | Redis token bucket via middleware: 600 req/min per user, 60/min for unauthenticated (`/auth/login` 10/min per IP), webhook 120/min per repo |
| Security headers | Caddy sets HSTS, CSP (`default-src 'self'`), X-Content-Type-Options, Referrer-Policy; API sets `Cache-Control: no-store` |
| CORS | allow-list = frontend origin only |
| Logging | structlog JSON with request id, user id, route, status, latency; bodies never logged |
| Audit | every mutating endpoint writes `audit_logs` inside the same transaction |

### 17.2 Endpoints (V1)

| Method & path | Role | Purpose |
|---|---|---|
| `POST /auth/login` | public | email+password → access + refresh |
| `POST /auth/refresh` | public | rotate refresh → new pair |
| `POST /auth/logout` | any | revoke refresh chain |
| `GET /auth/me` | any | current user + role |
| `POST /users` · `GET /users` · `PATCH /users/{id}` | admin | user management |
| `POST /api-keys` · `GET /api-keys` · `DELETE /api-keys/{id}` | sec_eng+ | CI keys (secret shown once) |
| `POST /repositories` | sec_eng+ | register repo `{name, clone_url, provider, default_branch, enabled_scanners?, policy?}`; server generates webhook secret and returns it once |
| `GET /repositories` · `GET /repositories/{id}` · `PATCH /repositories/{id}` · `DELETE /repositories/{id}` | dev+/sec_eng+ | list/detail/update/soft-delete |
| `GET /repositories/{id}/context` | dev+ | latest parsed manifest + extracted assets with provenance |
| `PATCH /repositories/{id}/assets/{asset_id}` | sec_eng+ | override criticality/sensitivity (audited) |
| `POST /scans` | dev+ | `{repository_id, ref?, commit_sha?, scanners?}` → 202 `{id, status, deduplicated}` |
| `GET /scans` · `GET /scans/{id}` | viewer+ | list (filter repo/status) / detail incl. scanner_runs and summary |
| `POST /scans/{id}/cancel` | dev+ | request cancel |
| `GET /scans/{id}/events` | viewer+ | SSE stream of status changes (dashboard live view) |
| `GET /findings` | viewer+ | filters: repository, scan, source_type, scanner, severity, priority, status, reachability, exposure, search; sort: risk, cvss, epss, severity, first_seen |
| `GET /findings/{id}` | viewer+ | finding + latest risk score with factors + reachability + attack paths + explanation (composite view for the detail page) |
| `PATCH /findings/{id}` | dev+ (limited) / sec_eng+ | `{status, status_reason}` (audited) |
| `POST /findings/{id}/explain` | dev+ | generate (or return cached) explanation; 202 + poll if async |
| `GET /risks` | viewer+ | ranked risk scores for a scan (`?scan_id=` required, or latest per repo) — the "risk ranking" view |
| `GET /risks/{finding_id}` | viewer+ | score + factors + overrides |
| `GET /graph?scan_id=` | viewer+ | nodes + edges (pruned by kind filter, max 5 000 nodes; 413 above with hint) |
| `GET /graph/nodes/{id}/neighbors?depth≤3` | viewer+ | recursive-CTE neighbourhood |
| `GET /attack-paths?scan_id=` · `GET /attack-paths/{id}` | viewer+ | ranked paths / detail with evidence |
| `GET /sbom?scan_id=` · `GET /sbom/components/{id}` | viewer+ | components, dependency edges, linked findings; `?format=cyclonedx` returns the raw SBOM |
| `GET /dashboard/summary` | viewer+ | counts by priority/source/repo, trend over last N scans, top paths |
| `POST /webhooks/github` | signature | HMAC-verified; push/pull_request → scan |
| `GET /healthz` · `GET /readyz` · `GET /metrics` | public / internal | liveness; readiness (DB + Redis); Prometheus (internal network only) |

### 17.3 Representative schemas

```python
class ScanCreate(BaseModel, extra="forbid"):
    repository_id: UUID
    ref: str | None = Field(None, max_length=255, pattern=r"^[\w./-]+$")
    commit_sha: str | None = Field(None, pattern=r"^[0-9a-f]{40}$")
    scanners: list[ScannerName] | None = None

class ScanOut(BaseModel):
    id: UUID; repository_id: UUID; commit_sha: str; ref: str
    trigger: Trigger; status: ScanStatus; status_reason: str | None
    deduplicated: bool = False
    scanner_runs: list[ScannerRunOut]
    summary: ScanSummary | None
    created_at: datetime; started_at: datetime | None; finished_at: datetime | None

class RiskFactorOut(BaseModel):
    group: Literal["likelihood", "impact"]; name: str; value: float
    raw_value: str; source: str; confidence: str; applicable: bool
    evidence: dict[str, Any]

class RiskScoreOut(BaseModel):
    finding_id: UUID; scan_job_id: UUID; model_version: str
    likelihood: float; impact: float; effective_impact: float
    score: float; priority: Priority
    factors: list[RiskFactorOut]; overrides: list[str]

class Problem(BaseModel):          # RFC 7807
    type: str; title: str; status: int; detail: str | None; instance: str
    errors: list[FieldError] | None = None
```

## 18. Frontend architecture

React 18 + TypeScript + Vite. Routing: React Router. Server state: TanStack
Query (all data is server-owned; no Redux). Styling: Tailwind + a headless
component set (Radix/shadcn-style, copied in, not a dependency tree). Charts:
Recharts. Graph view: Cytoscape.js (handles 5 000 nodes with canvas
rendering; force layouts; path highlighting). Tables: TanStack Table with
server-side pagination. Auth: access token in memory, refresh token in an
`HttpOnly; Secure; SameSite=Strict` cookie scoped to `/api/v1/auth/refresh`.
Live scan status: SSE via `EventSource`.

```
frontend/src/
  app/            router, providers, layout (sidebar nav), error boundary
  api/            generated client from OpenAPI (openapi-typescript + fetch wrapper), auth interceptor
  features/
    overview/     OverviewPage: KPI tiles, priority distribution, trend, top attack paths
    repositories/ list, detail (context panel, policy editor), connect dialog
    scans/        list, detail (scanner cards with live status), trigger dialog
    findings/     FindingsTable (filters, sort by CVSS vs Risk toggle), FindingDetailPage
                  (tabs: Overview · Evidence · Reachability · Context · Attack paths · Explanation)
    risk/         RiskRankingPage (same table, default sort risk, factor chips)
    attack-paths/ list + PathDiagram (linear hop view with evidence popovers)
    graph/        GraphPage (Cytoscape, kind filters, "highlight path")
    sbom/         components table, dependency drill-down            [stretch view; MVP = filter on Findings]
    secrets/      findings filtered source_type=secret                [stretch]
    iac/          findings filtered source_type=iac                   [stretch]
    explanations/ list of generated explanations                      [stretch; MVP shows inside detail]
    auth/         login, api keys
  components/ui/  primitives
  lib/            formatting, risk colour scale (shared with charts), constants
```

Explanations render as text nodes only (no `dangerouslySetInnerHTML`
anywhere; ESLint rule enforced). All ids in URLs validated client-side as UUIDs.

## 19. CI/CD architecture

### 19.1 Two integration paths

```
A. Webhook (push / PR opened / synchronize)
   GitHub ──HMAC──▶ POST /webhooks/github ──▶ scan_jobs (trigger=push|pull_request)
   RiskGraph does NOT call back to GitHub in V1 (no GitHub App credentials to protect);
   results are visible in the dashboard and via path B.

B. GitHub Action  (action/ in this repo, published as riskgraph-action)
   job:
     - uses: <org>/riskgraph-action@v1
       with: { api_url, api_key (secret), repository_id, policy: warn|fail|info, timeout: 20m }
   steps inside the action (Node 20 or composite + Python):
     1. POST /scans {repository_id, commit_sha: GITHUB_SHA, ref: GITHUB_REF}  (dedups with webhook-created scan)
     2. poll GET /scans/{id} until terminal (backoff 10 s → 30 s)
     3. GET /risks?scan_id=  → summary
     4. write $GITHUB_STEP_SUMMARY (markdown table: priority counts, top 5 findings with links, top attack path)
     5. if PR: upsert one PR comment (marker `<!-- riskgraph -->`) via GITHUB_TOKEN
     6. exit code per policy
```

Path B is what makes the demo work from a laptop: the runner (self-hosted for
the demo) reaches RiskGraph; GitHub never needs to reach the laptop. Path A
needs a public URL and is shown with a tunnel only.

### 19.2 Policy (from `riskgraph.yaml` `policy:` or repository settings; action input overrides)

```yaml
policy:
  mode: warn                # info | warn | fail
  fail_when:
    max_score: 70           # any finding ≥ 70 fails (mode=fail) / warns (mode=warn)
    priorities: [critical]  # or by band
    new_only: true          # only findings first seen in this scan (or on this PR's commits)
    include_statuses: [open]
  ignore_scanner_failures: false   # PARTIAL scans fail closed by default when mode=fail
```

Defaults are `info` — the brief's rule "no hard-coded production policies" is
honoured: nothing fails until a repository opts in.

### 19.3 RiskGraph's own CI (`.github/workflows/ci.yml`)

```
push/PR ──▶ lint (ruff, mypy --strict on modules, eslint, tsc)
        ──▶ unit tests (pytest -m "not docker", vitest)
        ──▶ integration tests (services: postgres, redis; pytest -m docker needs Docker → runs on ubuntu-latest with docker available)
        ──▶ security self-scan (Gitleaks, Semgrep, Trivy fs — the same tools, dog-fooding; and RiskGraph action against itself once deployed = stretch)
        ──▶ build images (api, worker, frontend, scanners/*) with buildx, tag sha
        ──▶ container scan (Trivy image on built images; fail on Critical fixable)
        ──▶ push to GHCR on main
release tag ──▶ deploy workflow: ssh to VM, `docker compose pull && up -d` (Phase 18), migrate service runs first
```
