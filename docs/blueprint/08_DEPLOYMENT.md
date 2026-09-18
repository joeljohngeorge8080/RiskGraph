# RiskGraph — Deployment, NFRs, Failure Handling (section 27)

## 27.1 Deployment architecture

Same Compose file, three profiles: `dev`, `test`, `prod`.

```
                         Internet
                             │ :443 (only published port)
                    ┌────────▼────────┐
                    │ caddy           │  auto-TLS (Let's Encrypt or internal CA for demo),
                    │ /  → frontend   │  HSTS, CSP, gzip, request size limit 10 MB
                    │ /api → api:8000 │
                    └───┬─────────┬───┘
            ┌───────────▼──┐  ┌──▼─────────────┐
            │ frontend     │  │ api ×1 (uvicorn │
            │ (static)     │  │ 2 workers)      │
            └──────────────┘  └──┬──────────┬───┘
                                 │          │
   ┌──────────────┐   ┌──────────▼──┐  ┌────▼────────┐   ┌──────────────┐
   │ beat         │──▶│ redis 7     │◀─│ worker ×1   │──▶│ docker-socket│──▶ /var/run/docker.sock
   │ (schedules)  │   │ (auth, no   │  │ (celery,    │   │ -proxy       │    (host)
   └──────────────┘   │  persistence│  │  non-root)  │   └──────────────┘
                      │  needed)    │  └───┬─────────┘         │ creates
   ┌──────────────┐   └─────────────┘      │                   ▼
   │ postgres 16  │◀─────────────────────────┘        ephemeral scanner containers
   │ volume pgdata│                           volumes: workspaces (tmp), scan_output, trivy_cache
   └──────┬───────┘
          │ nightly pg_dump → backups volume → (optional) aws s3 cp
   ┌──────▼───────┐  ┌──────────────┐  ┌──────────────────────────┐
   │ migrate      │  │ ollama       │  │ prometheus + grafana     │
   │ (one-shot,   │  │ (profile:    │  │ (profile: observability) │
   │  runs first) │  │  llm)        │  │  internal network only   │
   └──────────────┘  └──────────────┘  └──────────────────────────┘
```

| Item | Decision |
|---|---|
| Host | any Linux box with Docker: the dev laptop for the demo; optional AWS EC2 `t3.medium` (2 vCPU/4 GB is the floor; `t3.large` if Ollama runs on the VM) with a 30 GB gp3 volume, security group 443 + 22 from one IP |
| Secrets | `.env` on the host, mode 0600, never in the image; JWT key, DB/Redis passwords, webhook secrets, optional LLM key. Secrets Manager not used (one host, no rotation requirement) |
| Images | built in CI, pushed to GHCR with sha + semver tags; VM pulls by tag |
| Deploy | `deploy.yml`: ssh → `docker compose -f … --profile prod pull` → `run --rm migrate` → `up -d`; health check gate on `/readyz` |
| Rollback | re-run deploy with previous tag; migrations are reversible (`alembic downgrade -1` rehearsed in CI) |
| Backups | `infrastructure/scripts/backup.sh` nightly via host cron: `pg_dump -Fc`, 14-day retention, optional `aws s3 cp` with a backup-only IAM user; `restore.sh` rehearsed in Phase 18 (a backup that was never restored does not exist) |
| Logs | JSON to stdout; `docker logs`; Loki not included (stretch) |
| Metrics | `/metrics` on api and worker (internal network); Prometheus + Grafana profile with dashboards for scan duration, scanner failures, queue depth, API latency, risk-engine time |
| Updates | Dependabot for Python/npm/Actions; scanner image digests bumped by a monthly manual PR that re-records fixtures |

## 27.2 Non-functional requirements (measurable targets)

| Area | Target (V1) | Measured in |
|---|---|---|
| API latency | p95 < 300 ms for list endpoints at 10 k findings; p95 < 800 ms for `GET /findings/{id}` composite | P16 perf |
| Scan throughput | 1 medium repo (≤ 50 MB, ≤ 5 k files) end-to-end ≤ 10 min on a 4-core laptop; 2 concurrent scans | P16 |
| Max repository | 500 MB clone, 50 k files (configurable; larger refused with a clear reason) | P3 |
| Scanner timeouts | per-scanner defaults §9.2; hard-kill verified | P3 |
| Graph | build + load ≤ 1 s at 5 k nodes; attack-path search ≤ 2 s at 5 k/20 k with 10 sinks, k=3 | P9/P10 |
| Risk engine | ≤ 50 ms per finding; ≤ 5 s per scan of 1 k findings | P11 |
| Availability | single host; target "no data loss": every state change is in Postgres; a worker crash never loses a scan (reaper marks it and it can be re-run) | P3 |
| Reliability | scanner failure isolated (PARTIAL); Redis outage → API still serves reads, scan creation returns 503 with retry-after | P16 |
| Security | threat table fully mitigated or residual-documented; zero Critical fixable CVEs in shipped images | P15/P18 |
| Maintainability | mypy strict on modules, ruff clean, ≥ 80 % line coverage on `modules/` (parsers/risk/graph ≥ 90 %) | CI |
| Observability | every log line has request or task id + scan id where applicable; the five metrics in §27.1 exported | P1/P18 |

## 27.3 Failure handling (graceful degradation table)

| Failure | Behaviour |
|---|---|
| Trivy / Semgrep / Checkov / Syft / Gitleaks crashes or times out | that `scanner_run` = FAILED/TIMED_OUT with excerpt; others continue; scan ends PARTIAL; findings from the failed scanner keep prior status (no false "fixed"); policy `fail` mode fails closed unless `ignore_scanner_failures` |
| Gitleaks (or any) output malformed | parser raises `ParseError` → scanner_run FAILED with the JSON error excerpt; raw file kept for debugging |
| Syft fails | Trivy findings still attach to components created `discovered_by=trivy`; SBOM view shows "inventory incomplete" |
| Repository unavailable / auth failure / too large | scan FAILED at CLONING with reason; no retries beyond 2 infra attempts |
| GitHub webhook signature invalid | 401, logged, counted; no scan |
| Redis down | API: reads work; `POST /scans` → 503 + `Retry-After`; rate limiter fails open for authenticated users and closed for anonymous; worker reconnects with backoff; in-flight tasks are marked by the reaper if lost |
| PostgreSQL down | `/readyz` red; API 503; worker pauses (tasks retry with backoff, then land in FAILED with reason when max retries exceeded; raw outputs remain on disk for re-analysis via CLI) |
| NVD / EPSS / KEV unreachable | factors use cached values; missing → `unknown` with flag; scan continues; Beat retries refresh |
| Ollama / Anthropic unavailable | explanation status `fallback` with template text; scans unaffected |
| Graph build raises invariant error | ANALYZING fails for graph/paths/risk stages only; findings and enrichment are still stored; scan ends PARTIAL with `analysis_error` |
| Scanner exceeds timeout | container killed by label; TIMED_OUT; partial output ignored (never parse a truncated JSON) |
| Docker daemon / proxy unreachable | infra retry ×2 with backoff; then FAILED; alert metric |
| Disk full (workspaces/outputs) | pre-flight free-space check before clone (≥ 3× repo cap); scan refused with reason |
