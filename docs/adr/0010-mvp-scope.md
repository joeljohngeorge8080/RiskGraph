# ADR-0010: MVP vertical slice and its deviations from the blueprint

Status: accepted · Date: 2026-10-21

## Context
The owner asked for a working MVP before continuing the phased roadmap. The MVP takes a GitHub URL, clones the repository, runs four scanners, normalizes the four reports, merges them into one list, gives every finding a prioritization score, and shows it all in a simple FastAPI + React + TypeScript web UI. This slice cuts across roadmap Phases 2–5, 11 and 13, and it skips some of what those phases require (auth, context, reachability, graph).

## Decision
| Area | Blueprint | MVP |
|---|---|---|
| Auth (ADR-0004) | users, JWT, RBAC, API keys | **none**; the API is bound to 127.0.0.1; `create_app` refuses to start with `env=prod` |
| Repositories | registered repos, providers | public `github.com` only; created on first scan; URL rebuilt from a strict `owner/name` parse |
| Scanners | Trivy (vuln only), Semgrep, Gitleaks, Checkov, Syft | Trivy with `vuln,secret,misconfig`, Semgrep, Checkov (IaC frameworks only), Gitleaks; no Syft |
| Overlap | each tool owns one domain | **deliberate overlap**: Trivy secrets overlap Gitleaks, and Trivy/Semgrep Dockerfile rules overlap Checkov, so merging is meaningful |
| Merge | fingerprints + Trivy↔Syft correlation | per-scanner fingerprints (§10.2), plus cross-scanner merge keys from curated tables (`normalization/families.py`): secret families with overlapping line ranges, and IaC check topics with the same resource. Unmapped checks never merge |
| Score | §14 with context (X, R, D, P, C from manifest/IaC/reachability) | §14.3 **context-free** case: X=0.5, R=0.6 (n/a for secrets and IaC), D=P=C=0.5; E from EPSS/KEV/CVSS; plus a **corroboration factor** K = 1 + 0.05·min(n−1, 2) when several scanners agree. Model `v1-cf.1` |
| Bands | 70/45/20 | **kept** (owner's decision). Without context the base score tops out around 42–46, so High/Critical come from the §14.5 overrides: KEV → at least High; format-valid live credential → Critical (every scanned repository is public) |
| Threat intel | NVD + EPSS + KEV with Beat refresh | EPSS (FIRST API) and CISA KEV (cisa.gov, with CISA's GitHub mirror as fallback) fetched during analysis, cached in `vulnerabilities` with TTLs; CVSS comes from Trivy's data; no NVD client; failures degrade to CVSS |
| Pagination | cursor | offset/limit (≤ 200) |
| Tables | 20 V1 tables | 9: repositories, scan_jobs, scanner_runs, findings, finding_occurrences, scan_findings, vulnerabilities, risk_scores, risk_factors |
| UI | 9 views | 2 pages: scan list with a new-scan form; scan detail with scanner cards, summary, filterable findings table and a score-breakdown drawer |

## Consequences
- (+) A usable, demonstrable increment. Every module created follows the blueprint names (`normalization`, `context`, `risk`, `scanners`, `scans`, `findings`) so later phases extend rather than rename.
- (−) Scores are only comparable within this model version. When context arrives (Phase 7+), the model version changes and the bands become reachable without overrides.
- (−) No auth means the API must never be exposed. This is enforced by Compose port bindings and the prod guard.
- (→) Phase 2 (auth skeleton) remains the next roadmap phase. Its tables must be added by new migrations on top of `fc3b3ff80221`.
