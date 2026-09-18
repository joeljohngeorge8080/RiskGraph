# ADR-0003: UUID v7 ids, single tenant, deletion policy

Status: accepted · Date: 2026-09-19

## Context
Ids appear in URLs and logs; the brief lists `organizations` and `projects`; per-scan tables grow without bound.

## Decision
- Primary keys are UUID v7 generated in the application (time-ordered, index-friendly, not enumerable).
- Single tenant: no `organization_id`/`tenant_id` columns. One deployment serves one organization; `project` = repository.
- Deletion: `repositories` soft-delete (`deleted_at`) because findings history has audit value; per-scan derived tables (`components`, `graph_*`, `reachability_results`, `risk_scores`, `attack_paths`) are hard-deleted by a retention job (keep last 20 scans per repository plus scans referenced by open findings); `findings` and `audit_logs` are never deleted by the application.

## Alternatives considered
### Multi-tenant from day one — rejected
Real pro: SaaS option later without a rewrite. Rejected: doubles every repository query's scoping surface and test matrix for a project whose non-goal is SaaS. Documented retrofit cost accepted.
### bigint serial ids — rejected
Enumerable in URLs; harder to merge data across environments.

## Consequences
- (−) a future multi-tenant version is a schema-wide migration
- (→) upgrade trigger: a second organization must share one instance
