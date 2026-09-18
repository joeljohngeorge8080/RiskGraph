# ADR-0008: Synchronous SQLAlchemy sessions

Status: accepted · Date: 2026-09-19

## Context
FastAPI supports async handlers; Celery workers are synchronous; the same repository layer must serve both.

## Decision
Synchronous SQLAlchemy 2 with psycopg 3. FastAPI endpoints that touch the database are plain `def` (run in the threadpool). One session-per-request / session-per-task pattern.

## Alternatives considered
### Async SQLAlchemy (asyncpg) — rejected
Real pros: higher concurrency for I/O-bound endpoints. Rejected: two session flavours (worker is sync), greenlet complications, and the API's load is small; SSE endpoints are async and do not touch the ORM directly.

## Consequences
- (−) API throughput bounded by the threadpool (default 40); adequate for NFRs
- (→) trigger: measured API p95 miss caused by DB wait → async for read endpoints only
