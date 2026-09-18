# ADR-0007: Celery + Redis for background work

Status: accepted · Date: 2026-09-19

## Context
The kit's default is a Postgres job table. Scans need fan-out to five scanner containers, fan-in, per-task time limits, revocation, scheduling and retries. Redis is also needed for rate limiting and a machine-wide scanner-slot semaphore.

## Decision
Celery 5 with Redis 7 as broker and result backend; queues `scan` and `analysis`; Celery Beat for schedules. Canvas: `chain(clone, chord(group(scanners), collect), analyze, finalize)`.

## Alternatives considered
### Postgres job table + worker loop — rejected
Real pros: transactional enqueue, one fewer service. Rejected: chord/fan-in, time limits and revocation would be hand-rolled; Redis is required anyway.
### arq / Dramatiq — rejected
Lighter than Celery; weaker canvas primitives and smaller training footprint.

## Consequences
- (−) result-backend growth (expire results at 24 h), chord edge cases, Celery's configuration surface
- (→) trigger: > 2 weeks lost to Celery quirks → arq or job table behind the `scans.orchestration` seam
