# ADR-0001: Modular monolith with API and worker roles

Status: accepted · Date: 2026-09-19 · Deciders: project owner, architect session

## Context
One developer, a pipeline of ten stages, and a brief that lists thirteen logical layers. Each layer as a service would be a distributed-systems tax paid with no rent.

## Decision
One Python package `riskgraph` with domain modules (`modules/<domain>/{router,service,repo,schemas,models,tasks}.py`), deployed as two process roles that import the same code: `api` (FastAPI) and `worker` (Celery, plus `beat`). Modules depend downward only; cross-module imports go through `modules/<x>/__init__.py`.

## Alternatives considered
### Services per pipeline stage — rejected
Real pros: independent scaling of scanner workers; clearer failure isolation. Rejected: network failure modes, tracing and deployment complexity for one person; the worker role already isolates the heavy stage.
### Single flat package (no module boundaries) — rejected
Faster to start; becomes a ball of mud by Phase 9 when graph, risk and explain all need each other's tables.

## Consequences
- (+) one deploy, one log stream, transactions across modules, local debugging
- (−) shared fate of api and worker code (a bad import breaks both); discipline needed on boundaries (import-linter contract in Phase 1)
- (→) upgrade trigger: a module needs independent scaling proven by measurement → extract that module behind its existing interface

## Compliance
A PR adding a second deployable or a cross-module import of a private file violates this ADR unless it supersedes it.
