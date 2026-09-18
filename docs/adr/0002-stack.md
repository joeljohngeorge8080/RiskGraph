# ADR-0002: Stack

Status: accepted · Date: 2026-09-19

## Context
The brief fixes Python, FastAPI, PostgreSQL, Celery, Redis, Docker, React, GitHub Actions. Remaining choices are toolchain and libraries. Full comparison table: `docs/blueprint/04_TECH_STACK.md`.

## Decision
Python 3.12+, uv, ruff, mypy --strict; FastAPI + Pydantic v2; SQLAlchemy 2 + Alembic + psycopg 3; Celery 5 + Redis 7; structlog; pytest + Hypothesis; React 18 + TypeScript + Vite + TanStack Query/Table + Tailwind + Cytoscape.js; Caddy; Ollama default LLM behind an adapter.

## Alternatives considered
Django/DRF (batteries; rejected: drags ORM/template stack), SQLModel (rejected: lags on partial indexes/JSONB), poetry+black+flake8 (rejected: uv+ruff are faster and fewer), Jinja2+HTMX frontend (rejected: brief requires an interactive graph dashboard).

## Consequences
- (+) maximal training saturation, one language per tier, lockfiles everywhere
- (−) two languages overall (Python, TypeScript); frontend build is a separate toolchain
- (→) every new dependency is logged in `docs/TECH_STACK.md` with reason and date
