.RECIPEPREFIX := >
.DEFAULT_GOAL := help
SHELL := /bin/bash

BACKEND := backend
UV := uv --directory $(BACKEND)

help: ## Show targets
> @grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

.env:
> cp .env.example .env
> @echo "Created .env from .env.example — set RISKGRAPH_SECRET_KEY before prod use."

dev: .env ## Start the full local stack (postgres, redis, migrate, api, worker, beat, frontend)
> docker compose up --build

dev-detached: .env ## Same, in the background
> docker compose up --build -d

down: ## Stop the stack (keeps volumes)
> docker compose down

nuke: ## Stop the stack and delete volumes (destroys local data)
> docker compose down -v

logs: ## Tail all logs
> docker compose logs -f --tail=100

install: ## Install backend (uv) and frontend (npm) dependencies
> $(UV) sync
> cd frontend && npm install

lint: ## Ruff + mypy + eslint + tsc
> $(UV) run ruff check .
> $(UV) run ruff format --check .
> $(UV) run mypy
> cd frontend && npm run lint && npm run typecheck

fmt: ## Auto-format backend
> $(UV) run ruff check --fix .
> $(UV) run ruff format .

test: ## Unit tests (no services)
> $(UV) run pytest -m "not db and not docker and not e2e and not perf"

test-services: ## Start postgres+redis for db-marked tests on the host
> docker compose -f docker-compose.test.yml up -d --wait

test-db: ## Tests that need postgres+redis (run test-services first)
> $(UV) run pytest -m db

test-all: ## Everything except perf
> $(UV) run pytest -m "not perf"

migrate: ## Apply migrations against the running compose postgres
> docker compose run --rm migrate

migration: ## Autogenerate a migration: make migration m="add findings"
> docker compose run --rm migrate alembic revision --autogenerate -m "$(m)"

shell-api: ## Shell in the api container
> docker compose exec api bash

.PHONY: help dev dev-detached down nuke logs install lint fmt test test-services test-db test-all migrate migration shell-api
