.RECIPEPREFIX := >
.DEFAULT_GOAL := help
SHELL := /bin/bash

BACKEND := backend
UV := uv --directory $(BACKEND)
SCANNER_PREFIX ?= $(HOME)/.local/share/riskgraph-tools
# Host-run backend (no Docker): scanners from `make scanner-tools`, data under ./.data
LOCAL_ENV := set -a && . ./.env && set +a && \
  export RISKGRAPH_SCANNER_BIN_DIR=$(SCANNER_PREFIX)/bin \
         RISKGRAPH_SEMGREP_RULES_PATH=$(SCANNER_PREFIX)/semgrep-rules \
         RISKGRAPH_TRIVY_CACHE_DIR=$(HOME)/.cache/riskgraph/trivy \
         RISKGRAPH_DATA_DIR=$(CURDIR)/.data &&
# db-marked tests: reach postgres/redis on the .env ports (dev stack or test-services).
# Only these keys are read; sourcing .env would also set RISKGRAPH_ENV=dev.
TEST_DB_ENV := pg=$$(sed -n 's/^POSTGRES_PORT=//p' .env 2>/dev/null || true) && \
  rp=$$(sed -n 's/^REDIS_PORT=//p' .env 2>/dev/null || true) && \
  rpw=$$(sed -n 's/^REDIS_PASSWORD=//p' .env 2>/dev/null || true) && \
  export RISKGRAPH_DATABASE_URL=postgresql+psycopg://riskgraph:riskgraph@localhost:$${pg:-5432}/riskgraph_test \
         RISKGRAPH_REDIS_URL=redis://:$${rpw:-riskgraph}@localhost:$${rp:-6379}/1 &&

help: ## Show targets
> @grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

.env:
> cp .env.example .env
> @echo "Created .env from .env.example — set RISKGRAPH_SECRET_KEY before prod use."

# The worker hands Docker host paths to the daemon (ADR-0014): the volumes' host mountpoints.
HOST_PATHS = export RISKGRAPH_HOST_DATA_DIR=$$(docker volume create riskgraph-data >/dev/null && docker volume inspect -f '{{.Mountpoint}}' riskgraph-data) \
  RISKGRAPH_HOST_TRIVY_CACHE_DIR=$$(docker volume create riskgraph-trivy-cache >/dev/null && docker volume inspect -f '{{.Mountpoint}}' riskgraph-trivy-cache) && \
  (docker network inspect riskgraph_egress >/dev/null 2>&1 || docker network create riskgraph_egress >/dev/null) && \
  $(MAKE) --no-print-directory scanner-images &&

scanner-images: ## Build the pinned scanner images (docker/scanner-versions.env, ADR-0014)
> infrastructure/scripts/build-scanner-images.sh

dev: .env ## Start the full local stack (postgres, redis, migrate, api, worker, beat, frontend)
> $(HOST_PATHS) docker compose up --build

dev-detached: .env ## Same, in the background
> $(HOST_PATHS) docker compose up --build -d

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

test-db: ## Tests that need postgres+redis (dev stack or test-services running)
> @$(TEST_DB_ENV) $(UV) run pytest -m "db and not llm"

test-llm: ## Explanations with the real local model (needs Ollama and test-services)
> @$(TEST_DB_ENV) $(UV) run pytest -m llm -s

test-all: ## Everything except perf
> @$(TEST_DB_ENV) $(UV) run pytest -m "not perf and not llm"

scanner-tools: ## Install trivy, semgrep, checkov, gitleaks into $(SCANNER_PREFIX) (host runs)
> infrastructure/scripts/install-scanners.sh $(SCANNER_PREFIX)

api-local: .env ## Run the API on the host (needs RISKGRAPH_DATABASE_URL/REDIS_URL in .env)
> $(LOCAL_ENV) $(UV) run alembic upgrade head && $(UV) run uvicorn --factory riskgraph.entrypoints.api:create_app --host 127.0.0.1 --port 8000

worker-local: .env ## Run the Celery worker on the host
> $(LOCAL_ENV) $(UV) run celery -A riskgraph.entrypoints.worker:celery_app worker -Q scan,analysis -c 2 --loglevel INFO

e2e: ## Full pipeline with the real scanners (needs scanner-tools, postgres, redis)
> @$(TEST_DB_ENV) export RISKGRAPH_SCANNER_BIN_DIR=$(SCANNER_PREFIX)/bin RISKGRAPH_SEMGREP_RULES_PATH=$(SCANNER_PREFIX)/semgrep-rules RISKGRAPH_TRIVY_CACHE_DIR=$(HOME)/.cache/riskgraph/trivy && $(UV) run pytest -m e2e

migrate: ## Apply migrations against the running compose postgres
> docker compose run --rm migrate

migration: ## Autogenerate a migration: make migration m="add findings"
> docker compose run --rm migrate alembic revision --autogenerate -m "$(m)"

shell-api: ## Shell in the api container
> docker compose exec api bash

.PHONY: help dev dev-detached down nuke logs install lint fmt test test-services test-db test-llm test-all scanner-tools api-local worker-local e2e migrate migration shell-api
