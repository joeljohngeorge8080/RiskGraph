# syntax=docker/dockerfile:1.7
# RiskGraph backend image. Targets:
#   runtime  api, beat, migrate
#   worker   runtime + git + trivy/semgrep/checkov/gitleaks in /opt/scanners (ADR-0009)
FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
COPY --from=ghcr.io/astral-sh/uv:0.11 /uv /usr/local/bin/uv
RUN groupadd --gid 10001 riskgraph && useradd --uid 10001 --gid 10001 --create-home riskgraph
WORKDIR /app

FROM base AS deps
COPY backend/pyproject.toml backend/uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project

FROM base AS scanner-tools
# Versions: docker/scanner-versions.env. Release tarballs are checksum-verified.
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates git \
    && rm -rf /var/lib/apt/lists/*
COPY docker/scanner-versions.env /build/docker/scanner-versions.env
COPY infrastructure/scripts/install-scanners.sh /build/infrastructure/scripts/install-scanners.sh
RUN UV_PYTHON_DOWNLOADS=never SCANNER_PYTHON=/usr/local/bin/python3.12 \
    /build/infrastructure/scripts/install-scanners.sh /opt/scanners

FROM base AS runtime
COPY --from=deps /app/.venv /app/.venv
COPY --chown=riskgraph:riskgraph backend/ /app/
RUN --mount=type=cache,target=/root/.cache/uv uv sync --frozen --no-dev
ENV PATH="/app/.venv/bin:$PATH"
# Pre-created with the right owner so named volumes mounted here inherit it.
RUN mkdir -p /var/lib/riskgraph/workspaces /var/lib/riskgraph/scan_output /var/cache/riskgraph/trivy \
    && chown -R riskgraph:riskgraph /var/lib/riskgraph /var/cache/riskgraph
USER riskgraph
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/healthz', timeout=2).status==200 else 1)" || exit 1
CMD ["uvicorn", "--factory", "riskgraph.entrypoints.api:create_app", "--host", "0.0.0.0", "--port", "8000"]

FROM runtime AS worker
USER root
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=scanner-tools /opt/scanners /opt/scanners
ENV RISKGRAPH_SCANNER_BIN_DIR=/opt/scanners/bin \
    RISKGRAPH_SEMGREP_RULES_PATH=/opt/scanners/semgrep-rules \
    RISKGRAPH_TRIVY_CACHE_DIR=/var/cache/riskgraph/trivy
USER riskgraph
HEALTHCHECK NONE
CMD ["celery", "-A", "riskgraph.entrypoints.worker:celery_app", "worker", "-Q", "scan,analysis", "--concurrency", "2"]
