# syntax=docker/dockerfile:1.7
# RiskGraph backend image: used by api, worker, beat and migrate services.
FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
COPY --from=ghcr.io/astral-sh/uv:0.11 /uv /usr/local/bin/uv
RUN groupadd --gid 10001 riskgraph && useradd --uid 10001 --gid 10001 --create-home riskgraph
WORKDIR /app

FROM base AS deps
COPY backend/pyproject.toml backend/uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project

FROM base AS runtime
COPY --from=deps /app/.venv /app/.venv
COPY --chown=riskgraph:riskgraph backend/ /app/
RUN --mount=type=cache,target=/root/.cache/uv uv sync --frozen --no-dev
ENV PATH="/app/.venv/bin:$PATH"
USER riskgraph
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/healthz', timeout=2).status==200 else 1)" || exit 1
CMD ["uvicorn", "--factory", "riskgraph.entrypoints.api:create_app", "--host", "0.0.0.0", "--port", "8000"]
