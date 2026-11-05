"""FastAPI application factory.

Run with ``uvicorn --factory riskgraph.entrypoints.api:create_app``. Keeping the app
behind a factory means importing this module never reads the environment, so tests can
build apps with explicit settings.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from riskgraph import __version__
from riskgraph.modules.authz.router import router as authz_router
from riskgraph.modules.context.router import router as context_router
from riskgraph.modules.explain.router import router as explain_router
from riskgraph.modules.findings.router import router as findings_router
from riskgraph.modules.graph.router import router as graph_router
from riskgraph.modules.repositories.router import router as repositories_router
from riskgraph.modules.risk.router import router as risk_router
from riskgraph.modules.sbom.router import router as sbom_router
from riskgraph.modules.scans import router as scans_router
from riskgraph.shared import health
from riskgraph.shared.config import Settings, get_settings
from riskgraph.shared.logging import configure_logging, get_logger
from riskgraph.shared.problems import register_problem_handlers
from riskgraph.shared.request_id import RequestIdMiddleware

API_PREFIX = "/api/v1"


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level, settings.log_json)
    log = get_logger(__name__)
    if settings.is_prod:
        # MVP has no authentication (ADR-0010): it must never be deployed as production.
        raise RuntimeError("RiskGraph MVP has no authentication; refusing to start with env=prod")

    docs_enabled = settings.api_docs_enabled and not settings.is_prod
    app = FastAPI(
        title="RiskGraph API",
        version=__version__,
        docs_url=f"{API_PREFIX}/docs" if docs_enabled else None,
        redoc_url=None,
        openapi_url=f"{API_PREFIX}/openapi.json" if docs_enabled else None,
    )
    # Middleware order: CORS outermost so preflight succeeds; request id inside it.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID", "X-API-Key"],
        expose_headers=["X-Request-ID"],
    )
    app.add_middleware(RequestIdMiddleware)
    register_problem_handlers(app)

    app.include_router(health.router, prefix=API_PREFIX)
    app.include_router(scans_router, prefix=API_PREFIX)
    app.include_router(findings_router, prefix=API_PREFIX)
    app.include_router(graph_router, prefix=API_PREFIX)
    app.include_router(repositories_router, prefix=API_PREFIX)
    app.include_router(context_router, prefix=API_PREFIX)
    app.include_router(sbom_router, prefix=API_PREFIX)
    app.include_router(risk_router, prefix=API_PREFIX)
    app.include_router(explain_router, prefix=API_PREFIX)
    app.include_router(authz_router, prefix=API_PREFIX)

    log.info("api_configured", env=settings.env, docs=docs_enabled)
    log.warning("auth_disabled_mvp", detail="bind the API to localhost only (ADR-0010)")
    return app
