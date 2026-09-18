"""FastAPI application factory.

Run with ``uvicorn --factory riskgraph.entrypoints.api:create_app``. Keeping the app
behind a factory means importing this module never reads the environment, so tests can
build apps with explicit settings.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from riskgraph import __version__
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

    log.info("api_configured", env=settings.env, docs=docs_enabled)
    return app
