"""Liveness and readiness endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from riskgraph import __version__
from riskgraph.shared.db import check_database
from riskgraph.shared.logging import get_logger
from riskgraph.shared.problems import problem_response
from riskgraph.shared.redis import check_redis

router = APIRouter(tags=["health"])
log = get_logger(__name__)


class Health(BaseModel):
    status: str
    version: str


class Readiness(BaseModel):
    status: str
    checks: dict[str, str]


@router.get("/healthz", response_model=Health)
def healthz() -> Health:
    """Process is up. Never touches dependencies."""
    return Health(status="ok", version=__version__)


@router.get("/readyz", response_model=Readiness, responses={503: {"description": "Not ready"}})
def readyz(request: Request) -> JSONResponse:
    """Dependencies reachable. Returns 503 problem+json with per-check detail otherwise."""
    checks: dict[str, str] = {}
    for name, probe in (("database", check_database), ("redis", check_redis)):
        try:
            probe()
            checks[name] = "ok"
        except Exception as exc:
            log.warning("readiness_check_failed", check=name, error=type(exc).__name__)
            checks[name] = f"error: {type(exc).__name__}"
    if all(v == "ok" for v in checks.values()):
        return JSONResponse(Readiness(status="ok", checks=checks).model_dump())
    return problem_response(
        request,
        status=503,
        slug="not-ready",
        title="Service Unavailable",
        detail="One or more dependencies are unavailable",
        extra={"checks": checks},
    )
