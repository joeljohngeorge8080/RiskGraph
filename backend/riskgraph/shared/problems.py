"""RFC 7807 problem details.

All error responses from the API use ``application/problem+json``. Services raise
``Problem`` (or a subclass); routers never build error bodies by hand. Stack traces are
never returned.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from riskgraph.shared.logging import get_logger

log = get_logger(__name__)

PROBLEM_TYPE_BASE = "https://riskgraph.dev/problems/"
MEDIA_TYPE = "application/problem+json"


class Problem(Exception):  # noqa: N818 - RFC 7807 term; subclasses read as HTTP semantics
    """A service-level error with an HTTP mapping."""

    status: int = 500
    slug: str = "internal-error"
    title: str = "Internal Server Error"

    def __init__(self, detail: str | None = None, *, extra: dict[str, Any] | None = None):
        super().__init__(detail or self.title)
        self.detail = detail
        self.extra = extra or {}


class NotFound(Problem):
    status = 404
    slug = "not-found"
    title = "Not Found"


class Conflict(Problem):
    status = 409
    slug = "conflict"
    title = "Conflict"


class Unauthorized(Problem):
    status = 401
    slug = "unauthorized"
    title = "Unauthorized"


class Forbidden(Problem):
    status = 403
    slug = "forbidden"
    title = "Forbidden"


class UnprocessableEntity(Problem):
    status = 422
    slug = "unprocessable-entity"
    title = "Unprocessable Entity"


class TooManyRequests(Problem):
    status = 429
    slug = "too-many-requests"
    title = "Too Many Requests"


class ServiceUnavailable(Problem):
    status = 503
    slug = "service-unavailable"
    title = "Service Unavailable"


def problem_response(
    request: Request,
    *,
    status: int,
    slug: str,
    title: str,
    detail: str | None = None,
    extra: dict[str, Any] | None = None,
) -> JSONResponse:
    body: dict[str, Any] = {
        "type": PROBLEM_TYPE_BASE + slug,
        "title": title,
        "status": status,
        "instance": str(request.url.path),
    }
    if detail:
        body["detail"] = detail
    request_id = getattr(request.state, "request_id", None)
    if request_id:
        body["request_id"] = request_id
    if extra:
        body.update(extra)
    return JSONResponse(body, status_code=status, media_type=MEDIA_TYPE)


def register_problem_handlers(app: FastAPI) -> None:
    @app.exception_handler(Problem)
    async def _problem(request: Request, exc: Problem) -> JSONResponse:
        return problem_response(
            request,
            status=exc.status,
            slug=exc.slug,
            title=exc.title,
            detail=exc.detail,
            extra=exc.extra,
        )

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        errors = [
            {"loc": [str(p) for p in e.get("loc", ())], "msg": e.get("msg"), "type": e.get("type")}
            for e in exc.errors()
        ]
        return problem_response(
            request,
            status=422,
            slug="validation-error",
            title="Unprocessable Entity",
            detail="Request validation failed",
            extra={"errors": errors},
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        slug = {404: "not-found", 405: "method-not-allowed"}.get(exc.status_code, "http-error")
        detail = exc.detail if isinstance(exc.detail, str) else None
        return problem_response(
            request, status=exc.status_code, slug=slug, title=detail or "Error", detail=None
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled_error", path=request.url.path)
        return problem_response(
            request,
            status=500,
            slug="internal-error",
            title="Internal Server Error",
            detail="An unexpected error occurred",
        )
