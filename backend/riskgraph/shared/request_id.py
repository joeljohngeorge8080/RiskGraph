"""Request-id middleware: accepts or generates ``X-Request-ID``, binds it to logs."""

from __future__ import annotations

import re
import time
import uuid

import structlog
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from riskgraph.shared.logging import get_logger

HEADER = "X-Request-ID"
_SAFE_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
log = get_logger("riskgraph.http")


class RequestIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        incoming = request.headers.get(HEADER, "")
        request_id = incoming if _SAFE_ID.match(incoming) else str(uuid.uuid4())
        request.state.request_id = request_id
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)
        started = time.perf_counter()
        try:
            response = await call_next(request)
        finally:
            elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
            log.info(
                "request",
                method=request.method,
                path=request.url.path,
                duration_ms=elapsed_ms,
            )
        response.headers[HEADER] = request_id
        response.headers["Cache-Control"] = "no-store"
        return response
