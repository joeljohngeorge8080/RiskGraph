"""Route inventory endpoint (X5 part 1, plan §4 X5 "route inventory endpoint")."""

from __future__ import annotations

import uuid
from collections import Counter
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from riskgraph.modules.authz.schemas import RouteOut, RoutesOut
from riskgraph.modules.authz.service import list_routes
from riskgraph.modules.findings.router import require_scan
from riskgraph.shared.db import get_session

router = APIRouter(tags=["authz"])
SessionDep = Annotated[Session, Depends(get_session)]
Status = Literal["guarded", "custom", "none_found", "unresolved", "unknown_framework"]


@router.get("/scans/{scan_id}/routes", response_model=RoutesOut)
def scan_routes(
    scan_id: uuid.UUID,
    session: SessionDep,
    status: Status | None = None,
    framework: Annotated[str | None, Query(max_length=32)] = None,
) -> RoutesOut:
    """Every route the extractor found, by file and line, with its guard status. A guard is
    at most inferred; ``none_found`` is only said when every place a guard could come
    from was resolved (ADR-0022). Scans from before X5 have no routes."""
    require_scan(session, scan_id)
    routes = [RouteOut.from_payload(row.id, row.payload) for row in list_routes(session, scan_id)]
    counts = Counter(r.guard_status for r in routes)
    items = [
        r
        for r in routes
        if (status is None or r.guard_status == status)
        and (framework is None or r.framework == framework)
    ]
    return RoutesOut(items=items, total=len(items), by_status=dict(sorted(counts.items())))
