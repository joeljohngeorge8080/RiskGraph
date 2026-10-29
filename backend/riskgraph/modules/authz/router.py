"""Route inventory endpoint (X5 part 1, plan §4 X5 "route inventory endpoint")."""

from __future__ import annotations

import uuid
from collections import Counter
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from riskgraph.modules.authz.schemas import ManualCheckOut, ManualChecksOut, RouteOut, RoutesOut
from riskgraph.modules.authz.service import MANUAL_ORDER, list_routes, manual_checks
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


@router.get("/scans/{scan_id}/authz/manual", response_model=ManualChecksOut)
def scan_manual_checks(
    scan_id: uuid.UUID,
    session: SessionDep,
    kind: Literal["bola", "policy_unchecked", "unresolved", "unknown_framework", "custom"]
    | None = None,
) -> ManualChecksOut:
    """Manual verification required: every BOLA hypothesis (test it with two users), every
    route a manifest rule could not be checked against, and every route whose guard is
    undecided or only a name that looks like authentication. Ordered by kind, then file
    and line; ``by_kind`` counts the whole scan."""
    require_scan(session, scan_id)
    items = [ManualCheckOut(**i) for i in manual_checks(session, scan_id)]
    counts = Counter(i.kind for i in items)
    shown = [i for i in items if kind is None or i.kind == kind]
    return ManualChecksOut(
        items=shown,
        total=len(shown),
        by_kind={k: counts[k] for k in MANUAL_ORDER if counts[k]},
    )
