"""SBOM endpoint: the scan's package inventory (blueprint §17, roadmap P5)."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from riskgraph.modules.findings.router import require_scan
from riskgraph.modules.sbom.service import page_components
from riskgraph.shared.db import get_session

router = APIRouter(tags=["sbom"])
SessionDep = Annotated[Session, Depends(get_session)]


class ComponentOut(BaseModel):
    id: uuid.UUID
    purl: str
    name: str
    version: str
    ecosystem: str
    location: str | None
    discovered_by: str
    findings: int


class SbomOut(BaseModel):
    items: list[ComponentOut]
    total: int


@router.get("/scans/{scan_id}/sbom", response_model=SbomOut)
def scan_sbom(
    scan_id: uuid.UUID,
    session: SessionDep,
    ecosystem: Annotated[str | None, Query(max_length=32)] = None,
    name: Annotated[str | None, Query(max_length=256)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
) -> SbomOut:
    require_scan(session, scan_id)
    rows, total = page_components(
        session, scan_id, ecosystem=ecosystem, name=name, limit=limit, offset=offset
    )
    return SbomOut(
        items=[
            ComponentOut(
                id=c.id,
                purl=c.purl,
                name=c.name,
                version=c.version,
                ecosystem=c.ecosystem,
                location=c.location,
                discovered_by=c.discovered_by,
                findings=n,
            )
            for c, n in rows
        ],
        total=total,
    )
