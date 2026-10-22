"""Context endpoint: the environment a repository was last scanned in (blueprint §17.2)."""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from riskgraph.modules.context.service import list_assets
from riskgraph.modules.scans.models import ScanJob
from riskgraph.shared.db import get_session
from riskgraph.shared.problems import NotFound
from riskgraph.shared.vocabulary import ScanStatus

router = APIRouter(prefix="/repositories", tags=["context"])
SessionDep = Annotated[Session, Depends(get_session)]
FINISHED = (ScanStatus.COMPLETED, ScanStatus.PARTIAL)


class AssetOut(BaseModel):
    kind: str
    name: str
    source_path: str
    attrs: dict[str, Any]


class ContextOut(BaseModel):
    repository_id: uuid.UUID
    scan_id: uuid.UUID
    commit_sha: str | None
    context: dict[str, Any]
    iac: dict[str, Any]
    assets: list[AssetOut]


@router.get("/{repository_id}/context", response_model=ContextOut)
def repository_context(repository_id: uuid.UUID, session: SessionDep) -> ContextOut:
    scan = session.scalars(
        select(ScanJob)
        .where(ScanJob.repository_id == repository_id, ScanJob.status.in_(FINISHED))
        .order_by(ScanJob.created_at.desc())
        .limit(1)
    ).first()
    if scan is None:
        raise NotFound("no finished scan for this repository")
    summary = scan.summary or {}
    return ContextOut(
        repository_id=repository_id,
        scan_id=scan.id,
        commit_sha=scan.commit_sha,
        context=summary.get("context", {}),
        iac=summary.get("iac", {}),
        assets=[
            AssetOut(kind=a.kind, name=a.name, source_path=a.source_path, attrs=a.attrs)
            for a in list_assets(session, scan.id)
        ],
    )
