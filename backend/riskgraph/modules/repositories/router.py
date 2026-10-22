"""Repository endpoints: list and per-repository scan history (trend)."""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from riskgraph.modules.repositories.models import Repository
from riskgraph.shared.db import get_session
from riskgraph.shared.problems import NotFound

router = APIRouter(prefix="/repositories", tags=["repositories"])
SessionDep = Annotated[Session, Depends(get_session)]


class TrendPoint(BaseModel):
    scan_id: uuid.UUID
    status: str
    requested_ref: str
    commit_sha: str | None
    created_at: str
    findings: int | None
    by_priority: dict[str, int]
    new: int | None
    fixed: int | None
    max_score: float | None


class RepositorySummary(BaseModel):
    id: uuid.UUID
    full_name: str
    url: str
    scans: int
    last_scan: TrendPoint | None


class RepositoryDetail(RepositorySummary):
    history: list[TrendPoint]


def _point(scan: Any) -> TrendPoint:
    summary: dict[str, Any] = scan.summary or {}
    hist = summary.get("history") or {}
    return TrendPoint(
        scan_id=scan.id,
        status=scan.status.value,
        requested_ref=scan.requested_ref,
        commit_sha=scan.commit_sha,
        created_at=scan.created_at.isoformat(),
        findings=summary.get("findings"),
        by_priority={k: int(v) for k, v in (summary.get("by_priority") or {}).items()},
        new=hist.get("new"),
        fixed=hist.get("fixed"),
        max_score=summary.get("max_score"),
    )


def _summary(
    session: Session, repo: Repository, history: int
) -> tuple[RepositorySummary, list[TrendPoint]]:
    from riskgraph.modules.scans import ScanJob

    scans = list(
        session.scalars(
            select(ScanJob)
            .where(ScanJob.repository_id == repo.id)
            .order_by(ScanJob.created_at.desc())
            .limit(history)
        )
    )
    total = session.execute(
        select(func.count()).select_from(ScanJob).where(ScanJob.repository_id == repo.id)
    ).scalar_one()
    out = RepositorySummary(
        id=repo.id,
        full_name=f"{repo.owner}/{repo.name}",
        url=f"https://github.com/{repo.owner}/{repo.name}",
        scans=int(total),
        last_scan=_point(scans[0]) if scans else None,
    )
    return out, [_point(s) for s in reversed(scans)]


@router.get("", response_model=list[RepositorySummary])
def list_repositories(
    session: SessionDep, limit: Annotated[int, Query(ge=1, le=200)] = 50
) -> list[RepositorySummary]:
    repos = session.scalars(select(Repository).order_by(Repository.full_name).limit(limit))
    return [_summary(session, r, 1)[0] for r in repos]


@router.get("/{repository_id}", response_model=RepositoryDetail)
def get_repository(
    repository_id: uuid.UUID,
    session: SessionDep,
    history: Annotated[int, Query(ge=1, le=200)] = 30,
) -> RepositoryDetail:
    repo = session.get(Repository, repository_id)
    if repo is None:
        raise NotFound("Repository not found")
    summary, points = _summary(session, repo, history)
    return RepositoryDetail(**summary.model_dump(), history=points)
