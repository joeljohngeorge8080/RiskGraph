"""Risk ranking endpoints (blueprint §17): ``GET /risks`` and ``GET /risks/{finding_id}``."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from riskgraph.modules.findings.router import require_scan, risk_out
from riskgraph.modules.findings.schemas import RiskScoreOut
from riskgraph.modules.risk import repo
from riskgraph.shared.db import get_session
from riskgraph.shared.problems import NotFound, UnprocessableEntity
from riskgraph.shared.vocabulary import FindingStatus, Priority, ScanStatus, SourceType

router = APIRouter(prefix="/risks", tags=["risks"])
SessionDep = Annotated[Session, Depends(get_session)]
FINISHED = (ScanStatus.COMPLETED, ScanStatus.PARTIAL)
DEFAULT_FACTORS = frozenset({"default", "default_unknown", "not_applicable"})


class RiskItemOut(BaseModel):
    rank: int
    finding_id: uuid.UUID
    title: str
    source_type: SourceType
    category: str
    file: str | None
    line: int | None
    status: FindingStatus
    score: float
    priority: Priority
    likelihood: float
    impact: float
    effective_impact: float | None
    model_version: str
    overrides: list[str]


class RiskListOut(BaseModel):
    scan_id: uuid.UUID
    items: list[RiskItemOut]
    total: int


class RiskDetailOut(RiskScoreOut):
    finding_id: uuid.UUID
    scan_id: uuid.UUID
    reasons: list[str]  # the non-default factors: what moved this score off the baseline


def _latest_scan(session: Session, repository_id: uuid.UUID) -> uuid.UUID:
    from riskgraph.modules.scans import ScanJob  # scans imports risk: lazy, like require_scan

    sid = session.scalars(
        select(ScanJob.id)
        .where(ScanJob.repository_id == repository_id, ScanJob.status.in_(FINISHED))
        .order_by(ScanJob.created_at.desc())
        .limit(1)
    ).first()
    if sid is None:
        raise NotFound("no finished scan for this repository")
    return sid


def _scan_id(
    session: Session, scan_id: uuid.UUID | None, repository_id: uuid.UUID | None
) -> uuid.UUID:
    if scan_id is not None and repository_id is None:
        require_scan(session, scan_id)
        return scan_id
    if repository_id is not None and scan_id is None:
        return _latest_scan(session, repository_id)
    raise UnprocessableEntity("pass exactly one of scan_id or repository_id")


@router.get("", response_model=RiskListOut)
def list_risks(
    session: SessionDep,
    scan_id: uuid.UUID | None = None,
    repository_id: uuid.UUID | None = None,
    priority: Annotated[list[Priority] | None, Query()] = None,
    include_excluded: bool = False,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> RiskListOut:
    """Ranked scores for a scan (or a repository's latest finished scan).

    False positives and accepted risks are left out unless ``include_excluded`` (§14.5).
    """
    sid = _scan_id(session, scan_id, repository_id)
    rows, total = repo.ranked(
        session,
        sid,
        priorities=priority or [],
        include_excluded=include_excluded,
        limit=limit,
        offset=offset,
    )
    return RiskListOut(
        scan_id=sid,
        total=total,
        items=[
            RiskItemOut(
                rank=offset + i + 1,
                finding_id=f.id,
                title=f.title,
                source_type=f.source_type,
                category=f.category,
                file=(f.location or {}).get("file"),
                line=(f.location or {}).get("line_start"),
                status=f.status,
                score=float(s.score),
                priority=s.priority,
                likelihood=float(s.likelihood),
                impact=float(s.impact),
                effective_impact=float(s.effective_impact)
                if s.effective_impact is not None
                else None,
                model_version=s.model_version,
                overrides=[str(o.get("rule")) for o in s.overrides],
            )
            for i, (s, f) in enumerate(rows)
        ],
    )


@router.get("/{finding_id}", response_model=RiskDetailOut)
def risk_detail(
    finding_id: uuid.UUID,
    session: SessionDep,
    scan_id: uuid.UUID | None = None,
    repository_id: uuid.UUID | None = None,
) -> RiskDetailOut:
    """Score, factors and overrides of one finding in a scan."""
    sid = _scan_id(session, scan_id, repository_id)
    found = repo.score_of(session, sid, finding_id)
    if found is None:
        raise NotFound("no score for this finding in this scan")
    s, factors = found
    out = risk_out(s, factors)
    reasons = [
        f"{x.name}={x.raw_value or x.value} ({x.source})"
        for x in factors
        if x.applicable and x.source not in DEFAULT_FACTORS and x.group != "adjustment"
    ] + [f"{x.name} ({x.source})" for x in factors if x.name == "I*"]
    return RiskDetailOut(**out.model_dump(), finding_id=finding_id, scan_id=sid, reasons=reasons)
