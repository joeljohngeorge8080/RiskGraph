"""Risk-ranking queries (blueprint §17: ``GET /risks``). SQL only; the rules live in model.

Not imported by ``risk/__init__``: findings imports risk, so this module imports findings.
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from riskgraph.modules.findings import Finding
from riskgraph.modules.risk.models import RiskFactor, RiskScore
from riskgraph.shared.vocabulary import FindingStatus, Priority

# §14.5: excluded from ranking, kept in audit. Everything else is ranked.
EXCLUDED_FROM_RANKING = (FindingStatus.FALSE_POSITIVE, FindingStatus.ACCEPTED_RISK)


def ranked(
    session: Session,
    scan_id: uuid.UUID,
    *,
    priorities: list[Priority],
    include_excluded: bool,
    limit: int,
    offset: int,
) -> tuple[list[tuple[RiskScore, Finding]], int]:
    """Scores of one scan, highest first; ties by priority, then finding id (stable)."""
    where = [RiskScore.scan_job_id == scan_id]
    if priorities:
        where.append(RiskScore.priority.in_(priorities))
    if not include_excluded:
        where.append(Finding.status.not_in(EXCLUDED_FROM_RANKING))
    base = (
        select(RiskScore, Finding).join(Finding, Finding.id == RiskScore.finding_id).where(*where)
    )
    total = session.scalar(select(func.count()).select_from(base.subquery())) or 0
    rows = session.execute(
        base.order_by(RiskScore.score.desc(), RiskScore.priority_rank.desc(), RiskScore.finding_id)
        .limit(limit)
        .offset(offset)
    ).tuples()
    return list(rows.all()), int(total)


def score_of(
    session: Session, scan_id: uuid.UUID, finding_id: uuid.UUID
) -> tuple[RiskScore, list[RiskFactor]] | None:
    row = session.scalars(
        select(RiskScore).where(
            RiskScore.scan_job_id == scan_id, RiskScore.finding_id == finding_id
        )
    ).first()
    if row is None:
        return None
    factors = list(
        session.scalars(
            select(RiskFactor).where(RiskFactor.risk_score_id == row.id).order_by(RiskFactor.id)
        )
    )
    return row, factors
