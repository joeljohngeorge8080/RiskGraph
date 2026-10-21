"""Persist merged findings for a scan and query them for the API."""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Select, case, delete, func, or_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from riskgraph.modules.context import Vulnerability
from riskgraph.modules.findings.models import Finding, FindingOccurrence, ScanFinding
from riskgraph.modules.normalization import MergedFinding
from riskgraph.modules.risk import RiskFactor, RiskScore
from riskgraph.shared.db.uuid7 import uuid7
from riskgraph.shared.problems import NotFound
from riskgraph.shared.vocabulary import Priority, Severity, SourceType

MAX_EVIDENCE_KEYS = 12


def clear_scan(session: Session, scan_id: uuid.UUID) -> None:
    """Remove a scan's analysis output so ``analyze`` can be re-run idempotently."""
    session.execute(delete(RiskScore).where(RiskScore.scan_job_id == scan_id))
    session.execute(delete(ScanFinding).where(ScanFinding.scan_job_id == scan_id))
    session.execute(delete(FindingOccurrence).where(FindingOccurrence.scan_job_id == scan_id))


def _evidence(value: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, item in list(value.items())[:MAX_EVIDENCE_KEYS]:
        if item is None:
            continue
        if isinstance(item, str):
            item = item[:500]
        elif isinstance(item, list):
            item = [str(x)[:300] for x in item[:5]]
        elif not isinstance(item, int | float | bool):
            item = str(item)[:300]
        out[key] = item
    return out


def persist_merged(
    session: Session,
    *,
    repository_id: uuid.UUID,
    scan_id: uuid.UUID,
    run_ids: dict[str, uuid.UUID],
    merged: MergedFinding,
    now: dt.datetime,
) -> uuid.UUID:
    rep = merged.representative
    values: dict[str, Any] = {
        "repository_id": repository_id,
        "merge_key": merged.merge_key,
        "source_type": merged.source_type,
        "category": rep.category,
        "title": rep.title[:500],
        "description": rep.description,
        "severity": merged.severity,
        "rule_id": rep.rule_id[:300],
        "vulnerability_id": rep.vulnerability_id,
        "package": rep.package,
        "location": rep.location.as_dict(),
        "cwe_ids": list(merged.cwe_ids),
        "detected_by": list(merged.detected_by),
        "remediation": rep.remediation,
        "status": "open",
        "first_seen_scan_id": scan_id,
        "last_seen_scan_id": scan_id,
        "first_seen_at": now,
        "last_seen_at": now,
    }
    stmt = insert(Finding).values(id=uuid7(), **values)
    refreshed = (
        "category",
        "title",
        "description",
        "severity",
        "rule_id",
        "package",
        "location",
        "cwe_ids",
        "detected_by",
        "remediation",
        "last_seen_scan_id",
        "last_seen_at",
    )
    update = {k: stmt.excluded[k] for k in refreshed} | {"updated_at": now}
    upsert = stmt.on_conflict_do_update(
        index_elements=["repository_id", "merge_key"], set_=update
    ).returning(Finding.id)
    finding_id: uuid.UUID = session.execute(upsert).scalar_one()

    session.add(
        ScanFinding(
            scan_job_id=scan_id, finding_id=finding_id, detected_by=list(merged.detected_by)
        )
    )
    session.add_all(
        FindingOccurrence(
            scan_job_id=scan_id,
            scanner_run_id=run_ids[m.scanner.value],
            finding_id=finding_id,
            scanner=m.scanner,
            rule_id=m.rule_id[:300],
            fingerprint=m.fingerprint,
            scanner_severity=m.scanner_severity,
            severity=m.severity,
            title=m.title[:500],
            location=m.location.as_dict(),
            evidence=_evidence(m.evidence),
            created_at=now,
        )
        for m in merged.members
    )
    return finding_id


# --- queries -------------------------------------------------------------------------

SORTS = ("risk", "score", "severity", "title", "file")

_SEVERITY_RANK = case(
    {s.value: s.rank for s in Severity},
    value=Finding.severity,
    else_=0,
)


@dataclass(frozen=True, slots=True)
class FindingFilters:
    priority: tuple[Priority, ...] = ()
    source_type: tuple[SourceType, ...] = ()
    scanner: tuple[str, ...] = ()
    severity: tuple[Severity, ...] = ()
    q: str | None = None
    min_score: float | None = None


def _base_query(scan_id: uuid.UUID) -> Select[Any]:
    return (
        select(Finding, ScanFinding.detected_by, RiskScore, Vulnerability)
        .join(ScanFinding, ScanFinding.finding_id == Finding.id)
        .join(
            RiskScore,
            (RiskScore.finding_id == Finding.id)
            & (RiskScore.scan_job_id == ScanFinding.scan_job_id),
        )
        .outerjoin(Vulnerability, Vulnerability.id == Finding.vulnerability_id)
        .where(ScanFinding.scan_job_id == scan_id)
    )


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def list_scan_findings(
    session: Session,
    scan_id: uuid.UUID,
    filters: FindingFilters,
    *,
    sort: str = "risk",
    order: str = "desc",
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[tuple[Finding, list[str], RiskScore, Vulnerability | None]], int]:
    query = _base_query(scan_id)
    if filters.priority:
        query = query.where(RiskScore.priority.in_(filters.priority))
    if filters.source_type:
        query = query.where(Finding.source_type.in_(filters.source_type))
    if filters.severity:
        query = query.where(Finding.severity.in_(filters.severity))
    if filters.scanner:
        query = query.where(ScanFinding.detected_by.overlap(list(filters.scanner)))
    if filters.q:
        pattern = f"%{_escape_like(filters.q)}%"
        query = query.where(
            or_(
                Finding.title.ilike(pattern, escape="\\"),
                Finding.location["file"].astext.ilike(pattern, escape="\\"),
                Finding.rule_id.ilike(pattern, escape="\\"),
            )
        )
    if filters.min_score is not None:
        query = query.where(RiskScore.score >= filters.min_score)

    total = session.execute(select(func.count()).select_from(query.subquery())).scalar_one()

    desc = order != "asc"
    columns: list[Any]
    match sort:
        case "score":
            columns = [RiskScore.score]
        case "severity":
            columns = [_SEVERITY_RANK, RiskScore.score]
        case "title":
            columns = [Finding.title]
        case "file":
            columns = [Finding.location["file"].astext, Finding.location["line_start"].as_integer()]
        case _:
            columns = [RiskScore.priority_rank, RiskScore.score]
    ordered = [c.desc() if desc else c.asc() for c in columns]
    query = query.order_by(*ordered, Finding.title.asc(), Finding.id.asc())
    rows = session.execute(query.limit(limit).offset(offset)).tuples().all()
    return [(f, list(d), r, v) for f, d, r, v in rows], int(total)


@dataclass(frozen=True, slots=True)
class FindingDetail:
    finding: Finding
    scan_id: uuid.UUID | None
    detected_by: list[str]
    occurrences: list[FindingOccurrence]
    score: RiskScore | None
    factors: list[RiskFactor]
    vulnerability: Vulnerability | None


def get_finding_detail(
    session: Session, finding_id: uuid.UUID, scan_id: uuid.UUID | None
) -> FindingDetail:
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise NotFound("Finding not found")
    scan_id = scan_id or finding.last_seen_scan_id
    link = session.get(ScanFinding, (scan_id, finding_id)) if scan_id is not None else None
    if scan_id is not None and link is None:
        raise NotFound("Finding was not seen in that scan")
    occurrences = list(
        session.scalars(
            select(FindingOccurrence)
            .where(
                FindingOccurrence.finding_id == finding_id, FindingOccurrence.scan_job_id == scan_id
            )
            .order_by(FindingOccurrence.scanner, FindingOccurrence.rule_id)
        )
    )
    score_row = session.scalars(
        select(RiskScore).where(
            RiskScore.finding_id == finding_id, RiskScore.scan_job_id == scan_id
        )
    ).one_or_none()
    factors: list[RiskFactor] = []
    if score_row is not None:
        order = {"likelihood": 0, "impact": 1, "adjustment": 2}
        factors = sorted(
            session.scalars(select(RiskFactor).where(RiskFactor.risk_score_id == score_row.id)),
            key=lambda f: (order.get(f.group, 9), "EXRTDPCK".find(f.name)),
        )
    vuln = (
        session.get(Vulnerability, finding.vulnerability_id) if finding.vulnerability_id else None
    )
    return FindingDetail(
        finding=finding,
        scan_id=scan_id,
        detected_by=list(link.detected_by) if link else list(finding.detected_by),
        occurrences=occurrences,
        score=score_row,
        factors=factors,
        vulnerability=vuln,
    )
