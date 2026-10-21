"""Finding endpoints: the prioritized list for a scan and one finding's breakdown."""

from __future__ import annotations

import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from riskgraph.modules.findings import service
from riskgraph.modules.findings.schemas import (
    FindingDetailOut,
    FindingList,
    FindingListItem,
    OccurrenceOut,
    RiskFactorOut,
    RiskScoreOut,
    VulnerabilityOut,
)
from riskgraph.shared.db import get_session
from riskgraph.shared.problems import NotFound
from riskgraph.shared.vocabulary import Priority, ScannerName, Severity, SourceType

router = APIRouter(tags=["findings"])
SessionDep = Annotated[Session, Depends(get_session)]


def _float(value: object) -> float | None:
    return float(value) if value is not None else None  # type: ignore[arg-type]


@router.get("/scans/{scan_id}/findings", response_model=FindingList)
def list_findings(
    scan_id: uuid.UUID,
    session: SessionDep,
    priority: Annotated[list[Priority] | None, Query()] = None,
    source_type: Annotated[list[SourceType] | None, Query()] = None,
    scanner: Annotated[list[ScannerName] | None, Query()] = None,
    severity: Annotated[list[Severity] | None, Query()] = None,
    q: Annotated[str | None, Query(max_length=100)] = None,
    min_score: Annotated[float | None, Query(ge=0, le=100)] = None,
    sort: Annotated[Literal["risk", "score", "severity", "title", "file"], Query()] = "risk",
    order: Annotated[Literal["asc", "desc"], Query()] = "desc",
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> FindingList:
    from riskgraph.modules.scans import ScanJob

    if session.get(ScanJob, scan_id) is None:
        raise NotFound("Scan not found")
    filters = service.FindingFilters(
        priority=tuple(priority or ()),
        source_type=tuple(source_type or ()),
        scanner=tuple(s.value for s in scanner or ()),
        severity=tuple(severity or ()),
        q=q or None,
        min_score=min_score,
    )
    rows, total = service.list_scan_findings(
        session, scan_id, filters, sort=sort, order=order, limit=limit, offset=offset
    )
    items = [
        FindingListItem(
            id=f.id,
            title=f.title,
            source_type=f.source_type,
            category=f.category,
            severity=f.severity,
            priority=r.priority,
            score=float(r.score),
            detected_by=detected_by,
            location=f.location,
            rule_id=f.rule_id,
            vulnerability_id=f.vulnerability_id,
            package=f.package,
            epss=_float(v.epss) if v else None,
            kev=v.kev if v else None,
        )
        for f, detected_by, r, v in rows
    ]
    return FindingList(items=items, total=total, limit=limit, offset=offset)


@router.get("/findings/{finding_id}", response_model=FindingDetailOut)
def get_finding(
    finding_id: uuid.UUID,
    session: SessionDep,
    scan_id: Annotated[uuid.UUID | None, Query()] = None,
) -> FindingDetailOut:
    d = service.get_finding_detail(session, finding_id, scan_id)
    f, s, v = d.finding, d.score, d.vulnerability
    return FindingDetailOut(
        id=f.id,
        scan_id=d.scan_id,
        title=f.title,
        description=f.description,
        remediation=f.remediation,
        source_type=f.source_type,
        category=f.category,
        severity=f.severity,
        rule_id=f.rule_id,
        cwe_ids=list(f.cwe_ids),
        location=f.location,
        package=f.package,
        detected_by=d.detected_by,
        status=f.status,
        first_seen_at=f.first_seen_at,
        last_seen_at=f.last_seen_at,
        occurrences=[
            OccurrenceOut(
                scanner=o.scanner,
                rule_id=o.rule_id,
                title=o.title,
                severity=o.severity,
                scanner_severity=o.scanner_severity,
                location=o.location,
                evidence=o.evidence,
            )
            for o in d.occurrences
        ],
        risk=RiskScoreOut(
            model_version=s.model_version,
            score=float(s.score),
            priority=s.priority,
            likelihood=float(s.likelihood),
            impact=float(s.impact),
            corroboration=float(s.corroboration),
            overrides=s.overrides,
            factors=[
                RiskFactorOut(
                    group=x.group,
                    name=x.name,
                    value=float(x.value),
                    raw_value=x.raw_value,
                    source=x.source,
                    confidence=x.confidence,
                    applicable=x.applicable,
                    evidence=x.evidence,
                )
                for x in d.factors
            ],
            computed_at=s.computed_at,
        )
        if s is not None
        else None,
        vulnerability=VulnerabilityOut(
            id=v.id,
            cvss_vector=v.cvss_vector,
            cvss_base=_float(v.cvss_base),
            cvss_impact=_float(v.cvss_impact),
            cvss_exploitability=_float(v.cvss_exploitability),
            cvss_source=v.cvss_source,
            epss=_float(v.epss),
            epss_percentile=_float(v.epss_percentile),
            kev=v.kev,
            kev_added=v.kev_added,
        )
        if v is not None
        else None,
    )
