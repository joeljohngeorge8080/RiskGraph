"""Finding endpoints: prioritized list, breakdown, triage, scan diff and the CI gate."""

from __future__ import annotations

import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from riskgraph.modules import audit, graph
from riskgraph.modules.findings import history, service, triage
from riskgraph.modules.findings.models import Finding
from riskgraph.modules.findings.schemas import (
    AttackPathOut,
    AuditOut,
    DiffItem,
    DiffOut,
    FindingDetailOut,
    FindingList,
    FindingListItem,
    GateOut,
    OccurrenceOut,
    ReachabilityOut,
    RiskFactorOut,
    RiskScoreOut,
    TriageIn,
    TriageOut,
    VulnerabilityOut,
)
from riskgraph.modules.risk import RiskScore
from riskgraph.shared.db import get_session
from riskgraph.shared.problems import NotFound
from riskgraph.shared.vocabulary import (
    FindingChange,
    FindingStatus,
    Priority,
    ReachabilityTier,
    ScannerName,
    Severity,
    SourceType,
)

router = APIRouter(tags=["findings"])
SessionDep = Annotated[Session, Depends(get_session)]


def _float(value: object) -> float | None:
    return float(value) if value is not None else None  # type: ignore[arg-type]


def require_scan(session: Session, scan_id: uuid.UUID):  # type: ignore[no-untyped-def]
    """The scan or 404 (scans imports findings, so the model is imported lazily)."""
    from riskgraph.modules.scans import ScanJob

    scan = session.get(ScanJob, scan_id)
    if scan is None:
        raise NotFound("Scan not found")
    return scan


def path_out(p: graph.AttackPath, finding_ids: list[uuid.UUID]) -> AttackPathOut:
    return AttackPathOut(
        id=p.id,
        source=p.source,
        sink=p.sink,
        rank=p.rank,
        hops=p.hops,
        nodes=p.nodes,
        edges=p.edges,
        probability=float(p.probability),
        sink_impact=float(p.sink_impact),
        score=float(p.score),
        finding_ids=finding_ids,
    )


@router.get("/scans/{scan_id}/findings", response_model=FindingList)
def list_findings(
    scan_id: uuid.UUID,
    session: SessionDep,
    priority: Annotated[list[Priority] | None, Query()] = None,
    source_type: Annotated[list[SourceType] | None, Query()] = None,
    scanner: Annotated[list[ScannerName] | None, Query()] = None,
    severity: Annotated[list[Severity] | None, Query()] = None,
    status: Annotated[list[FindingStatus] | None, Query()] = None,
    change: Annotated[list[FindingChange] | None, Query()] = None,
    reachability: Annotated[list[ReachabilityTier] | None, Query()] = None,
    q: Annotated[str | None, Query(max_length=100)] = None,
    min_score: Annotated[float | None, Query(ge=0, le=100)] = None,
    sort: Annotated[Literal["risk", "score", "severity", "title", "file"], Query()] = "risk",
    order: Annotated[Literal["asc", "desc"], Query()] = "desc",
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> FindingList:
    """``status`` defaults to ``open``: triaged and fixed findings are hidden unless asked for."""
    require_scan(session, scan_id)
    filters = service.FindingFilters(
        priority=tuple(priority or ()),
        source_type=tuple(source_type or ()),
        scanner=tuple(s.value for s in scanner or ()),
        severity=tuple(severity or ()),
        status=tuple(status) if status else (FindingStatus.OPEN,),
        change=tuple(change or ()),
        reachability=tuple(reachability or ()),
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
            status=f.status,
            change=c,
            reachability=tier,
        )
        for f, detected_by, r, v, c, tier in rows
    ]
    return FindingList(items=items, total=total, limit=limit, offset=offset)


@router.get("/findings/{finding_id}", response_model=FindingDetailOut)
def get_finding(
    finding_id: uuid.UUID,
    session: SessionDep,
    scan_id: Annotated[uuid.UUID | None, Query()] = None,
) -> FindingDetailOut:
    d = service.get_finding_detail(session, finding_id, scan_id)
    f, s, v, reach = d.finding, d.score, d.vulnerability, d.reachability
    paths = graph.paths_for_finding(session, d.scan_id, f.id) if d.scan_id else []
    path_findings = graph.path_findings(session, [p.id for p in paths])
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
        status_reason=f.status_reason,
        status_changed_at=f.status_changed_at,
        change=d.change,
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
            effective_impact=_float(s.effective_impact),
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
        reachability=ReachabilityOut(
            tier=reach.tier,
            confidence=reach.confidence,
            evidence=reach.evidence,
            analyzer_version=reach.analyzer_version,
        )
        if reach is not None
        else None,
        attack_paths=[path_out(p, path_findings.get(p.id, [])) for p in paths],
        history=[
            AuditOut(
                at=a.at,
                actor=a.actor,
                action=a.action,
                before=a.before,
                after=a.after,
                reason=a.reason,
            )
            for a in audit.history(session, "finding", f.id)
        ],
    )


@router.patch("/findings/{finding_id}", response_model=TriageOut)
def triage_finding(finding_id: uuid.UUID, body: TriageIn, session: SessionDep) -> TriageOut:
    """Mark a finding false positive / accepted risk / won't fix, or reopen it (audited)."""
    f = triage.set_status(session, finding_id, body.status, body.reason)
    return TriageOut(
        id=f.id,
        status=f.status,
        status_reason=f.status_reason,
        status_changed_at=f.status_changed_at,
    )


def _diff_items(rows: list[tuple[Finding, RiskScore | None]]) -> list[DiffItem]:
    return [
        DiffItem(
            id=f.id,
            title=f.title,
            source_type=f.source_type,
            severity=f.severity,
            location=f.location,
            status=f.status,
            priority=r.priority if r else None,
            score=float(r.score) if r else None,
        )
        for f, r in rows
    ]


@router.get("/scans/{scan_id}/diff", response_model=DiffOut)
def scan_diff(
    scan_id: uuid.UUID,
    session: SessionDep,
    against: Annotated[uuid.UUID | None, Query()] = None,
) -> DiffOut:
    scan = require_scan(session, scan_id)
    if against is not None:
        other = require_scan(session, against)
        if other.repository_id != scan.repository_id:
            raise NotFound("The scans belong to different repositories")
    d = history.diff_scans(session, scan_id, scan.repository_id, scan.requested_ref, against)
    return DiffOut(
        scan_id=scan_id,
        previous_scan_id=d.previous_scan_id,
        new=_diff_items(d.new),
        reopened=_diff_items(d.reopened),
        fixed=_diff_items(d.fixed),
    )


@router.get("/scans/{scan_id}/gate", response_model=GateOut)
def scan_gate(
    scan_id: uuid.UUID,
    session: SessionDep,
    fail_on: Annotated[list[Priority] | None, Query()] = None,
    max_score: Annotated[float | None, Query(ge=0, le=100)] = None,
    new_only: bool = False,
    include_statuses: Annotated[list[FindingStatus] | None, Query()] = None,
) -> GateOut:
    """Blueprint §19 policy check, e.g. ``?fail_on=critical&fail_on=high&new_only=true``."""
    scan = require_scan(session, scan_id)
    policy = triage.GatePolicy(
        fail_on=tuple(fail_on) if fail_on else (Priority.CRITICAL,),
        max_score=max_score,
        new_only=new_only,
        include_statuses=tuple(include_statuses) if include_statuses else (FindingStatus.OPEN,),
    )
    result = triage.evaluate_gate(session, scan_id, policy)
    passed = result.passed and scan.status.value in ("COMPLETED", "PARTIAL")
    return GateOut(
        scan_id=scan_id,
        scan_status=scan.status.value,
        passed=passed,
        policy=result.policy,
        evaluated=result.evaluated,
        violations=result.violations,
    )
