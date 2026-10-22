"""Triage (status changes by a person) and the CI gate policy."""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from riskgraph.modules.audit import record
from riskgraph.modules.findings.models import Finding, ScanFinding
from riskgraph.modules.risk import RiskScore
from riskgraph.shared.problems import NotFound, UnprocessableEntity
from riskgraph.shared.vocabulary import (
    TRIAGE_STATUSES,
    FindingChange,
    FindingStatus,
    Priority,
)

SETTABLE = (FindingStatus.OPEN, *TRIAGE_STATUSES)
MAX_REASON = 500


class InvalidTriage(UnprocessableEntity):
    slug = "invalid-triage"
    title = "Invalid status change"


def set_status(
    session: Session, finding_id: uuid.UUID, status: FindingStatus, reason: str | None
) -> Finding:
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise NotFound("Finding not found")
    if status not in SETTABLE:
        raise InvalidTriage("'fixed' is set by scans, not by hand")
    reason = (reason or "").strip() or None
    if status is not FindingStatus.OPEN and reason is None:
        raise InvalidTriage("A reason is required for this status")
    if reason is not None and len(reason) > MAX_REASON:
        raise InvalidTriage(f"Reason is longer than {MAX_REASON} characters")
    before = {"status": finding.status.value, "reason": finding.status_reason}
    finding.status = status
    finding.status_reason = reason
    finding.status_changed_at = dt.datetime.now(dt.UTC)
    if status is not FindingStatus.FIXED:
        finding.fixed_in_scan_id = None
    record(
        session,
        action="finding.status",
        entity="finding",
        entity_id=finding.id,
        before=before,
        after={"status": status.value, "reason": reason},
        reason=reason,
    )
    session.flush()
    return finding


# --- gate ----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class GatePolicy:
    """Blueprint §19 ``fail_when``: any matching finding fails the gate."""

    fail_on: tuple[Priority, ...] = (Priority.CRITICAL,)
    max_score: float | None = None
    new_only: bool = False
    include_statuses: tuple[FindingStatus, ...] = (FindingStatus.OPEN,)

    def as_dict(self) -> dict[str, Any]:
        return {
            "fail_on": [p.value for p in self.fail_on],
            "max_score": self.max_score,
            "new_only": self.new_only,
            "include_statuses": [s.value for s in self.include_statuses],
        }


@dataclass(frozen=True, slots=True)
class GateResult:
    passed: bool
    policy: dict[str, Any]
    violations: list[dict[str, Any]] = field(default_factory=list)
    evaluated: int = 0


def evaluate_gate(session: Session, scan_id: uuid.UUID, policy: GatePolicy) -> GateResult:
    query = (
        select(Finding, ScanFinding.change, RiskScore)
        .join(ScanFinding, ScanFinding.finding_id == Finding.id)
        .join(
            RiskScore,
            (RiskScore.finding_id == Finding.id)
            & (RiskScore.scan_job_id == ScanFinding.scan_job_id),
        )
        .where(ScanFinding.scan_job_id == scan_id, Finding.status.in_(policy.include_statuses))
    )
    if policy.new_only:
        query = query.where(ScanFinding.change.in_((FindingChange.NEW, FindingChange.REOPENED)))
    rows = session.execute(query).tuples().all()
    violations: list[dict[str, Any]] = []
    for finding, change, score in rows:
        reasons = []
        if score.priority in policy.fail_on:
            reasons.append(f"priority {score.priority.value}")
        if policy.max_score is not None and float(score.score) >= policy.max_score:
            reasons.append(f"score {float(score.score):.1f} >= {policy.max_score:g}")
        if reasons:
            violations.append(
                {
                    "finding_id": str(finding.id),
                    "title": finding.title,
                    "priority": score.priority.value,
                    "score": float(score.score),
                    "change": change.value,
                    "location": finding.location,
                    "reasons": reasons,
                }
            )
    violations.sort(key=lambda v: (-float(v["score"]), str(v["title"])))
    return GateResult(not violations, policy.as_dict(), violations[:100], len(rows))
