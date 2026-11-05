"""Scan-to-scan history: new / existing / reopened findings and fixed detection.

Runs at the end of ``analyze`` inside its write transaction. Everything is derived from
stored rows, so re-running the analysis of a scan gives the same result.

Rules (blueprint §10.2, ADR-0013):
- the *previous* scan is the latest COMPLETED/PARTIAL scan of the same repository and ref;
- ``new``: not in the previous scan and first seen in this scan;
- ``reopened``: not in the previous scan but seen in an earlier one (it came back);
- ``existing``: in the previous scan;
- a finding open in the previous scan and absent now becomes ``fixed`` only if every
  scanner that reported it succeeded in this scan, and, for a package in an image (X2),
  only if that image was scanned in this scan; otherwise it is left alone;
- a ``fixed`` finding seen again becomes ``open``; triage statuses (false positive,
  accepted risk, won't fix) are never changed automatically.
"""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from riskgraph.modules.findings.models import Finding, ScanFinding
from riskgraph.modules.risk import RiskScore
from riskgraph.shared.vocabulary import FindingChange, FindingStatus


def previous_scan_id(
    session: Session, repository_id: uuid.UUID, ref: str, before: uuid.UUID
) -> uuid.UUID | None:
    # Late import: scans depends on findings, not the other way round.
    from riskgraph.modules.scans.models import ScanJob

    current = session.get(ScanJob, before)
    if current is None:
        return None
    return session.scalars(
        select(ScanJob.id)
        .where(
            ScanJob.repository_id == repository_id,
            ScanJob.requested_ref == ref,
            ScanJob.id != before,
            ScanJob.status.in_(("COMPLETED", "PARTIAL")),
            ScanJob.created_at < current.created_at,
        )
        .order_by(ScanJob.created_at.desc())
        .limit(1)
    ).one_or_none()


def apply_history(
    session: Session,
    *,
    scan_id: uuid.UUID,
    repository_id: uuid.UUID,
    ref: str,
    succeeded_scanners: set[str],
    now: dt.datetime,
    scanned_images: set[str] | None = None,
) -> dict[str, Any]:
    prev = previous_scan_id(session, repository_id, ref, scan_id)
    current = dict(
        session.execute(
            select(ScanFinding.finding_id, Finding.first_seen_scan_id)
            .join(Finding, Finding.id == ScanFinding.finding_id)
            .where(ScanFinding.scan_job_id == scan_id)
        )
        .tuples()
        .all()
    )
    previous: set[uuid.UUID] = (
        set(session.scalars(select(ScanFinding.finding_id).where(ScanFinding.scan_job_id == prev)))
        if prev
        else set()
    )

    counts = {c.value: 0 for c in FindingChange}
    for finding_id, first_seen in current.items():
        if finding_id in previous:
            change = FindingChange.EXISTING
        elif prev is None or first_seen == scan_id:
            change = FindingChange.NEW
        else:
            change = FindingChange.REOPENED
        counts[change.value] += 1
        session.execute(
            update(ScanFinding)
            .where(ScanFinding.scan_job_id == scan_id, ScanFinding.finding_id == finding_id)
            .values(change=change)
        )

    # Seen again after being fixed: back to open.
    session.execute(
        update(Finding)
        .where(Finding.id.in_(current), Finding.status == FindingStatus.FIXED)
        .values(
            status=FindingStatus.OPEN,
            status_reason="seen again after being fixed",
            status_changed_at=now,
            fixed_in_scan_id=None,
        )
    )

    fixed = 0
    if prev is not None:
        gone = previous - set(current)
        for finding in session.scalars(select(Finding).where(Finding.id.in_(gone))):
            if finding.status is not FindingStatus.OPEN:
                continue
            if not set(finding.detected_by) <= succeeded_scanners:
                continue  # a scanner that reported it did not run cleanly: no verdict
            image = (finding.package or {}).get("image")
            if image and image not in (scanned_images or set()):
                continue  # its image was not scanned this time (pull failed, cap): no verdict
            finding.status = FindingStatus.FIXED
            finding.status_reason = "not reported by the next scan"
            finding.status_changed_at = now
            finding.fixed_in_scan_id = scan_id
            fixed += 1
        session.flush()
    # Re-analysis: findings this scan marked fixed earlier stay counted.
    fixed = max(
        fixed,
        int(
            session.execute(
                select(func.count()).select_from(Finding).where(Finding.fixed_in_scan_id == scan_id)
            ).scalar_one()
        ),
    )

    by_status = dict(
        session.execute(
            select(Finding.status, func.count())
            .join(ScanFinding, ScanFinding.finding_id == Finding.id)
            .where(ScanFinding.scan_job_id == scan_id)
            .group_by(Finding.status)
        )
        .tuples()
        .all()
    )
    return {
        "previous_scan_id": str(prev) if prev else None,
        "new": counts[FindingChange.NEW.value],
        "existing": counts[FindingChange.EXISTING.value],
        "reopened": counts[FindingChange.REOPENED.value],
        "fixed": fixed,
        "by_status": {str(getattr(k, "value", k)): int(v) for k, v in by_status.items()},
    }


@dataclass(frozen=True, slots=True)
class ScanDiff:
    previous_scan_id: uuid.UUID | None
    new: list[tuple[Finding, RiskScore | None]]
    reopened: list[tuple[Finding, RiskScore | None]]
    fixed: list[tuple[Finding, RiskScore | None]]


def diff_scans(
    session: Session,
    scan_id: uuid.UUID,
    repository_id: uuid.UUID,
    ref: str,
    against: uuid.UUID | None,
) -> ScanDiff:
    """Findings that appeared, came back or disappeared between ``against`` and ``scan_id``.

    Without ``against`` the previous scan of the same repository and ref is used.
    """
    base = against or previous_scan_id(session, repository_id, ref, scan_id)

    def ids(sid: uuid.UUID | None) -> set[uuid.UUID]:
        if sid is None:
            return set()
        return set(
            session.scalars(select(ScanFinding.finding_id).where(ScanFinding.scan_job_id == sid))
        )

    now_ids, then_ids = ids(scan_id), ids(base)
    changes = dict(
        session.execute(
            select(ScanFinding.finding_id, ScanFinding.change).where(
                ScanFinding.scan_job_id == scan_id
            )
        )
        .tuples()
        .all()
    )

    def rows(
        finding_ids: set[uuid.UUID], score_scan: uuid.UUID | None
    ) -> list[tuple[Finding, RiskScore | None]]:
        if not finding_ids:
            return []
        scores = {
            r.finding_id: r
            for r in session.scalars(
                select(RiskScore).where(
                    RiskScore.scan_job_id == score_scan, RiskScore.finding_id.in_(finding_ids)
                )
            )
        }
        found = session.scalars(select(Finding).where(Finding.id.in_(finding_ids))).all()
        out = [(f, scores.get(f.id)) for f in found]
        out.sort(key=lambda x: (-(float(x[1].score) if x[1] else 0.0), x[0].title))
        return out[:500]

    appeared = now_ids - then_ids
    if against is None:
        reopened = {f for f in appeared if changes.get(f) is FindingChange.REOPENED}
    else:
        reopened = set()
    return ScanDiff(
        previous_scan_id=base,
        new=rows(appeared - reopened, scan_id),
        reopened=rows(reopened, scan_id),
        fixed=rows(then_ids - now_ids, base),
    )
