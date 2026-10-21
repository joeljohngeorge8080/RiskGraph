"""SQL for scans: compare-and-set transitions (safe under Celery redelivery)."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from riskgraph.modules.scans.models import ScanJob, ScannerRun
from riskgraph.modules.scans.state import check_run, check_scan
from riskgraph.shared.vocabulary import ACTIVE_SCAN_STATUSES, RunStatus, ScannerName, ScanStatus


def cas_scan(
    session: Session,
    scan_id: uuid.UUID,
    from_: ScanStatus,
    to: ScanStatus,
    reason: str | None = None,
    **values: Any,
) -> bool:
    check_scan(from_, to)
    if reason is not None:
        values["status_reason"] = reason[:2000]
    result = session.execute(
        update(ScanJob)
        .where(ScanJob.id == scan_id, ScanJob.status == from_)
        .values(status=to, updated_at=func.now(), **values)
        .execution_options(synchronize_session=False)
    )
    return bool(result.rowcount == 1)  # type: ignore[attr-defined]


def cas_run(
    session: Session, run_id: uuid.UUID, from_: RunStatus, to: RunStatus, **values: Any
) -> bool:
    check_run(from_, to)
    result = session.execute(
        update(ScannerRun)
        .where(ScannerRun.id == run_id, ScannerRun.status == from_)
        .values(status=to, updated_at=func.now(), **values)
        .execution_options(synchronize_session=False)
    )
    return bool(result.rowcount == 1)  # type: ignore[attr-defined]


def get_run(session: Session, scan_id: uuid.UUID, scanner: ScannerName) -> ScannerRun | None:
    return session.scalars(
        select(ScannerRun).where(ScannerRun.scan_job_id == scan_id, ScannerRun.scanner == scanner)
    ).one_or_none()


def runs_for(session: Session, scan_id: uuid.UUID) -> list[ScannerRun]:
    return list(
        session.scalars(
            select(ScannerRun).where(ScannerRun.scan_job_id == scan_id).order_by(ScannerRun.scanner)
        )
    )


def active_scan(session: Session, repository_id: uuid.UUID, ref: str) -> ScanJob | None:
    return session.scalars(
        select(ScanJob).where(
            ScanJob.repository_id == repository_id,
            ScanJob.requested_ref == ref,
            ScanJob.status.in_(ACTIVE_SCAN_STATUSES),
        )
    ).one_or_none()


def count_active(session: Session) -> int:
    return int(
        session.execute(
            select(func.count())
            .select_from(ScanJob)
            .where(ScanJob.status.in_(ACTIVE_SCAN_STATUSES))
        ).scalar_one()
    )
