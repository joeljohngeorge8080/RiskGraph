"""Lost-worker recovery (blueprint §9.2, "Lost worker"), run by Beat.

- A scanner run still RUNNING after two of its longest timeouts means its worker died:
  it becomes TIMED_OUT.
- A scan with no progress for an hour becomes FAILED with the reason recorded.

Both checks use ``updated_at`` (scans) and ``started_at`` (runs), so a healthy scan is
never touched however long it legitimately takes, as long as it keeps moving.
"""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from riskgraph.modules.scans import repo
from riskgraph.modules.scans.models import ScanJob, ScannerRun
from riskgraph.shared.config import Settings
from riskgraph.shared.logging import get_logger
from riskgraph.shared.vocabulary import RunStatus, ScanStatus

log = get_logger(__name__)
STALE_SCAN_S = 3600


@dataclass
class ReapResult:
    runs_timed_out: int = 0
    scans_failed: int = 0
    failed_scan_ids: list[uuid.UUID] = field(default_factory=list)


def reap(session: Session, settings: Settings, now: dt.datetime) -> ReapResult:
    result = ReapResult()
    longest = max(
        settings.timeout_trivy_s,
        settings.timeout_semgrep_s,
        settings.timeout_checkov_s,
        settings.timeout_gitleaks_s,
        settings.timeout_syft_s,
    )
    run_cutoff = now - dt.timedelta(seconds=2 * longest)
    for run in session.scalars(
        select(ScannerRun).where(
            ScannerRun.status == RunStatus.RUNNING, ScannerRun.started_at < run_cutoff
        )
    ):
        if repo.cas_run(
            session,
            run.id,
            RunStatus.RUNNING,
            RunStatus.TIMED_OUT,
            finished_at=now,
            error_excerpt="reaped: the worker stopped reporting",
        ):
            result.runs_timed_out += 1

    scan_cutoff = now - dt.timedelta(seconds=STALE_SCAN_S)
    stale = session.scalars(
        select(ScanJob).where(
            ScanJob.status.in_(
                [
                    ScanStatus.PENDING,
                    ScanStatus.QUEUED,
                    ScanStatus.CLONING,
                    ScanStatus.SCANNING,
                    ScanStatus.ANALYZING,
                ]
            ),
            ScanJob.updated_at < scan_cutoff,
        )
    ).all()
    for scan in stale:
        if repo.cas_scan(
            session,
            scan.id,
            scan.status,
            ScanStatus.FAILED,
            "reaped: no progress for an hour",
            finished_at=now,
        ):
            result.scans_failed += 1
            result.failed_scan_ids.append(scan.id)
    session.flush()
    log.info("reaped", runs=result.runs_timed_out, scans=result.scans_failed)
    return result
