"""Scan use cases for the API: create (with dedup and a concurrency cap), list, get."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from riskgraph.modules.repositories import (
    Repository,
    get_or_create,
    parse_github_url,
    validate_ref,
)
from riskgraph.modules.scans import orchestration, repo
from riskgraph.modules.scans.models import ScanJob, ScannerRun
from riskgraph.modules.scans.storage import report_path
from riskgraph.shared.config import Settings
from riskgraph.shared.logging import get_logger
from riskgraph.shared.problems import NotFound, ServiceUnavailable, TooManyRequests
from riskgraph.shared.vocabulary import RunStatus, ScannerName, ScanStatus

log = get_logger(__name__)
ALL_SCANNERS = [ScannerName.TRIVY, ScannerName.SEMGREP, ScannerName.CHECKOV, ScannerName.GITLEAKS]


class TooManyActiveScans(TooManyRequests):
    slug = "too-many-active-scans"
    title = "Too many scans running"


@dataclass(frozen=True, slots=True)
class ScanView:
    scan: ScanJob
    repository: Repository
    runs: list[ScannerRun]
    deduplicated: bool = False


def _view(session: Session, scan: ScanJob, deduplicated: bool = False) -> ScanView:
    repository = session.get(Repository, scan.repository_id)
    if repository is None:
        raise NotFound("Repository for this scan no longer exists")
    return ScanView(scan, repository, repo.runs_for(session, scan.id), deduplicated)


def create_scan(session: Session, repo_url: str, ref: str | None, settings: Settings) -> ScanView:
    owner, name = parse_github_url(repo_url)
    ref = validate_ref(ref)
    repository = get_or_create(session, owner, name)

    existing = repo.active_scan(session, repository.id, ref)
    if existing is not None:
        return _view(session, existing, deduplicated=True)
    if repo.count_active(session) >= settings.max_active_scans:
        raise TooManyActiveScans(
            f"At most {settings.max_active_scans} scans may run at once; try again shortly"
        )

    scan = ScanJob(
        repository_id=repository.id,
        requested_ref=ref,
        status=ScanStatus.PENDING,
        enabled_scanners=[s.value for s in ALL_SCANNERS],
        summary={},
    )
    try:
        with session.begin_nested():
            session.add(scan)
            session.flush()
    except IntegrityError:
        # Lost a race with an identical request: the partial unique index caught it.
        existing = repo.active_scan(session, repository.id, ref)
        if existing is None:
            raise
        return _view(session, existing, deduplicated=True)
    session.add_all(
        ScannerRun(scan_job_id=scan.id, scanner=s, status=RunStatus.QUEUED) for s in ALL_SCANNERS
    )
    session.flush()
    return _view(session, scan)


def start_scan(session: Session, scan_id: uuid.UUID, settings: Settings) -> None:
    """Mark QUEUED, commit, then enqueue; a queue failure marks the scan FAILED (503)."""
    repo.cas_scan(session, scan_id, ScanStatus.PENDING, ScanStatus.QUEUED)
    session.commit()
    try:
        orchestration.enqueue(scan_id, ALL_SCANNERS, settings)
    except Exception as exc:
        log.exception("enqueue_failed", scan_id=str(scan_id))
        repo.cas_scan(session, scan_id, ScanStatus.QUEUED, ScanStatus.FAILED, "queue unavailable")
        session.commit()
        raise ServiceUnavailable("The scan queue is unavailable; try again later") from exc
    finally:
        session.expire_all()  # CAS updates bypass the identity map


def get_scan(session: Session, scan_id: uuid.UUID) -> ScanView:
    scan = session.get(ScanJob, scan_id)
    if scan is None:
        raise NotFound("Scan not found")
    return _view(session, scan)


def list_scans(
    session: Session, *, status: ScanStatus | None, limit: int, offset: int
) -> tuple[list[ScanView], int]:
    query = select(ScanJob)
    if status is not None:
        query = query.where(ScanJob.status == status)
    total = session.execute(select(func.count()).select_from(query.subquery())).scalar_one()
    scans = session.scalars(
        query.order_by(ScanJob.created_at.desc(), ScanJob.id.desc()).limit(limit).offset(offset)
    )
    return [_view(session, s) for s in scans], int(total)


def report_file(
    session: Session, scan_id: uuid.UUID, scanner: ScannerName, settings: Settings
) -> Path:
    run = repo.get_run(session, scan_id, scanner)
    if run is None or not run.output_path:
        raise NotFound("No stored report for that scanner")
    path = report_path(settings.scan_output_root, scan_id, scanner)
    if not path.is_file():
        raise NotFound("Report file is no longer available")
    return path
