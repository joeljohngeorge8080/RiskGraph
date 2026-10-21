"""Scan endpoints. Routers parse and call services (CLAUDE.md)."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Response, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from riskgraph.modules.scans import service
from riskgraph.modules.scans.schemas import (
    RepositoryOut,
    ScanCreate,
    ScanList,
    ScannerRunOut,
    ScanOut,
)
from riskgraph.shared.config import Settings, get_settings
from riskgraph.shared.db import get_session
from riskgraph.shared.vocabulary import ScannerName, ScanStatus

router = APIRouter(prefix="/scans", tags=["scans"])

SessionDep = Annotated[Session, Depends(get_session)]
SettingsDep = Annotated[Settings, Depends(get_settings)]


def to_out(view: service.ScanView) -> ScanOut:
    scan, repository = view.scan, view.repository
    return ScanOut(
        id=scan.id,
        repository=RepositoryOut(
            id=repository.id,
            full_name=f"{repository.owner}/{repository.name}",
            url=f"https://github.com/{repository.owner}/{repository.name}",
        ),
        requested_ref=scan.requested_ref,
        commit_sha=scan.commit_sha,
        status=scan.status,
        status_reason=scan.status_reason,
        created_at=scan.created_at,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        risk_model_version=scan.risk_model_version,
        summary=scan.summary or {},
        scanner_runs=[
            ScannerRunOut(
                scanner=r.scanner,
                status=r.status,
                version=r.scanner_version,
                exit_code=r.exit_code,
                duration_ms=r.duration_ms,
                raw_findings_count=r.raw_findings_count,
                output_bytes=r.output_bytes,
                error_excerpt=r.error_excerpt,
                report_available=bool(r.output_path),
            )
            for r in view.runs
        ],
        deduplicated=view.deduplicated,
    )


@router.post("", status_code=status.HTTP_202_ACCEPTED, response_model=ScanOut)
def create_scan(
    body: ScanCreate, response: Response, session: SessionDep, settings: SettingsDep
) -> ScanOut:
    view = service.create_scan(session, body.repo_url, body.ref, settings)
    if view.deduplicated:
        response.status_code = status.HTTP_200_OK
        return to_out(view)
    session.commit()
    service.start_scan(session, view.scan.id, settings)
    return to_out(service.get_scan(session, view.scan.id))


@router.get("", response_model=ScanList)
def list_scans(
    session: SessionDep,
    status_filter: Annotated[ScanStatus | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> ScanList:
    views, total = service.list_scans(session, status=status_filter, limit=limit, offset=offset)
    return ScanList(items=[to_out(v) for v in views], total=total)


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: uuid.UUID, session: SessionDep) -> ScanOut:
    return to_out(service.get_scan(session, scan_id))


@router.get("/{scan_id}/reports/{scanner}", response_class=FileResponse)
def download_report(
    scan_id: uuid.UUID, scanner: ScannerName, session: SessionDep, settings: SettingsDep
) -> FileResponse:
    path = service.report_file(session, scan_id, scanner, settings)
    return FileResponse(
        path,
        media_type="application/json",
        filename=f"riskgraph-{str(scan_id)[:8]}-{scanner.value}.json",
        headers={"X-Content-Type-Options": "nosniff"},
    )
