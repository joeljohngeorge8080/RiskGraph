"""SBOM persistence and the Trivy-to-Syft join (blueprint §10.2, "Cross-scanner correlation").

The join key is the purl with qualifiers and subpath removed: Syft and Trivy may append
different ``?distro=`` qualifiers to the same package.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from dataclasses import dataclass

from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from riskgraph.modules.findings.models import ScanFinding
from riskgraph.modules.sbom.models import SbomComponent
from riskgraph.modules.scanners.syft.parser import Component

MAX_PURL = 512


def canonical_purl(purl: str) -> str:
    base = purl.split("#", 1)[0].split("?", 1)[0]
    return base[:MAX_PURL]


@dataclass(frozen=True, slots=True)
class PackageSeen:
    """A package a scanner reported with a purl (Trivy SCA findings)."""

    purl: str
    name: str
    version: str
    location: str | None


def _ecosystem(purl: str) -> str:
    if not purl.startswith("pkg:"):
        return ""
    return purl[4:].split("/", 1)[0][:32]


def persist_components(
    session: Session,
    scan_id: uuid.UUID,
    syft: Iterable[Component],
    trivy_seen: Iterable[PackageSeen],
) -> dict[str, uuid.UUID]:
    """Write the scan's SBOM. Returns canonical purl -> component id for attaching."""
    rows: dict[str, dict[str, object]] = {}
    for c in syft:
        key = canonical_purl(c.purl)
        rows.setdefault(
            key,
            {
                "purl": key,
                "name": c.name,
                "version": c.version,
                "ecosystem": c.ecosystem,
                "location": c.location,
                "discovered_by": "syft",
            },
        )
    for p in trivy_seen:
        key = canonical_purl(p.purl)
        rows.setdefault(
            key,
            {
                "purl": key,
                "name": p.name[:256],
                "version": p.version[:128],
                "ecosystem": _ecosystem(key),
                "location": p.location[:512] if p.location else None,
                "discovered_by": "trivy",
            },
        )
    session.execute(delete(SbomComponent).where(SbomComponent.scan_job_id == scan_id))
    ids: dict[str, uuid.UUID] = {}
    for key, values in rows.items():
        row = SbomComponent(id=uuid.uuid4(), scan_job_id=scan_id, **values)
        session.add(row)
        ids[key] = row.id
    session.flush()
    return ids


def attach_findings(
    session: Session,
    scan_id: uuid.UUID,
    links: dict[uuid.UUID, uuid.UUID],
) -> int:
    """Set ``scan_findings.component_id`` for each finding_id -> component_id link."""
    attached = 0
    for finding_id, component_id in links.items():
        result = session.execute(
            update(ScanFinding)
            .where(ScanFinding.scan_job_id == scan_id, ScanFinding.finding_id == finding_id)
            .values(component_id=component_id)
        )
        attached += int(getattr(result, "rowcount", 0) or 0)
    return attached


def clear(session: Session, scan_id: uuid.UUID) -> None:
    session.execute(
        update(ScanFinding).where(ScanFinding.scan_job_id == scan_id).values(component_id=None)
    )
    session.execute(delete(SbomComponent).where(SbomComponent.scan_job_id == scan_id))


def list_components(session: Session, scan_id: uuid.UUID) -> list[SbomComponent]:
    return list(
        session.scalars(
            select(SbomComponent)
            .where(SbomComponent.scan_job_id == scan_id)
            .order_by(SbomComponent.ecosystem, SbomComponent.name, SbomComponent.version)
        )
    )


def page_components(
    session: Session,
    scan_id: uuid.UUID,
    *,
    ecosystem: str | None,
    name: str | None,
    limit: int,
    offset: int,
) -> tuple[list[tuple[SbomComponent, int]], int]:
    """One page of the scan's SBOM, each component with its number of attached findings."""
    where = [SbomComponent.scan_job_id == scan_id]
    if ecosystem:
        where.append(SbomComponent.ecosystem == ecosystem)
    if name:
        # a prefix match on the indexed column; the value is bound, never interpolated
        escaped = name.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        where.append(SbomComponent.name.like(f"{escaped}%", escape="\\"))
    total = session.scalar(select(func.count()).select_from(SbomComponent).where(*where)) or 0
    counts = (
        select(ScanFinding.component_id, func.count().label("n"))
        .where(ScanFinding.scan_job_id == scan_id, ScanFinding.component_id.is_not(None))
        .group_by(ScanFinding.component_id)
        .subquery()
    )
    rows = session.execute(
        select(SbomComponent, func.coalesce(counts.c.n, 0))
        .outerjoin(counts, counts.c.component_id == SbomComponent.id)
        .where(*where)
        .order_by(SbomComponent.ecosystem, SbomComponent.name, SbomComponent.version)
        .limit(limit)
        .offset(offset)
    ).all()
    return [(c, int(n)) for c, n in rows], int(total)
