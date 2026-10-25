"""Persist evidence and its links; read it back for the API."""

from __future__ import annotations

import uuid
from collections.abc import Iterable

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from riskgraph.modules.evidence.contract import Evidence
from riskgraph.modules.evidence.models import EdgeEvidence, EvidenceRow, FindingEvidence


def clear(session: Session, scan_id: uuid.UUID) -> None:
    """Drop a scan's evidence; the link rows go with it (cascade)."""
    session.execute(delete(EvidenceRow).where(EvidenceRow.scan_job_id == scan_id))


def persist_evidence(session: Session, scan_id: uuid.UUID, evidence: Iterable[Evidence]) -> None:
    rows = {
        e.id: {
            "scan_job_id": scan_id,
            "id": e.id,
            "producer": e.producer,
            "kind": e.kind,
            "assurance": e.assurance.value,
            "confidence": e.confidence,
            "payload": e.payload(),
            "raw_run_id": e.raw.scanner_run_id if e.raw else None,
            "raw_pointer": e.raw.pointer[:512] if e.raw else None,
            "observed_at": e.observed_at,
            "data_as_of": e.data_as_of,
        }
        for e in evidence
    }
    if rows:
        stmt = insert(EvidenceRow).values(list(rows.values()))
        session.execute(stmt.on_conflict_do_nothing(index_elements=["scan_job_id", "id"]))


def link_finding(
    session: Session, scan_id: uuid.UUID, finding_id: uuid.UUID, evidence_ids: Iterable[str]
) -> None:
    rows = [
        {"scan_job_id": scan_id, "finding_id": finding_id, "evidence_id": i}
        for i in dict.fromkeys(evidence_ids)
    ]
    if rows:
        session.execute(insert(FindingEvidence).values(rows).on_conflict_do_nothing())


def link_edge(
    session: Session, scan_id: uuid.UUID, edge_id: uuid.UUID, evidence_ids: Iterable[str]
) -> None:
    rows = [
        {"scan_job_id": scan_id, "edge_id": edge_id, "evidence_id": i}
        for i in dict.fromkeys(evidence_ids)
    ]
    if rows:
        session.execute(insert(EdgeEvidence).values(rows).on_conflict_do_nothing())


def evidence_for_finding(
    session: Session, scan_id: uuid.UUID, finding_id: uuid.UUID
) -> list[EvidenceRow]:
    """Strongest first: verified before inferred before hypothesis, then by kind."""
    rows = session.scalars(
        select(EvidenceRow)
        .join(
            FindingEvidence,
            (FindingEvidence.scan_job_id == EvidenceRow.scan_job_id)
            & (FindingEvidence.evidence_id == EvidenceRow.id),
        )
        .where(FindingEvidence.scan_job_id == scan_id, FindingEvidence.finding_id == finding_id)
    ).all()
    order = {"verified": 0, "inferred": 1, "hypothesis": 2}
    return sorted(rows, key=lambda r: (order.get(r.assurance, 3), r.kind, r.id))


def evidence_for_edges(
    session: Session, edge_ids: Iterable[uuid.UUID]
) -> dict[uuid.UUID, list[str]]:
    ids = list(edge_ids)
    out: dict[uuid.UUID, list[str]] = {i: [] for i in ids}
    if ids:
        for edge_id, evidence_id in session.execute(
            select(EdgeEvidence.edge_id, EdgeEvidence.evidence_id)
            .where(EdgeEvidence.edge_id.in_(ids))
            .order_by(EdgeEvidence.evidence_id)
        ):
            out[edge_id].append(evidence_id)
    return out
