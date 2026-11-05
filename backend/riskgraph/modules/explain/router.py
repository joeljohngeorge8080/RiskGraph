"""Explanation endpoints. Explanations narrate the score; they never change it (§15)."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from riskgraph.modules.explain import service
from riskgraph.modules.explain.models import AiExplanation
from riskgraph.modules.findings.router import require_scan
from riskgraph.shared.config import Settings, get_settings
from riskgraph.shared.db import get_session
from riskgraph.shared.problems import NotFound

router = APIRouter(prefix="/findings", tags=["explanations"])
SessionDep = Annotated[Session, Depends(get_session)]
SettingsDep = Annotated[Settings, Depends(get_settings)]


class EvidenceRef(BaseModel):
    id: str
    label: str


class ReasonOut(BaseModel):
    claim: str
    evidence: list[EvidenceRef]


class ExplanationOut(BaseModel):
    finding_id: uuid.UUID
    scan_id: uuid.UUID
    status: str  # validated (model output that passed the validator) | fallback (template)
    generator: str
    summary: str
    reasons: list[ReasonOut]
    impact: str
    remediation_steps: list[str]
    caveats: str
    evidence_hash: str
    attempts: int
    latency_ms: int
    created_at: dt.datetime


def _out(row: AiExplanation, scan_id: uuid.UUID) -> ExplanationOut:
    d, labels = row.draft, row.evidence_ids
    return ExplanationOut(
        finding_id=row.finding_id,
        scan_id=scan_id,
        status=row.status,
        generator=row.generator,
        summary=d["summary"],
        reasons=[
            ReasonOut(
                claim=r["claim"],
                evidence=[EvidenceRef(id=e, label=labels.get(e, e)) for e in r["evidence_ids"]],
            )
            for r in d["reasons"]
        ],
        impact=d["impact"],
        remediation_steps=list(d["remediation_steps"]),
        caveats=d.get("caveats", ""),
        evidence_hash=row.evidence_hash,
        attempts=row.attempts,
        latency_ms=row.latency_ms,
        created_at=row.created_at,
    )


@router.get("/{finding_id}/explanation", response_model=ExplanationOut)
def get_explanation(
    finding_id: uuid.UUID, scan_id: uuid.UUID, session: SessionDep
) -> ExplanationOut:
    """The stored explanation for the finding's current evidence; 404 until one exists."""
    require_scan(session, scan_id)
    pack = service.build_pack(session, scan_id, finding_id)
    row = service.cached(session, finding_id, pack.digest())
    if row is None:
        raise NotFound("no explanation yet for this evidence; POST to generate one")
    return _out(row, scan_id)


@router.post("/{finding_id}/explanation", response_model=ExplanationOut)
def create_explanation(
    finding_id: uuid.UUID,
    scan_id: uuid.UUID,
    session: SessionDep,
    settings: SettingsDep,
    refresh: bool = False,
) -> ExplanationOut:
    """Generate (or return the cached) explanation. Synchronous: bounded by the model
    timeout, and the template answers at once when the model is unavailable."""
    require_scan(session, scan_id)
    adapter = service.adapter_from_settings(settings)
    try:
        row = service.explain(session, scan_id, finding_id, adapter, refresh=refresh)
    finally:
        if adapter is not None:
            adapter.close()
    session.commit()
    return _out(row, scan_id)
