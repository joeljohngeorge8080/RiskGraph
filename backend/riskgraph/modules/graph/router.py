"""Attack paths and the security graph of a scan."""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from riskgraph.modules.findings.router import path_out, require_scan
from riskgraph.modules.findings.schemas import AttackPathOut
from riskgraph.modules.graph import service
from riskgraph.shared.db import get_session

router = APIRouter(tags=["graph"])
SessionDep = Annotated[Session, Depends(get_session)]


class GraphNodeOut(BaseModel):
    key: str
    kind: str
    label: str
    properties: dict[str, Any]


class GraphEdgeOut(BaseModel):
    source: str
    target: str
    kind: str
    probability: float | None
    finding_ids: list[str]


class GraphOut(BaseModel):
    nodes: list[GraphNodeOut]
    edges: list[GraphEdgeOut]
    truncated: bool


@router.get("/scans/{scan_id}/attack-paths", response_model=list[AttackPathOut])
def attack_paths(scan_id: uuid.UUID, session: SessionDep) -> list[AttackPathOut]:
    require_scan(session, scan_id)
    paths = service.list_paths(session, scan_id)
    findings = service.path_findings(session, [p.id for p in paths])
    return [path_out(p, findings.get(p.id, [])) for p in paths]


@router.get("/scans/{scan_id}/graph", response_model=GraphOut)
def scan_graph(scan_id: uuid.UUID, session: SessionDep) -> GraphOut:
    require_scan(session, scan_id)
    g = service.load_graph(session, scan_id)
    return GraphOut(
        nodes=[
            GraphNodeOut(key=n.key, kind=n.kind, label=n.label, properties=n.properties)
            for n in g["nodes"]
        ],
        edges=[
            GraphEdgeOut(
                source=e.source,
                target=e.target,
                kind=e.kind,
                probability=float(e.probability) if e.probability is not None else None,
                finding_ids=list(e.evidence.get("findings", [])),
            )
            for e in g["edges"]
        ],
        truncated=g["truncated"],
    )
