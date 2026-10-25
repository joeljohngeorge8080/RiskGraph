"""Attack paths and the security graph of a scan."""

from __future__ import annotations

import uuid
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from riskgraph.modules.findings.router import path_out, require_scan
from riskgraph.modules.findings.schemas import AttackPathOut
from riskgraph.modules.graph import service
from riskgraph.shared.db import get_session
from riskgraph.shared.problems import NotFound

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


class ReachNodeOut(GraphNodeOut):
    distance: int


class ReachOut(BaseModel):
    origin: str
    direction: str
    depth: int
    nodes: list[ReachNodeOut]
    edges: list[GraphEdgeOut]


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


def _edge_out(e: Any) -> GraphEdgeOut:
    return GraphEdgeOut(
        source=e.source,
        target=e.target,
        kind=e.kind,
        probability=float(e.probability) if e.probability is not None else None,
        finding_ids=list(e.evidence.get("findings", [])),
    )


@router.get("/scans/{scan_id}/graph/reach", response_model=ReachOut)
def graph_reach(
    scan_id: uuid.UUID,
    session: SessionDep,
    node: Annotated[str, Query(min_length=1, max_length=160)],
    direction: Literal["upstream", "downstream"] = "upstream",
    depth: Annotated[int, Query(ge=1, le=service.MAX_REACH_DEPTH)] = 3,
) -> ReachOut:
    """Upstream: what can reach ``node``; downstream: what ``node`` can reach."""
    require_scan(session, scan_id)
    found = service.reach(session, scan_id, node, direction, depth)
    if found is None:
        raise NotFound("Node not in this scan's graph")
    distances = found["distances"]
    return ReachOut(
        origin=node,
        direction=direction,
        depth=depth,
        nodes=[
            ReachNodeOut(
                key=n.key,
                kind=n.kind,
                label=n.label,
                properties=n.properties,
                distance=distances[n.key],
            )
            for n in found["nodes"]
        ],
        edges=[_edge_out(e) for e in found["edges"]],
    )


@router.get("/scans/{scan_id}/graph", response_model=GraphOut)
def scan_graph(scan_id: uuid.UUID, session: SessionDep) -> GraphOut:
    require_scan(session, scan_id)
    g = service.load_graph(session, scan_id)
    return GraphOut(
        nodes=[
            GraphNodeOut(key=n.key, kind=n.kind, label=n.label, properties=n.properties)
            for n in g["nodes"]
        ],
        edges=[_edge_out(e) for e in g["edges"]],
        truncated=g["truncated"],
    )
