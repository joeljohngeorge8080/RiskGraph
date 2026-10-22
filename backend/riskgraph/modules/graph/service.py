"""Persist a scan's graph and attack paths; read them back for the API."""

from __future__ import annotations

import uuid
from decimal import Decimal
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from riskgraph.modules.graph.attack import AttackAnalysis
from riskgraph.modules.graph.models import AttackPath, AttackPathFinding, GraphEdge, GraphNode

MAX_GRAPH_NODES = 2000


def clear(session: Session, scan_id: uuid.UUID) -> None:
    session.execute(delete(AttackPath).where(AttackPath.scan_job_id == scan_id))
    session.execute(delete(GraphEdge).where(GraphEdge.scan_job_id == scan_id))
    session.execute(delete(GraphNode).where(GraphNode.scan_job_id == scan_id))


def _dec(value: float | None, places: str) -> Decimal | None:
    return None if value is None else Decimal(str(value)).quantize(Decimal(places))


def persist(
    session: Session,
    scan_id: uuid.UUID,
    analysis: AttackAnalysis,
    finding_ids: dict[int, uuid.UUID],
) -> None:
    """``finding_ids`` maps merged-list index → findings.id for evidence references."""

    def ids(indices: list[int]) -> list[str]:
        return [str(finding_ids[i]) for i in indices if i in finding_ids]

    session.add_all(
        GraphNode(
            scan_job_id=scan_id,
            key=n["key"][:160],
            kind=n["kind"],
            label=str(n["label"])[:200],
            properties={
                k: (ids([v])[0] if k == "finding" and v in finding_ids else v)
                for k, v in n["properties"].items()
            },
        )
        for n in analysis.nodes.values()
    )
    session.add_all(
        GraphEdge(
            scan_job_id=scan_id,
            source=e["source"][:160],
            target=e["target"][:160],
            kind=e["kind"],
            probability=_dec(e["probability"], "0.00001"),
            evidence={"findings": ids(e["findings"])},
        )
        for e in analysis.edges
    )
    for p in analysis.paths:
        row = AttackPath(
            scan_job_id=scan_id,
            source=p.source,
            sink=p.sink,
            rank=p.rank,
            hops=p.hops,
            nodes=[{"key": k, "label": label} for k, label in zip(p.nodes, p.labels, strict=True)],
            edges=[{**e, "findings": ids(e["findings"])} for e in p.edges],
            probability=_dec(p.probability, "0.00001") or Decimal(0),
            sink_impact=_dec(p.sink_impact, "0.0001") or Decimal(0),
            score=_dec(p.score, "0.01") or Decimal(0),
        )
        session.add(row)
        session.flush()
        session.add_all(
            AttackPathFinding(attack_path_id=row.id, finding_id=finding_ids[i])
            for i in p.findings
            if i in finding_ids
        )


def list_paths(session: Session, scan_id: uuid.UUID) -> list[AttackPath]:
    return list(
        session.scalars(
            select(AttackPath)
            .where(AttackPath.scan_job_id == scan_id)
            .order_by(AttackPath.score.desc(), AttackPath.sink, AttackPath.rank)
        )
    )


def paths_for_finding(
    session: Session, scan_id: uuid.UUID, finding_id: uuid.UUID
) -> list[AttackPath]:
    return list(
        session.scalars(
            select(AttackPath)
            .join(AttackPathFinding, AttackPathFinding.attack_path_id == AttackPath.id)
            .where(AttackPath.scan_job_id == scan_id, AttackPathFinding.finding_id == finding_id)
            .order_by(AttackPath.score.desc())
        )
    )


def path_findings(session: Session, path_ids: list[uuid.UUID]) -> dict[uuid.UUID, list[uuid.UUID]]:
    out: dict[uuid.UUID, list[uuid.UUID]] = {}
    for pid, fid in session.execute(
        select(AttackPathFinding.attack_path_id, AttackPathFinding.finding_id).where(
            AttackPathFinding.attack_path_id.in_(path_ids)
        )
    ).tuples():
        out.setdefault(pid, []).append(fid)
    return out


def load_graph(session: Session, scan_id: uuid.UUID) -> dict[str, Any]:
    total = session.execute(
        select(func.count()).select_from(GraphNode).where(GraphNode.scan_job_id == scan_id)
    ).scalar_one()
    nodes = list(
        session.scalars(
            select(GraphNode)
            .where(GraphNode.scan_job_id == scan_id)
            .order_by(GraphNode.key)
            .limit(MAX_GRAPH_NODES)
        )
    )
    keys = {n.key for n in nodes}
    edges = [
        e
        for e in session.scalars(select(GraphEdge).where(GraphEdge.scan_job_id == scan_id))
        if e.source in keys and e.target in keys
    ]
    return {"nodes": nodes, "edges": edges, "truncated": int(total) > len(nodes)}
