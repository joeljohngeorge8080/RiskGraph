"""Per-scan security graph and attack paths (blueprint §12, §13, §16; ADR-0006).

The graph is a projection rebuilt from typed data on every analysis; rows here are
derived and deleted with their scan.
"""

from __future__ import annotations

import uuid
from decimal import Decimal
from typing import Any

from sqlalchemy import ForeignKey, Index, Numeric, SmallInteger, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from riskgraph.shared.db import Base, UUIDPrimaryKeyMixin


class GraphNode(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "graph_nodes"
    __table_args__ = (UniqueConstraint("scan_job_id", "key", name="uq_graph_nodes_scan_key"),)

    scan_job_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False
    )
    key: Mapped[str] = mapped_column(String(160), nullable=False)  # e.g. "service:api"
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    label: Mapped[str] = mapped_column(String(200), nullable=False)
    properties: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)


class GraphEdge(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "graph_edges"
    __table_args__ = (Index("ix_graph_edges_scan", "scan_job_id"),)

    scan_job_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False
    )
    source: Mapped[str] = mapped_column(String(160), nullable=False)
    target: Mapped[str] = mapped_column(String(160), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    probability: Mapped[Decimal | None] = mapped_column(Numeric(6, 5))
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)


class AttackPath(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "attack_paths"
    __table_args__ = (Index("ix_attack_paths_scan_score", "scan_job_id", "score"),)

    scan_job_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False
    )
    source: Mapped[str] = mapped_column(String(160), nullable=False)
    sink: Mapped[str] = mapped_column(String(160), nullable=False)
    rank: Mapped[int] = mapped_column(SmallInteger, nullable=False)  # 1..k per sink
    hops: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    nodes: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    edges: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False)
    probability: Mapped[Decimal] = mapped_column(Numeric(6, 5), nullable=False)
    sink_impact: Mapped[Decimal] = mapped_column(Numeric(5, 4), nullable=False)
    score: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False)


class AttackPathFinding(Base):
    __tablename__ = "attack_path_findings"

    attack_path_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("attack_paths.id", ondelete="CASCADE"), primary_key=True
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True
    )
