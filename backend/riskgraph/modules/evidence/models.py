"""Stored evidence, scan-scoped (ADR-0017). Rows are derived and go with their scan.

The same evidence id can appear in many scans; within one scan it is stored once and
linked from every finding and edge that rests on it.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    String,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from riskgraph.shared.db import Base


class EvidenceRow(Base):
    __tablename__ = "evidence"
    __table_args__ = (
        CheckConstraint(
            "assurance IN ('verified', 'inferred', 'hypothesis')", name="evidence_assurance"
        ),
        CheckConstraint("confidence IN ('high', 'medium', 'low')", name="evidence_confidence"),
    )

    scan_job_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="CASCADE"), primary_key=True
    )
    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # sha256 of the payload
    producer: Mapped[str] = mapped_column(String(96), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    assurance: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[str] = mapped_column(String(8), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    raw_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scanner_runs.id", ondelete="CASCADE")
    )
    raw_pointer: Mapped[str | None] = mapped_column(String(512))
    observed_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    data_as_of: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))


class FindingEvidence(Base):
    __tablename__ = "finding_evidence"
    __table_args__ = (
        ForeignKeyConstraint(
            ["scan_job_id", "evidence_id"],
            ["evidence.scan_job_id", "evidence.id"],
            ondelete="CASCADE",
            name="fk_finding_evidence_evidence",
        ),
        Index("ix_finding_evidence_finding", "finding_id"),
    )

    scan_job_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True
    )
    evidence_id: Mapped[str] = mapped_column(String(64), primary_key=True)


class EdgeEvidence(Base):
    __tablename__ = "edge_evidence"
    __table_args__ = (
        ForeignKeyConstraint(
            ["scan_job_id", "evidence_id"],
            ["evidence.scan_job_id", "evidence.id"],
            ondelete="CASCADE",
            name="fk_edge_evidence_evidence",
        ),
    )

    edge_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("graph_edges.id", ondelete="CASCADE"), primary_key=True
    )
    evidence_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_job_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
