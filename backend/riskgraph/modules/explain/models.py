"""Stored explanations, one per (finding, evidence hash): re-opening a finding is free."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from riskgraph.shared.db import Base, UUIDPrimaryKeyMixin


class AiExplanation(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "ai_explanations"
    __table_args__ = (
        UniqueConstraint("finding_id", "evidence_hash", name="uq_ai_explanations_evidence"),
        CheckConstraint("status IN ('validated', 'fallback')", name="ai_explanation_status"),
        Index("ix_ai_explanations_scan", "scan_job_id"),
    )

    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    # the scan it was first generated for; the cache key does not include it
    scan_job_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False
    )
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    prompt_version: Mapped[str] = mapped_column(String(32), nullable=False)
    generator: Mapped[str] = mapped_column(String(96), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    draft: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    evidence_ids: Mapped[dict[str, str]] = mapped_column(JSONB, nullable=False)
    validation_errors: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    attempts: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    latency_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
