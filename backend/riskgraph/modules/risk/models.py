"""Risk scores and the factors that produced them (blueprint §16.5).

A score is reproducible from its factor rows and ``model_version`` alone.
"""

from __future__ import annotations

import datetime as dt
import uuid
from decimal import Decimal
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Numeric,
    SmallInteger,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from riskgraph.shared.db import Base, UUIDPrimaryKeyMixin, str_enum
from riskgraph.shared.vocabulary import Priority


class RiskScore(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "risk_scores"
    __table_args__ = (
        UniqueConstraint("scan_job_id", "finding_id", name="uq_risk_scores_scan_finding"),
        Index(
            "ix_risk_scores_ranking",
            "scan_job_id",
            text("priority_rank DESC"),
            text("score DESC"),
        ),
    )

    scan_job_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    model_version: Mapped[str] = mapped_column(String(32), nullable=False)
    likelihood: Mapped[Decimal] = mapped_column(Numeric(5, 4), nullable=False)
    impact: Mapped[Decimal] = mapped_column(Numeric(5, 4), nullable=False)
    corroboration: Mapped[Decimal] = mapped_column(Numeric(4, 3), nullable=False)
    # §14.4: impact raised by an attack path this finding is evidence on (else NULL)
    effective_impact: Mapped[Decimal | None] = mapped_column(Numeric(5, 4))
    score: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False)
    priority: Mapped[Priority] = mapped_column(str_enum(Priority, "priority"), nullable=False)
    priority_rank: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    overrides: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list, nullable=False)
    computed_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class RiskFactor(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "risk_factors"
    __table_args__ = (Index("ix_risk_factors_score", "risk_score_id"),)

    risk_score_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("risk_scores.id", ondelete="CASCADE"), nullable=False
    )
    group: Mapped[str] = mapped_column(String(16), nullable=False)  # likelihood|impact|adjustment
    name: Mapped[str] = mapped_column(String(8), nullable=False)  # E X R T D P C K I*
    value: Mapped[Decimal] = mapped_column(Numeric(5, 4), nullable=False)
    raw_value: Mapped[str | None] = mapped_column(String(200))
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    applicable: Mapped[bool] = mapped_column(Boolean, nullable=False)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
