"""Reachability verdict per finding per scan (blueprint §11.3, §16)."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from riskgraph.shared.db import Base, UUIDPrimaryKeyMixin, str_enum
from riskgraph.shared.vocabulary import ReachabilityTier


class ReachabilityResult(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "reachability_results"
    __table_args__ = (
        UniqueConstraint("scan_job_id", "finding_id", name="uq_reachability_scan_finding"),
    )

    scan_job_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    tier: Mapped[ReachabilityTier] = mapped_column(
        str_enum(ReachabilityTier, "reachability_tier"), nullable=False
    )
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    analyzer_version: Mapped[str] = mapped_column(String(32), nullable=False)
