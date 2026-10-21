"""Scan jobs and per-scanner runs (blueprint §16.2, trimmed for the MVP)."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from riskgraph.shared.db import Base, TimestampMixin, UUIDPrimaryKeyMixin, str_enum
from riskgraph.shared.vocabulary import (
    ACTIVE_SCAN_STATUSES,
    RunStatus,
    ScannerName,
    ScanStatus,
)

_ACTIVE = ", ".join(f"'{s.value}'" for s in ACTIVE_SCAN_STATUSES)


class ScanJob(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "scan_jobs"
    __table_args__ = (
        Index("ix_scan_jobs_repository_created", "repository_id", text("created_at DESC")),
        Index("ix_scan_jobs_status", "status"),
        # At most one active scan per (repository, ref): POST /scans deduplicates on it.
        Index(
            "uq_scan_jobs_active_per_ref",
            "repository_id",
            "requested_ref",
            unique=True,
            postgresql_where=text(f"status IN ({_ACTIVE})"),
        ),
    )

    repository_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False
    )
    requested_ref: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    commit_sha: Mapped[str | None] = mapped_column(String(40))
    status: Mapped[ScanStatus] = mapped_column(
        str_enum(ScanStatus, "scan_status"), default=ScanStatus.PENDING, nullable=False
    )
    status_reason: Mapped[str | None] = mapped_column(Text)
    trigger: Mapped[str] = mapped_column(String(16), default="manual", nullable=False)
    enabled_scanners: Mapped[list[str]] = mapped_column(ARRAY(String(32)), nullable=False)
    risk_model_version: Mapped[str | None] = mapped_column(String(32))
    summary: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))


class ScannerRun(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "scanner_runs"
    __table_args__ = (UniqueConstraint("scan_job_id", "scanner", name="uq_scanner_runs_scan"),)

    scan_job_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False
    )
    scanner: Mapped[ScannerName] = mapped_column(
        str_enum(ScannerName, "scanner_name"), nullable=False
    )
    scanner_version: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[RunStatus] = mapped_column(
        str_enum(RunStatus, "run_status"), default=RunStatus.QUEUED, nullable=False
    )
    exit_code: Mapped[int | None] = mapped_column(Integer)
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    # Relative to settings.scan_output_root; never an absolute or user-derived path.
    output_path: Mapped[str | None] = mapped_column(String(200))
    output_sha256: Mapped[str | None] = mapped_column(String(64))
    output_bytes: Mapped[int | None] = mapped_column(BigInteger)
    raw_findings_count: Mapped[int | None] = mapped_column(Integer)
    error_excerpt: Mapped[str | None] = mapped_column(Text)
