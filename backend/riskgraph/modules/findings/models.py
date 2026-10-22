"""Merged findings and their per-scanner occurrences (blueprint §16.3, MVP shape).

``findings`` holds one row per *merged* issue per repository and survives across scans
(keyed by ``merge_key``). ``finding_occurrences`` keeps every native scanner result, so
nothing a scanner said is lost by merging. ``scan_findings`` says which findings a given
scan saw, and by which scanners.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from riskgraph.shared.db import Base, TimestampMixin, UUIDPrimaryKeyMixin, str_enum
from riskgraph.shared.vocabulary import (
    FindingChange,
    FindingStatus,
    ScannerName,
    Severity,
    SourceType,
)


class Finding(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("repository_id", "merge_key", name="uq_findings_repo_merge_key"),
        Index("ix_findings_vulnerability", "vulnerability_id"),
        Index("ix_findings_repo_source", "repository_id", "source_type"),
    )

    repository_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False
    )
    merge_key: Mapped[str] = mapped_column(String(64), nullable=False)
    source_type: Mapped[SourceType] = mapped_column(
        str_enum(SourceType, "source_type"), nullable=False
    )
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(str_enum(Severity, "severity"), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(300), nullable=False)
    vulnerability_id: Mapped[str | None] = mapped_column(String(64))
    package: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    location: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    cwe_ids: Mapped[list[str]] = mapped_column(ARRAY(String(16)), default=list, nullable=False)
    detected_by: Mapped[list[str]] = mapped_column(ARRAY(String(32)), nullable=False)
    remediation: Mapped[str | None] = mapped_column(Text)
    status: Mapped[FindingStatus] = mapped_column(
        str_enum(FindingStatus, "finding_status"), default=FindingStatus.OPEN, nullable=False
    )
    status_reason: Mapped[str | None] = mapped_column(Text)
    status_changed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    fixed_in_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="SET NULL")
    )
    first_seen_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="SET NULL")
    )
    last_seen_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="SET NULL")
    )
    first_seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class FindingOccurrence(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "finding_occurrences"
    __table_args__ = (
        UniqueConstraint(
            "scan_job_id", "scanner", "fingerprint", name="uq_occurrences_scan_scanner_fp"
        ),
        Index("ix_occurrences_finding_scan", "finding_id", "scan_job_id"),
    )

    scan_job_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False
    )
    scanner_run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scanner_runs.id", ondelete="CASCADE"), nullable=False
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    scanner: Mapped[ScannerName] = mapped_column(
        str_enum(ScannerName, "scanner_name"), nullable=False
    )
    rule_id: Mapped[str] = mapped_column(String(300), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    scanner_severity: Mapped[str | None] = mapped_column(String(32))
    severity: Mapped[Severity] = mapped_column(str_enum(Severity, "severity"), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    location: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    # Redacted and size-capped; never contains a raw secret or source snippet.
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: dt.datetime.now(dt.UTC), nullable=False
    )


class ScanFinding(Base):
    __tablename__ = "scan_findings"

    scan_job_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="CASCADE"), primary_key=True
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True
    )
    detected_by: Mapped[list[str]] = mapped_column(ARRAY(String(32)), nullable=False)
    # The SBOM component an SCA finding attaches to in this scan (P5), if any.
    component_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("sbom_components.id", ondelete="SET NULL")
    )
    change: Mapped[FindingChange] = mapped_column(
        str_enum(FindingChange, "finding_change"), default=FindingChange.NEW, nullable=False
    )
