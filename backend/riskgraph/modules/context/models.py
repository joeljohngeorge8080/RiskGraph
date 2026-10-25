"""Vulnerability intelligence cache: CVSS from scanner data, EPSS and KEV from feeds."""

from __future__ import annotations

import datetime as dt
import uuid
from decimal import Decimal
from typing import Any

from sqlalchemy import Boolean, Date, DateTime, ForeignKey, Index, Numeric, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from riskgraph.shared.db import Base, TimestampMixin, UUIDPrimaryKeyMixin


class Vulnerability(TimestampMixin, Base):
    __tablename__ = "vulnerabilities"
    __table_args__ = (Index("ix_vulnerabilities_kev", "kev"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # CVE-… or GHSA-…
    cvss_version: Mapped[str | None] = mapped_column(String(8))
    cvss_vector: Mapped[str | None] = mapped_column(String(200))
    cvss_base: Mapped[Decimal | None] = mapped_column(Numeric(3, 1))
    cvss_impact: Mapped[Decimal | None] = mapped_column(Numeric(3, 1))
    cvss_exploitability: Mapped[Decimal | None] = mapped_column(Numeric(3, 1))
    cvss_source: Mapped[str | None] = mapped_column(String(32))
    epss: Mapped[Decimal | None] = mapped_column(Numeric(6, 5))
    epss_percentile: Mapped[Decimal | None] = mapped_column(Numeric(6, 5))
    epss_date: Mapped[dt.date | None] = mapped_column(Date)
    epss_fetched_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    nvd_checked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    kev: Mapped[bool | None] = mapped_column(Boolean)
    kev_added: Mapped[dt.date | None] = mapped_column(Date)
    kev_checked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))


class Asset(UUIDPrimaryKeyMixin, Base):
    """Environment assets extracted from a scan's Kubernetes and Compose files (P7).

    One row per asset per scan. ``source_path`` is repo-relative and only displayed; it is
    never opened. ``attrs`` holds the typed, bounded fields the extractor chose to keep.
    """

    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("scan_job_id", "kind", "name", name="uq_assets_scan_kind_name"),
    )

    scan_job_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    source_path: Mapped[str] = mapped_column(String(512), nullable=False)
    attrs: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
