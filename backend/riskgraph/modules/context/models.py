"""Vulnerability intelligence cache: CVSS from scanner data, EPSS and KEV from feeds."""

from __future__ import annotations

import datetime as dt
from decimal import Decimal

from sqlalchemy import Boolean, Date, DateTime, Index, Numeric, String
from sqlalchemy.orm import Mapped, mapped_column

from riskgraph.shared.db import Base, TimestampMixin


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
    kev: Mapped[bool | None] = mapped_column(Boolean)
    kev_added: Mapped[dt.date | None] = mapped_column(Date)
    kev_checked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
