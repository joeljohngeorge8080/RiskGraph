"""End-of-life cycles from endoflife.date, refreshed by Beat (expansion X2)."""

from __future__ import annotations

import datetime as dt

from sqlalchemy import Boolean, Date, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from riskgraph.shared.db import Base


class RuntimeEol(Base):
    __tablename__ = "runtime_eol"

    product: Mapped[str] = mapped_column(String(32), primary_key=True)
    cycle: Mapped[str] = mapped_column(String(32), primary_key=True)
    eol_date: Mapped[dt.date | None] = mapped_column(Date)
    eol_flag: Mapped[bool | None] = mapped_column(Boolean)
    latest: Mapped[str | None] = mapped_column(String(64))
    release_date: Mapped[dt.date | None] = mapped_column(Date)
    fetched_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
