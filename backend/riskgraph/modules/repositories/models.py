"""Registered repositories. MVP: public github.com repositories only (ADR-0010)."""

from __future__ import annotations

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from riskgraph.shared.db import Base, TimestampMixin, UUIDPrimaryKeyMixin


class Repository(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "repositories"

    provider: Mapped[str] = mapped_column(String(16), default="github", nullable=False)
    owner: Mapped[str] = mapped_column(String(100), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    # Lower-cased "owner/name"; GitHub names are case-insensitive.
    full_name: Mapped[str] = mapped_column(String(201), unique=True, nullable=False)
    # Always rebuilt from owner/name by the service, never taken from a request verbatim.
    clone_url: Mapped[str] = mapped_column(String(300), nullable=False)
