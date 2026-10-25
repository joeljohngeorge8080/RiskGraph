"""One row per package per scan. Syft is the inventory owner; Trivy adds packages it saw
that Syft did not, marked ``discovered_by='trivy'`` so nothing is lost (blueprint §10.2).

Packages installed in an image the repository names (X2) carry the image; repository
packages have ``image`` NULL. A package is unique per scan and image (NULLs not distinct).
"""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from riskgraph.shared.db import Base, UUIDPrimaryKeyMixin


class SbomComponent(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "sbom_components"
    __table_args__ = (
        UniqueConstraint(
            "scan_job_id",
            "purl",
            "image",
            name="uq_sbom_components_scan_purl_image",
            postgresql_nulls_not_distinct=True,
        ),
        Index("ix_sbom_components_name", "scan_job_id", "name"),
    )

    scan_job_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False
    )
    purl: Mapped[str] = mapped_column(String(512), nullable=False)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    version: Mapped[str] = mapped_column(String(128), nullable=False)
    ecosystem: Mapped[str] = mapped_column(String(32), nullable=False)
    location: Mapped[str | None] = mapped_column(String(512))
    discovered_by: Mapped[str] = mapped_column(String(16), nullable=False)
    image: Mapped[str | None] = mapped_column(String(255))  # X2: None for repository packages
