"""Packages installed in the images a repository names (expansion X2 part 2).

Reviewed by hand.
- ``sbom_components.image``: nullable, the image a package is installed in; NULL for the
  repository's own packages, so existing rows keep their meaning.
- The unique key becomes (scan, purl, image) with NULLs not distinct: the same package
  may be in the repository and in an image, but never twice in either.

Revision ID: b8d3f1a6c2e9
Revises: a7c2e9f4b1d6
Create Date: 2026-10-26 06:00:00
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "b8d3f1a6c2e9"
down_revision = "a7c2e9f4b1d6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("sbom_components", sa.Column("image", sa.String(length=255), nullable=True))
    op.drop_constraint("uq_sbom_components_scan_purl", "sbom_components", type_="unique")
    op.create_unique_constraint(
        "uq_sbom_components_scan_purl_image",
        "sbom_components",
        ["scan_job_id", "purl", "image"],
        postgresql_nulls_not_distinct=True,
    )


def downgrade() -> None:
    # Refuse rather than delete: the old key cannot hold a package seen in two places.
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM sbom_components WHERE image IS NOT NULL) THEN "
        "RAISE EXCEPTION 'cannot downgrade: image packages exist in sbom_components'; "
        "END IF; END $$"
    )
    op.drop_constraint("uq_sbom_components_scan_purl_image", "sbom_components", type_="unique")
    op.create_unique_constraint(
        "uq_sbom_components_scan_purl", "sbom_components", ["scan_job_id", "purl"]
    )
    op.drop_column("sbom_components", "image")
