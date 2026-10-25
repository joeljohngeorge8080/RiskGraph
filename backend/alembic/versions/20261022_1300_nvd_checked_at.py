"""NVD CVSS freshness: vulnerabilities.nvd_checked_at (P7, blueprint §11).

Reviewed by hand. Additive: a nullable timestamp, so existing rows keep their values and
NVD is fetched for them on the next refresh. Rollback drops only the column.

Revision ID: 9a4d2c7e1b30
Revises: 5c1e0a9d2f47
Create Date: 2026-10-22 13:00:00
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "9a4d2c7e1b30"
down_revision = "5c1e0a9d2f47"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "vulnerabilities",
        sa.Column("nvd_checked_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("vulnerabilities", "nvd_checked_at")
