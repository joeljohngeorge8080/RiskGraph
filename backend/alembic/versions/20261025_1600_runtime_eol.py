"""Runtime end-of-life data and RiskGraph's own analyzers as a producer (expansion X2).

Reviewed by hand.
- New: ``runtime_eol``, endoflife.date cycles refreshed by Beat (PK product + cycle).
- ``scanner_runs.scanner`` and ``finding_occurrences.scanner`` accept ``riskgraph``: the
  producer of findings RiskGraph derives itself (runtime EOL now, authorization in X5),
  so every finding keeps a producer and a run (ADR-0018).

Revision ID: a7c2e9f4b1d6
Revises: f3a9c1d7b2e8
Create Date: 2026-10-25 16:00:00
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "a7c2e9f4b1d6"
down_revision = "f3a9c1d7b2e8"
branch_labels = None
depends_on = None

OLD = ("trivy", "semgrep", "checkov", "gitleaks", "syft")
NEW = (*OLD, "riskgraph")
TABLES = ("scanner_runs", "finding_occurrences")


def _check(values: tuple[str, ...]) -> str:
    return "scanner IN (" + ", ".join(f"'{v}'" for v in values) + ")"


def upgrade() -> None:
    op.create_table(
        "runtime_eol",
        sa.Column("product", sa.String(length=32), nullable=False),
        sa.Column("cycle", sa.String(length=32), nullable=False),
        sa.Column("eol_date", sa.Date(), nullable=True),
        sa.Column("eol_flag", sa.Boolean(), nullable=True),
        sa.Column("latest", sa.String(length=64), nullable=True),
        sa.Column("release_date", sa.Date(), nullable=True),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("product", "cycle"),
    )
    for table in TABLES:
        op.drop_constraint("scanner_name", table, type_="check")
        op.create_check_constraint("scanner_name", table, _check(NEW))


def downgrade() -> None:
    # Refuse rather than rewrite: a riskgraph-produced finding has no scanner to fall back on.
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM scanner_runs WHERE scanner = 'riskgraph') "
        "OR EXISTS (SELECT 1 FROM finding_occurrences WHERE scanner = 'riskgraph') THEN "
        "RAISE EXCEPTION 'cannot downgrade: riskgraph-produced findings exist'; END IF; END $$"
    )
    for table in TABLES:
        op.drop_constraint("scanner_name", table, type_="check")
        op.create_check_constraint("scanner_name", table, _check(OLD))
    op.drop_table("runtime_eol")
