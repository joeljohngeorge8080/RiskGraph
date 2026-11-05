"""Joern as a scanner name (expansion X4 part 2, ADR-0025).

Reviewed by hand.
- ``scanner_runs.scanner`` and ``finding_occurrences.scanner`` accept ``joern``: the tier-2
  taint engine of the opt-in ``deep`` scan profile.

Revision ID: d4e8b2c6f1a3
Revises: b8d3f1a6c2e9
Create Date: 2026-11-05 09:00:00
"""

from __future__ import annotations

from alembic import op

revision = "d4e8b2c6f1a3"
down_revision = "b8d3f1a6c2e9"
branch_labels = None
depends_on = None

OLD = ("trivy", "semgrep", "checkov", "gitleaks", "syft", "riskgraph")
NEW = (*OLD, "joern")
TABLES = ("scanner_runs", "finding_occurrences")


def _check(values: tuple[str, ...]) -> str:
    return "scanner IN (" + ", ".join(f"'{v}'" for v in values) + ")"


def upgrade() -> None:
    for table in TABLES:
        op.drop_constraint("scanner_name", table, type_="check")
        op.create_check_constraint("scanner_name", table, _check(NEW))


def downgrade() -> None:
    # Refuse rather than rewrite: a joern run or finding has no other scanner to become.
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM scanner_runs WHERE scanner = 'joern') "
        "OR EXISTS (SELECT 1 FROM finding_occurrences WHERE scanner = 'joern') THEN "
        "RAISE EXCEPTION 'cannot downgrade: joern runs exist'; END IF; END $$"
    )
    for table in TABLES:
        op.drop_constraint("scanner_name", table, type_="check")
        op.create_check_constraint("scanner_name", table, _check(OLD))
