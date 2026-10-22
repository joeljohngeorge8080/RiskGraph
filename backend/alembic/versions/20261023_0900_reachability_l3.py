"""Reachability tier L3: a vulnerable symbol is called on a path from an entry point (ADR-0015).

Reviewed by hand. Only the CHECK list changes; existing rows keep their tiers.

Revision ID: c4f0a7e2d913
Revises: 9a4d2c7e1b30
Create Date: 2026-10-23 09:00:00
"""

from __future__ import annotations

from alembic import op

revision = "c4f0a7e2d913"
down_revision = "9a4d2c7e1b30"
branch_labels = None
depends_on = None

OLD = ("L0", "L1", "L2", "unknown", "n_a")
NEW = ("L0", "L1", "L2", "L3", "unknown", "n_a")


def _check(values: tuple[str, ...]) -> str:
    return "tier IN (" + ", ".join(f"'{v}'" for v in values) + ")"


def upgrade() -> None:
    op.drop_constraint("reachability_tier", "reachability_results", type_="check")
    op.create_check_constraint("reachability_tier", "reachability_results", _check(NEW))


def downgrade() -> None:
    # Refuse rather than rewrite: an L3 row has no L2 equivalent.
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM reachability_results WHERE tier = 'L3') THEN "
        "RAISE EXCEPTION 'cannot downgrade: reachability_results has L3 rows'; END IF; END $$"
    )
    op.drop_constraint("reachability_tier", "reachability_results", type_="check")
    op.create_check_constraint("reachability_tier", "reachability_results", _check(OLD))
