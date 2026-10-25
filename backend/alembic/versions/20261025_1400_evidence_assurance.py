"""Evidence and assurance (ADR-0017, expansion X1).

Reviewed by hand.
- New: ``evidence`` (scan-scoped, PK scan + id), ``finding_evidence`` and ``edge_evidence``.
- ``graph_edges.assurance``, NOT NULL. Existing rows are backfilled by the builder's own
  rule (ADR-0017): AUTHENTICATES_AS is a hypothesis (family match); EXPLOIT takes the tier
  of the finding that set its probability (L3 verified, L2 inferred, otherwise
  hypothesis); RUNS_AS to the synthetic unknown identity is inferred; everything else is
  a manifest declaration, verified. Rows from before X1 get no edge_evidence links: their
  evidence was never recorded.
- ``findings.source_type`` accepts ``runtime`` and ``authz`` (producers arrive in X2, X5).

Revision ID: f3a9c1d7b2e8
Revises: e1b7d3a9c2f4
Create Date: 2026-10-25 14:00:00
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "f3a9c1d7b2e8"
down_revision = "e1b7d3a9c2f4"
branch_labels = None
depends_on = None

OLD_SOURCE_TYPES = ("sca", "sast", "secret", "iac")
NEW_SOURCE_TYPES = (*OLD_SOURCE_TYPES, "runtime", "authz")
ASSURANCE = "assurance IN ('verified', 'inferred', 'hypothesis')"


def _source_check(values: tuple[str, ...]) -> str:
    return "source_type IN (" + ", ".join(f"'{v}'" for v in values) + ")"


def upgrade() -> None:
    op.create_table(
        "evidence",
        sa.Column("scan_job_id", sa.UUID(), nullable=False),
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("producer", sa.String(length=96), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("assurance", sa.String(length=16), nullable=False),
        sa.Column("confidence", sa.String(length=8), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("raw_run_id", sa.UUID(), nullable=True),
        sa.Column("raw_pointer", sa.String(length=512), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("data_as_of", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(ASSURANCE, name="evidence_assurance"),
        sa.CheckConstraint("confidence IN ('high', 'medium', 'low')", name="evidence_confidence"),
        sa.ForeignKeyConstraint(["scan_job_id"], ["scan_jobs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["raw_run_id"], ["scanner_runs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("scan_job_id", "id"),
    )
    op.create_table(
        "finding_evidence",
        sa.Column("scan_job_id", sa.UUID(), nullable=False),
        sa.Column("finding_id", sa.UUID(), nullable=False),
        sa.Column("evidence_id", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["scan_job_id", "evidence_id"],
            ["evidence.scan_job_id", "evidence.id"],
            ondelete="CASCADE",
            name="fk_finding_evidence_evidence",
        ),
        sa.PrimaryKeyConstraint("scan_job_id", "finding_id", "evidence_id"),
    )
    op.create_index("ix_finding_evidence_finding", "finding_evidence", ["finding_id"])
    op.create_table(
        "edge_evidence",
        sa.Column("edge_id", sa.UUID(), nullable=False),
        sa.Column("evidence_id", sa.String(length=64), nullable=False),
        sa.Column("scan_job_id", sa.UUID(), nullable=False),
        sa.ForeignKeyConstraint(["edge_id"], ["graph_edges.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["scan_job_id", "evidence_id"],
            ["evidence.scan_job_id", "evidence.id"],
            ondelete="CASCADE",
            name="fk_edge_evidence_evidence",
        ),
        sa.PrimaryKeyConstraint("edge_id", "evidence_id"),
    )

    op.add_column("graph_edges", sa.Column("assurance", sa.String(length=16), nullable=True))
    op.execute(
        """
        UPDATE graph_edges e SET assurance = CASE r.tier
            WHEN 'L3' THEN 'verified' WHEN 'L2' THEN 'inferred' ELSE 'hypothesis' END
        FROM reachability_results r
        WHERE e.kind = 'EXPLOIT'
          AND r.scan_job_id = e.scan_job_id
          AND r.finding_id::text = e.evidence -> 'findings' ->> 0
        """
    )
    op.execute(
        """
        UPDATE graph_edges SET assurance = CASE
            WHEN kind IN ('AUTHENTICATES_AS', 'EXPLOIT') THEN 'hypothesis'
            WHEN kind = 'RUNS_AS' AND target = 'identity:unknown-identity' THEN 'inferred'
            ELSE 'verified' END
        WHERE assurance IS NULL
        """
    )
    op.alter_column("graph_edges", "assurance", nullable=False)
    op.create_check_constraint("graph_edge_assurance", "graph_edges", ASSURANCE)

    op.drop_constraint("source_type", "findings", type_="check")
    op.create_check_constraint("source_type", "findings", _source_check(NEW_SOURCE_TYPES))


def downgrade() -> None:
    # Refuse rather than rewrite: a runtime or authz finding has no older equivalent.
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM findings WHERE source_type IN ('runtime', 'authz'))"
        " THEN RAISE EXCEPTION 'cannot downgrade: findings has runtime or authz rows'; "
        "END IF; END $$"
    )
    op.drop_constraint("source_type", "findings", type_="check")
    op.create_check_constraint("source_type", "findings", _source_check(OLD_SOURCE_TYPES))
    op.drop_constraint("graph_edge_assurance", "graph_edges", type_="check")
    op.drop_column("graph_edges", "assurance")
    op.drop_table("edge_evidence")
    op.drop_index("ix_finding_evidence_finding", table_name="finding_evidence")
    op.drop_table("finding_evidence")
    op.drop_table("evidence")
