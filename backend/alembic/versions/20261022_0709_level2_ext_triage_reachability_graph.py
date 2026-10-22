"""MVP level 2 extended: triage/history, reachability, security graph and attack paths.

Reviewed by hand (docs/phases/PHASE_MVP2_EXT.md). Added manually: the findings.status CHECK
(existing column, values already 'open'), a server default so scan_findings.change can be
added NOT NULL to existing rows, and a named foreign key.

Revision ID: b7dac1b028da
Revises: fc3b3ff80221
Create Date: 2026-10-22 07:09:24.206979
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "b7dac1b028da"
down_revision = "fc3b3ff80221"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "audit_logs",
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor", sa.String(length=100), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("entity", sa.String(length=32), nullable=False),
        sa.Column("entity_id", sa.UUID(), nullable=False),
        sa.Column("before", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("after", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_audit_logs_entity", "audit_logs", ["entity", "entity_id", "at"], unique=False
    )
    op.create_table(
        "attack_paths",
        sa.Column("scan_job_id", sa.UUID(), nullable=False),
        sa.Column("source", sa.String(length=160), nullable=False),
        sa.Column("sink", sa.String(length=160), nullable=False),
        sa.Column("rank", sa.SmallInteger(), nullable=False),
        sa.Column("hops", sa.SmallInteger(), nullable=False),
        sa.Column("nodes", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("edges", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("probability", sa.Numeric(precision=6, scale=5), nullable=False),
        sa.Column("sink_impact", sa.Numeric(precision=5, scale=4), nullable=False),
        sa.Column("score", sa.Numeric(precision=5, scale=2), nullable=False),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.ForeignKeyConstraint(["scan_job_id"], ["scan_jobs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_attack_paths_scan_score", "attack_paths", ["scan_job_id", "score"], unique=False
    )
    op.create_table(
        "graph_edges",
        sa.Column("scan_job_id", sa.UUID(), nullable=False),
        sa.Column("source", sa.String(length=160), nullable=False),
        sa.Column("target", sa.String(length=160), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("probability", sa.Numeric(precision=6, scale=5), nullable=True),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.ForeignKeyConstraint(["scan_job_id"], ["scan_jobs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_graph_edges_scan", "graph_edges", ["scan_job_id"], unique=False)
    op.create_table(
        "graph_nodes",
        sa.Column("scan_job_id", sa.UUID(), nullable=False),
        sa.Column("key", sa.String(length=160), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("label", sa.String(length=200), nullable=False),
        sa.Column("properties", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.ForeignKeyConstraint(["scan_job_id"], ["scan_jobs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_job_id", "key", name="uq_graph_nodes_scan_key"),
    )
    op.create_table(
        "attack_path_findings",
        sa.Column("attack_path_id", sa.UUID(), nullable=False),
        sa.Column("finding_id", sa.UUID(), nullable=False),
        sa.ForeignKeyConstraint(["attack_path_id"], ["attack_paths.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("attack_path_id", "finding_id"),
    )
    op.create_table(
        "reachability_results",
        sa.Column("scan_job_id", sa.UUID(), nullable=False),
        sa.Column("finding_id", sa.UUID(), nullable=False),
        sa.Column(
            "tier",
            sa.Enum(
                "L0",
                "L1",
                "L2",
                "unknown",
                "n_a",
                name="reachability_tier",
                native_enum=False,
                create_constraint=True,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("confidence", sa.String(length=16), nullable=False),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("analyzer_version", sa.String(length=32), nullable=False),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_job_id"], ["scan_jobs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_job_id", "finding_id", name="uq_reachability_scan_finding"),
    )
    op.add_column("findings", sa.Column("status_reason", sa.Text(), nullable=True))
    op.add_column(
        "findings", sa.Column("status_changed_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("findings", sa.Column("fixed_in_scan_id", sa.UUID(), nullable=True))
    op.create_foreign_key(
        "fk_findings_fixed_in_scan",
        "findings",
        "scan_jobs",
        ["fixed_in_scan_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_check_constraint(
        "finding_status",
        "findings",
        "status IN ('open', 'fixed', 'false_positive', 'accepted_risk', 'wont_fix')",
    )
    op.add_column(
        "risk_scores",
        sa.Column("effective_impact", sa.Numeric(precision=5, scale=4), nullable=True),
    )
    op.add_column(
        "scan_findings",
        sa.Column(
            "change",
            sa.Enum(
                "new",
                "existing",
                "reopened",
                name="finding_change",
                native_enum=False,
                create_constraint=True,
                length=32,
            ),
            nullable=False,
            server_default="existing",
        ),
    )
    op.alter_column("scan_findings", "change", server_default=None)


def downgrade() -> None:
    op.drop_column("scan_findings", "change")
    op.drop_column("risk_scores", "effective_impact")
    # WARNING: constraint name is None; this directive will fail as
    # rendered.  Add a name, or use a naming convention; see
    # https://alembic.sqlalchemy.org/en/latest/naming.html
    op.drop_constraint("finding_status", "findings", type_="check")
    op.drop_constraint("fk_findings_fixed_in_scan", "findings", type_="foreignkey")
    op.drop_column("findings", "fixed_in_scan_id")
    op.drop_column("findings", "status_changed_at")
    op.drop_column("findings", "status_reason")
    op.drop_table("reachability_results")
    op.drop_table("attack_path_findings")
    op.drop_table("graph_nodes")
    op.drop_index("ix_graph_edges_scan", table_name="graph_edges")
    op.drop_table("graph_edges")
    op.drop_index("ix_attack_paths_scan_score", table_name="attack_paths")
    op.drop_table("attack_paths")
    op.drop_index("ix_audit_logs_entity", table_name="audit_logs")
    op.drop_table("audit_logs")
