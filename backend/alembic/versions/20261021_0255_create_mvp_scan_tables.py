"""Create the MVP scan tables (reviewed by hand; see docs/phases/PHASE_MVP.md).

Revision ID: fc3b3ff80221
Revises: (none)
Create Date: 2026-10-21 02:55:45.484109
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "fc3b3ff80221"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "repositories",
        sa.Column("provider", sa.String(length=16), nullable=False),
        sa.Column("owner", sa.String(length=100), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("full_name", sa.String(length=201), nullable=False),
        sa.Column("clone_url", sa.String(length=300), nullable=False),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("full_name"),
    )
    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("cvss_version", sa.String(length=8), nullable=True),
        sa.Column("cvss_vector", sa.String(length=200), nullable=True),
        sa.Column("cvss_base", sa.Numeric(precision=3, scale=1), nullable=True),
        sa.Column("cvss_impact", sa.Numeric(precision=3, scale=1), nullable=True),
        sa.Column("cvss_exploitability", sa.Numeric(precision=3, scale=1), nullable=True),
        sa.Column("cvss_source", sa.String(length=32), nullable=True),
        sa.Column("epss", sa.Numeric(precision=6, scale=5), nullable=True),
        sa.Column("epss_percentile", sa.Numeric(precision=6, scale=5), nullable=True),
        sa.Column("epss_date", sa.Date(), nullable=True),
        sa.Column("epss_fetched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("kev", sa.Boolean(), nullable=True),
        sa.Column("kev_added", sa.Date(), nullable=True),
        sa.Column("kev_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_vulnerabilities_kev", "vulnerabilities", ["kev"], unique=False)
    op.create_table(
        "scan_jobs",
        sa.Column("repository_id", sa.UUID(), nullable=False),
        sa.Column("requested_ref", sa.String(length=255), nullable=False),
        sa.Column("commit_sha", sa.String(length=40), nullable=True),
        sa.Column(
            "status",
            sa.Enum(
                "PENDING",
                "QUEUED",
                "CLONING",
                "SCANNING",
                "ANALYZING",
                "COMPLETED",
                "PARTIAL",
                "FAILED",
                name="scan_status",
                native_enum=False,
                create_constraint=True,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("status_reason", sa.Text(), nullable=True),
        sa.Column("trigger", sa.String(length=16), nullable=False),
        sa.Column("enabled_scanners", postgresql.ARRAY(sa.String(length=32)), nullable=False),
        sa.Column("risk_model_version", sa.String(length=32), nullable=True),
        sa.Column("summary", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["repository_id"], ["repositories.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_scan_jobs_repository_created",
        "scan_jobs",
        ["repository_id", sa.literal_column("created_at DESC")],
        unique=False,
    )
    op.create_index("ix_scan_jobs_status", "scan_jobs", ["status"], unique=False)
    op.create_index(
        "uq_scan_jobs_active_per_ref",
        "scan_jobs",
        ["repository_id", "requested_ref"],
        unique=True,
        postgresql_where=sa.text(
            "status IN ('PENDING', 'QUEUED', 'CLONING', 'SCANNING', 'ANALYZING')"
        ),
    )
    op.create_table(
        "findings",
        sa.Column("repository_id", sa.UUID(), nullable=False),
        sa.Column("merge_key", sa.String(length=64), nullable=False),
        sa.Column(
            "source_type",
            sa.Enum(
                "sca",
                "sast",
                "secret",
                "iac",
                name="source_type",
                native_enum=False,
                create_constraint=True,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "severity",
            sa.Enum(
                "critical",
                "high",
                "medium",
                "low",
                "info",
                name="severity",
                native_enum=False,
                create_constraint=True,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("rule_id", sa.String(length=300), nullable=False),
        sa.Column("vulnerability_id", sa.String(length=64), nullable=True),
        sa.Column("package", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("location", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("cwe_ids", postgresql.ARRAY(sa.String(length=16)), nullable=False),
        sa.Column("detected_by", postgresql.ARRAY(sa.String(length=32)), nullable=False),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("first_seen_scan_id", sa.UUID(), nullable=True),
        sa.Column("last_seen_scan_id", sa.UUID(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["first_seen_scan_id"], ["scan_jobs.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["last_seen_scan_id"], ["scan_jobs.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["repository_id"], ["repositories.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("repository_id", "merge_key", name="uq_findings_repo_merge_key"),
    )
    op.create_index(
        "ix_findings_repo_source", "findings", ["repository_id", "source_type"], unique=False
    )
    op.create_index("ix_findings_vulnerability", "findings", ["vulnerability_id"], unique=False)
    op.create_table(
        "scanner_runs",
        sa.Column("scan_job_id", sa.UUID(), nullable=False),
        sa.Column(
            "scanner",
            sa.Enum(
                "trivy",
                "semgrep",
                "checkov",
                "gitleaks",
                name="scanner_name",
                native_enum=False,
                create_constraint=True,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("scanner_version", sa.String(length=64), nullable=True),
        sa.Column(
            "status",
            sa.Enum(
                "QUEUED",
                "RUNNING",
                "SUCCEEDED",
                "FAILED",
                "TIMED_OUT",
                "SKIPPED",
                name="run_status",
                native_enum=False,
                create_constraint=True,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("output_path", sa.String(length=200), nullable=True),
        sa.Column("output_sha256", sa.String(length=64), nullable=True),
        sa.Column("output_bytes", sa.BigInteger(), nullable=True),
        sa.Column("raw_findings_count", sa.Integer(), nullable=True),
        sa.Column("error_excerpt", sa.Text(), nullable=True),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["scan_job_id"], ["scan_jobs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_job_id", "scanner", name="uq_scanner_runs_scan"),
    )
    op.create_table(
        "finding_occurrences",
        sa.Column("scan_job_id", sa.UUID(), nullable=False),
        sa.Column("scanner_run_id", sa.UUID(), nullable=False),
        sa.Column("finding_id", sa.UUID(), nullable=False),
        sa.Column(
            "scanner",
            sa.Enum(
                "trivy",
                "semgrep",
                "checkov",
                "gitleaks",
                name="scanner_name",
                native_enum=False,
                create_constraint=True,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("rule_id", sa.String(length=300), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("scanner_severity", sa.String(length=32), nullable=True),
        sa.Column(
            "severity",
            sa.Enum(
                "critical",
                "high",
                "medium",
                "low",
                "info",
                name="severity",
                native_enum=False,
                create_constraint=True,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("location", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_job_id"], ["scan_jobs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scanner_run_id"], ["scanner_runs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "scan_job_id", "scanner", "fingerprint", name="uq_occurrences_scan_scanner_fp"
        ),
    )
    op.create_index(
        "ix_occurrences_finding_scan",
        "finding_occurrences",
        ["finding_id", "scan_job_id"],
        unique=False,
    )
    op.create_table(
        "risk_scores",
        sa.Column("scan_job_id", sa.UUID(), nullable=False),
        sa.Column("finding_id", sa.UUID(), nullable=False),
        sa.Column("model_version", sa.String(length=32), nullable=False),
        sa.Column("likelihood", sa.Numeric(precision=5, scale=4), nullable=False),
        sa.Column("impact", sa.Numeric(precision=5, scale=4), nullable=False),
        sa.Column("corroboration", sa.Numeric(precision=4, scale=3), nullable=False),
        sa.Column("score", sa.Numeric(precision=5, scale=2), nullable=False),
        sa.Column(
            "priority",
            sa.Enum(
                "critical",
                "high",
                "medium",
                "low",
                name="priority",
                native_enum=False,
                create_constraint=True,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("priority_rank", sa.SmallInteger(), nullable=False),
        sa.Column("overrides", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("computed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_job_id"], ["scan_jobs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_job_id", "finding_id", name="uq_risk_scores_scan_finding"),
    )
    op.create_index(
        "ix_risk_scores_ranking",
        "risk_scores",
        ["scan_job_id", sa.literal_column("priority_rank DESC"), sa.literal_column("score DESC")],
        unique=False,
    )
    op.create_table(
        "scan_findings",
        sa.Column("scan_job_id", sa.UUID(), nullable=False),
        sa.Column("finding_id", sa.UUID(), nullable=False),
        sa.Column("detected_by", postgresql.ARRAY(sa.String(length=32)), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_job_id"], ["scan_jobs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("scan_job_id", "finding_id"),
    )
    op.create_table(
        "risk_factors",
        sa.Column("risk_score_id", sa.UUID(), nullable=False),
        sa.Column("group", sa.String(length=16), nullable=False),
        sa.Column("name", sa.String(length=8), nullable=False),
        sa.Column("value", sa.Numeric(precision=5, scale=4), nullable=False),
        sa.Column("raw_value", sa.String(length=200), nullable=True),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("confidence", sa.String(length=16), nullable=False),
        sa.Column("applicable", sa.Boolean(), nullable=False),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.ForeignKeyConstraint(["risk_score_id"], ["risk_scores.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_risk_factors_score", "risk_factors", ["risk_score_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_risk_factors_score", table_name="risk_factors")
    op.drop_table("risk_factors")
    op.drop_table("scan_findings")
    op.drop_index("ix_risk_scores_ranking", table_name="risk_scores")
    op.drop_table("risk_scores")
    op.drop_index("ix_occurrences_finding_scan", table_name="finding_occurrences")
    op.drop_table("finding_occurrences")
    op.drop_table("scanner_runs")
    op.drop_index("ix_findings_vulnerability", table_name="findings")
    op.drop_index("ix_findings_repo_source", table_name="findings")
    op.drop_table("findings")
    op.drop_index(
        "uq_scan_jobs_active_per_ref",
        table_name="scan_jobs",
        postgresql_where=sa.text(
            "status IN ('PENDING', 'QUEUED', 'CLONING', 'SCANNING', 'ANALYZING')"
        ),
    )
    op.drop_index("ix_scan_jobs_status", table_name="scan_jobs")
    op.drop_index("ix_scan_jobs_repository_created", table_name="scan_jobs")
    op.drop_table("scan_jobs")
    op.drop_index("ix_vulnerabilities_kev", table_name="vulnerabilities")
    op.drop_table("vulnerabilities")
    op.drop_table("repositories")
