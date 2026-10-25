"""Container runner, SBOM and environment assets: P3 cancel, P4 Syft, P5 SBOM, P7 assets.

Reviewed by hand (docs/phases/PHASE_03.md). Changes:
- scan_status CHECK gains CANCELLED (cancel is a terminal state, blueprint §9.1).
- scanner_name CHECK (scanner_runs, finding_occurrences) gains syft.
- sbom_components: one row per package per scan (Syft inventory, Trivy-only purls too).
- scan_findings.component_id: which component an SCA finding attaches to in that scan.
- assets: environment assets extracted from Kubernetes and Compose (P7), per scan.

Downgrade drops the new tables and restores the old CHECK lists. Cancelled scans become
FAILED (reason kept) and Syft-only runs are removed, because the old lists cannot hold them.

Revision ID: 5c1e0a9d2f47
Revises: b7dac1b028da
Create Date: 2026-10-22 12:00:00
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "5c1e0a9d2f47"
down_revision = "b7dac1b028da"
branch_labels = None
depends_on = None

SCAN_STATUSES_OLD = (
    "PENDING",
    "QUEUED",
    "CLONING",
    "SCANNING",
    "ANALYZING",
    "COMPLETED",
    "PARTIAL",
    "FAILED",
)
SCAN_STATUSES_NEW = (*SCAN_STATUSES_OLD, "CANCELLED")
SCANNERS_OLD = ("trivy", "semgrep", "checkov", "gitleaks")
SCANNERS_NEW = (*SCANNERS_OLD, "syft")


def _in_list(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{v}'" for v in values)


def _replace_check(table: str, name: str, column: str, values: tuple[str, ...]) -> None:
    op.drop_constraint(name, table, type_="check")
    op.create_check_constraint(name, table, f"{column} IN ({_in_list(values)})")


def upgrade() -> None:
    _replace_check("scan_jobs", "scan_status", "status", SCAN_STATUSES_NEW)
    _replace_check("scanner_runs", "scanner_name", "scanner", SCANNERS_NEW)
    _replace_check("finding_occurrences", "scanner_name", "scanner", SCANNERS_NEW)

    op.create_table(
        "sbom_components",
        sa.Column("scan_job_id", sa.UUID(), nullable=False),
        sa.Column("purl", sa.String(length=512), nullable=False),
        sa.Column("name", sa.String(length=256), nullable=False),
        sa.Column("version", sa.String(length=128), nullable=False),
        sa.Column("ecosystem", sa.String(length=32), nullable=False),
        sa.Column("location", sa.String(length=512), nullable=True),
        sa.Column("discovered_by", sa.String(length=16), nullable=False),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.ForeignKeyConstraint(["scan_job_id"], ["scan_jobs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_job_id", "purl", name="uq_sbom_components_scan_purl"),
    )
    op.create_index("ix_sbom_components_name", "sbom_components", ["scan_job_id", "name"])

    op.add_column("scan_findings", sa.Column("component_id", sa.UUID(), nullable=True))
    op.create_foreign_key(
        "fk_scan_findings_component",
        "scan_findings",
        "sbom_components",
        ["component_id"],
        ["id"],
        ondelete="SET NULL",
    )

    op.create_table(
        "assets",
        sa.Column("scan_job_id", sa.UUID(), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("source_path", sa.String(length=512), nullable=False),
        sa.Column("attrs", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.ForeignKeyConstraint(["scan_job_id"], ["scan_jobs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_job_id", "kind", "name", name="uq_assets_scan_kind_name"),
    )


def downgrade() -> None:
    op.drop_table("assets")
    op.drop_constraint("fk_scan_findings_component", "scan_findings", type_="foreignkey")
    op.drop_column("scan_findings", "component_id")
    op.drop_index("ix_sbom_components_name", table_name="sbom_components")
    op.drop_table("sbom_components")
    # The old CHECK lists cannot hold these rows. Cancelled scans become FAILED with the
    # reason kept; Syft-only rows (no findings of their own) are removed.
    op.execute(
        "UPDATE scan_jobs SET status = 'FAILED', "
        "status_reason = 'cancelled (schema downgraded)' WHERE status = 'CANCELLED'"
    )
    op.execute("DELETE FROM finding_occurrences WHERE scanner = 'syft'")
    op.execute("DELETE FROM scanner_runs WHERE scanner = 'syft'")
    _replace_check("finding_occurrences", "scanner_name", "scanner", SCANNERS_OLD)
    _replace_check("scanner_runs", "scanner_name", "scanner", SCANNERS_OLD)
    _replace_check("scan_jobs", "scan_status", "status", SCAN_STATUSES_OLD)
