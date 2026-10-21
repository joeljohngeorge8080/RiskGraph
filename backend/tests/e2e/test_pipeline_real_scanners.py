"""Full pipeline with the real scanner binaries on the kitchen-sink repository.

Run with ``make e2e`` (needs ``make scanner-tools``, Postgres and Redis). Trivy needs
network on its first run to download its vulnerability DB.
"""

from __future__ import annotations

import pytest
from riskgraph.modules.scanners import SubprocessRunner
from riskgraph.modules.scans import repo, service
from riskgraph.modules.scans.orchestration import run_pipeline_inline
from riskgraph.modules.scans.service import ALL_SCANNERS
from riskgraph.shared.config import Settings
from riskgraph.shared.db import session_scope
from riskgraph.shared.vocabulary import RunStatus, ScanStatus
from sqlalchemy import text

from tests.fixtures.repos import kitchen_sink
from tests.pipeline_support import LocalDirCloner, make_deps

pytestmark = [pytest.mark.e2e, pytest.mark.db]

RAW_SECRETS = [
    kitchen_sink.FAKE_AWS_KEY_ID,
    kitchen_sink.FAKE_AWS_SECRET,
    kitchen_sink.FILES["deploy/id_rsa"].splitlines()[3],
]


@pytest.fixture()
def real_settings(settings: Settings) -> Settings:
    missing = [
        t
        for t in ("trivy", "semgrep", "checkov", "gitleaks")
        if not (settings.scanner_bin_dir / t).exists()
    ]
    if missing:
        pytest.skip(f"scanner binaries not installed in {settings.scanner_bin_dir}: {missing}")
    return settings


def test_real_scanners_end_to_end(db: None, real_settings: Settings) -> None:
    deps = make_deps(
        real_settings,
        runner=SubprocessRunner(real_settings.scanner_bin_dir),
        cloner=LocalDirCloner(),
    )
    with session_scope() as s:
        sid = service.create_scan(
            s, "https://github.com/acme/kitchen-sink", None, real_settings
        ).scan.id

    assert run_pipeline_inline(sid, ALL_SCANNERS, deps) is ScanStatus.COMPLETED

    with session_scope() as s:
        runs = repo.runs_for(s, sid)
        assert {r.scanner.value: r.status for r in runs} == {
            n.value: RunStatus.SUCCEEDED for n in ALL_SCANNERS
        }
        assert all(r.scanner_version and r.raw_findings_count for r in runs)
        summary = s.execute(
            text("SELECT summary FROM scan_jobs WHERE id = :id"), {"id": sid}
        ).scalar_one()
        assert set(summary["by_source_type"]) == {"sca", "sast", "secret", "iac"}
        merged = s.execute(
            text(
                "SELECT f.source_type, sf.detected_by FROM scan_findings sf "
                "JOIN findings f ON f.id = sf.finding_id WHERE sf.scan_job_id = :id"
            ),
            {"id": sid},
        ).all()
        assert any(st == "secret" and {"gitleaks", "trivy"} <= set(d) for st, d in merged)
        assert any(st == "iac" and {"checkov", "trivy"} <= set(d) for st, d in merged)

        # Threat T-09: no raw secret anywhere in the database ...
        for table in (
            "findings",
            "finding_occurrences",
            "scanner_runs",
            "risk_factors",
            "scan_jobs",
        ):
            query = f"SELECT coalesce(string_agg(t::text, ''), '') FROM {table} t"  # noqa: S608
            dump = s.execute(text(query)).scalar_one()
            for raw in RAW_SECRETS:
                assert raw not in dump, f"raw secret leaked into {table}"

    # ... nor in any stored report.
    for name in ALL_SCANNERS:
        stored = (real_settings.scan_output_root / str(sid) / f"{name.value}.json").read_text()
        for raw in RAW_SECRETS:
            assert raw not in stored, f"raw secret leaked into {name.value}.json"
