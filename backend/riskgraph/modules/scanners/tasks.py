"""Celery tasks for the scanner tool databases (blueprint §9.2)."""

from __future__ import annotations

from celery import shared_task

from riskgraph.modules.scanners.tooldb import refresh_trivy_db
from riskgraph.modules.scans import pipeline
from riskgraph.shared.logging import get_logger
from riskgraph.shared.vocabulary import ScannerName

log = get_logger(__name__)


@shared_task(name="riskgraph.scanners.refresh_trivy_db")
def refresh_trivy_db_task() -> str:
    """Beat: refresh Trivy's DB while holding the lock every Trivy scan takes."""
    deps = pipeline.default_deps()
    settings = deps.settings
    with pipeline.redis_scanner_lock(ScannerName.TRIVY, settings.timeout_trivy_db_s) as acquired:
        if not acquired:
            return "skipped: scans hold the trivy lock"
        result = refresh_trivy_db(deps.runner, settings, settings.data_dir / "tooldb" / "logs")
    if result.exit_code == 0:
        log.info("trivy_db_refreshed", duration_ms=result.duration_ms)
        return "ok"
    log.warning("trivy_db_refresh_failed", exit_code=result.exit_code, timed_out=result.timed_out)
    return f"failed: exit={result.exit_code} timed_out={result.timed_out}"
