"""Celery tasks: thin wrappers around ``pipeline`` stages.

Every task swallows unexpected exceptions after recording them on the scan: a raising
chord member would stop ``collect`` from ever running and leave the scan stuck.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from celery import shared_task

from riskgraph.modules.scanners.docker_runner import DockerRunner
from riskgraph.modules.scans import pipeline, reaper
from riskgraph.shared.celery import get_celery_app
from riskgraph.shared.config import get_settings
from riskgraph.shared.db import session_scope
from riskgraph.shared.logging import get_logger
from riskgraph.shared.vocabulary import RunStatus, ScannerName, ScanStatus

EXPLAIN_TASK = "riskgraph.explain.top_findings"  # modules/explain/tasks.py

log = get_logger(__name__)


def _guard(stage: str, scan_id: str) -> None:
    log.exception("stage_crashed", stage=stage, scan_id=scan_id)
    try:
        pipeline.fail_scan(uuid.UUID(scan_id), f"{stage} failed (internal error)")
    except Exception:
        log.exception("fail_scan_crashed", scan_id=scan_id)


@shared_task(name="riskgraph.scans.clone")
def clone_task(scan_id: str) -> bool:
    try:
        return pipeline.clone(uuid.UUID(scan_id), pipeline.default_deps())
    except Exception:
        _guard("clone", scan_id)
        return False


@shared_task(name="riskgraph.scans.run_scanner")
def run_scanner_task(scan_id: str, scanner: str) -> dict[str, str]:
    try:
        status = pipeline.run_scanner(
            uuid.UUID(scan_id), ScannerName(scanner), pipeline.default_deps()
        )
    except Exception:
        log.exception("stage_crashed", stage="run_scanner", scan_id=scan_id, scanner=scanner)
        status = RunStatus.FAILED
    return {"scanner": scanner, "status": status.value}


@shared_task(name="riskgraph.scans.collect")
def collect_task(_results: list[Any], scan_id: str) -> None:
    try:
        pipeline.collect(uuid.UUID(scan_id), pipeline.default_deps())
    except Exception:
        _guard("collect", scan_id)


@shared_task(name="riskgraph.scans.analyze")
def analyze_task(scan_id: str) -> None:
    try:
        pipeline.analyze(uuid.UUID(scan_id), pipeline.default_deps())
    except Exception:
        _guard("analyze", scan_id)


@shared_task(name="riskgraph.scans.kill")
def kill_task(scan_id: str) -> None:
    """Stop a cancelled scan's containers and remove its workspace (worker has Docker)."""
    try:
        deps = pipeline.default_deps()
        sid = uuid.UUID(scan_id)
        if isinstance(deps.runner, DockerRunner):
            deps.runner.kill_scan(sid)
        pipeline.discard_workspace(deps, sid)
    except Exception:
        log.exception("kill_crashed", scan_id=scan_id)


@shared_task(name="riskgraph.scans.reap")
def reap_task() -> dict[str, int]:
    """Beat: recover runs and scans whose worker died (blueprint §9.2)."""
    settings = get_settings()
    with session_scope() as s:
        result = reaper.reap(s, settings, dt.datetime.now(dt.UTC))
    deps = pipeline.default_deps(settings)
    for sid in result.failed_scan_ids:
        if isinstance(deps.runner, DockerRunner):
            deps.runner.kill_scan(sid)
        pipeline.discard_workspace(deps, sid)
    return {"runs_timed_out": result.runs_timed_out, "scans_failed": result.scans_failed}


@shared_task(name="riskgraph.scans.finalize")
def finalize_task(scan_id: str) -> str | None:
    try:
        status = pipeline.finalize(uuid.UUID(scan_id), pipeline.default_deps())
    except Exception:
        _guard("finalize", scan_id)
        return None
    if status in (ScanStatus.COMPLETED, ScanStatus.PARTIAL) and get_settings().explain_top_n:
        try:
            # by name: scans must not import explain (explain reads findings and risk)
            get_celery_app().signature(EXPLAIN_TASK, args=(scan_id,)).apply_async()
        except Exception:
            # the scan is done either way; explanations can be generated on demand
            log.exception("explain_enqueue_failed", scan_id=scan_id)
    return status.value if status else None
