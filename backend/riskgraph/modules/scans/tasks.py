"""Celery tasks: thin wrappers around ``pipeline`` stages.

Every task swallows unexpected exceptions after recording them on the scan: a raising
chord member would stop ``collect`` from ever running and leave the scan stuck.
"""

from __future__ import annotations

import uuid
from typing import Any

from celery import shared_task

from riskgraph.modules.scans import pipeline
from riskgraph.shared.logging import get_logger
from riskgraph.shared.vocabulary import RunStatus, ScannerName

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


@shared_task(name="riskgraph.scans.finalize")
def finalize_task(scan_id: str) -> str | None:
    try:
        status = pipeline.finalize(uuid.UUID(scan_id), pipeline.default_deps())
    except Exception:
        _guard("finalize", scan_id)
        return None
    return status.value if status else None
