"""Explain a finished scan's top Critical findings in the background (blueprint §15.3)."""

from __future__ import annotations

import uuid

from celery import shared_task

from riskgraph.modules.explain.service import adapter_from_settings, explain, top_critical
from riskgraph.shared.config import get_settings
from riskgraph.shared.db import session_scope
from riskgraph.shared.logging import get_logger

log = get_logger(__name__)
TASK_NAME = "riskgraph.explain.top_findings"


@shared_task(name=TASK_NAME)
def explain_top_findings_task(scan_id: str) -> dict[str, int]:
    settings = get_settings()
    sid = uuid.UUID(scan_id)
    with session_scope() as s:
        ids = top_critical(s, sid, settings.explain_top_n)
    adapter = adapter_from_settings(settings)
    counts = {"validated": 0, "fallback": 0, "failed": 0}
    try:
        for fid in ids:
            try:
                with session_scope() as s:  # one transaction per finding: progress is kept
                    counts[explain(s, sid, fid, adapter).status] += 1
            except Exception:
                counts["failed"] += 1
                log.exception("explanation_failed", scan_id=scan_id, finding_id=str(fid))
    finally:
        if adapter is not None:
            adapter.close()
    log.info("explanations_done", scan_id=scan_id, **counts)
    return counts
