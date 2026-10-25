"""Celery canvas for a scan (ADR-0007) and an inline equivalent for tests and e2e.

    chain(clone, chord(group(run_scanner x N), collect), scan_images, analyze, finalize)

``scan_images`` (X2) runs on the scan queue: it starts containers, like the scanners.

Task names are strings, so the API process builds this canvas without importing the
worker's task module.
"""

from __future__ import annotations

import uuid
from typing import Any

from celery import chain, chord, group
from celery.canvas import Signature

from riskgraph.modules.scanners import get_scanner
from riskgraph.modules.scans import pipeline, repo
from riskgraph.shared.celery import QUEUE_ANALYSIS, QUEUE_SCAN, get_celery_app
from riskgraph.shared.config import Settings
from riskgraph.shared.db import session_scope
from riskgraph.shared.vocabulary import ScannerName, ScanStatus

ANALYZE_TIME_LIMIT_S = 900


def _sig(name: str, *args: object, immutable: bool = True, **options: Any) -> Signature:
    return get_celery_app().signature(name, args=args, immutable=immutable).set(**options)


def build_canvas(scan_id: uuid.UUID, scanners: list[ScannerName], settings: Settings) -> Signature:
    sid = str(scan_id)
    header = group(
        _sig(
            "riskgraph.scans.run_scanner",
            sid,
            name.value,
            queue=QUEUE_SCAN,
            soft_time_limit=get_scanner(name).timeout_s(settings) + 60,
            time_limit=get_scanner(name).timeout_s(settings) + 120,
        )
        for name in scanners
    )
    return chain(
        _sig(
            "riskgraph.scans.clone",
            sid,
            queue=QUEUE_SCAN,
            time_limit=settings.clone_timeout_s + 120,
        ),
        chord(header, _sig("riskgraph.scans.collect", sid, immutable=False, queue=QUEUE_ANALYSIS)),
        _sig(
            "riskgraph.scans.scan_images",
            sid,
            queue=QUEUE_SCAN,
            soft_time_limit=pipeline.image_stage_time_limit_s(settings),
            time_limit=pipeline.image_stage_time_limit_s(settings) + 60,
        ),
        _sig("riskgraph.scans.analyze", sid, queue=QUEUE_ANALYSIS, time_limit=ANALYZE_TIME_LIMIT_S),
        _sig("riskgraph.scans.finalize", sid, queue=QUEUE_ANALYSIS),
    )


def enqueue(scan_id: uuid.UUID, scanners: list[ScannerName], settings: Settings) -> None:
    build_canvas(scan_id, scanners, settings).apply_async()


def enqueue_kill(scan_id: uuid.UUID) -> None:
    """Ask the worker (the only process with Docker access) to stop a cancelled scan."""
    _sig("riskgraph.scans.kill", str(scan_id), queue=QUEUE_SCAN).apply_async()


def run_pipeline_inline(
    scan_id: uuid.UUID, scanners: list[ScannerName], deps: pipeline.PipelineDeps
) -> ScanStatus | None:
    """Run every stage in this process, in order. Used by tests and ``make e2e``."""
    with session_scope() as s:
        repo.cas_scan(s, scan_id, ScanStatus.PENDING, ScanStatus.QUEUED)
    pipeline.clone(scan_id, deps)
    for name in scanners:
        pipeline.run_scanner(scan_id, name, deps)
    pipeline.collect(scan_id, deps)
    pipeline.scan_images(scan_id, deps)
    pipeline.analyze(scan_id, deps)
    return pipeline.finalize(scan_id, deps)
