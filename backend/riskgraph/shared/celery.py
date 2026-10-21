"""Celery application factory (ADR-0007).

Lives in ``shared`` so the API can enqueue work without importing the worker entrypoint.
Tasks are declared with ``shared_task`` in ``modules/<x>/tasks.py`` and registered by the
worker through ``include``; the API only builds signatures by task name.
"""

from __future__ import annotations

from functools import lru_cache

from celery import Celery
from kombu import Queue

from riskgraph.shared.config import Settings, get_settings

QUEUE_SCAN = "scan"
QUEUE_ANALYSIS = "analysis"

TASK_MODULES = ["riskgraph.modules.scans.tasks"]


def create_celery(settings: Settings | None = None) -> Celery:
    settings = settings or get_settings()
    app = Celery(
        "riskgraph", broker=settings.redis_url, backend=settings.redis_url, include=TASK_MODULES
    )
    app.conf.update(
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        timezone="UTC",
        enable_utc=True,
        task_acks_late=True,
        task_reject_on_worker_lost=True,
        worker_prefetch_multiplier=1,
        task_track_started=True,
        result_expires=24 * 3600,
        broker_connection_retry_on_startup=True,
        task_default_queue=QUEUE_ANALYSIS,
        task_queues=(Queue(QUEUE_SCAN), Queue(QUEUE_ANALYSIS)),
        beat_schedule={},
        worker_hijack_root_logger=False,
    )
    app.conf.riskgraph_settings = settings
    return app


@lru_cache(maxsize=1)
def get_celery_app() -> Celery:
    """Process-wide Celery app; the worker entrypoint and the API share this instance."""
    return create_celery()
