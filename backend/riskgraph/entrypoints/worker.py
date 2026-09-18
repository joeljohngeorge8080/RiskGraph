"""Celery application (ADR-0007).

Run with ``celery -A riskgraph.entrypoints.worker:celery_app worker -Q scan,analysis``
and ``celery -A riskgraph.entrypoints.worker:celery_app beat``. Module import reads
settings on purpose: a worker with a bad configuration must not start.
"""

from __future__ import annotations

from celery import Celery
from celery.signals import setup_logging, task_postrun, task_prerun
from kombu import Queue

from riskgraph.shared.config import Settings, get_settings
from riskgraph.shared.logging import configure_logging

QUEUE_SCAN = "scan"
QUEUE_ANALYSIS = "analysis"


def create_celery(settings: Settings | None = None) -> Celery:
    settings = settings or get_settings()
    app = Celery("riskgraph", broker=settings.redis_url, backend=settings.redis_url)
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


celery_app = create_celery()


@setup_logging.connect
def _configure_worker_logging(**_: object) -> None:
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_json)


@task_prerun.connect
def _bind_task_context(task_id: str | None = None, task: object = None, **_: object) -> None:
    import structlog

    structlog.contextvars.clear_contextvars()
    structlog.contextvars.bind_contextvars(task_id=task_id, task=getattr(task, "name", None))


@task_postrun.connect
def _clear_task_context(**_: object) -> None:
    import structlog

    structlog.contextvars.clear_contextvars()


@celery_app.task(name="riskgraph.ping")
def ping() -> str:
    """Smoke task: proves broker, worker and result backend work end to end."""
    return "pong"
