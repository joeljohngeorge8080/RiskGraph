"""Celery application (ADR-0007).

Run with ``celery -A riskgraph.entrypoints.worker:celery_app worker -Q scan,analysis``
and ``celery -A riskgraph.entrypoints.worker:celery_app beat``. Module import reads
settings on purpose: a worker with a bad configuration must not start.
"""

from __future__ import annotations

from celery.signals import setup_logging, task_postrun, task_prerun

from riskgraph.shared.celery import QUEUE_ANALYSIS, QUEUE_SCAN, create_celery, get_celery_app
from riskgraph.shared.config import get_settings
from riskgraph.shared.logging import configure_logging

__all__ = ["QUEUE_ANALYSIS", "QUEUE_SCAN", "celery_app", "create_celery", "ping"]

celery_app = get_celery_app()


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
