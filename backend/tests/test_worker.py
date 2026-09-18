from __future__ import annotations

from riskgraph.entrypoints.worker import QUEUE_ANALYSIS, QUEUE_SCAN, celery_app, ping


def test_celery_configuration_is_safe() -> None:
    conf = celery_app.conf
    assert conf.task_serializer == "json"
    assert conf.accept_content == ["json"]  # never pickle: broker messages are untrusted
    assert conf.task_acks_late is True
    assert {q.name for q in conf.task_queues} == {QUEUE_SCAN, QUEUE_ANALYSIS}


def test_ping_task_runs_eagerly() -> None:
    celery_app.conf.task_always_eager = True
    try:
        assert ping.apply().get() == "pong"
    finally:
        celery_app.conf.task_always_eager = False
