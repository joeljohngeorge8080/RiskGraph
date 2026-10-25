"""Scanner runtime against Postgres and Redis: cancel, the reaper and the slot cap (P3)."""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from riskgraph.entrypoints.api import create_app
from riskgraph.modules.scanners.slots import KEY, SlotLimiter, SlotTimeoutError
from riskgraph.modules.scans import orchestration, reaper
from riskgraph.modules.scans.models import ScanJob, ScannerRun
from riskgraph.shared.config import Settings, get_settings
from riskgraph.shared.db import dispose_engine, session_scope
from riskgraph.shared.redis import get_redis
from riskgraph.shared.vocabulary import RunStatus, ScanStatus
from sqlalchemy import select

pytestmark = pytest.mark.db
URL = "https://github.com/acme/kitchen-sink"


@pytest.fixture()
def kills(monkeypatch: pytest.MonkeyPatch) -> list[uuid.UUID]:
    calls: list[uuid.UUID] = []
    monkeypatch.setattr(orchestration, "enqueue_kill", lambda sid: calls.append(sid))
    monkeypatch.setattr(orchestration, "enqueue", lambda sid, scanners, settings: None)
    return calls


@pytest.fixture()
def api(db: None, settings: Settings, kills: list[uuid.UUID]) -> Iterator[TestClient]:
    app = create_app(settings)
    app.dependency_overrides[get_settings] = lambda: settings
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    dispose_engine()


def _create(api: TestClient) -> str:
    resp = api.post("/api/v1/scans", json={"repo_url": URL, "ref": ""})
    assert resp.status_code == 202
    return str(resp.json()["id"])


def test_cancel_stops_the_scan_and_its_pending_runs(api: TestClient) -> None:
    sid = _create(api)
    resp = api.post(f"/api/v1/scans/{sid}/cancel")
    assert resp.status_code == 202 and resp.json()["status"] == "CANCELLED"
    runs = api.get(f"/api/v1/scans/{sid}").json()["scanner_runs"]
    assert {r["status"] for r in runs} == {"FAILED"}
    with session_scope() as s:
        scan = s.get(ScanJob, uuid.UUID(sid))
        assert scan is not None and scan.status is ScanStatus.CANCELLED
        assert scan.finished_at is not None


def test_cancel_asks_the_worker_to_kill_containers(api: TestClient, kills: list[uuid.UUID]) -> None:
    sid = _create(api)
    api.post(f"/api/v1/scans/{sid}/cancel")
    assert kills == [uuid.UUID(sid)]


def test_a_finished_scan_cannot_be_cancelled(api: TestClient) -> None:
    sid = _create(api)
    assert api.post(f"/api/v1/scans/{sid}/cancel").status_code == 202
    assert api.post(f"/api/v1/scans/{sid}/cancel").status_code == 409


def test_the_reaper_times_out_dead_runs_and_fails_stale_scans(
    api: TestClient, settings: Settings
) -> None:
    sid = _create(api)
    now = dt.datetime.now(dt.UTC)
    with session_scope() as s:
        scan = s.get(ScanJob, uuid.UUID(sid))
        assert scan is not None
        scan.status = ScanStatus.SCANNING
        scan.updated_at = now - dt.timedelta(hours=2)
        runs = list(s.scalars(select(ScannerRun).where(ScannerRun.scan_job_id == scan.id)))
        dead = runs[0]
        dead.status = RunStatus.RUNNING
        dead.started_at = now - dt.timedelta(hours=2)
        dead_id = dead.id
    with session_scope() as s:
        result = reaper.reap(s, settings, now)
    assert result.runs_timed_out == 1 and result.scans_failed == 1
    with session_scope() as s:
        assert s.get(ScannerRun, dead_id).status is RunStatus.TIMED_OUT  # type: ignore[union-attr]
        scan = s.get(ScanJob, uuid.UUID(sid))
        assert scan is not None and scan.status is ScanStatus.FAILED
        assert "reaped" in (scan.status_reason or "")


def test_a_healthy_running_scan_is_left_alone(api: TestClient, settings: Settings) -> None:
    sid = _create(api)
    now = dt.datetime.now(dt.UTC)
    with session_scope() as s:
        scan = s.get(ScanJob, uuid.UUID(sid))
        assert scan is not None
        scan.status = ScanStatus.SCANNING  # updated just now: progressing
    with session_scope() as s:
        result = reaper.reap(s, settings, now)
    assert result.scans_failed == 0
    with session_scope() as s:  # close the scan, so it does not stay active for other tests
        scan = s.get(ScanJob, uuid.UUID(sid))
        assert scan is not None
        scan.status = ScanStatus.FAILED


def test_the_slot_limiter_caps_concurrent_containers() -> None:
    client = get_redis()
    client.delete(KEY)
    limiter = SlotLimiter(client, max_slots=1, lease_s=60, poll_s=0.01)
    with limiter.slot(wait_s=1), pytest.raises(SlotTimeoutError), limiter.slot(wait_s=0.05):
        pass
    with limiter.slot(wait_s=1):  # released: a slot is available again
        pass
    client.delete(KEY)


class _ContainerOnlyRunner:
    """Stands in for the container runner: refuses any run that has no scanner image."""

    def __init__(self) -> None:
        from tests.pipeline_support import FixtureRunner

        self.inner = FixtureRunner()

    def run(self, spec: object) -> object:
        from riskgraph.modules.scanners import RunResult

        if getattr(spec, "image", None) is None:
            return RunResult(None, False, 0, "refused: no image", True)
        return self.inner.run(spec)  # type: ignore[arg-type]


def test_reachability_still_runs_when_scanners_are_containers(settings: Settings) -> None:
    """Regression: the extractor has no image, so it must not go through the container runner."""
    from riskgraph.modules.scans import service
    from riskgraph.modules.scans.orchestration import run_pipeline_inline
    from riskgraph.modules.scans.service import ALL_SCANNERS

    from tests.pipeline_support import LocalDirCloner, make_deps

    with session_scope() as s:
        sid = service.create_scan(s, URL, "regression", settings).scan.id
    status = run_pipeline_inline(
        sid,
        ALL_SCANNERS,
        make_deps(settings, runner=_ContainerOnlyRunner(), cloner=LocalDirCloner()),
    )
    assert status is not None
    with session_scope() as s:
        scan = s.get(ScanJob, sid)
        assert scan is not None
        assert scan.summary["reachability"]["status"] == "ok", (
            scan.status,
            scan.status_reason,
            scan.summary["reachability"],
        )
