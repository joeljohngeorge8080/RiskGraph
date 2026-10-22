from __future__ import annotations

import uuid
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from riskgraph.entrypoints.api import create_app
from riskgraph.modules.scans import orchestration
from riskgraph.modules.scans.orchestration import run_pipeline_inline
from riskgraph.modules.scans.service import ALL_SCANNERS
from riskgraph.shared.config import Settings, get_settings
from riskgraph.shared.db import dispose_engine

from tests.pipeline_support import make_deps

pytestmark = pytest.mark.db
URL = "https://github.com/acme/kitchen-sink"


@pytest.fixture()
def enqueued(monkeypatch: pytest.MonkeyPatch) -> list[uuid.UUID]:
    calls: list[uuid.UUID] = []
    monkeypatch.setattr(orchestration, "enqueue", lambda sid, scanners, settings: calls.append(sid))
    return calls


@pytest.fixture()
def api(db: None, settings: Settings) -> Iterator[TestClient]:
    app = create_app(settings)
    app.dependency_overrides[get_settings] = lambda: settings
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    dispose_engine()


def _completed_scan(api: TestClient, settings: Settings, enqueued: list[uuid.UUID]) -> str:
    resp = api.post("/api/v1/scans", json={"repo_url": URL})
    assert resp.status_code == 202, resp.text
    sid = uuid.UUID(resp.json()["id"])
    # the API already moved it to QUEUED; run the rest inline
    from riskgraph.modules.scans import pipeline

    deps = make_deps(settings)
    pipeline.clone(sid, deps)
    for name in ALL_SCANNERS:
        pipeline.run_scanner(sid, name, deps)
    pipeline.collect(sid, deps)
    pipeline.analyze(sid, deps)
    pipeline.finalize(sid, deps)
    return str(sid)


def test_create_scan_enqueues_and_dedups(api: TestClient, enqueued: list[uuid.UUID]) -> None:
    resp = api.post("/api/v1/scans", json={"repo_url": URL, "ref": "main"})
    assert resp.status_code == 202
    body = resp.json()
    assert body["status"] == "QUEUED" and body["deduplicated"] is False
    assert body["repository"]["full_name"] == "acme/kitchen-sink"
    assert [r["status"] for r in body["scanner_runs"]] == ["QUEUED"] * 5
    assert enqueued == [uuid.UUID(body["id"])]

    again = api.post("/api/v1/scans", json={"repo_url": URL + ".git", "ref": "main"})
    assert again.status_code == 200
    assert again.json()["deduplicated"] is True and again.json()["id"] == body["id"]
    assert len(enqueued) == 1


@pytest.mark.parametrize(
    ("payload", "slug"),
    [
        ({"repo_url": "https://gitlab.com/a/b"}, "invalid-repository-url"),
        ({"repo_url": "file:///etc/passwd"}, "invalid-repository-url"),
        ({"repo_url": URL, "ref": "--upload-pack=x"}, "invalid-ref"),
        ({"repo_url": URL, "extra": 1}, "validation-error"),
        ({}, "validation-error"),
    ],
)
def test_create_scan_rejects_bad_input(
    api: TestClient, enqueued: list[uuid.UUID], payload: dict[str, object], slug: str
) -> None:
    resp = api.post("/api/v1/scans", json=payload)
    assert resp.status_code == 422
    assert resp.headers["content-type"].startswith("application/problem+json")
    assert resp.json()["type"].endswith(slug)
    assert enqueued == []


def test_concurrency_cap(api: TestClient, enqueued: list[uuid.UUID], settings: Settings) -> None:
    capped = settings.model_copy(update={"max_active_scans": 1})
    api.app.dependency_overrides[get_settings] = lambda: capped  # type: ignore[attr-defined]
    assert api.post("/api/v1/scans", json={"repo_url": URL}).status_code == 202
    resp = api.post("/api/v1/scans", json={"repo_url": "https://github.com/acme/other"})
    assert resp.status_code == 429


def test_queue_failure_is_503_and_marks_failed(
    api: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_: object) -> None:
        raise ConnectionError("redis down")

    monkeypatch.setattr(orchestration, "enqueue", boom)
    resp = api.post("/api/v1/scans", json={"repo_url": URL})
    assert resp.status_code == 503
    scans = api.get("/api/v1/scans").json()
    assert scans["items"][0]["status"] == "FAILED"
    assert scans["items"][0]["status_reason"] == "queue unavailable"


def test_get_and_list_scans(api: TestClient, enqueued: list[uuid.UUID], settings: Settings) -> None:
    sid = _completed_scan(api, settings, enqueued)
    one = api.get(f"/api/v1/scans/{sid}").json()
    assert one["status"] == "COMPLETED" and one["summary"]["findings"] == 31
    assert all(r["report_available"] for r in one["scanner_runs"])
    listing = api.get("/api/v1/scans", params={"status": "COMPLETED"}).json()
    assert listing["total"] == 1 and listing["items"][0]["id"] == sid
    assert api.get(f"/api/v1/scans/{uuid.uuid4()}").status_code == 404
    assert api.get("/api/v1/scans/not-a-uuid").status_code == 422


def test_findings_sort_filter_and_detail(
    api: TestClient, enqueued: list[uuid.UUID], settings: Settings
) -> None:
    sid = _completed_scan(api, settings, enqueued)
    base = f"/api/v1/scans/{sid}/findings"
    page = api.get(base, params={"limit": 200}).json()
    assert page["total"] == 31
    keys = [
        ({"critical": 3, "high": 2, "medium": 1, "low": 0}[i["priority"]], i["score"])
        for i in page["items"]
    ]
    assert keys == sorted(keys, reverse=True)

    crit = api.get(base, params={"priority": "critical"}).json()
    assert crit["total"] == 2 and all(i["source_type"] == "secret" for i in crit["items"])
    gl = api.get(base, params={"scanner": "gitleaks"}).json()
    assert gl["total"] == 3 and all("gitleaks" in i["detected_by"] for i in gl["items"])
    multi = api.get(base, params=[("scanner", "checkov"), ("source_type", "iac")]).json()
    assert multi["total"] > 0
    q = api.get(base, params={"q": "main.tf"}).json()
    assert q["total"] > 0 and all("main.tf" in i["location"]["file"] for i in q["items"])
    assert api.get(base, params={"q": "%"}).json()["total"] == 0  # LIKE wildcards are escaped
    by_title = api.get(base, params={"sort": "title", "order": "asc", "limit": 200}).json()["items"]
    assert [i["title"] for i in by_title] == sorted(i["title"] for i in by_title)
    assert api.get(base, params={"sort": "drop table"}).status_code == 422

    top = page["items"][0]
    detail = api.get(f"/api/v1/findings/{top['id']}", params={"scan_id": sid}).json()
    assert detail["risk"]["score"] == top["score"]
    assert [f["name"] for f in detail["risk"]["factors"]] == [
        "E",
        "X",
        "R",
        "T",
        "D",
        "P",
        "C",
        "K",
    ]
    assert {o["scanner"] for o in detail["occurrences"]} == set(top["detected_by"])
    assert detail["risk"]["overrides"]
    assert api.get(f"/api/v1/findings/{uuid.uuid4()}").status_code == 404


def test_report_download(api: TestClient, enqueued: list[uuid.UUID], settings: Settings) -> None:
    sid = _completed_scan(api, settings, enqueued)
    resp = api.get(f"/api/v1/scans/{sid}/reports/gitleaks")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/json"
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert "attachment" in resp.headers["content-disposition"]
    assert '"Secret":' not in resp.text and "SecretHMAC" in resp.text
    assert api.get(f"/api/v1/scans/{sid}/reports/nmap").status_code == 422
    assert api.get(f"/api/v1/scans/{sid}/reports/..%2F..%2Fetc").status_code in (404, 422)
    assert api.get(f"/api/v1/scans/{uuid.uuid4()}/reports/trivy").status_code == 404


def test_prod_refuses_to_start_without_auth(settings: Settings) -> None:
    with pytest.raises(RuntimeError, match="no authentication"):
        create_app(settings.model_copy(update={"env": "prod"}))


def test_inline_runner_matches_api_flow(api: TestClient, settings: Settings) -> None:
    from riskgraph.modules.scans import service
    from riskgraph.shared.db import session_scope

    with session_scope() as s:
        sid = service.create_scan(s, URL, None, settings).scan.id
    assert run_pipeline_inline(sid, ALL_SCANNERS, make_deps(settings)).value == "COMPLETED"  # type: ignore[union-attr]
