"""GET /risks and /risks/{finding_id} against Postgres (P11)."""

from __future__ import annotations

import uuid
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from riskgraph.entrypoints.api import create_app
from riskgraph.modules.scans import service
from riskgraph.modules.scans.orchestration import run_pipeline_inline
from riskgraph.modules.scans.service import ALL_SCANNERS
from riskgraph.shared.config import Settings, get_settings
from riskgraph.shared.db import dispose_engine, session_scope
from riskgraph.shared.vocabulary import ScanStatus

from tests.fixtures.repos import kitchen_sink
from tests.pipeline_support import LocalDirCloner, make_deps

pytestmark = pytest.mark.db
URL = "https://github.com/acme/kitchen-sink"


@pytest.fixture()
def api(db: None, settings: Settings) -> Iterator[TestClient]:
    app = create_app(settings)
    app.dependency_overrides[get_settings] = lambda: settings
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    dispose_engine()


@pytest.fixture()
def scan(api: TestClient, settings: Settings) -> tuple[str, str]:
    with session_scope() as s:
        view = service.create_scan(s, URL, "", settings)
        sid, rid = view.scan.id, view.repository.id
    cloner = LocalDirCloner(extra={"riskgraph.yaml": kitchen_sink.MANIFEST})
    status = run_pipeline_inline(sid, ALL_SCANNERS, make_deps(settings, cloner=cloner))
    assert status in (ScanStatus.COMPLETED, ScanStatus.PARTIAL)
    return str(sid), str(rid)


def test_risks_are_ranked_by_score_and_match_the_findings(
    api: TestClient, scan: tuple[str, str]
) -> None:
    sid, rid = scan
    body = api.get("/api/v1/risks", params={"scan_id": sid, "limit": 200}).json()
    items = body["items"]
    assert body["total"] == len(items) == 32
    scores = [i["score"] for i in items]
    assert scores == sorted(scores, reverse=True)
    assert [i["rank"] for i in items] == list(range(1, 33))
    assert {i["model_version"] for i in items} == {"v1-ctx.4"}
    # the same ranking through the repository's latest finished scan
    latest = api.get("/api/v1/risks", params={"repository_id": rid, "limit": 200}).json()
    assert latest["scan_id"] == sid and [i["finding_id"] for i in latest["items"]] == [
        i["finding_id"] for i in items
    ]
    page = api.get("/api/v1/risks", params={"scan_id": sid, "limit": 5, "offset": 5}).json()
    assert [i["rank"] for i in page["items"]] == [6, 7, 8, 9, 10]
    crit = api.get("/api/v1/risks", params={"scan_id": sid, "priority": "critical"}).json()
    assert crit["total"] >= 1 and {i["priority"] for i in crit["items"]} == {"critical"}


def test_triaged_noise_leaves_the_ranking_but_stays_retrievable(
    api: TestClient, scan: tuple[str, str]
) -> None:
    sid, _ = scan
    top = api.get("/api/v1/risks", params={"scan_id": sid, "limit": 1}).json()["items"][0]
    resp = api.patch(
        f"/api/v1/findings/{top['finding_id']}",
        json={"status": "false_positive", "reason": "test fixture"},
    )
    assert resp.status_code == 200, resp.text
    after = api.get("/api/v1/risks", params={"scan_id": sid, "limit": 200}).json()
    assert after["total"] == 31 and top["finding_id"] not in {
        i["finding_id"] for i in after["items"]
    }
    every = api.get(
        "/api/v1/risks", params={"scan_id": sid, "limit": 200, "include_excluded": True}
    ).json()
    assert every["total"] == 32
    # §14.5: excluded from ranking, kept in audit: the score itself is still there
    detail = api.get(f"/api/v1/risks/{top['finding_id']}", params={"scan_id": sid})
    assert detail.status_code == 200


def test_risk_detail_lists_factors_and_the_reasons_off_baseline(
    api: TestClient, scan: tuple[str, str]
) -> None:
    sid, _ = scan
    items = api.get("/api/v1/risks", params={"scan_id": sid, "limit": 200}).json()["items"]
    on_path = next(i for i in items if i["effective_impact"] is not None)
    d = api.get(f"/api/v1/risks/{on_path['finding_id']}", params={"scan_id": sid}).json()
    assert d["score"] == on_path["score"] and d["finding_id"] == on_path["finding_id"]
    names = {f["name"] for f in d["factors"]}
    assert {"E", "X", "R", "T", "D", "P", "C", "K", "I*"} <= names
    assert any(r.startswith("X=") and "manifest" in r for r in d["reasons"])
    assert any(r.startswith("I* (attack_path)") for r in d["reasons"])


def test_risks_parameter_errors(api: TestClient, scan: tuple[str, str]) -> None:
    sid, rid = scan
    both = api.get("/api/v1/risks", params={"scan_id": sid, "repository_id": rid})
    assert both.status_code == 422
    assert api.get("/api/v1/risks").status_code == 422
    assert api.get("/api/v1/risks", params={"scan_id": str(uuid.uuid4())}).status_code == 404
    assert api.get("/api/v1/risks", params={"repository_id": str(uuid.uuid4())}).status_code == 404
    missing = api.get(f"/api/v1/risks/{uuid.uuid4()}", params={"scan_id": sid})
    assert missing.status_code == 404
