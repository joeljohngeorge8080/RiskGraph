"""Graph neighbourhood queries against Postgres (P9): recursive CTE over graph_edges."""

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
def sid(api: TestClient, settings: Settings) -> str:
    with session_scope() as s:
        scan_id = service.create_scan(s, URL, "", settings).scan.id
    cloner = LocalDirCloner(extra={"riskgraph.yaml": kitchen_sink.MANIFEST})
    status = run_pipeline_inline(scan_id, ALL_SCANNERS, make_deps(settings, cloner=cloner))
    assert status in (ScanStatus.COMPLETED, ScanStatus.PARTIAL)
    return str(scan_id)


def _reach(api: TestClient, sid: str, **params: str | int) -> dict:  # type: ignore[type-arg]
    resp = api.get(f"/api/v1/scans/{sid}/graph/reach", params=params)
    assert resp.status_code == 200, resp.text
    return resp.json()  # type: ignore[no-any-return]


def test_what_can_reach_the_pii_store(api: TestClient, sid: str) -> None:
    body = _reach(api, sid, node="data_store:users-db", direction="upstream", depth=3)
    dist = {n["key"]: n["distance"] for n in body["nodes"]}
    assert dist["data_store:users-db"] == 0
    assert dist["identity:app-role"] == 1 and dist["service:app"] == 1
    assert dist["internet"] == 2  # internet -> app -> users-db
    creds = [k for k in dist if k.startswith("credential:")]
    assert creds and all(dist[k] == 2 for k in creds)  # key -> app-role -> users-db
    kinds = {(e["source"], e["target"], e["kind"]) for e in body["edges"]}
    assert ("service:app", "data_store:users-db", "CONNECTS_TO") in kinds


def test_depth_bounds_the_walk(api: TestClient, sid: str) -> None:
    one = _reach(api, sid, node="data_store:users-db", direction="upstream", depth=1)
    assert max(n["distance"] for n in one["nodes"]) == 1
    assert "internet" not in {n["key"] for n in one["nodes"]}


def test_downstream_from_the_internet_and_nothing_upstream(api: TestClient, sid: str) -> None:
    down = _reach(api, sid, node="internet", direction="downstream", depth=4)
    keys = {n["key"] for n in down["nodes"]}
    assert {"service:app", "identity:app-role", "data_store:users-db"} <= keys
    up = _reach(api, sid, node="internet", direction="upstream", depth=8)
    assert [n["key"] for n in up["nodes"]] == ["internet"]  # invariant: no in-edges


def test_unknown_node_scan_and_bad_params(api: TestClient, sid: str) -> None:
    base = f"/api/v1/scans/{sid}/graph/reach"
    assert api.get(base, params={"node": "service:nope"}).status_code == 404
    assert api.get(base, params={"node": "internet", "depth": 9}).status_code == 422
    assert api.get(base, params={"node": "internet", "direction": "sideways"}).status_code == 422
    # quotes and SQL in the key are bound parameters, so they only fail to match
    assert api.get(base, params={"node": "x' OR '1'='1"}).status_code == 404
    other = f"/api/v1/scans/{uuid.uuid4()}/graph/reach"
    assert api.get(other, params={"node": "internet"}).status_code == 404
