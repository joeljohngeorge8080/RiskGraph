"""The route inventory through a real scan and the API (X5 part 1, ADR-0022)."""

from __future__ import annotations

import textwrap
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from riskgraph.entrypoints.api import create_app
from riskgraph.modules.scans import ScanJob, service
from riskgraph.modules.scans.orchestration import run_pipeline_inline
from riskgraph.modules.scans.service import ALL_SCANNERS
from riskgraph.shared.config import Settings, get_settings
from riskgraph.shared.db import dispose_engine, session_scope
from riskgraph.shared.vocabulary import ScanStatus

from tests.pipeline_support import LocalDirCloner, make_deps

pytestmark = pytest.mark.db
URL = "https://github.com/acme/routes"
APP = textwrap.dedent(
    """
    from flask import Flask
    from flask_login import login_required
    app = Flask(__name__)

    @app.get("/admin/users/<int:user_id>")
    @login_required
    def user(user_id):
        return ""

    @app.post("/admin/users")
    def create_user():
        return ""

    @app.get("/team")
    @team_required
    def team():
        return ""
    """
)


@pytest.fixture()
def api(db: None, settings: Settings) -> Iterator[TestClient]:
    app = create_app(settings)
    app.dependency_overrides[get_settings] = lambda: settings
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    dispose_engine()


def _scan(settings: Settings) -> str:
    with session_scope() as s:
        sid = service.create_scan(s, URL, "", settings).scan.id
    deps = make_deps(settings, cloner=LocalDirCloner(extra={"routes_app.py": APP}))
    assert run_pipeline_inline(sid, ALL_SCANNERS, deps) is ScanStatus.COMPLETED
    return str(sid)


def test_a_scan_serves_its_route_inventory(api: TestClient, settings: Settings) -> None:
    sid = _scan(settings)
    body = api.get(f"/api/v1/scans/{sid}/routes").json()
    ours = {r["full_path"]: r for r in body["items"] if r["file"] == "routes_app.py"}
    assert set(ours) == {"/admin/users/<int:user_id>", "/admin/users", "/team"}
    user = ours["/admin/users/<int:user_id>"]
    assert user["guard_status"] == "guarded" and user["guards"] == ["login_required"]
    assert user["params"] == ["user_id"] and user["methods"] == ["GET"]
    assert user["assurance"] == "verified" and user["framework"] == "flask"
    assert ours["/admin/users"]["guard_status"] == "none_found"
    assert ours["/team"]["guard_status"] == "custom"
    assert ours["/team"]["custom_guards"] == ["team_required"]
    assert body["total"] == len(body["items"]) and sum(body["by_status"].values()) == body["total"]

    only = api.get(f"/api/v1/scans/{sid}/routes", params={"status": "none_found"}).json()
    assert {r["guard_status"] for r in only["items"]} == {"none_found"}
    assert only["by_status"] == body["by_status"]  # the counts are of the whole scan
    assert api.get(f"/api/v1/scans/{sid}/routes", params={"status": "bogus"}).status_code == 422

    with session_scope() as s:
        scan = s.get(ScanJob, sid)
        assert scan is not None
        routes = scan.summary["routes"]
    assert routes["status"] == "ok" and routes["routes"] == body["total"]
    assert routes["by_status"] == body["by_status"]


def test_an_unknown_scan_is_404(api: TestClient) -> None:
    missing = "00000000-0000-7000-8000-000000000000"
    assert api.get(f"/api/v1/scans/{missing}/routes").status_code == 404
