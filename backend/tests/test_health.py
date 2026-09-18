from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from riskgraph import __version__
from riskgraph.shared.problems import MEDIA_TYPE


def test_healthz_reports_version(client: TestClient) -> None:
    r = client.get("/api/v1/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "version": __version__}
    assert r.headers["Cache-Control"] == "no-store"


def test_request_id_is_echoed_or_generated(client: TestClient) -> None:
    r = client.get("/api/v1/healthz", headers={"X-Request-ID": "abc-123"})
    assert r.headers["X-Request-ID"] == "abc-123"
    r = client.get("/api/v1/healthz", headers={"X-Request-ID": "bad id with spaces <>"})
    assert r.headers["X-Request-ID"] != "bad id with spaces <>"
    assert len(r.headers["X-Request-ID"]) == 36


def test_unknown_route_is_problem_json(client: TestClient) -> None:
    r = client.get("/api/v1/does-not-exist")
    assert r.status_code == 404
    assert r.headers["content-type"].startswith(MEDIA_TYPE)
    body = r.json()
    assert body["status"] == 404
    assert body["type"].endswith("/not-found")
    assert body["instance"] == "/api/v1/does-not-exist"
    assert "request_id" in body


def test_readyz_reports_503_when_dependencies_down(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from riskgraph.shared import health

    def boom() -> None:
        raise ConnectionError("down")

    monkeypatch.setattr(health, "check_database", boom)
    monkeypatch.setattr(health, "check_redis", boom)
    r = client.get("/api/v1/readyz")
    assert r.status_code == 503
    assert r.headers["content-type"].startswith(MEDIA_TYPE)
    assert r.json()["checks"] == {
        "database": "error: ConnectionError",
        "redis": "error: ConnectionError",
    }


@pytest.mark.db
def test_readyz_ok_with_real_services(client: TestClient) -> None:
    r = client.get("/api/v1/readyz")
    assert r.status_code == 200, r.text
    assert r.json() == {"status": "ok", "checks": {"database": "ok", "redis": "ok"}}
