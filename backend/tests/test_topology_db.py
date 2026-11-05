"""A repository with Compose and Kubernetes but no manifest gets a graph (X3 part 1)."""

from __future__ import annotations

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

from tests.pipeline_support import LocalDirCloner, make_deps
from tests.test_context_sbom_db import COMPOSE, K8S

pytestmark = pytest.mark.db
URL = "https://github.com/acme/no-manifest"
PUBLISHED = COMPOSE + "    ports: ['8000:8000']\n"


@pytest.fixture()
def api(db: None, settings: Settings) -> Iterator[TestClient]:
    app = create_app(settings)
    app.dependency_overrides[get_settings] = lambda: settings
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    dispose_engine()


def _scan(settings: Settings, extra: dict[str, str]) -> str:
    with session_scope() as s:
        sid = service.create_scan(s, URL, "", settings).scan.id
    deps = make_deps(settings, cloner=LocalDirCloner(extra=extra))
    assert run_pipeline_inline(sid, ALL_SCANNERS, deps) is ScanStatus.COMPLETED
    return str(sid)


def test_compose_and_kubernetes_without_a_manifest_give_an_inferred_path(
    api: TestClient, settings: Settings
) -> None:
    sid = _scan(settings, {"docker-compose.yml": PUBLISHED, "k8s.yaml": K8S})
    paths = api.get(f"/api/v1/scans/{sid}/attack-paths").json()
    assert paths, "no path from the derived topology"
    assert {p["sink"] for p in paths} == {"identity:sa:app-sa"}
    assert {p["assurance"] for p in paths} <= {"inferred", "hypothesis"}
    assert "inferred" in {p["assurance"] for p in paths}
    graph = api.get(f"/api/v1/scans/{sid}/graph").json()
    kinds = {n["kind"] for n in graph["nodes"]}
    assert {"internet", "service", "identity"} <= kinds
    edges = {e["kind"] for e in graph["edges"]}
    assert {"EXPOSES", "EXPLOIT", "RUNS_AS"} <= edges
    assert all(e["evidence_ids"] for e in graph["edges"])


def test_without_iac_or_manifest_there_is_still_no_path(
    api: TestClient, settings: Settings
) -> None:
    sid = _scan(settings, {})
    assert api.get(f"/api/v1/scans/{sid}/attack-paths").json() == []
