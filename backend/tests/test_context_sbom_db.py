"""Context and SBOM endpoints against Postgres (P7, P5): what the latest scan saw."""

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

from tests.pipeline_support import LocalDirCloner, make_deps

pytestmark = pytest.mark.db
URL = "https://github.com/acme/kitchen-sink"

COMPOSE = "services:\n  app:\n    build: .\n"
K8S = """
apiVersion: v1
kind: Service
metadata: {name: app-lb}
spec: {type: LoadBalancer, selector: {app: app}}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: app-admin}
roleRef: {kind: ClusterRole, name: cluster-admin}
subjects: [{kind: ServiceAccount, name: app-sa}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: app}
spec:
  template:
    metadata: {labels: {app: app}}
    spec: {serviceAccountName: app-sa, containers: [{name: app}]}
"""


@pytest.fixture()
def api(db: None, settings: Settings) -> Iterator[TestClient]:
    app = create_app(settings)
    app.dependency_overrides[get_settings] = lambda: settings
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    dispose_engine()


def _scan(settings: Settings, extra: dict[str, str]) -> tuple[str, str]:
    with session_scope() as s:
        view = service.create_scan(s, URL, "", settings)
        sid, rid = view.scan.id, view.repository.id
    status = run_pipeline_inline(
        sid, ALL_SCANNERS, make_deps(settings, cloner=LocalDirCloner(extra=extra))
    )
    assert status in (ScanStatus.COMPLETED, ScanStatus.PARTIAL)
    return str(sid), str(rid)


def test_context_endpoint_returns_assets_and_kubernetes_privilege(
    api: TestClient, settings: Settings
) -> None:
    sid, rid = _scan(settings, {"docker-compose.yml": COMPOSE, "deploy/k8s.yaml": K8S})
    resp = api.get(f"/api/v1/repositories/{rid}/context")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["scan_id"] == sid
    kinds = {(a["kind"], a["name"]) for a in body["assets"]}
    assert {("service", "app"), ("service", "app-lb"), ("workload", "app")} <= kinds
    assert ("binding", "app-admin") in kinds
    workloads = body["context"]["kubernetes_workloads"]
    assert workloads == [
        {"name": "app", "file": "deploy/k8s.yaml", "exposure": "internet", "privilege": "admin"}
    ]
    # the RBAC privilege reaches a code finding through the same-named Compose service
    items = api.get(f"/api/v1/scans/{sid}/findings", params={"limit": 200}).json()["items"]
    sca = next(i for i in items if (i.get("package") or {}).get("name") == "pyyaml")
    detail = api.get(f"/api/v1/findings/{sca['id']}", params={"scan_id": sid}).json()
    factors = {f["name"]: f for f in detail["risk"]["factors"]}
    assert factors["P"]["source"] == "kubernetes" and factors["P"]["value"] == 1.0
    assert factors["X"]["source"] == "kubernetes"


def test_context_endpoint_404s_without_a_finished_scan(api: TestClient) -> None:
    resp = api.get(f"/api/v1/repositories/{uuid.uuid4()}/context")
    assert resp.status_code == 404
    assert resp.headers["content-type"].startswith("application/problem+json")


def test_sbom_endpoint_pages_filters_and_counts_findings(
    api: TestClient, settings: Settings
) -> None:
    sid, _ = _scan(settings, {})
    resp = api.get(f"/api/v1/scans/{sid}/sbom", params={"limit": 500})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] == len(body["items"]) > 0
    by_name = {c["name"]: c for c in body["items"]}
    assert by_name["pyyaml"]["findings"] >= 1  # Trivy CVEs attached to the Syft package
    pypi = api.get(f"/api/v1/scans/{sid}/sbom", params={"ecosystem": "pypi"}).json()
    assert pypi["total"] >= 3 and {c["ecosystem"] for c in pypi["items"]} == {"pypi"}
    page = api.get(f"/api/v1/scans/{sid}/sbom", params={"limit": 1, "offset": 1}).json()
    assert len(page["items"]) == 1 and page["total"] == body["total"]
    # LIKE metacharacters are matched literally, not as wildcards
    assert api.get(f"/api/v1/scans/{sid}/sbom", params={"name": "%"}).json()["total"] == 0
    assert api.get(f"/api/v1/scans/{sid}/sbom", params={"name": "pyy"}).json()["total"] >= 1
    assert api.get(f"/api/v1/scans/{uuid.uuid4()}/sbom").status_code == 404
