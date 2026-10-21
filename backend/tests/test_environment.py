from __future__ import annotations

from riskgraph.modules.context import ContextResolver, ManifestResult, parse_manifest
from riskgraph.shared.vocabulary import SourceType

MANIFEST = """
version: 1
services:
  - name: web
    path: ""
    exposure: internet
  - name: api
    path: backend/
    exposure: internet
    auth: required
    runs_as: api-role
    connects_to: [orders-db]
  - name: admin
    path: backend/admin/
    exposure: internal
    auth: none
    connects_to: [api]
  - name: batch
    path: jobs/
    exposure: isolated
identities:
  - name: api-role
    privilege: admin
    can_access: [vault]
data_stores:
  - name: orders-db
    sensitivity: pii
  - name: vault
    sensitivity: credentials
criticality:
  api: high
  batch: low
"""


def _resolver(text: str = MANIFEST) -> ContextResolver:
    result = parse_manifest(text)
    assert result.status == "valid", result.warnings
    return ContextResolver(result)


def test_longest_path_prefix_wins() -> None:
    r = _resolver()
    assert r.service_for("backend/admin/views.py").name == "admin"  # type: ignore[union-attr]
    assert r.service_for("./backend/app.py").name == "api"  # type: ignore[union-attr]
    assert r.service_for("README.md").name == "web"  # type: ignore[union-attr]


def test_exposure_labels() -> None:
    r = _resolver()
    api = r.for_finding("backend/app.py", SourceType.SCA)
    assert api.exposure is not None and api.exposure.label == "internet_auth"
    web = r.for_finding("index.js", SourceType.SAST)
    # internet with auth not declared: assume no auth, but say so
    assert web.exposure is not None and web.exposure.label == "internet_noauth"
    assert web.exposure.confidence == "medium"
    batch = r.for_finding("jobs/run.py", SourceType.SCA)
    assert batch.exposure is not None and batch.exposure.label == "isolated"


def test_data_sensitivity_two_hops_prefers_most_sensitive() -> None:
    r = _resolver()
    api = r.for_finding("backend/app.py", SourceType.SCA)
    # orders-db (pii) is 1 hop; vault (credentials) is 2 hops via api-role
    assert api.data is not None and api.data.label == "credentials"
    assert api.data.evidence["path"] == ["api", "api-role", "vault"]
    assert api.data.confidence == "medium"
    assert api.privilege is not None and api.privilege.label == "admin"
    assert api.criticality is not None and api.criticality.label == "high"


def test_data_sensitivity_stops_after_two_hops() -> None:
    r = _resolver()
    admin = r.for_finding("backend/admin/x.py", SourceType.SCA)
    # admin -> api -> orders-db is 2 hops (pii); vault would be 3 hops away
    assert admin.data is not None and admin.data.label == "pii"
    assert admin.privilege is None and admin.criticality is None


def test_secret_in_public_repo_is_internet_exposed_without_manifest() -> None:
    r = ContextResolver(ManifestResult("absent"))
    secret = r.for_finding("deploy/id_rsa", SourceType.SECRET)
    assert secret.exposure is not None
    assert (secret.exposure.label, secret.exposure.source) == (
        "internet_noauth",
        "repository_visibility",
    )
    sca = r.for_finding("requirements.txt", SourceType.SCA)
    assert sca.exposure is None and sca.service is None


def test_secret_keeps_service_impact_context() -> None:
    r = _resolver()
    secret = r.for_finding("backend/settings.py", SourceType.SECRET)
    assert secret.exposure is not None and secret.exposure.source == "repository_visibility"
    assert secret.privilege is not None and secret.privilege.label == "admin"


def test_summary_counts_findings_per_service() -> None:
    no_web = MANIFEST.replace('  - name: web\n    path: ""\n    exposure: internet\n', "")
    r = _resolver(no_web)
    r.for_finding("backend/app.py", SourceType.SCA)
    r.for_finding("backend/app.py", SourceType.SAST)
    r.for_finding("README.md", SourceType.SAST)
    s = r.summary()
    assert s["manifest"] == "valid" and s["unmapped_findings"] == 1
    api = next(x for x in s["services"] if x["name"] == "api")
    assert api == {
        "name": "api",
        "path": "backend/",
        "exposure": "internet_auth",
        "privilege": "admin",
        "data": "credentials",
        "criticality": "high",
        "findings": 2,
    }
