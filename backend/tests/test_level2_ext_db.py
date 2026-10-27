"""MVP level 2 extended: reachability, attack paths, triage and history (DB + API)."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from riskgraph.entrypoints.api import create_app
from riskgraph.modules.audit import AuditLog
from riskgraph.modules.findings import Finding
from riskgraph.modules.scanners import RunResult
from riskgraph.modules.scans import service
from riskgraph.modules.scans.orchestration import run_pipeline_inline
from riskgraph.modules.scans.service import ALL_SCANNERS
from riskgraph.shared.config import Settings, get_settings
from riskgraph.shared.db import dispose_engine, session_scope
from riskgraph.shared.vocabulary import ScanStatus
from sqlalchemy import func, select

from tests.fixtures.repos import kitchen_sink
from tests.pipeline_support import FixtureRunner, LocalDirCloner, make_deps

pytestmark = pytest.mark.db
URL = "https://github.com/acme/kitchen-sink"


@pytest.fixture()
def api(db: None, settings: Settings) -> Iterator[TestClient]:
    app = create_app(settings)
    app.dependency_overrides[get_settings] = lambda: settings
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    dispose_engine()


def _scan(
    settings: Settings, *, manifest: bool = True, runner: FixtureRunner | None = None, ref: str = ""
) -> str:
    with session_scope() as s:
        sid = service.create_scan(s, URL, ref, settings).scan.id
    cloner = LocalDirCloner(extra={"riskgraph.yaml": kitchen_sink.MANIFEST} if manifest else {})
    status = run_pipeline_inline(
        sid, ALL_SCANNERS, make_deps(settings, runner=runner, cloner=cloner)
    )
    assert status in (ScanStatus.COMPLETED, ScanStatus.PARTIAL)
    return str(sid)


def _findings(api: TestClient, sid: str, **params: Any) -> list[dict[str, Any]]:
    resp = api.get(f"/api/v1/scans/{sid}/findings", params={"limit": 200, **params})
    assert resp.status_code == 200, resp.text
    return list(resp.json()["items"])


def _by_package(items: list[dict[str, Any]], name: str) -> list[dict[str, Any]]:
    return [i for i in items if (i.get("package") or {}).get("name") == name]


def test_reachability_tiers_on_the_kitchen_sink(api: TestClient, settings: Settings) -> None:
    sid = _scan(settings, manifest=False)
    items = _findings(api, sid)
    assert {i["reachability"] for i in _by_package(items, "pyyaml")} == {"L2"}
    assert {i["reachability"] for i in _by_package(items, "requests")} == {"L1"}
    assert {i["reachability"] for i in _by_package(items, "django")} == {"L0"}
    # Flask routes in app.py call subprocess and execute directly: the enclosing function is
    # an entry point, so SAST there is L3. Semgrep's generic.secrets rules are secrets, so no
    # SAST finding is left in deploy/id_rsa (blueprint §11.3: secrets are n_a).
    sast = [i for i in items if i["source_type"] == "sast" and i["location"]["file"] == "app.py"]
    assert sast and {i["reachability"] for i in sast} == {"L3"}
    assert not [i for i in items if i["source_type"] == "sast" and i["reachability"] == "unknown"]
    assert all(i["reachability"] is None for i in items if i["source_type"] in ("secret", "iac"))
    summary = api.get(f"/api/v1/scans/{sid}").json()["summary"]["reachability"]
    assert summary["status"] == "ok" and summary["entry_points"] >= 1
    assert api.get(f"/api/v1/scans/{sid}/findings", params={"reachability": "L0"}).json()[
        "total"
    ] == len(_by_package(items, "django"))

    detail = api.get(
        f"/api/v1/findings/{_by_package(items, 'pyyaml')[0]['id']}", params={"scan_id": sid}
    ).json()
    assert detail["reachability"]["tier"] == "L2"
    assert detail["reachability"]["evidence"]["importers"] == ["app.py"]
    r = next(f for f in detail["risk"]["factors"] if f["name"] == "R")
    assert (r["value"], r["source"]) == (0.8, "reachability")


def test_attack_paths_and_effective_impact(api: TestClient, settings: Settings) -> None:
    plain = _scan(settings, manifest=False, ref="plain")
    sid = _scan(settings)
    paths = api.get(f"/api/v1/scans/{sid}/attack-paths").json()
    labels = {" → ".join(n["label"] for n in p["nodes"]) for p in paths}
    assert "Internet → app → users-db" in labels  # exploit of reachable code in app
    assert "aws credential · main.tf:3 → app-role → users-db" in labels
    # grouped by assurance, then by score (X3 part 2)
    group = {"verified": 0, "inferred": 1, "hypothesis": 2}
    assert paths == sorted(paths, key=lambda p: (group[p["assurance"]], -p["score"]))
    assert api.get(f"/api/v1/scans/{plain}/attack-paths").json() == []  # no manifest, no paths

    graph = api.get(f"/api/v1/scans/{sid}/graph").json()
    kinds = {n["kind"] for n in graph["nodes"]}
    assert {"internet", "service", "identity", "data_store", "credential"} <= kinds
    assert any(e["kind"] == "EXPLOIT" and e["probability"] for e in graph["edges"])

    summary = api.get(f"/api/v1/scans/{sid}").json()["summary"]["graph"]
    assert summary["paths"] == len(paths) and summary["findings_on_paths"] > 0

    # findings on paths carry their paths; where the path implies more impact than the
    # finding itself, the I* adjustment raises it (never lowers: §14.4 takes the max)
    raised = 0
    for fid in {f for p in paths for f in p["finding_ids"]}:
        detail = api.get(f"/api/v1/findings/{fid}", params={"scan_id": sid}).json()
        assert detail["attack_paths"]
        if detail["risk"]["effective_impact"] is not None:
            assert detail["risk"]["effective_impact"] > detail["risk"]["impact"]
            assert any(
                f["name"] == "I*" and f["source"] == "attack_path"
                for f in detail["risk"]["factors"]
            )
            raised += 1
    assert raised > 0


def test_history_new_existing_fixed_reopened(api: TestClient, settings: Settings) -> None:
    first = _scan(settings, manifest=False)
    h1 = api.get(f"/api/v1/scans/{first}").json()["summary"]["history"]
    assert h1["previous_scan_id"] is None and h1["new"] == 29 and h1["fixed"] == 0

    second = _scan(settings, manifest=False)
    h2 = api.get(f"/api/v1/scans/{second}").json()["summary"]["history"]
    assert (h2["previous_scan_id"], h2["new"], h2["existing"], h2["fixed"]) == (first, 0, 29, 0)
    assert _findings(api, second, change="new") == []

    # the private key file is deleted: the scanners that reported it ran cleanly → fixed.
    # One finding: the private key, reported by gitleaks, trivy and semgrep and merged.
    third = _scan(settings, manifest=False, runner=FixtureRunner(drop_files={"deploy/id_rsa"}))
    h3 = api.get(f"/api/v1/scans/{third}").json()["summary"]["history"]
    assert h3["fixed"] == 1 and h3["new"] == 0
    diff = api.get(f"/api/v1/scans/{third}/diff").json()
    assert diff["previous_scan_id"] == second and len(diff["fixed"]) == 1
    fixed_ids = {i["id"] for i in diff["fixed"]}
    assert diff["fixed"][0]["status"] == "fixed"

    fourth = _scan(settings, manifest=False)  # it comes back
    h4 = api.get(f"/api/v1/scans/{fourth}").json()["summary"]["history"]
    assert h4["reopened"] == 1 and h4["new"] == 0
    reopened = _findings(api, fourth, change="reopened")
    assert {i["id"] for i in reopened} == fixed_ids and all(i["status"] == "open" for i in reopened)
    assert {
        i["id"] for i in api.get(f"/api/v1/scans/{fourth}/diff").json()["reopened"]
    } == fixed_ids

    explicit = api.get(f"/api/v1/scans/{fourth}/diff", params={"against": first}).json()
    assert explicit["new"] == [] and explicit["fixed"] == []


def test_no_fixed_verdict_when_a_reporting_scanner_failed(
    api: TestClient, settings: Settings
) -> None:
    _scan(settings, manifest=False)
    broken = FixtureRunner(
        drop_files={"deploy/id_rsa"}, fail={"gitleaks": RunResult(2, False, 1, "crash")}
    )
    sid = _scan(settings, manifest=False, runner=broken)
    # The private key is merged across gitleaks, trivy and semgrep. Gitleaks failed, so the
    # finding must stay open, never "fixed", although the other two reporters succeeded.
    diff = api.get(f"/api/v1/scans/{sid}/diff").json()
    owned_by_failed = [i for i in diff["fixed"] if i["source_type"] == "secret"]
    assert owned_by_failed and all(i["status"] == "open" for i in owned_by_failed)
    assert api.get(f"/api/v1/scans/{sid}").json()["summary"]["history"]["fixed"] == 0


def test_triage_is_validated_audited_and_sticky(api: TestClient, settings: Settings) -> None:
    sid = _scan(settings, manifest=False)
    secret = next(i for i in _findings(api, sid) if i["source_type"] == "secret")
    url = f"/api/v1/findings/{secret['id']}"

    assert api.patch(url, json={"status": "false_positive"}).status_code == 422  # reason required
    assert api.patch(url, json={"status": "fixed", "reason": "x"}).status_code == 422
    assert api.patch(url, json={"status": "bogus", "reason": "x"}).status_code == 422
    resp = api.patch(url, json={"status": "accepted_risk", "reason": "test key, revoked"})
    assert resp.status_code == 200 and resp.json()["status"] == "accepted_risk"

    assert secret["id"] not in {i["id"] for i in _findings(api, sid)}  # default: open only
    assert secret["id"] in {i["id"] for i in _findings(api, sid, status="accepted_risk")}
    detail = api.get(url, params={"scan_id": sid}).json()
    assert detail["status_reason"] == "test key, revoked"
    assert detail["history"][0]["after"]["status"] == "accepted_risk"
    with session_scope() as s:
        assert s.execute(select(func.count()).select_from(AuditLog)).scalar_one() == 1

    again = _scan(settings, manifest=False)  # a re-scan does not reopen a triaged finding
    assert secret["id"] not in {i["id"] for i in _findings(api, again)}
    assert api.patch(url, json={"status": "open"}).json()["status"] == "open"
    assert api.patch(f"/api/v1/findings/{uuid.uuid4()}", json={"status": "open"}).status_code == 404


def test_gate(api: TestClient, settings: Settings) -> None:
    sid = _scan(settings, manifest=False)
    gate = api.get(f"/api/v1/scans/{sid}/gate").json()
    assert gate["passed"] is False and gate["policy"]["fail_on"] == ["critical"]
    assert all(v["priority"] == "critical" for v in gate["violations"])
    for v in gate["violations"]:
        api.patch(
            f"/api/v1/findings/{v['finding_id']}", json={"status": "accepted_risk", "reason": "ok"}
        )
    assert api.get(f"/api/v1/scans/{sid}/gate").json()["passed"] is True

    strict = api.get(f"/api/v1/scans/{sid}/gate", params={"max_score": 1}).json()
    assert strict["passed"] is False and "score" in strict["violations"][0]["reasons"][0]
    second = _scan(settings, manifest=False)
    new_only = api.get(
        f"/api/v1/scans/{second}/gate", params={"max_score": 1, "new_only": "true"}
    ).json()
    assert new_only["passed"] is True and new_only["evaluated"] == 0


def test_repositories_trend(api: TestClient, settings: Settings) -> None:
    _scan(settings, manifest=False)
    _scan(settings, manifest=False, runner=FixtureRunner(drop_files={"deploy/id_rsa"}))
    repos = api.get("/api/v1/repositories").json()
    assert len(repos) == 1 and repos[0]["scans"] == 2
    detail = api.get(f"/api/v1/repositories/{repos[0]['id']}").json()
    points = detail["history"]
    assert [p["findings"] for p in points] == [29, 28]
    assert points[1]["fixed"] == 1 and points[0]["new"] == 29
    assert api.get(f"/api/v1/repositories/{uuid.uuid4()}").status_code == 404


def test_reanalysis_is_idempotent_with_graph_and_history(settings: Settings, db: None) -> None:
    from riskgraph.modules.graph import AttackPath
    from riskgraph.modules.reachability import ReachabilityResult
    from riskgraph.modules.scans import pipeline, repo

    deps = make_deps(
        settings, cloner=LocalDirCloner(extra={"riskgraph.yaml": kitchen_sink.MANIFEST})
    )
    with session_scope() as s:
        sid = service.create_scan(s, URL, "", settings).scan.id
        repo.cas_scan(s, sid, ScanStatus.PENDING, ScanStatus.QUEUED)
    pipeline.clone(sid, deps)
    for name in ALL_SCANNERS:
        pipeline.run_scanner(sid, name, deps)
    pipeline.collect(sid, deps)

    def counts() -> tuple[int, int, int]:
        with session_scope() as s:
            return (
                s.execute(select(func.count()).select_from(AttackPath)).scalar_one(),
                s.execute(select(func.count()).select_from(ReachabilityResult)).scalar_one(),
                s.execute(select(func.count()).select_from(Finding)).scalar_one(),
            )

    pipeline.analyze(sid, deps)
    first = counts()
    pipeline.analyze(sid, deps)
    assert counts() == first and first[0] > 0 and first[1] > 0
    assert pipeline.finalize(sid, deps) is ScanStatus.COMPLETED
