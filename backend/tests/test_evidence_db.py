"""Evidence and assurance end to end: stored, linked, served, and backfilled (ADR-0017, X1)."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from riskgraph.entrypoints.api import create_app
from riskgraph.modules.evidence import EdgeEvidence, EvidenceRow, FindingEvidence
from riskgraph.modules.findings import Finding
from riskgraph.modules.graph import AttackPath, GraphEdge
from riskgraph.modules.risk import RiskFactor, RiskScore
from riskgraph.modules.scans import pipeline, repo, service
from riskgraph.modules.scans.models import ScannerRun
from riskgraph.modules.scans.service import ALL_SCANNERS
from riskgraph.shared.config import Settings, get_settings
from riskgraph.shared.db import dispose_engine, session_scope
from riskgraph.shared.vocabulary import ScannerName, ScanStatus, SourceType
from sqlalchemy import delete, func, select

from tests.conftest import _alembic
from tests.fixtures.repos import kitchen_sink
from tests.pipeline_support import LocalDirCloner, make_deps
from tests.test_level2_ext_db import URL, _scan

pytestmark = pytest.mark.db
LEVELS = {"verified", "inferred", "hypothesis"}


@pytest.fixture()
def api(db: None, settings: Settings) -> Iterator[TestClient]:
    app = create_app(settings)
    app.dependency_overrides[get_settings] = lambda: settings
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    dispose_engine()


def _count(model: Any, scan_id: uuid.UUID) -> int:
    with session_scope() as s:
        return s.execute(
            select(func.count()).select_from(model).where(model.scan_job_id == scan_id)
        ).scalar_one()


def test_every_edge_and_finding_rests_on_stored_evidence(
    api: TestClient, settings: Settings
) -> None:
    sid = uuid.UUID(_scan(settings))
    with session_scope() as s:
        edges = s.scalars(select(GraphEdge).where(GraphEdge.scan_job_id == sid)).all()
        assert edges and {e.assurance for e in edges} <= LEVELS
        linked = {
            edge_id
            for (edge_id,) in s.execute(
                select(EdgeEvidence.edge_id).where(EdgeEvidence.scan_job_id == sid)
            )
        }
        assert linked == {e.id for e in edges}  # no edge without evidence
        # the kitchen-sink manifest lists `credentials: [aws]`: a family match only
        auth = [e for e in edges if e.kind == "AUTHENTICATES_AS"]
        assert auth and {e.assurance for e in auth} == {"hypothesis"}

        findings = s.scalars(select(Finding.id)).all()
        with_evidence = set(
            s.scalars(select(FindingEvidence.finding_id).where(FindingEvidence.scan_job_id == sid))
        )
        assert with_evidence == set(findings)

        trivy = {r.scanner.value: r.id for r in repo.runs_for(s, sid)}["trivy"]
        matches = s.scalars(
            select(EvidenceRow).where(
                EvidenceRow.scan_job_id == sid, EvidenceRow.kind == "package_match"
            )
        ).all()
        assert matches and all(m.raw_run_id == trivy and m.raw_pointer == "" for m in matches)


def test_hypothesis_paths_never_raise_a_score(api: TestClient, settings: Settings) -> None:
    sid = uuid.UUID(_scan(settings))
    paths = api.get(f"/api/v1/scans/{sid}/attack-paths").json()
    assert paths and {p["assurance"] for p in paths} <= LEVELS
    assert "hypothesis" in {p["assurance"] for p in paths}  # the AWS key's paths
    with session_scope() as s:
        labels = {
            " → ".join(n["label"] for n in p.nodes): p
            for p in s.scalars(select(AttackPath).where(AttackPath.scan_job_id == sid))
        }
        raised = s.scalars(
            select(RiskFactor)
            .join(RiskScore, RiskScore.id == RiskFactor.risk_score_id)
            .where(RiskScore.scan_job_id == sid, RiskFactor.name == "I*")
        ).all()
        for factor in raised:
            path = labels[factor.evidence["path"]]
            assert {e["assurance"] for e in path.edges} <= {"verified", "inferred"}, factor


def test_the_api_serves_evidence_and_assurance(api: TestClient, settings: Settings) -> None:
    sid = _scan(settings)
    items = api.get(f"/api/v1/scans/{sid}/findings", params={"limit": 200}).json()["items"]
    sca = next(i for i in items if i["source_type"] == "sca")
    detail = api.get(f"/api/v1/findings/{sca['id']}", params={"scan_id": sid}).json()
    kinds = [e["kind"] for e in detail["evidence"]]
    assert "package_match" in kinds
    match = next(e for e in detail["evidence"] if e["kind"] == "package_match")
    assert match["assurance"] == "verified" and match["producer"].startswith("trivy@")
    assert match["facts"]["vulnerability_id"] == sca["rule_id"] or match["facts"]["package"]
    assert match["raw_pointer"] == "" and match["raw_run_id"]

    graph = api.get(f"/api/v1/scans/{sid}/graph").json()
    assert graph["edges"] and all(e["assurance"] in LEVELS for e in graph["edges"])
    assert all(e["evidence_ids"] for e in graph["edges"])


def test_reanalysis_replaces_evidence_instead_of_piling_it_up(settings: Settings, db: None) -> None:
    with session_scope() as s:
        sid = service.create_scan(s, URL, "", settings).scan.id
        repo.cas_scan(s, sid, ScanStatus.PENDING, ScanStatus.QUEUED)
    deps = make_deps(
        settings, cloner=LocalDirCloner(extra={"riskgraph.yaml": kitchen_sink.MANIFEST})
    )
    pipeline.clone(sid, deps)
    for name in ALL_SCANNERS:
        pipeline.run_scanner(sid, name, deps)
    pipeline.collect(sid, deps)
    pipeline.analyze(sid, deps)
    before = (_count(EvidenceRow, sid), _count(FindingEvidence, sid), _count(EdgeEvidence, sid))
    pipeline.analyze(sid, deps)  # a redelivered message
    after = (_count(EvidenceRow, sid), _count(FindingEvidence, sid), _count(EdgeEvidence, sid))
    pipeline.finalize(sid, deps)
    assert before[0] > 0 and before[2] > 0 and after == before


def test_the_migration_backfill_matches_the_builder(settings: Settings, db: None) -> None:
    """Downgrade a real scan, upgrade it again: SQL backfill == what the builder wrote."""
    sid = uuid.UUID(_scan(settings))
    with session_scope() as s:
        # X5's authorization edges did not exist before X1, so no backfill rule covers them
        s.execute(delete(GraphEdge).where(GraphEdge.kind.in_(("UNGUARDED", "BOLA_SUSPECT"))))
        built = {
            (e.source, e.target, e.kind): e.assurance
            for e in s.scalars(select(GraphEdge).where(GraphEdge.scan_job_id == sid))
        }
    assert {"verified", "hypothesis"} <= set(built.values())
    # X2's downgrade refuses while riskgraph runs or runtime/authz findings exist (by
    # design); this test is about X1's backfill, so drop them first (the kitchen sink's
    # authz findings, X5, build no graph edge, so the comparison is unchanged)
    with session_scope() as s:
        s.execute(delete(Finding).where(Finding.source_type == SourceType.AUTHZ))
        s.execute(delete(ScannerRun).where(ScannerRun.scanner == ScannerName.RISKGRAPH))
    _alembic("downgrade", "e1b7d3a9c2f4")
    _alembic("upgrade", "head")
    with session_scope() as s:
        backfilled = {
            (e.source, e.target, e.kind): e.assurance
            for e in s.scalars(select(GraphEdge).where(GraphEdge.scan_job_id == sid))
        }
        assert s.execute(select(func.count()).select_from(EvidenceRow)).scalar_one() == 0
    assert backfilled == built


def test_attack_paths_are_grouped_by_assurance_and_name_what_is_missing(
    api: TestClient, settings: Settings
) -> None:
    sid = _scan(settings)
    paths = api.get(f"/api/v1/scans/{sid}/attack-paths").json()
    order = {"verified": 0, "inferred": 1, "hypothesis": 2}
    groups = [order[p["assurance"]] for p in paths]
    assert groups == sorted(groups) and 2 in groups
    for g in set(groups):  # each group by score
        scores = [p["score"] for p in paths if order[p["assurance"]] == g]
        assert scores == sorted(scores, reverse=True)
    for p in paths:
        hyp_edges = [e for e in p["edges"] if e["assurance"] == "hypothesis"]
        assert [(m["source"], m["target"], m["kind"]) for m in p["missing_evidence"]] == [
            (e["source"], e["target"], e["kind"]) for e in hyp_edges
        ]
    needed = {m["needed"] for p in paths for m in p["missing_evidence"]}
    assert any("an `owns:` entry would" in n for n in needed), needed
