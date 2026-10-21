from __future__ import annotations

import json
import uuid

import httpx
import pytest
from riskgraph.modules.findings import Finding, FindingFilters, list_scan_findings
from riskgraph.modules.risk import RiskFactor, RiskScore
from riskgraph.modules.scanners import RunResult
from riskgraph.modules.scans import pipeline, repo, service
from riskgraph.modules.scans.models import ScanJob
from riskgraph.modules.scans.orchestration import run_pipeline_inline
from riskgraph.modules.scans.service import ALL_SCANNERS
from riskgraph.shared.config import Settings
from riskgraph.shared.db import session_scope
from riskgraph.shared.http import OutboundClient
from riskgraph.shared.vocabulary import Priority, RunStatus, ScanStatus, SourceType
from sqlalchemy import func, select

from tests.pipeline_support import FAKE_SHA, FixtureRunner, LocalDirCloner, make_deps

pytestmark = pytest.mark.db
URL = "https://github.com/acme/kitchen-sink"


def _new_scan(settings: Settings, ref: str = "") -> uuid.UUID:
    with session_scope() as s:
        return service.create_scan(s, URL, ref, settings).scan.id


def _scan(scan_id: uuid.UUID) -> ScanJob:
    with session_scope() as s:
        scan = s.get(ScanJob, scan_id)
        assert scan is not None
        s.expunge(scan)
        return scan


def test_full_pipeline_with_recorded_reports(db: None, settings: Settings) -> None:
    sid = _new_scan(settings)
    status = run_pipeline_inline(sid, ALL_SCANNERS, make_deps(settings))
    assert status is ScanStatus.COMPLETED
    scan = _scan(sid)
    assert scan.commit_sha == FAKE_SHA and scan.risk_model_version == "v1-ctx.1"
    summary = scan.summary
    assert summary["raw_findings"] == 47 and summary["findings"] == 27
    assert summary["cross_scanner"] >= 10
    assert set(summary["by_scanner"]) == {"trivy", "semgrep", "checkov", "gitleaks"}
    assert summary["by_priority"]["critical"] == 2  # two live credentials
    assert summary["context"]["manifest"] == "absent"
    assert summary["context"]["unmapped_findings"] == 27

    with session_scope() as s:
        runs = repo.runs_for(s, sid)
        assert all(r.status is RunStatus.SUCCEEDED and r.output_sha256 for r in runs)
        assert all(r.scanner_version == "1.2.3" for r in runs)
        rows, total = list_scan_findings(s, sid, FindingFilters(), limit=200)
        assert total == 27
        ranks = [(r.priority_rank, float(r.score)) for _, _, r, _ in rows]
        assert ranks == sorted(ranks, reverse=True)
        assert rows[0][0].source_type is SourceType.SECRET
        factors = s.execute(select(func.count()).select_from(RiskFactor)).scalar_one()
        assert factors == 27 * 8

    # stored reports are redacted and the workspace is gone
    for name in ALL_SCANNERS:
        text = (settings.scan_output_root / str(sid) / f"{name.value}.json").read_text()
        assert '"Secret"' not in text and "code_block" not in text
    assert not (settings.workspace_root / str(sid)).exists()


def test_analyze_is_idempotent_and_rescans_reuse_findings(db: None, settings: Settings) -> None:
    deps = make_deps(settings)
    sid = _new_scan(settings)
    with session_scope() as s:
        repo.cas_scan(s, sid, ScanStatus.PENDING, ScanStatus.QUEUED)
    pipeline.clone(sid, deps)
    for name in ALL_SCANNERS:
        pipeline.run_scanner(sid, name, deps)
    pipeline.collect(sid, deps)
    pipeline.analyze(sid, deps)
    with session_scope() as s:
        first = s.execute(select(func.count()).select_from(RiskScore)).scalar_one()
    pipeline.analyze(sid, deps)  # redelivered message
    with session_scope() as s:
        assert s.execute(select(func.count()).select_from(RiskScore)).scalar_one() == first
    pipeline.finalize(sid, deps)

    sid2 = _new_scan(settings)
    assert run_pipeline_inline(sid2, ALL_SCANNERS, deps) is ScanStatus.COMPLETED
    with session_scope() as s:
        assert s.execute(select(func.count()).select_from(Finding)).scalar_one() == 27
        f = s.scalars(select(Finding).limit(1)).one()
        assert f.first_seen_scan_id == sid and f.last_seen_scan_id == sid2


def test_failed_scanner_gives_partial(db: None, settings: Settings) -> None:
    runner = FixtureRunner(fail={"semgrep": RunResult(2, False, 3, "rule parse error")})
    sid = _new_scan(settings)
    assert run_pipeline_inline(sid, ALL_SCANNERS, make_deps(settings, runner)) is ScanStatus.PARTIAL
    with session_scope() as s:
        runs = {r.scanner.value: r for r in repo.runs_for(s, sid)}
        assert runs["semgrep"].status is RunStatus.FAILED
        assert "rule parse error" in (runs["semgrep"].error_excerpt or "")
        assert runs["trivy"].status is RunStatus.SUCCEEDED
    assert "semgrep" not in _scan(sid).summary["by_scanner"]


def test_timeouts_are_recorded(db: None, settings: Settings) -> None:
    runner = FixtureRunner(fail={n.value: RunResult(None, True, 9, "") for n in ALL_SCANNERS})
    sid = _new_scan(settings)
    assert run_pipeline_inline(sid, ALL_SCANNERS, make_deps(settings, runner)) is ScanStatus.FAILED
    with session_scope() as s:
        assert {r.status for r in repo.runs_for(s, sid)} == {RunStatus.TIMED_OUT}
    assert _scan(sid).status_reason == "all scanners failed"


def test_clone_failure_fails_scan_and_skips_scanners(db: None, settings: Settings) -> None:
    deps = make_deps(settings, cloner=LocalDirCloner(error="repository not found or not public"))
    sid = _new_scan(settings)
    assert run_pipeline_inline(sid, ALL_SCANNERS, deps) is ScanStatus.FAILED
    assert _scan(sid).status_reason == "repository not found or not public"
    with session_scope() as s:
        assert {r.status for r in repo.runs_for(s, sid)} == {RunStatus.SKIPPED}


def test_enrichment_feeds_drive_the_score(db: None, settings: Settings) -> None:
    from riskgraph.shared.vocabulary import ScannerName

    from tests.scanner_fixtures import load

    trivy = load(ScannerName.TRIVY)
    cves = sorted(
        {
            v["VulnerabilityID"]
            for r in trivy["Results"]
            for v in r.get("Vulnerabilities") or []
            if v["VulnerabilityID"].startswith("CVE-")
        }
    )
    kev_cve = cves[0]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.first.org":
            ids = request.url.params["cve"].split(",")
            return httpx.Response(200, json={"data": [{"cve": c, "epss": "0.001"} for c in ids]})
        body = {"vulnerabilities": [{"cveID": kev_cve, "dateAdded": "2022-01-10"}]}
        return httpx.Response(200, content=json.dumps(body))

    deps = make_deps(
        settings,
        outbound=lambda: OutboundClient(transport=httpx.MockTransport(handler)),
    )
    enriched = settings.model_copy(update={"enrichment_enabled": True})
    deps.settings = enriched
    sid = _new_scan(settings)
    assert run_pipeline_inline(sid, ALL_SCANNERS, deps) is ScanStatus.COMPLETED
    with session_scope() as s:
        rows, _ = list_scan_findings(
            s, sid, FindingFilters(source_type=(SourceType.SCA,)), limit=200
        )
        kev_row = next(r for r in rows if r[0].vulnerability_id == kev_cve)
        assert kev_row[2].priority is Priority.HIGH and kev_row[3] is not None and kev_row[3].kev
        e = s.scalars(
            select(RiskFactor).where(
                RiskFactor.risk_score_id == kev_row[2].id, RiskFactor.name == "E"
            )
        ).one()
        assert e.source == "kev"
        other = next(
            r
            for r in rows
            if r[0].vulnerability_id not in (kev_cve, None)
            and r[0].vulnerability_id.startswith("CVE-")
        )
        e2 = s.scalars(
            select(RiskFactor).where(
                RiskFactor.risk_score_id == other[2].id, RiskFactor.name == "E"
            )
        ).one()
        assert e2.source == "epss" and float(e2.value) == pytest.approx(0.25)
    assert _scan(sid).summary["intel"]["kev_listed"] == 1


KITCHEN_MANIFEST = """
version: 1
services:
  - name: app
    path: ""
    exposure: internet
    auth: none
    runs_as: app-role
    connects_to: [users-db]
identities:
  - name: app-role
    privilege: admin
data_stores:
  - name: users-db
    kind: sqlite
    sensitivity: pii
criticality:
  app: high
"""


def _factor(s: object, score_id: uuid.UUID, name: str) -> RiskFactor:
    return s.scalars(  # type: ignore[attr-defined, no-any-return]
        select(RiskFactor).where(RiskFactor.risk_score_id == score_id, RiskFactor.name == name)
    ).one()


def test_manifest_context_raises_scores(db: None, settings: Settings) -> None:
    base_id = _new_scan(settings)
    assert run_pipeline_inline(base_id, ALL_SCANNERS, make_deps(settings)) is ScanStatus.COMPLETED

    cloner = LocalDirCloner(extra={"riskgraph.yaml": KITCHEN_MANIFEST})
    sid = _new_scan(settings, "ctx")
    assert run_pipeline_inline(sid, ALL_SCANNERS, make_deps(settings, cloner=cloner)) is (
        ScanStatus.COMPLETED
    )
    ctx = _scan(sid).summary["context"]
    assert ctx["manifest"] == "valid" and ctx["unmapped_findings"] == 0
    assert ctx["services"][0]["findings"] == 27

    with session_scope() as s:
        before = {
            r[0].id: float(r[2].score)
            for r in list_scan_findings(s, base_id, FindingFilters(), limit=200)[0]
        }
        rows, _ = list_scan_findings(s, sid, FindingFilters(), limit=200)
        assert all(float(r[2].score) >= before[r[0].id] for r in rows)
        sast = next(r for r in rows if r[0].source_type is SourceType.SAST)
        x = _factor(s, sast[2].id, "X")
        assert (x.source, x.raw_value, float(x.value)) == ("manifest", "internet_noauth", 1.0)
        assert _factor(s, sast[2].id, "D").raw_value == "pii"
        assert _factor(s, sast[2].id, "P").raw_value == "admin"
        secret = next(r for r in rows if r[0].source_type is SourceType.SECRET)
        assert _factor(s, secret[2].id, "X").source == "repository_visibility"
        top = [r[2].priority for r in rows]
        assert top.count(Priority.CRITICAL) > 2  # context, not only overrides, reaches critical


def test_invalid_manifest_is_a_warning_not_a_failure(db: None, settings: Settings) -> None:
    cloner = LocalDirCloner(extra={"riskgraph.yaml": "version: 1\nservices: [oops\n"})
    sid = _new_scan(settings)
    assert run_pipeline_inline(sid, ALL_SCANNERS, make_deps(settings, cloner=cloner)) is (
        ScanStatus.COMPLETED
    )
    ctx = _scan(sid).summary["context"]
    assert ctx["manifest"] == "invalid" and ctx["warnings"]
    assert ctx["services"] == []


def test_dedup_index_blocks_two_active_scans(db: None, settings: Settings) -> None:
    sid = _new_scan(settings, "main")
    with session_scope() as s:
        again = service.create_scan(s, URL, "main", settings)
    assert again.deduplicated and again.scan.id == sid
    other = _new_scan(settings, "dev")  # another ref is a different scan
    assert other != sid
