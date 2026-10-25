"""Image scanning end to end (X2 part 2, ADR-0018): stage, findings, SBOM, history."""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from riskgraph.entrypoints.api import create_app
from riskgraph.modules.evidence import EvidenceRow, FindingEvidence
from riskgraph.modules.findings import Finding
from riskgraph.modules.reachability.models import ReachabilityResult
from riskgraph.modules.scanners import RunResult, RunSpec
from riskgraph.modules.scans import repo, service
from riskgraph.modules.scans.models import ScanJob
from riskgraph.modules.scans.orchestration import run_pipeline_inline
from riskgraph.modules.scans.service import ALL_SCANNERS
from riskgraph.modules.scans.storage import read_image_index
from riskgraph.shared.config import Settings, get_settings
from riskgraph.shared.db import dispose_engine, session_scope
from riskgraph.shared.vocabulary import FindingStatus, ScanStatus, SourceType
from sqlalchemy import select

from tests.fixtures.repos import kitchen_sink
from tests.pipeline_support import IMAGE_FIXTURES, FixtureRunner, LocalDirCloner, make_deps

pytestmark = pytest.mark.db
URL = "https://github.com/acme/image-app"
PY = "docker.io/library/python:3.8-slim"
NODE = "docker.io/library/node:14"
REDIS = "docker.io/library/redis:7"  # public, but no recorded report: a failed pull
CORP = "registry.corp.local:5000/cache:1"  # never on the allow-list
TRIVY_DB = dt.datetime(2026, 10, 25, 1, 20, 33, tzinfo=dt.UTC)


def _build(dest: Path) -> Path:
    kitchen_sink.build(dest)
    (dest / "Dockerfile").write_text("FROM python:3.8-slim\nCOPY . /app\n", encoding="utf-8")
    (dest / "docker-compose.images.yml").write_text(
        "services:\n"
        "  web: {image: 'node:14'}\n"
        "  cache: {image: 'redis:7'}\n"
        f"  corp: {{image: '{CORP}'}}\n",
        encoding="utf-8",
    )
    return dest


def _scan(settings: Settings, runner: FixtureRunner | None = None) -> uuid.UUID:
    with session_scope() as s:
        sid = service.create_scan(s, URL, "", settings).scan.id
    deps = make_deps(
        settings,
        runner=runner or FixtureRunner(images=dict(IMAGE_FIXTURES)),
        cloner=LocalDirCloner(build=_build),
    )
    status = run_pipeline_inline(sid, ALL_SCANNERS, deps)
    assert status in (ScanStatus.COMPLETED, ScanStatus.PARTIAL)
    return sid


def _summary(sid: uuid.UUID) -> dict[str, Any]:
    with session_scope() as s:
        scan = s.get(ScanJob, sid)
        assert scan is not None
        return dict(scan.summary or {})


def _image_findings(image: str | None = None) -> list[Finding]:
    with session_scope() as s:
        rows = s.scalars(select(Finding)).all()
        out = [
            f for f in rows if (f.package or {}).get("image") and f.source_type is SourceType.SCA
        ]
        if image:
            out = [f for f in out if (f.package or {})["image"] == image]
        s.expunge_all()
        return out


def test_allowed_images_are_scanned_and_failures_are_warnings(db: None, settings: Settings) -> None:
    runner = FixtureRunner(images=dict(IMAGE_FIXTURES))
    sid = _scan(settings, runner)
    with session_scope() as s:
        assert s.get(ScanJob, sid).status is ScanStatus.COMPLETED  # type: ignore[union-attr]
    pulled = [c[-1] for c in runner.calls if c[:2] == ("trivy", "image")]
    assert sorted(pulled) == sorted([PY, NODE, REDIS])  # the internal registry never
    for argv in (c for c in runner.calls if c[:2] == ("trivy", "image")):
        assert "--list-all-pkgs" in argv and argv[-1] != CORP

    images = _summary(sid)["images"]
    assert images["scanned"] == sorted([NODE, PY])
    by_ref = {r["ref"]: r for r in images["results"]}
    assert by_ref[REDIS]["status"] == "failed" and "MANIFEST_UNKNOWN" in by_ref[REDIS]["warning"]
    assert CORP not in by_ref
    assert any("MANIFEST_UNKNOWN" in w for w in images["warnings"])


def test_image_findings_carry_the_image_advisory_version_and_data_date(
    db: None, settings: Settings
) -> None:
    sid = _scan(settings)
    py, node = _image_findings(PY), _image_findings(NODE)
    assert py and node
    for f in [*py, *node]:
        assert f.source_type is SourceType.SCA and f.detected_by == ["trivy"]
        assert f.vulnerability_id and f.package and f.package["version"]
        assert f.location["resource"] == f.package["image"]
    assert py[0].location["file"] == "Dockerfile" and py[0].location["line_start"] == 1
    assert node[0].location["file"] == "docker-compose.images.yml"
    assert any(f.package and f.package.get("fixed_version") for f in py)

    with session_scope() as s:
        ids = [f.id for f in [*py, *node]]
        # image packages: reachability is not assessable, so no verdict is stored
        assert not s.scalars(
            select(ReachabilityResult).where(ReachabilityResult.finding_id.in_(ids))
        ).all()
        evidence = s.scalars(
            select(EvidenceRow)
            .join(FindingEvidence, FindingEvidence.evidence_id == EvidenceRow.id)
            .where(FindingEvidence.finding_id.in_(ids), EvidenceRow.kind == "image_package")
        ).all()
        assert len({e.id for e in evidence}) >= len(ids)
        assert {e.data_as_of for e in evidence} == {TRIVY_DB}
        assert {e.payload["facts"]["image"] for e in evidence} == {PY, NODE}
        assert all(e.raw_run_id is None for e in evidence)

    summary = _summary(sid)
    assert summary["images"]["findings"] == len(py) + len(node)
    assert summary["reachability"]  # the rest of the analysis still ran


def test_end_of_support_base_os_becomes_a_runtime_finding(db: None, settings: Settings) -> None:
    sid = _scan(settings)
    with session_scope() as s:
        found = s.scalars(select(Finding).where(Finding.source_type == SourceType.RUNTIME)).all()
        os_eol = [f for f in found if f.rule_id.startswith("runtime-eol:os:")]
        assert [f.rule_id for f in os_eol] == ["runtime-eol:os:debian:10.13"]
        [eol] = s.scalars(
            select(EvidenceRow)
            .join(FindingEvidence, FindingEvidence.evidence_id == EvidenceRow.id)
            .where(FindingEvidence.finding_id == os_eol[0].id)
        ).all()
        assert eol.kind == "eol" and eol.assurance == "verified"
        assert eol.data_as_of == dt.datetime(2026, 10, 25, 12, 33, 56, 623859, tzinfo=dt.UTC)
    assert _summary(sid)["images"]["eol_findings"] == 1


def test_image_packages_are_in_the_sbom_with_their_image(
    api: TestClient, settings: Settings
) -> None:
    sid = _scan(settings)
    everything = api.get(f"/api/v1/scans/{sid}/sbom", params={"limit": 500}).json()
    image = api.get(f"/api/v1/scans/{sid}/sbom", params={"origin": "image", "limit": 500}).json()
    repo = api.get(f"/api/v1/scans/{sid}/sbom", params={"origin": "repository"}).json()
    assert image["total"] > 0 and repo["total"] > 0
    assert everything["total"] == image["total"] + repo["total"]
    assert {c["image"] for c in image["items"]} == {PY, NODE}
    assert all(c["image"] is None for c in repo["items"])
    assert any(c["findings"] > 0 for c in image["items"])  # findings attach per image
    # fields from before X2 are unchanged
    assert set(repo["items"][0]) == {
        "id", "purl", "name", "version", "ecosystem", "location", "discovered_by", "image",
        "findings",
    }  # fmt: skip
    assert api.get(f"/api/v1/scans/{sid}/sbom", params={"origin": "x"}).status_code == 422
    assert _summary(sid)["sbom"]["image_packages"] == image["total"]


def test_at_most_the_cap_is_scanned(db: None, settings: Settings) -> None:
    capped = settings.model_copy(update={"image_scan_max_refs": 1})
    runner = FixtureRunner(images=dict(IMAGE_FIXTURES))
    sid = _scan(capped, runner)
    assert len([c for c in runner.calls if c[:2] == ("trivy", "image")]) == 1
    results = _summary(sid)["images"]["results"]
    assert [r["status"] for r in results] == ["scanned", "skipped", "skipped"]
    assert "more than 1 images" in results[1]["warning"]


def test_without_a_clean_trivy_run_no_image_is_pulled(db: None, settings: Settings) -> None:
    runner = FixtureRunner(
        images=dict(IMAGE_FIXTURES), fail={"trivy": RunResult(1, False, 1, "boom")}
    )
    sid = _scan(settings, runner)
    assert not [c for c in runner.calls if c[:2] == ("trivy", "image")]
    results = _summary(sid)["images"]["results"]
    assert results and {r["status"] for r in results} == {"skipped"}
    assert not _image_findings()


def test_a_failed_pull_does_not_mark_image_findings_fixed(db: None, settings: Settings) -> None:
    _scan(settings)
    before = {f.id for f in _image_findings()}
    assert before
    # same repository, the registry refuses every pull this time
    _scan(settings, FixtureRunner())
    after = _image_findings()
    assert {f.id for f in after} == before
    assert {f.status for f in after} == {FindingStatus.OPEN}


def test_the_stage_is_idempotent(db: None, settings: Settings) -> None:
    from riskgraph.modules.scans import pipeline

    runner = FixtureRunner(images=dict(IMAGE_FIXTURES))
    sid = _scan(settings, runner)
    calls = len(runner.calls)
    with session_scope() as s:  # a redelivered message after the scan moved on
        s.get(ScanJob, sid).status = ScanStatus.ANALYZING  # type: ignore[union-attr]
    pipeline.scan_images(sid, make_deps(settings, runner=runner))
    assert len(runner.calls) == calls


def test_a_cancelled_scan_stops_pulling_images(db: None, settings: Settings) -> None:
    from riskgraph.modules.scans import pipeline

    with session_scope() as s:
        sid = service.create_scan(s, URL, "", settings).scan.id

    class CancelAfterFirst(FixtureRunner):
        def run(self, spec: RunSpec) -> RunResult:
            result = super().run(spec)
            if tuple(spec.argv[:2]) == ("trivy", "image"):
                with session_scope() as s:  # what a cancel does to the row
                    scan = s.get(ScanJob, sid)
                    assert scan is not None
                    scan.status = ScanStatus.CANCELLED
            return result

    runner = CancelAfterFirst(images=dict(IMAGE_FIXTURES))
    deps = make_deps(settings, runner=runner, cloner=LocalDirCloner(build=_build))
    with session_scope() as s:
        repo.cas_scan(s, sid, ScanStatus.PENDING, ScanStatus.QUEUED)
    pipeline.clone(sid, deps)
    for name in ALL_SCANNERS:
        pipeline.run_scanner(sid, name, deps)
    pipeline.collect(sid, deps)
    pipeline.scan_images(sid, deps)
    assert len([c for c in runner.calls if c[:2] == ("trivy", "image")]) == 1
    index = read_image_index(settings.scan_output_root, sid)
    assert index is not None
    assert [e["status"] for e in index["images"]][1:] == ["skipped", "skipped"]
    pipeline.discard_workspace(deps, sid)


@pytest.fixture()
def api(db: None, settings: Settings) -> Iterator[TestClient]:
    app = create_app(settings)
    app.dependency_overrides[get_settings] = lambda: settings
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    dispose_engine()
