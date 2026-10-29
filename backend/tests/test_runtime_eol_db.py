"""Runtime EOL end to end: Beat refresh, a scan's findings, evidence, assets (expansion X2)."""

from __future__ import annotations

import datetime as dt
import json
import uuid
from pathlib import Path

import httpx
import pytest
from riskgraph.modules.context import list_assets
from riskgraph.modules.evidence import EvidenceRow, FindingEvidence
from riskgraph.modules.findings import Finding, FindingOccurrence
from riskgraph.modules.risk import RiskScore
from riskgraph.modules.runtime import load_feeds, parse_cycles, refresh_eol, store_cycles
from riskgraph.modules.scans import repo, service
from riskgraph.modules.scans.models import ScanJob
from riskgraph.modules.scans.orchestration import run_pipeline_inline
from riskgraph.modules.scans.service import ALL_SCANNERS
from riskgraph.shared.config import Settings
from riskgraph.shared.db import session_scope
from riskgraph.shared.http import OutboundClient, OutboundError
from riskgraph.shared.vocabulary import ScannerName, ScanStatus, SourceType
from sqlalchemy import select

from tests.fixtures.repos import kitchen_sink
from tests.pipeline_support import LocalDirCloner, make_deps

pytestmark = pytest.mark.db
FEEDS = Path(__file__).parent / "fixtures" / "eol"
FETCHED = dt.datetime(2026, 10, 25, 6, 0, tzinfo=dt.UTC)


def _seed() -> None:
    with session_scope() as s:
        for product in ("python", "nodejs"):
            doc = json.loads((FEEDS / f"{product}.json").read_text())
            store_cycles(s, parse_cycles(product, doc, FETCHED))


def _build(dest: Path) -> Path:
    kitchen_sink.build(dest)
    (dest / "Dockerfile").write_text(
        "FROM python:3.8-slim AS app\nCOPY . /app\nFROM node:14 AS assets\n", encoding="utf-8"
    )
    (dest / "docker-compose.override.yml").write_text(
        "services:\n  cache: {image: 'registry.corp.local:5000/cache:1'}\n", encoding="utf-8"
    )
    return dest


def _scan(settings: Settings) -> uuid.UUID:
    with session_scope() as s:
        sid = service.create_scan(s, "https://github.com/acme/eol-app", "", settings).scan.id
    deps = make_deps(settings, cloner=LocalDirCloner(build=_build))
    assert run_pipeline_inline(sid, ALL_SCANNERS, deps) is ScanStatus.COMPLETED
    return sid


def test_eol_runtimes_become_dated_findings_with_fresh_evidence(
    db: None, settings: Settings
) -> None:
    _seed()
    sid = _scan(settings)
    with session_scope() as s:
        found = s.scalars(select(Finding).where(Finding.source_type == SourceType.RUNTIME)).all()
        by_rule = {f.rule_id: f for f in found}
        assert set(by_rule) == {"runtime-eol:python:3.8", "runtime-eol:nodejs:14"}
        py = by_rule["runtime-eol:python:3.8"]
        assert "2024-10-07" in py.title and py.location == {
            "file": "Dockerfile",
            "line_start": 1,
            "line_end": 1,
        }
        assert py.package == {
            "name": "python",
            "version": "3.8",
            "fixed_version": "3.11",
            "ecosystem": "runtime",
        }
        # produced by RiskGraph's own run, not attributed to any scanner
        occ = s.scalars(
            select(FindingOccurrence).where(FindingOccurrence.finding_id == py.id)
        ).one()
        own = repo.get_run(s, sid, ScannerName.RISKGRAPH)
        assert own is not None and occ.scanner_run_id == own.id
        # interim score (ADR-0018): its own factors, never the IaC fallthrough
        score = s.scalars(select(RiskScore).where(RiskScore.finding_id == py.id)).one()
        assert score.model_version == "v1-ctx.4" and float(score.score) > 0

        [eol] = s.scalars(
            select(EvidenceRow)
            .join(FindingEvidence, FindingEvidence.evidence_id == EvidenceRow.id)
            .where(FindingEvidence.finding_id == py.id, EvidenceRow.kind == "eol")
        ).all()
        assert eol.assurance == "verified" and eol.data_as_of == FETCHED
        assert eol.payload["facts"]["advisory"] == "endoflife.date/python/3.8"
        assert eol.raw_run_id is None  # the riskgraph run stores no report

        # Trivy's matches carry the advisory DB build time from its version output
        trivy = s.scalars(
            select(EvidenceRow).where(
                EvidenceRow.scan_job_id == sid, EvidenceRow.kind == "package_match"
            )
        ).all()
        assert trivy and {e.data_as_of for e in trivy} == {
            dt.datetime(2026, 10, 25, 1, 20, 33, tzinfo=dt.UTC)
        }

        summary = s.get(ScanJob, sid).summary  # type: ignore[union-attr]
        assert summary["freshness"] == {
            "trivy_db": "2026-10-25T01:20:33+00:00",
            "eol": FETCHED.isoformat(),
        }
        assert summary["runtime"]["eol_findings"] == 2

        images = {a.name: a for a in list_assets(s, sid) if a.kind == "container_image"}
        assert set(images) == {
            "docker.io/library/python:3.8-slim",
            "docker.io/library/node:14",
            "registry.corp.local:5000/cache:1",
        }
        corp = images["registry.corp.local:5000/cache:1"]
        assert corp.attrs["allowed"] is False and "allow-list" in corp.attrs["reason"]
        assert images["docker.io/library/python:3.8-slim"].attrs["line"] == 1


def test_without_eol_data_there_are_no_runtime_findings(db: None, settings: Settings) -> None:
    sid = _scan(settings)
    with session_scope() as s:
        assert not s.scalars(select(Finding).where(Finding.source_type == SourceType.RUNTIME)).all()
        summary = s.get(ScanJob, sid).summary  # type: ignore[union-attr]
        assert summary["freshness"]["eol"] is None and summary["runtime"]["eol_data"] == []


def test_beat_refresh_stores_cycles_and_keeps_old_data_on_failure(db: None) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/python.json":
            return httpx.Response(200, content=(FEEDS / "python.json").read_bytes())
        return httpx.Response(503)

    client = OutboundClient(transport=httpx.MockTransport(handler))
    with session_scope() as s:
        counts = refresh_eol(s, client, FETCHED, products=("python", "nodejs"))
    assert counts["python"] > 10 and counts["nodejs"] == -1
    with session_scope() as s:
        feeds = load_feeds(s)
    assert feeds["python"]["3.8"].eol_date == dt.date(2024, 10, 7) and "nodejs" not in feeds


def test_the_eol_feed_is_on_the_outbound_allow_list() -> None:
    client = OutboundClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=[])))
    assert client.get_json("https://endoflife.date/api/python.json") == []
    with pytest.raises(OutboundError, match="not allowed"):
        client.get_json("https://endoflife.date/other/python.json")
