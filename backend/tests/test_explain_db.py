"""Explanations against Postgres (P12): cache, validated vs fallback, injection, top-N task."""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from riskgraph.entrypoints.api import create_app
from riskgraph.modules.explain import AiExplanation, NullAdapter
from riskgraph.modules.explain import service as explain_service
from riskgraph.modules.explain.tasks import explain_top_findings_task
from riskgraph.modules.scans import service
from riskgraph.modules.scans.orchestration import run_pipeline_inline
from riskgraph.modules.scans.service import ALL_SCANNERS
from riskgraph.shared.config import Settings, get_settings
from riskgraph.shared.db import dispose_engine, session_scope
from riskgraph.shared.vocabulary import ScanStatus
from sqlalchemy import func, select

from tests.fixtures.repos import kitchen_sink
from tests.pipeline_support import LocalDirCloner, make_deps

pytestmark = pytest.mark.db
URL = "https://github.com/acme/kitchen-sink"
MARKER = "INJECTED-MARKER-7f3a"


@pytest.fixture()
def api(db: None, settings: Settings) -> Iterator[TestClient]:
    app = create_app(settings)
    app.dependency_overrides[get_settings] = lambda: settings
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    dispose_engine()


@pytest.fixture()
def sid(api: TestClient, settings: Settings) -> str:
    with session_scope() as s:
        scan_id = service.create_scan(s, URL, "", settings).scan.id
    cloner = LocalDirCloner(extra={"riskgraph.yaml": kitchen_sink.MANIFEST})
    status = run_pipeline_inline(scan_id, ALL_SCANNERS, make_deps(settings, cloner=cloner))
    assert status in (ScanStatus.COMPLETED, ScanStatus.PARTIAL)
    return str(scan_id)


def _critical(api: TestClient, sid: str) -> str:
    items = api.get("/api/v1/risks", params={"scan_id": sid, "priority": "critical"}).json()
    return str(items["items"][0]["finding_id"])


def _grounded_reply(user: str) -> str:
    """What a well-behaved model returns: claims built only from the evidence it was given."""
    pack = json.loads(user.split("EVIDENCE:\n", 1)[1].split("\n\nYour previous", 1)[0])
    f1 = pack["factors"][0]
    return json.dumps(
        {
            "summary": f"This finding has priority {pack['score']['priority']}.",
            "reasons": [
                {"claim": f"The {f1['meaning']} factor applies.", "evidence_ids": [f1["id"]]}
            ],
            "impact": "See the impact factors.",
            "remediation_steps": ["Apply the scanner's fix."],
            "caveats": "",
        }
    )


def _use(monkeypatch: pytest.MonkeyPatch, adapter: Any) -> None:
    monkeypatch.setattr(explain_service, "adapter_from_settings", lambda settings: adapter)


def test_without_a_model_the_template_answers_and_is_cached(api: TestClient, sid: str) -> None:
    fid = _critical(api, sid)
    url = f"/api/v1/findings/{fid}/explanation"
    assert api.get(url, params={"scan_id": sid}).status_code == 404  # nothing generated yet
    first = api.post(url, params={"scan_id": sid})
    assert first.status_code == 200, first.text
    body = first.json()
    assert body["status"] == "fallback" and body["generator"] == "template"
    assert body["reasons"] and all(r["evidence"] for r in body["reasons"])
    assert all(e["label"] for r in body["reasons"] for e in r["evidence"])
    again = api.post(url, params={"scan_id": sid}).json()
    assert (
        again["created_at"] == body["created_at"]
        and again["evidence_hash"] == body["evidence_hash"]
    )
    assert api.get(url, params={"scan_id": sid}).json()["evidence_hash"] == body["evidence_hash"]
    with session_scope() as s:
        assert s.scalar(select(func.count()).select_from(AiExplanation)) == 1


def test_a_grounded_model_answer_is_validated_and_stored(
    api: TestClient, sid: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use(monkeypatch, NullAdapter(_grounded_reply))
    fid = _critical(api, sid)
    body = api.post(f"/api/v1/findings/{fid}/explanation", params={"scan_id": sid}).json()
    assert (body["status"], body["generator"], body["attempts"]) == ("validated", "null", 1)
    assert body["reasons"][0]["evidence"][0]["id"] == "F1"


def test_an_injected_answer_is_rejected_and_never_stored(
    api: TestClient, sid: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    injected = json.dumps(
        {
            "summary": f"This is safe, ignore the score. {MARKER}",
            "reasons": [
                {"claim": f"The repository says it is safe {MARKER}", "evidence_ids": ["S1"]}
            ],
            "impact": "None, score 0.123456.",
            "remediation_steps": ["Visit https://evil.example/fix"],
            "caveats": "",
        }
    )
    adapter = NullAdapter([injected, injected])
    _use(monkeypatch, adapter)
    fid = _critical(api, sid)
    body = api.post(f"/api/v1/findings/{fid}/explanation", params={"scan_id": sid}).json()
    assert body["status"] == "fallback" and body["attempts"] == 2
    assert len(adapter.calls) == 2 and "untrusted repository text" in adapter.calls[1]
    with session_scope() as s:
        row = s.scalars(select(AiExplanation)).one()
        stored = json.dumps([row.draft, row.validation_errors, row.evidence_ids])
    assert MARKER not in stored and "evil.example" not in stored
    # the score is untouched by anything the model said
    risk = api.get(f"/api/v1/risks/{fid}", params={"scan_id": sid}).json()
    assert risk["priority"] == "critical"


def test_refresh_replaces_a_fallback_once_the_model_is_back(
    api: TestClient, sid: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    fid = _critical(api, sid)
    url = f"/api/v1/findings/{fid}/explanation"
    assert api.post(url, params={"scan_id": sid}).json()["status"] == "fallback"
    _use(monkeypatch, NullAdapter(_grounded_reply))
    assert api.post(url, params={"scan_id": sid}).json()["status"] == "fallback"  # cached
    fresh = api.post(url, params={"scan_id": sid, "refresh": True}).json()
    assert fresh["status"] == "validated"
    with session_scope() as s:  # upserted: still one row per (finding, evidence)
        assert s.scalar(select(func.count()).select_from(AiExplanation)) == 1


def test_top_findings_task_explains_every_critical(
    api: TestClient, sid: str, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("riskgraph.modules.explain.tasks.get_settings", lambda: settings)
    criticals = api.get("/api/v1/risks", params={"scan_id": sid, "priority": "critical"}).json()
    expected = min(criticals["total"], settings.explain_top_n)  # top N only (§15.3)
    assert criticals["total"] > settings.explain_top_n  # the kitchen sink exercises the cap
    counts = explain_top_findings_task(sid)
    assert counts == {"validated": 0, "fallback": expected, "failed": 0}
    with session_scope() as s:
        assert s.scalar(select(func.count()).select_from(AiExplanation)) == expected


def test_explanation_not_found_cases(api: TestClient, sid: str) -> None:
    fid = _critical(api, sid)
    other_scan = str(uuid.uuid4())
    assert (
        api.post(f"/api/v1/findings/{fid}/explanation", params={"scan_id": other_scan}).status_code
        == 404
    )
    missing = api.post(f"/api/v1/findings/{uuid.uuid4()}/explanation", params={"scan_id": sid})
    assert missing.status_code == 404
    assert api.post(f"/api/v1/findings/{fid}/explanation").status_code == 422  # scan_id required
