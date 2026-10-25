"""P12 definition of done with the real local model: a Critical finding is explained,
validated and cached; with the model unreachable, the template answers instead.

Opt-in (``make test-llm``): needs Ollama with RISKGRAPH_OLLAMA_MODEL (default qwen3:4b)."""

from __future__ import annotations

import os
import time
import uuid

import httpx
import pytest
from riskgraph.modules.explain import OllamaAdapter
from riskgraph.modules.explain import service as explain
from riskgraph.modules.risk.repo import ranked
from riskgraph.modules.scans import service
from riskgraph.modules.scans.orchestration import run_pipeline_inline
from riskgraph.modules.scans.service import ALL_SCANNERS
from riskgraph.shared.config import Settings
from riskgraph.shared.db import session_scope
from riskgraph.shared.vocabulary import Priority, ScanStatus

from tests.fixtures.repos import kitchen_sink
from tests.pipeline_support import LocalDirCloner, make_deps

pytestmark = [pytest.mark.db, pytest.mark.llm]
URL = os.environ.get("RISKGRAPH_OLLAMA_URL", "http://127.0.0.1:11434")
MODEL = os.environ.get("RISKGRAPH_OLLAMA_MODEL", "qwen3:4b")


def _ollama_up() -> bool:
    try:
        tags = httpx.get(f"{URL}/api/tags", timeout=3).json()
    except (httpx.HTTPError, ValueError):
        return False
    return any(m.get("name") == MODEL for m in tags.get("models", []))


@pytest.fixture()
def criticals(db: None, settings: Settings) -> tuple[uuid.UUID, list[uuid.UUID]]:
    if not _ollama_up():
        pytest.skip(f"Ollama at {URL} with {MODEL} is not available")
    with session_scope() as s:
        sid = service.create_scan(s, "https://github.com/acme/kitchen-sink", "", settings).scan.id
    cloner = LocalDirCloner(extra={"riskgraph.yaml": kitchen_sink.MANIFEST})
    assert run_pipeline_inline(sid, ALL_SCANNERS, make_deps(settings, cloner=cloner)) in (
        ScanStatus.COMPLETED,
        ScanStatus.PARTIAL,
    )
    with session_scope() as s:
        rows, _ = ranked(
            s, sid, priorities=[Priority.CRITICAL], include_excluded=False, limit=5, offset=0
        )
    return sid, [r.finding_id for r, _ in rows]


def test_real_model_explains_a_critical_finding_and_the_result_is_cached(
    criticals: tuple[uuid.UUID, list[uuid.UUID]],
) -> None:
    sid, ids = criticals
    adapter = OllamaAdapter(URL, MODEL, timeout_s=120)
    try:
        with session_scope() as s:
            row = explain.explain(s, sid, ids[0], adapter)
            first = (row.status, row.generator, row.attempts, row.latency_ms, row.evidence_hash)
            summary, errors = row.draft["summary"], list(row.validation_errors)
        print(  # noqa: T201 (the live numbers go in the phase chapter)
            f"\nfirst: status={first[0]} generator={first[1]} attempts={first[2]} "
            f"latency_ms={first[3]}\nsummary: {summary}\nerrors: {errors}"
        )
        assert first[0] == "validated", errors  # the DoD: a validated model explanation
        started = time.monotonic()
        with session_scope() as s:
            again = explain.explain(s, sid, ids[0], adapter)
            assert (again.evidence_hash, again.latency_ms) == (first[4], first[3])
        assert time.monotonic() - started < 2.0  # cached: no model call
    finally:
        adapter.close()


def test_unreachable_model_falls_back_to_the_template(
    criticals: tuple[uuid.UUID, list[uuid.UUID]],
) -> None:
    sid, ids = criticals
    dead = OllamaAdapter("http://127.0.0.1:9", MODEL, timeout_s=5)  # nothing listens on port 9
    try:
        started = time.monotonic()
        with session_scope() as s:
            row = explain.explain(s, sid, ids[-1], dead)
            status, generator, errors = row.status, row.generator, list(row.validation_errors)
        elapsed = time.monotonic() - started
    finally:
        dead.close()
    print(f"\nunreachable: status={status} generator={generator} {elapsed:.2f}s {errors}")  # noqa: T201
    assert (status, generator) == ("fallback", "template") and "unreachable" in errors[0]
    assert elapsed < 6.0
