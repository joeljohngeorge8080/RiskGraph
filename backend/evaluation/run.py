"""Replay every scenario through the real pipeline, offline, and collect its findings.

    uv run python -m evaluation.run            # used by ``make eval-baseline``

Needs postgres and redis (``make test-services``) and refuses any database whose name
does not end in ``_test``, because it empties the tables first. Scanner reports come from
``evaluation/fixtures/<scenario>/…`` and EPSS/KEV from the frozen ``intel.json``, seeded
as fresh so the pipeline never calls a feed.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

# Before any riskgraph import reads settings (same defaults as tests/conftest.py).
os.environ.setdefault("RISKGRAPH_ENV", "test")
os.environ.setdefault("RISKGRAPH_LLM_PROVIDER", "none")
os.environ.setdefault("RISKGRAPH_LOG_JSON", "false")
os.environ.setdefault("RISKGRAPH_SECRET_KEY", "evaluation-only-not-a-secret-evaluation-only")

import datetime as dt
import json
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from decimal import Decimal
from functools import partial
from typing import Any

from riskgraph.modules.context import Vulnerability
from riskgraph.modules.findings import FindingFilters, list_scan_findings
from riskgraph.modules.scans import service
from riskgraph.modules.scans.orchestration import run_pipeline_inline
from riskgraph.modules.scans.service import ALL_SCANNERS
from riskgraph.shared.config import Settings, get_settings
from riskgraph.shared.db import dispose_engine, get_engine, session_scope
from riskgraph.shared.vocabulary import ScannerName, ScanStatus
from sqlalchemy import text
from sqlalchemy.engine import make_url
from tests.pipeline_support import FixtureRunner, LocalDirCloner, make_deps

from evaluation.record import FIXTURES, INTEL
from evaluation.scenarios import SCENARIOS, Scenario

BACKEND_DIR = Path(__file__).resolve().parent.parent


@dataclass(frozen=True, slots=True)
class Row:
    """One finding as every ranking method sees it, plus its label."""

    scenario: str
    fingerprint: str  # findings.merge_key: stable across runs, neutral for tie-breaks
    source_type: str
    severity: str
    category: str
    rule_id: str
    file: str
    package: str
    vulnerability_id: str
    cvss_base: float | None
    epss: float | None
    kev: bool
    reachability: str
    score: float
    priority: str
    priority_rank: int
    important: bool
    rationale: str
    defaulted: bool


class EvaluationError(RuntimeError):
    pass


def _report(scenario: str, scanner: ScannerName) -> Path:
    matches = sorted((FIXTURES / scenario / scanner.value).glob("*/report.json"))
    if not matches:
        raise EvaluationError(f"no recorded {scanner.value} report for {scenario}")
    return matches[-1]


def _guard(settings: Settings) -> None:
    name = make_url(str(settings.database_url)).database or ""
    if not name.endswith("_test"):
        raise EvaluationError(f"refusing to empty database {name!r}: name must end in _test")


def _reset_db() -> None:
    from alembic import command
    from alembic.config import Config

    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    command.upgrade(cfg, "head")
    with get_engine().begin() as conn:  # CASCADE reaches every scan-owned table
        conn.execute(text("TRUNCATE repositories, vulnerabilities CASCADE"))


def _seed_intel(now: dt.datetime) -> None:
    snap: dict[str, Any] = json.loads(INTEL.read_text())
    with session_scope() as s:
        for cve in snap["checked"]:
            epss = snap["epss"].get(cve)
            added = snap["kev"].get(cve)
            s.add(
                Vulnerability(
                    id=cve,
                    epss=Decimal(epss[0]) if epss else None,
                    epss_percentile=Decimal(epss[1]) if epss else None,
                    epss_date=dt.date.fromisoformat(epss[2]) if epss and epss[2] else None,
                    epss_fetched_at=now,
                    kev=added is not None,
                    kev_added=dt.date.fromisoformat(added) if added else None,
                    kev_checked_at=now,
                )
            )


def _scan(settings: Settings, scenario: Scenario) -> list[Row]:
    with session_scope() as s:
        sid = service.create_scan(
            s, f"https://github.com/riskgraph-eval/{scenario.name}", "", settings
        ).scan.id
    deps = make_deps(
        settings,
        runner=FixtureRunner(fixture=partial(_report, scenario.name)),
        cloner=LocalDirCloner(build=scenario.build),
    )
    status = run_pipeline_inline(sid, ALL_SCANNERS, deps)
    if status is not ScanStatus.COMPLETED:
        raise EvaluationError(f"{scenario.name}: scan ended {status}")
    rows: list[Row] = []
    with session_scope() as s:
        found, _ = list_scan_findings(s, sid, FindingFilters(), limit=10_000)
        for finding, _by, risk, vuln, _change, tier in found:
            facts: dict[str, Any] = {
                "source_type": finding.source_type.value,
                "package": str((finding.package or {}).get("name") or ""),
                "file": str(finding.location.get("file") or ""),
                "rule_id": finding.rule_id,
                "category": finding.category,
            }
            important, rationale, defaulted = scenario.label(facts)
            rows.append(
                Row(
                    scenario=scenario.name,
                    fingerprint=finding.merge_key,
                    severity=finding.severity.value,
                    vulnerability_id=finding.vulnerability_id or "",
                    cvss_base=float(vuln.cvss_base) if vuln and vuln.cvss_base else None,
                    epss=float(vuln.epss) if vuln and vuln.epss is not None else None,
                    kev=bool(vuln and vuln.kev),
                    reachability=tier.value if tier else "",
                    score=float(risk.score),
                    priority=risk.priority.value,
                    priority_rank=risk.priority_rank,
                    important=important,
                    rationale=rationale,
                    defaulted=defaulted,
                    **facts,
                )
            )
    return rows


@contextmanager
def _environment(data_dir: Path) -> Iterator[Settings]:
    """Settings for one evaluation run; the previous environment is restored after."""
    overrides = {
        # "on" so seeded EPSS/KEV count as known; with no outbound client nothing is fetched
        "RISKGRAPH_ENRICHMENT_ENABLED": "true",
        "RISKGRAPH_DATA_DIR": str(data_dir),
        "RISKGRAPH_TRIVY_CACHE_DIR": str(data_dir / "trivy"),  # never used on replay
    }
    saved = {k: os.environ.get(k) for k in overrides}
    os.environ.update(overrides)
    get_settings.cache_clear()
    try:
        yield get_settings()
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        get_settings.cache_clear()


def collect(names: list[str] | None = None) -> list[Row]:
    """Scan each scenario from its recorded reports; rows sorted by scenario, fingerprint."""
    data_dir = Path(tempfile.mkdtemp(prefix="riskgraph-eval-"))
    try:
        with _environment(data_dir) as settings:
            _guard(settings)
            _reset_db()
            _seed_intel(dt.datetime.now(dt.UTC))
            rows = [r for n in names or sorted(SCENARIOS) for r in _scan(settings, SCENARIOS[n])]
    finally:
        dispose_engine()
        shutil.rmtree(data_dir, ignore_errors=True)
    return sorted(rows, key=lambda r: (r.scenario, r.fingerprint))
