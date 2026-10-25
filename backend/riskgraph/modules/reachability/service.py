"""Run the extractor for one scan and classify findings (blueprint §11.3, ADR-0012)."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sqlalchemy import delete
from sqlalchemy.orm import Session

from riskgraph.modules.reachability.extract import ANALYZER_VERSION
from riskgraph.modules.reachability.graph import ModuleGraph, build
from riskgraph.modules.reachability.models import ReachabilityResult
from riskgraph.modules.reachability.tiers import UNKNOWN, TierClassifier, Verdict
from riskgraph.modules.scanners import RunSpec, ScannerRunner
from riskgraph.modules.scanners.runner import SELF_PYTHON
from riskgraph.shared.logging import get_logger
from riskgraph.shared.vocabulary import SourceType

log = get_logger(__name__)
EXTRACT_TIMEOUT_S = 300
EXTRACT_MEMORY = 2 * 1024 * 1024 * 1024
MAX_OUTPUT_BYTES = 200 * 1024 * 1024


@dataclass
class ReachabilityRun:
    status: str  # ok | failed | unavailable
    graph: ModuleGraph | None = None
    classifier: TierClassifier | None = None
    detail: str | None = None
    stats: dict[str, Any] = field(default_factory=dict)

    def classify(
        self,
        source_type: SourceType,
        file: str,
        package: dict[str, Any] | None,
        vulnerability_id: str | None = None,
        line: int | None = None,
    ) -> Verdict:
        if source_type not in (SourceType.SCA, SourceType.SAST):
            from riskgraph.modules.reachability.tiers import NOT_APPLICABLE

            return NOT_APPLICABLE
        if self.classifier is None:
            return UNKNOWN
        return self.classifier.classify(source_type, file, package, vulnerability_id, line)

    def summary(self, counts: dict[str, int]) -> dict[str, Any]:
        return {
            "status": self.status,
            "analyzer": ANALYZER_VERSION,
            "detail": self.detail,
            **self.stats,
            "tiers": counts,
        }


def run_extractor(
    runner: ScannerRunner,
    src: Path,
    work: Path,
    deps: dict[str, dict[str, Any]],
    manifest_entrypoints: list[str],
) -> ReachabilityRun:
    if not src.is_dir():
        return ReachabilityRun("unavailable", detail="checkout no longer on disk")
    work.mkdir(parents=True, exist_ok=True)
    out = work / "imports.json"
    result = runner.run(
        RunSpec(
            (SELF_PYTHON, "-I", "-m", "riskgraph.modules.reachability.extract", str(src), str(out)),
            cwd=work,
            log_dir=work,
            timeout_s=EXTRACT_TIMEOUT_S,
            network="none",
            env={"HOME": str(work), "TMPDIR": str(work)},
            fsize_limit=MAX_OUTPUT_BYTES,
            log_name="extract",
            memory_limit=EXTRACT_MEMORY,
        )
    )
    if result.timed_out:
        return ReachabilityRun("failed", detail="import extraction timed out")
    if result.exit_code != 0 or not out.is_file():
        log.warning("reachability_extract_failed", exit_code=result.exit_code)
        return ReachabilityRun(
            "failed", detail=f"import extraction failed (exit {result.exit_code})"
        )
    try:
        if out.stat().st_size > MAX_OUTPUT_BYTES:
            return ReachabilityRun("failed", detail="extraction output too large")
        extracted = json.loads(out.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ReachabilityRun("failed", detail="extraction output unreadable")
    graph = build(extracted, manifest_entrypoints)
    stats = {
        "files": len(graph.files),
        "entry_points": len(graph.entries),
        "reachable_files": len(graph.parent),
        "skipped_files": int(extracted.get("skipped") or 0),
        "truncated": bool(extracted.get("truncated")),
    }
    return ReachabilityRun("ok", graph, TierClassifier(graph, deps), stats=stats)


def clear(session: Session, scan_id: uuid.UUID) -> None:
    session.execute(delete(ReachabilityResult).where(ReachabilityResult.scan_job_id == scan_id))


def persist_verdict(
    session: Session, scan_id: uuid.UUID, finding_id: uuid.UUID, verdict: Verdict
) -> None:
    session.add(
        ReachabilityResult(
            scan_job_id=scan_id,
            finding_id=finding_id,
            tier=verdict.tier,
            confidence=verdict.confidence,
            evidence=verdict.evidence,
            analyzer_version=ANALYZER_VERSION,
        )
    )
