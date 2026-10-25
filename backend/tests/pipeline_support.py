"""Test doubles for the scan pipeline: replay recorded reports instead of running tools."""

from __future__ import annotations

import json
import shutil
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from riskgraph.modules.scanners import SCANNERS, RunResult, RunSpec, SubprocessRunner
from riskgraph.modules.scanners.runner import SELF_PYTHON
from riskgraph.modules.scans.clone import CloneError, CloneResult
from riskgraph.modules.scans.pipeline import PipelineDeps, no_lock
from riskgraph.modules.scans.workspace import ScanWorkspace
from riskgraph.shared.config import Settings
from riskgraph.shared.http import OutboundClient
from riskgraph.shared.vocabulary import ScannerName

from tests.fixtures.repos import kitchen_sink
from tests.scanner_fixtures import fixture_path

FAKE_SHA = "0123456789abcdef0123456789abcdef01234567"
TRIVY_DB = "2026-10-25 01:20:33.190884269 +0000 UTC"


@dataclass
class FixtureRunner:
    """Writes each scanner's recorded report where the real tool would have."""

    fail: dict[str, RunResult] = field(default_factory=dict)
    calls: list[tuple[str, ...]] = field(default_factory=list)
    # simulate a fix: results for these files are removed from the replayed reports
    drop_files: set[str] = field(default_factory=set)
    # where recorded reports come from (the evaluation replays its own scenarios)
    fixture: Callable[[ScannerName], Path] = fixture_path

    def run(self, spec: RunSpec) -> RunResult:
        argv = tuple(spec.argv)
        self.calls.append(argv)
        if argv and argv[0] == SELF_PYTHON:  # the reachability extractor: run it for real
            return SubprocessRunner(Path("/nonexistent")).run(spec)
        name = spec.log_dir.name
        spec.log_dir.mkdir(parents=True, exist_ok=True)
        if spec.log_name == "version":
            text = "1.2.3\n"
            if name == "trivy":  # the real output shape, so advisory freshness is read
                text = f"Version: 1.2.3\nVulnerability DB:\n  Version: 2\n  UpdatedAt: {TRIVY_DB}\n"
            (spec.log_dir / "version.stdout.log").write_text(text)
            return RunResult(0, False, 1, "")
        if name in self.fail:
            return self.fail[name]
        scanner = SCANNERS[ScannerName(name)]
        out = spec.log_dir.parent.parent / "out" / name / scanner.output_name
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.fixture(ScannerName(name)), out)
        if self.drop_files:
            out.write_text(json.dumps(_drop(json.loads(out.read_text()), self.drop_files)))
        return RunResult(0, False, 5, "")


def _drop(doc: Any, files: set[str]) -> Any:
    """Remove results for ``files`` from a gitleaks/trivy/semgrep/checkov report."""
    if isinstance(doc, list) and all(isinstance(x, dict) and "RuleID" in x for x in doc):
        return [x for x in doc if x.get("File") not in files]
    if isinstance(doc, dict) and "Results" in doc:
        doc["Results"] = [r for r in doc["Results"] if r.get("Target") not in files]
    if isinstance(doc, dict) and "results" in doc and isinstance(doc["results"], list):
        doc["results"] = [r for r in doc["results"] if r.get("path") not in files]
    return doc


@dataclass
class LocalDirCloner:
    """Builds a local repository (the kitchen sink by default) instead of cloning."""

    error: str | None = None
    extra: dict[str, str] = field(default_factory=dict)  # added files, e.g. riskgraph.yaml
    build: Callable[[Path], Path] = kitchen_sink.build

    def clone(self, ws: ScanWorkspace, clone_url: str, ref: str) -> CloneResult:
        if self.error:
            raise CloneError(self.error)
        self.build(ws.src)
        for rel, content in self.extra.items():
            (ws.src / rel).write_text(content, encoding="utf-8")
        size, files = ws.measure(10**9, 10**6)
        ws.make_readonly()
        return CloneResult(FAKE_SHA, size, files)


def make_deps(
    settings: Settings,
    runner: object | None = None,
    cloner: object | None = None,
    outbound: Callable[[], OutboundClient | None] | None = None,
) -> PipelineDeps:
    return PipelineDeps(
        settings=settings,
        runner=runner or FixtureRunner(),  # type: ignore[arg-type]
        cloner=cloner or LocalDirCloner(),  # type: ignore[arg-type]
        outbound=outbound or (lambda: None),
        kev_cache=lambda: None,
        scanner_lock=no_lock,
    )


def workspace_exists(settings: Settings) -> bool:
    root = Path(settings.workspace_root)
    return root.exists() and any(root.iterdir())
