"""Scanner adapters, the subprocess runner and report redaction (ADR-0009)."""

from riskgraph.modules.scanners.base import Command, ParseContext, Scanner, ScanPaths
from riskgraph.modules.scanners.redact import derive_key, scrub
from riskgraph.modules.scanners.registry import REDACTION_ORDER, SCANNERS, get_scanner
from riskgraph.modules.scanners.runner import RunResult, RunSpec, ScannerRunner, SubprocessRunner
from riskgraph.modules.scanners.trivy.parser import dependency_graph as trivy_dependency_graph

__all__ = [
    "REDACTION_ORDER",
    "SCANNERS",
    "Command",
    "ParseContext",
    "RunResult",
    "RunSpec",
    "ScanPaths",
    "Scanner",
    "ScannerRunner",
    "SubprocessRunner",
    "derive_key",
    "get_scanner",
    "scrub",
    "trivy_dependency_graph",
]
