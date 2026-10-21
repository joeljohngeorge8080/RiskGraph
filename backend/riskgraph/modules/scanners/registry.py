"""The scanner registry: an explicit dict, never plugin discovery (blueprint §9.2)."""

from __future__ import annotations

from riskgraph.modules.scanners.base import Scanner
from riskgraph.modules.scanners.checkov import CheckovScanner
from riskgraph.modules.scanners.gitleaks import GitleaksScanner
from riskgraph.modules.scanners.semgrep import SemgrepScanner
from riskgraph.modules.scanners.trivy import TrivyScanner
from riskgraph.shared.vocabulary import ScannerName

SCANNERS: dict[ScannerName, Scanner] = {
    ScannerName.TRIVY: TrivyScanner(),
    ScannerName.SEMGREP: SemgrepScanner(),
    ScannerName.CHECKOV: CheckovScanner(),
    ScannerName.GITLEAKS: GitleaksScanner(),
}

# Gitleaks first: its redaction yields the raw secrets every other report is scrubbed of.
REDACTION_ORDER = (
    ScannerName.GITLEAKS,
    ScannerName.TRIVY,
    ScannerName.SEMGREP,
    ScannerName.CHECKOV,
)


def get_scanner(name: ScannerName) -> Scanner:
    return SCANNERS[name]
