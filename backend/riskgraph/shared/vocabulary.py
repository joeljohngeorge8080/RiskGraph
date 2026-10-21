"""Domain vocabulary shared by several modules.

These enums appear in tables of more than one module, so they live here rather than in
any single module (which would force cross-module imports of model internals).
"""

from __future__ import annotations

from enum import StrEnum


class ScannerName(StrEnum):
    TRIVY = "trivy"
    SEMGREP = "semgrep"
    CHECKOV = "checkov"
    GITLEAKS = "gitleaks"


class SourceType(StrEnum):
    SCA = "sca"
    SAST = "sast"
    SECRET = "secret"  # noqa: S105 - a category name, not a credential
    IAC = "iac"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class Priority(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return _PRIORITY_RANK[self]


_PRIORITY_RANK = {Priority.CRITICAL: 3, Priority.HIGH: 2, Priority.MEDIUM: 1, Priority.LOW: 0}


class ScanStatus(StrEnum):
    PENDING = "PENDING"
    QUEUED = "QUEUED"
    CLONING = "CLONING"
    SCANNING = "SCANNING"
    ANALYZING = "ANALYZING"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"

    @property
    def is_terminal(self) -> bool:
        return self in {ScanStatus.COMPLETED, ScanStatus.PARTIAL, ScanStatus.FAILED}


ACTIVE_SCAN_STATUSES = (
    ScanStatus.PENDING,
    ScanStatus.QUEUED,
    ScanStatus.CLONING,
    ScanStatus.SCANNING,
    ScanStatus.ANALYZING,
)


class RunStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    SKIPPED = "SKIPPED"
