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
    SYFT = "syft"


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
    CANCELLED = "CANCELLED"

    @property
    def is_terminal(self) -> bool:
        return self in {
            ScanStatus.COMPLETED,
            ScanStatus.PARTIAL,
            ScanStatus.FAILED,
            ScanStatus.CANCELLED,
        }


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


class FindingStatus(StrEnum):
    OPEN = "open"
    FIXED = "fixed"  # set by the system only (fixed detection)
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    WONT_FIX = "wont_fix"


TRIAGE_STATUSES = (
    FindingStatus.FALSE_POSITIVE,
    FindingStatus.ACCEPTED_RISK,
    FindingStatus.WONT_FIX,
)


class FindingChange(StrEnum):
    """How a finding relates to the previous scan of the same repository and ref."""

    NEW = "new"
    EXISTING = "existing"
    REOPENED = "reopened"


class ReachabilityTier(StrEnum):
    L0 = "L0"  # package not imported anywhere in scope
    L1 = "L1"  # imported, but only from code no entry point reaches
    L2 = "L2"  # imported by code reachable from an entry point
    L3 = "L3"  # a curated vulnerable symbol is called on a path from an entry point (ADR-0015)
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "n_a"
