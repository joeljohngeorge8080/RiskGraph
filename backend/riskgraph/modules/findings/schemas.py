"""API schemas for findings and their risk breakdown."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from riskgraph.shared.vocabulary import (
    FindingChange,
    FindingStatus,
    Priority,
    ReachabilityTier,
    ScannerName,
    Severity,
    SourceType,
)


class FindingListItem(BaseModel):
    id: uuid.UUID
    title: str
    source_type: SourceType
    category: str
    severity: Severity
    priority: Priority
    score: float
    detected_by: list[str]
    location: dict[str, Any]
    rule_id: str
    vulnerability_id: str | None
    package: dict[str, Any] | None
    epss: float | None
    kev: bool | None
    status: FindingStatus
    change: FindingChange
    reachability: ReachabilityTier | None


class FindingList(BaseModel):
    items: list[FindingListItem]
    total: int
    limit: int
    offset: int


class RiskFactorOut(BaseModel):
    group: str
    name: str
    value: float
    raw_value: str | None
    source: str
    confidence: str
    applicable: bool
    evidence: dict[str, Any]


class RiskScoreOut(BaseModel):
    model_version: str
    score: float
    priority: Priority
    likelihood: float
    impact: float
    corroboration: float
    overrides: list[dict[str, Any]]
    factors: list[RiskFactorOut]
    effective_impact: float | None = None
    computed_at: dt.datetime


class OccurrenceOut(BaseModel):
    scanner: ScannerName
    rule_id: str
    title: str
    severity: Severity
    scanner_severity: str | None
    location: dict[str, Any]
    evidence: dict[str, Any]


class VulnerabilityOut(BaseModel):
    id: str
    cvss_vector: str | None
    cvss_base: float | None
    cvss_impact: float | None
    cvss_exploitability: float | None
    cvss_source: str | None
    epss: float | None
    epss_percentile: float | None
    kev: bool | None
    kev_added: dt.date | None


class FindingDetailOut(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID | None
    title: str
    description: str | None
    remediation: str | None
    source_type: SourceType
    category: str
    severity: Severity
    rule_id: str
    cwe_ids: list[str]
    location: dict[str, Any]
    package: dict[str, Any] | None
    detected_by: list[str]
    status: FindingStatus
    status_reason: str | None
    status_changed_at: dt.datetime | None
    change: FindingChange | None
    first_seen_at: dt.datetime
    last_seen_at: dt.datetime
    occurrences: list[OccurrenceOut]
    risk: RiskScoreOut | None
    vulnerability: VulnerabilityOut | None
    reachability: ReachabilityOut | None
    attack_paths: list[AttackPathOut]
    history: list[AuditOut]
    evidence: list[EvidenceOut] = []


class ReachabilityOut(BaseModel):
    tier: ReachabilityTier
    confidence: str
    evidence: dict[str, Any]
    analyzer_version: str


class AttackPathOut(BaseModel):
    id: uuid.UUID
    source: str
    sink: str
    rank: int
    hops: int
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    probability: float
    sink_impact: float
    score: float
    finding_ids: list[uuid.UUID]
    # ADR-0017: the weakest edge's assurance; None for paths stored before X1. Only paths
    # of at least "inferred" raise a finding's effective impact.
    assurance: str | None = None


class EvidenceOut(BaseModel):
    """One piece of evidence (ADR-0017). ``facts`` are small and display-safe."""

    id: str
    producer: str
    kind: str
    assurance: str
    confidence: str
    locations: list[dict[str, Any]]
    facts: dict[str, Any]
    steps: list[dict[str, Any]]
    raw_run_id: uuid.UUID | None  # the scanner run whose stored report holds it
    raw_pointer: str | None  # RFC 6901 pointer into that report; "" is the whole report
    observed_at: dt.datetime
    data_as_of: dt.datetime | None


class AuditOut(BaseModel):
    at: dt.datetime
    actor: str
    action: str
    before: dict[str, Any]
    after: dict[str, Any]
    reason: str | None


class TriageIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: FindingStatus
    reason: str | None = Field(default=None, max_length=500)


class TriageOut(BaseModel):
    id: uuid.UUID
    status: FindingStatus
    status_reason: str | None
    status_changed_at: dt.datetime | None


class DiffItem(BaseModel):
    id: uuid.UUID
    title: str
    source_type: SourceType
    severity: Severity
    location: dict[str, Any]
    status: FindingStatus
    priority: Priority | None = None
    score: float | None = None


class DiffOut(BaseModel):
    scan_id: uuid.UUID
    previous_scan_id: uuid.UUID | None
    new: list[DiffItem]
    reopened: list[DiffItem]
    fixed: list[DiffItem]


class GateOut(BaseModel):
    scan_id: uuid.UUID
    scan_status: str
    passed: bool
    policy: dict[str, Any]
    evaluated: int
    violations: list[dict[str, Any]]
