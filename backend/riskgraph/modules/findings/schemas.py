"""API schemas for findings and their risk breakdown."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from pydantic import BaseModel

from riskgraph.shared.vocabulary import Priority, ScannerName, Severity, SourceType


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
    status: str
    first_seen_at: dt.datetime
    last_seen_at: dt.datetime
    occurrences: list[OccurrenceOut]
    risk: RiskScoreOut | None
    vulnerability: VulnerabilityOut | None
