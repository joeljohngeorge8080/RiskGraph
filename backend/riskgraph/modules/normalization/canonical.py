"""Canonical finding model shared by all scanner parsers (blueprint §10.1).

Parsers turn a scanner's native JSON into ``RawFinding`` objects; nothing downstream
ever looks at scanner-native shapes again. Paths in a ``Location`` are opaque strings
from scanner output: they are displayed and hashed, never opened (CLAUDE.md).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from riskgraph.shared.vocabulary import ScannerName, Severity, SourceType


@dataclass(frozen=True, slots=True)
class Location:
    file: str
    line_start: int | None = None
    line_end: int | None = None
    resource: str | None = None

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"file": self.file}
        if self.line_start is not None:
            out["line_start"] = self.line_start
            out["line_end"] = self.line_end if self.line_end is not None else self.line_start
        if self.resource:
            out["resource"] = self.resource
        return out

    def overlaps(self, other: Location) -> bool:
        if self.line_start is None or other.line_start is None:
            return False
        a_end = self.line_end or self.line_start
        b_end = other.line_end or other.line_start
        return self.line_start <= b_end and other.line_start <= a_end


@dataclass(slots=True)
class RawFinding:
    """One native scanner result, already mapped to the canonical vocabulary."""

    scanner: ScannerName
    source_type: SourceType
    rule_id: str
    title: str
    severity: Severity
    location: Location
    category: str
    scanner_severity: str | None = None
    description: str | None = None
    cwe_ids: tuple[str, ...] = ()
    vulnerability_id: str | None = None
    # sca only: {name, version, purl, ecosystem, fixed_version}
    package: dict[str, Any] | None = None
    # sca only: {version, vector, base, source} as reported by the scanner
    cvss: dict[str, Any] | None = None
    remediation: str | None = None
    # Small, redacted, display-only details. Never a source snippet or a secret.
    evidence: dict[str, Any] = field(default_factory=dict)
    # Inputs for fingerprinting, merging and scoring (see normalization.fingerprint,
    # normalization.merge and risk.model): secret_hmac, secret_family, live_credential,
    # iac_topic, iac_family, confidence, impact, snippet_sha256.
    attrs: dict[str, Any] = field(default_factory=dict)
    fingerprint: str = ""
