"""The EvidencePack: everything an explanation may say, already computed (blueprint §15).

The LLM sees this and nothing else: no raw scanner output, no file contents. Scanner text
(titles, descriptions, remediation) is repository-influenced, so it travels only as
``untrusted_snippets``, at most five lines each, and the prompt labels it as data.

Every piece of evidence has an id (F1… factors, P1… paths, S1… snippets, plus SCORE and
FINDING) that a reason must cite. The pack's SHA-256 is the cache key.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

MAX_SNIPPET_LINES = 5
MAX_SNIPPET_CHARS = 400
MAX_PATHS = 3
MAX_FACTOR_EVIDENCE = 4
_NUMBER = re.compile(r"\d+(?:\.\d+)?")

FACTOR_NAMES = {
    "E": "exploitability",
    "X": "exposure",
    "R": "reachability",
    "T": "technical impact",
    "D": "data sensitivity",
    "P": "privilege",
    "C": "criticality",
    "K": "scanner agreement",
    "I*": "attack-path impact",
}


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class FindingEv(_Frozen):
    id: str = "FINDING"
    finding_id: str
    title: str
    source_type: str
    category: str
    severity: str
    scanners: list[str]
    file: str | None
    line: int | None
    vulnerability_id: str | None = None
    package: str | None = None
    version: str | None = None
    fixed_version: str | None = None
    cwe_ids: list[str] = Field(default_factory=list)


class ScoreEv(_Frozen):
    id: str = "SCORE"
    risk: float
    priority: str
    model_version: str
    likelihood: float
    impact: float
    effective_impact: float | None = None
    overrides: list[str] = Field(default_factory=list)


class FactorEv(_Frozen):
    id: str
    name: str
    meaning: str
    value: float
    label: str | None
    source: str
    confidence: str
    applicable: bool
    evidence: dict[str, str] = Field(default_factory=dict)


class PathEv(_Frozen):
    id: str
    label: str
    probability: float
    score: float
    sink: str
    hops: int
    # ADR-0017: the weakest edge's level; "hypothesis" paths are unproven
    assurance: str | None = None


class SnippetEv(_Frozen):
    id: str
    origin: str  # "scanner title", "scanner description", "scanner remediation"
    text: str


class EvidencePack(_Frozen):
    finding: FindingEv
    score: ScoreEv
    factors: list[FactorEv]
    paths: list[PathEv] = Field(default_factory=list)
    untrusted_snippets: list[SnippetEv] = Field(default_factory=list)

    def canonical_json(self) -> str:
        return self.model_dump_json()  # field order is fixed by the model, so this is stable

    def digest(self) -> str:
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()

    def ids(self) -> dict[str, str]:
        """Evidence id → a short human label (the UI shows these next to each reason)."""
        out = {"FINDING": "the finding", "SCORE": f"risk score {self.score.risk:g}"}
        out.update({f.id: f"{f.meaning} ({f.source})" for f in self.factors})
        out.update({p.id: p.label for p in self.paths})
        out.update({s.id: s.origin for s in self.untrusted_snippets})
        return out

    def numbers(self) -> set[str]:
        """Every number the evidence states, in the spellings an explanation may use."""
        text = self.canonical_json()
        found: set[str] = set()
        for raw in _NUMBER.findall(text):
            found |= spellings(float(raw))
        return found


def spellings(value: float) -> set[str]:
    """0.9 → {"0.9", "0.90", "90", "90.0"}: decimals, two places, and as a percentage."""
    out = {norm(value), norm(round(value, 2)), norm(round(value, 1)), norm(round(value))}
    if 0 <= value <= 1:
        pct = value * 100
        out |= {norm(round(pct, 1)), norm(round(pct))}
    return out


def norm(value: float) -> str:
    text = f"{value:.6f}".rstrip("0").rstrip(".")
    return text or "0"


def clip_lines(text: str | None) -> str | None:
    if not text:
        return None
    lines = [ln.rstrip() for ln in text.strip().splitlines() if ln.strip()][:MAX_SNIPPET_LINES]
    return "\n".join(lines)[:MAX_SNIPPET_CHARS] or None


def factor_evidence(evidence: dict[str, Any]) -> dict[str, str]:
    """A few scalar evidence entries per factor, as short strings (no nested scanner data)."""
    out: dict[str, str] = {}
    for key, value in evidence.items():
        if len(out) >= MAX_FACTOR_EVIDENCE:
            break
        if isinstance(value, (str, int, float, bool)):
            out[str(key)[:40]] = str(value)[:120]
        elif isinstance(value, list) and all(isinstance(v, str) for v in value):
            out[str(key)[:40]] = " → ".join(value)[:200]
    return out
