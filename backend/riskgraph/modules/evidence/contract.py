"""The evidence and assurance contract (ADR-0017, expansion plan §2.4).

Every fact the graph and the scores rest on is an ``Evidence`` record with a stable id, a
producer, an assurance level and, where it has one, a pointer into the stored raw report.
Every graph edge is a ``Relationship`` that names the evidence it rests on.

Assurance says what kind of support a claim has; confidence grades it within that level:
- verified: stated by an artifact we parsed (a manifest declaration, a scanner match, an
  L3 call chain);
- inferred: a documented rule applied to verified facts, with a known gap (import-level
  reachability, a name match between manifest and Kubernetes);
- hypothesis: a pattern suggests it and no artifact supports it (a credential family that
  matches an identity with no link proving the key belongs to it).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal

from riskgraph.modules.normalization import Location

MAX_STEPS = 50
MAX_FACTS = 24
MAX_FACT_KEY = 64
MAX_FACT_TEXT = 200
MAX_FACT_LIST = 20

Confidence = Literal["high", "medium", "low"]
FactValue = str | int | float | bool | None | tuple[str, ...]

# Kinds named in the plan (§2.4) plus the four X1 needs for today's findings.
KINDS = frozenset(
    {
        "declaration",  # the manifest states it
        "package_match",  # a scanner matched an installed version to an advisory
        "code_match",  # a SAST rule matched code
        "secret_match",  # a secret scanner matched a credential
        "misconfig",  # an IaC check failed
        "reachability",  # the reachability analyzer's tier and chain
        "taint_flow",
        "route",
        "auth_guard",
        "rbac_binding",
        "runtime_version",
        "image_package",
        "eol",
    }
)


class Assurance(StrEnum):
    VERIFIED = "verified"
    INFERRED = "inferred"
    HYPOTHESIS = "hypothesis"

    @property
    def rank(self) -> int:
        return _RANK[self]


_RANK = {Assurance.VERIFIED: 2, Assurance.INFERRED: 1, Assurance.HYPOTHESIS: 0}


def min_assurance(levels: Iterable[Assurance]) -> Assurance:
    """A chain is only as assured as its weakest link."""
    found = list(levels)
    if not found:
        raise ValueError("min_assurance of nothing")
    return min(found, key=lambda a: a.rank)


@dataclass(frozen=True, slots=True)
class RawRef:
    """Where in the stored raw report this came from. ``""`` is the whole report (RFC 6901)."""

    scanner_run_id: uuid.UUID
    pointer: str


@dataclass(frozen=True, slots=True)
class FlowStep:
    location: Location
    label: str


@dataclass(frozen=True, slots=True)
class Evidence:
    """Build with ``make_evidence``, which validates and computes the id."""

    id: str
    producer: str
    kind: str
    assurance: Assurance
    confidence: Confidence
    locations: tuple[Location, ...]
    facts: Mapping[str, FactValue]
    observed_at: dt.datetime
    steps: tuple[FlowStep, ...] = ()
    raw: RawRef | None = None
    data_as_of: dt.datetime | None = None

    def payload(self) -> dict[str, object]:
        """What is stored as JSONB and hashed into the id (time fields are separate)."""
        return {
            "producer": self.producer,
            "kind": self.kind,
            "assurance": self.assurance.value,
            "confidence": self.confidence,
            "locations": [loc.as_dict() for loc in self.locations],
            "facts": {k: list(v) if isinstance(v, tuple) else v for k, v in self.facts.items()},
            "steps": [{"location": s.location.as_dict(), "label": s.label} for s in self.steps],
        }


def make_evidence(
    *,
    producer: str,
    kind: str,
    assurance: Assurance,
    confidence: Confidence,
    observed_at: dt.datetime,
    locations: Iterable[Location] = (),
    facts: Mapping[str, object] | None = None,
    steps: Iterable[FlowStep] = (),
    raw: RawRef | None = None,
    data_as_of: dt.datetime | None = None,
) -> Evidence:
    if kind not in KINDS:
        raise ValueError(f"unknown evidence kind {kind!r}")
    if confidence not in ("high", "medium", "low"):
        raise ValueError(f"unknown confidence {confidence!r}")
    draft = Evidence(
        id="",
        producer=producer[:96],
        kind=kind,
        assurance=assurance,
        confidence=confidence,
        locations=tuple(locations),
        facts=_facts(facts or {}),
        observed_at=observed_at,
        steps=tuple(steps)[:MAX_STEPS],
        raw=raw,
        data_as_of=data_as_of,
    )
    canonical = json.dumps(draft.payload(), sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    return Evidence(
        id=digest,
        producer=draft.producer,
        kind=draft.kind,
        assurance=draft.assurance,
        confidence=draft.confidence,
        locations=draft.locations,
        facts=draft.facts,
        observed_at=draft.observed_at,
        steps=draft.steps,
        raw=draft.raw,
        data_as_of=draft.data_as_of,
    )


def _facts(raw: Mapping[str, object]) -> dict[str, FactValue]:
    out: dict[str, FactValue] = {}
    for key, value in list(raw.items())[:MAX_FACTS]:
        if not isinstance(key, str) or not key or len(key) > MAX_FACT_KEY:
            raise ValueError(f"fact key {key!r} must be a short string")
        out[key] = _fact(key, value)
    return out


def _fact(key: str, value: object) -> FactValue:
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        return value[:MAX_FACT_TEXT]
    if isinstance(value, list | tuple) and all(isinstance(v, str) for v in value):
        return tuple(v[:MAX_FACT_TEXT] for v in value[:MAX_FACT_LIST])
    raise ValueError(f"fact {key!r} must be a scalar or a list of strings")


@dataclass(frozen=True, slots=True)
class Relationship:
    """A graph edge and the evidence it rests on. No evidence, no edge."""

    source: str
    target: str
    kind: str
    assurance: Assurance
    evidence_ids: tuple[str, ...]
    p: float | None = None  # attacker transition probability, attack edges only
    findings: tuple[int, ...] = field(default=())  # merged-list indices, for I* and the API

    def __post_init__(self) -> None:
        if not self.evidence_ids:
            raise ValueError(f"{self.kind} {self.source} -> {self.target} has no evidence")
