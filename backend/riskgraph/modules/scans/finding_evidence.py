"""A finding's own evidence (ADR-0017): what each scanner reported, and what reachability found.

Pure. One ``*_match`` record per member of the merged finding (one per scanner rule hit),
verified because the scanner's report states it, linked to that scanner's stored raw
report. Plus one ``reachability`` record when the analyzer made a claim: L3 is verified
(a call chain in parsed code); L0-L2 are inferred (import-level rules with known gaps);
unknown and n/a make no claim and get no record.

Facts are small and display-safe: rule, severity, package coordinates, secret family.
Never a snippet, a secret or the scanner's free-form evidence.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Mapping
from typing import Any

from riskgraph.modules.evidence import Assurance, Evidence, RawRef, make_evidence
from riskgraph.modules.normalization import MergedFinding, RawFinding
from riskgraph.modules.reachability import ANALYZER_VERSION, Verdict
from riskgraph.shared.vocabulary import ReachabilityTier, SourceType

_KIND = {
    SourceType.SCA: "package_match",
    SourceType.SAST: "code_match",
    SourceType.SECRET: "secret_match",
    SourceType.IAC: "misconfig",
}
_REACH_ASSURANCE = {
    ReachabilityTier.L3: Assurance.VERIFIED,
    ReachabilityTier.L2: Assurance.INFERRED,
    ReachabilityTier.L1: Assurance.INFERRED,
    ReachabilityTier.L0: Assurance.INFERRED,
}


def finding_evidence(
    merged: MergedFinding,
    verdict: Verdict | None,
    run_ids: Mapping[str, uuid.UUID],
    versions: Mapping[str, str | None],
    now: dt.datetime,
) -> list[Evidence]:
    out = [
        _match(member, run_ids, versions, now)
        for member in merged.members
        if member.source_type in _KIND
    ]
    if verdict is not None and verdict.tier in _REACH_ASSURANCE:
        out.append(_reachability(merged, verdict, now))
    return out


def _match(
    f: RawFinding,
    run_ids: Mapping[str, uuid.UUID],
    versions: Mapping[str, str | None],
    now: dt.datetime,
) -> Evidence:
    scanner = f.scanner.value
    facts: dict[str, Any] = {"rule_id": f.rule_id, "severity": f.severity.value}
    confidence = "medium"
    if f.source_type is SourceType.SCA:
        pkg = f.package or {}
        facts |= {
            "vulnerability_id": f.vulnerability_id,
            "package": pkg.get("name"),
            "version": pkg.get("version"),
            "fixed_version": pkg.get("fixed_version"),
            "ecosystem": pkg.get("ecosystem"),
        }
        confidence = "high"  # an exact installed version inside an advisory range
    elif f.source_type is SourceType.SECRET:
        facts["family"] = f.attrs.get("secret_family")
        confidence = "high" if f.attrs.get("live_credential") else "medium"
    elif f.source_type is SourceType.SAST:
        own = str(f.attrs.get("confidence") or "").lower()
        confidence = own if own in ("high", "medium", "low") else "medium"
    elif f.location.resource:
        facts["resource"] = f.location.resource
    run_id = run_ids.get(scanner)
    return make_evidence(
        producer=f"{scanner}@{versions.get(scanner) or 'unknown'}",
        kind=_KIND[f.source_type],
        assurance=Assurance.VERIFIED,
        confidence=confidence,  # type: ignore[arg-type]
        observed_at=now,
        locations=(f.location,),
        facts={k: v for k, v in facts.items() if v is not None},
        raw=RawRef(run_id, "") if run_id else None,
    )


def _reachability(merged: MergedFinding, verdict: Verdict, now: dt.datetime) -> Evidence:
    facts: dict[str, Any] = {"tier": verdict.tier.value}
    for key, value in verdict.evidence.items():
        if _plain(value):
            facts[key] = value
    confidence = verdict.confidence if verdict.confidence in ("high", "medium", "low") else "low"
    return make_evidence(
        producer=f"riskgraph.reachability@{ANALYZER_VERSION}",
        kind="reachability",
        assurance=_REACH_ASSURANCE[verdict.tier],
        confidence=confidence,  # type: ignore[arg-type]
        observed_at=now,
        locations=(merged.location,),
        facts=facts,
    )


def _plain(value: object) -> bool:
    """What a fact may hold; anything else in a verdict is display detail, left out."""
    if value is None or isinstance(value, str | int | float | bool):
        return True
    return isinstance(value, list | tuple) and all(isinstance(v, str) for v in value)
