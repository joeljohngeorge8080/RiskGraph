"""A finding's own evidence (ADR-0017): what each scanner reported, and what reachability found.

Pure. One ``*_match`` record per member of the merged finding (one per scanner rule hit),
verified because the scanner's report states it, linked to that scanner's stored raw
report. Plus one ``reachability`` record when the analyzer made a claim: L3 is verified
(a call chain in parsed code); L0-L2 are inferred (import-level rules with known gaps);
unknown and n/a make no claim and get no record.

Runtime end-of-life findings (X2) get an ``eol`` record: the declaration is in the file
and the end date in the endoflife.date feed, so it is verified; ``data_as_of`` is the
feed's fetch time. Scanner matches carry their advisory data date when it is known
(Trivy's DB build time). Packages found in an image (X2 part 2) are ``image_package``
records with the image named; their report is stored apart from the run's report.

A hit of RiskGraph's own tier-1 taint rules (X4, ADR-0021) is a ``taint_flow`` record with
the trace's ordered steps (file and line only). It is inferred: a rule applied to parsed
code inside one function, with a catalogue that can miss sanitizers.

Facts are small and display-safe: rule, severity, package coordinates, secret family.
Never a snippet, a secret or the scanner's free-form evidence.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Mapping
from typing import Any

from riskgraph.modules.evidence import Assurance, Evidence, FlowStep, RawRef, make_evidence
from riskgraph.modules.normalization import Location, MergedFinding, RawFinding
from riskgraph.modules.reachability import ANALYZER_VERSION, Verdict
from riskgraph.shared.vocabulary import ReachabilityTier, SourceType

_KIND = {
    SourceType.SCA: "package_match",
    SourceType.SAST: "code_match",
    SourceType.SECRET: "secret_match",
    SourceType.IAC: "misconfig",
    SourceType.RUNTIME: "eol",
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
    data_as_of: Mapping[str, dt.datetime | None] | None = None,
) -> list[Evidence]:
    """``data_as_of`` maps a scanner to the build time of the advisory data it used."""
    out = [
        _match(member, run_ids, versions, now, (data_as_of or {}).get(member.scanner.value))
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
    as_of: dt.datetime | None = None,
) -> Evidence:
    scanner = f.scanner.value
    facts: dict[str, Any] = {"rule_id": f.rule_id, "severity": f.severity.value}
    confidence = "medium"
    image = (f.package or {}).get("image")
    if f.source_type is SourceType.SCA:
        pkg = f.package or {}
        facts |= {
            "vulnerability_id": f.vulnerability_id,
            "package": pkg.get("name"),
            "version": pkg.get("version"),
            "fixed_version": pkg.get("fixed_version"),
            "ecosystem": pkg.get("ecosystem"),
            "image": image,
        }
        confidence = "high"  # an exact installed version inside an advisory range
    elif f.source_type is SourceType.SECRET:
        facts["family"] = f.attrs.get("secret_family")
        confidence = "high" if f.attrs.get("live_credential") else "medium"
    elif f.source_type is SourceType.SAST:
        own = str(f.attrs.get("confidence") or "").lower()
        confidence = own if own in ("high", "medium", "low") else "medium"
    elif f.source_type is SourceType.RUNTIME:
        pkg = f.package or {}
        facts |= {
            "advisory": f.attrs.get("advisory"),
            "product": pkg.get("name"),
            "cycle": pkg.get("version"),
            "fixed_version": pkg.get("fixed_version"),
            "eol_date": f.attrs.get("eol_date"),
            "declared_by": f.attrs.get("declared_by"),
            "image": image,
        }
        confidence = "high"
        as_of = _parse_time(f.attrs.get("data_as_of")) or as_of
    elif f.location.resource:
        facts["resource"] = f.location.resource
    run_id = run_ids.get(scanner)
    # an image's report is stored on its own, not as the run's report: no raw pointer
    own_report = run_id and f.source_type is not SourceType.RUNTIME and not image
    kind = "image_package" if image and f.source_type is SourceType.SCA else _KIND[f.source_type]
    assurance = Assurance.VERIFIED
    steps: list[FlowStep] = []
    if f.attrs.get("analysis") == "intraprocedural":
        kind, assurance = "taint_flow", Assurance.INFERRED
        facts["analysis"] = "intraprocedural"
        steps = [
            FlowStep(Location(s["file"], s["line"], s["line"]), s["role"])
            for s in f.attrs.get("taint_steps") or []
        ]
    return make_evidence(
        producer=f"{scanner}@{versions.get(scanner) or 'unknown'}",
        kind=kind,
        assurance=assurance,
        confidence=confidence,  # type: ignore[arg-type]
        observed_at=now,
        locations=(f.location,),
        facts={k: v for k, v in facts.items() if v is not None},
        steps=steps,
        raw=RawRef(run_id, "") if own_report and run_id else None,
        data_as_of=as_of,
    )


def _parse_time(value: object) -> dt.datetime | None:
    if isinstance(value, str):
        try:
            return dt.datetime.fromisoformat(value)
        except ValueError:
            return None
    return None


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
