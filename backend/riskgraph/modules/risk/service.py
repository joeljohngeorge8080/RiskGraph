"""Score merged findings and persist scores with their factors."""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import replace
from decimal import Decimal

from sqlalchemy.orm import Session

from riskgraph.modules.context import FindingContext, Observed, VulnIntel
from riskgraph.modules.normalization import MergedFinding, families
from riskgraph.modules.risk.model import EffectiveImpact, ScoreInput, ScoreResult, score
from riskgraph.modules.risk.models import RiskFactor, RiskScore
from riskgraph.shared.vocabulary import SourceType


def input_for(
    merged: MergedFinding,
    intel: VulnIntel | None,
    context: FindingContext | None = None,
    reachability: Observed | None = None,
) -> ScoreInput:
    rep = merged.representative
    attrs = merged.attrs
    taint_cwe, taint_confidence = _taint(merged)
    return ScoreInput(
        source_type=merged.source_type,
        severity=merged.severity,
        category=rep.category,
        detected_by=merged.detected_by,
        cvss_impact=intel.cvss_impact if intel else None,
        cvss_exploitability=intel.cvss_exploitability if intel else None,
        epss=intel.epss if intel else None,
        epss_status=intel.epss_status if intel else "not_applicable",
        kev=intel.kev if intel else None,
        kev_status=intel.kev_status if intel else "not_applicable",
        live_credential=bool(attrs.get("live_credential")),
        confidence=attrs.get("confidence"),
        iac_family=attrs.get("iac_family"),
        assurance=attrs.get("assurance") if merged.source_type is SourceType.AUTHZ else None,
        context=context,
        reachability=reachability,
        image_package=bool((rep.package or {}).get("image")),
        taint_cwe=taint_cwe,
        taint_confidence=taint_confidence,
        eol_age_days=_eol_age(attrs) if merged.source_type is SourceType.RUNTIME else None,
    )


_CONFIDENCE_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def _taint(merged: MergedFinding) -> tuple[str | None, str | None]:
    """CWE class and rule confidence of the best tier-1 taint hit in a finding (ADR-0024).

    Read from the members: after a merge the representative is usually the generic rule
    (ADR-0021), whose attrs say nothing about the flow.
    """
    hits: list[tuple[int, str, str | None]] = []
    for m in merged.members:
        if m.attrs.get("analysis") != "intraprocedural":
            continue
        cwe = next((c for c in map(families.taint_family, m.cwe_ids) if c is not None), None)
        if cwe is None:
            continue
        confidence = str(m.attrs.get("confidence") or "").upper() or None
        hits.append((_CONFIDENCE_ORDER.get(confidence or "", 3), cwe, confidence))
    if not hits:
        return None, None
    _, cwe, confidence = min(hits)
    return cwe, confidence


def _eol_age(attrs: dict[str, object]) -> int | None:
    """Days from the end of support to the feed snapshot the finding was made from.

    The snapshot time, not the clock: a replay of the same data gives the same score. A
    missing or unreadable date means "unknown" and the model's dateless row applies.
    """
    eol, as_of = attrs.get("eol_date"), attrs.get("data_as_of")
    if not isinstance(eol, str) or not isinstance(as_of, str):
        return None
    try:
        end = dt.date.fromisoformat(eol)
        seen = dt.datetime.fromisoformat(as_of).date()
    except ValueError:
        return None
    return (seen - end).days


def score_finding(
    merged: MergedFinding,
    intel: VulnIntel | None,
    context: FindingContext | None = None,
    reachability: Observed | None = None,
) -> ScoreResult:
    return score(input_for(merged, intel, context, reachability))


def rescore(inp: ScoreInput, effective: EffectiveImpact) -> ScoreResult:
    """Second pass (§14.4): the same input with the attack path's effective impact."""
    return score(replace(inp, effective_impact=effective))


def persist_score(
    session: Session, scan_id: uuid.UUID, finding_id: uuid.UUID, result: ScoreResult
) -> RiskScore:
    row = RiskScore(
        scan_job_id=scan_id,
        finding_id=finding_id,
        model_version=result.model_version,
        likelihood=Decimal(str(result.likelihood)),
        impact=Decimal(str(result.impact)),
        corroboration=Decimal(str(result.corroboration)),
        effective_impact=(
            Decimal(str(result.effective_impact)) if result.effective_impact is not None else None
        ),
        score=Decimal(str(result.score)),
        priority=result.priority,
        priority_rank=result.priority.rank,
        overrides=result.overrides,
        computed_at=dt.datetime.now(dt.UTC),
    )
    session.add(row)
    session.flush()
    session.add_all(
        RiskFactor(
            risk_score_id=row.id,
            group=f.group,
            name=f.name,
            value=Decimal(str(round(f.value, 4))),
            raw_value=f.raw_value,
            source=f.source,
            confidence=f.confidence,
            applicable=f.applicable,
            evidence=f.evidence,
        )
        for f in result.factors
    )
    return row
