"""Score merged findings and persist scores with their factors."""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import replace
from decimal import Decimal

from sqlalchemy.orm import Session

from riskgraph.modules.context import FindingContext, Observed, VulnIntel
from riskgraph.modules.normalization import MergedFinding
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
    )


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
