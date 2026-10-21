"""Risk model v1-cf: the blueprint's hybrid model (§14) without deployment context.

    L = geomean(applicable likelihood factors)   E, X, R
    I = mean(impact factors)                     T, D, P, C
    K = 1 + 0.05 · min(scanners agreeing - 1, 2)
    score = min(100, 100 · L · I · K)

X, R, D, P, C use the blueprint's "unknown" values until the context phases exist, so
with K = 1 this is exactly the §14.3 context-free case. Pure function: same input, same
output, and every factor is returned with its provenance.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

from riskgraph.modules.risk import tables as t
from riskgraph.shared.vocabulary import Priority, Severity, SourceType


@dataclass(frozen=True, slots=True)
class ScoreInput:
    source_type: SourceType
    severity: Severity
    category: str = "other"
    detected_by: tuple[str, ...] = ()
    # sca
    cvss_impact: float | None = None
    cvss_exploitability: float | None = None
    epss: float | None = None
    epss_status: str = "not_applicable"
    kev: bool | None = None
    kev_status: str = "not_applicable"
    # secret
    live_credential: bool = False
    # sast
    confidence: str | None = None
    # iac
    iac_family: str | None = None


@dataclass(frozen=True, slots=True)
class Factor:
    group: str  # likelihood | impact | adjustment
    name: str
    value: float
    source: str
    confidence: str
    raw_value: str | None = None
    applicable: bool = True
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ScoreResult:
    model_version: str
    likelihood: float
    impact: float
    corroboration: float
    score: float
    priority: Priority
    overrides: list[dict[str, str]]
    factors: list[Factor]


def _clamp(value: float) -> float:
    return min(1.0, max(t.FLOOR, value))


def epss_to_e(epss: float) -> float:
    """log scale: 1e-4 → 0.05 (floor), 1e-3 → 0.25, 1e-2 → 0.5, 0.1 → 0.75, 1 → 1."""
    if epss <= 0:
        return t.FLOOR
    return _clamp((math.log10(epss) + 4) / 4)


def _exploitability(inp: ScoreInput) -> Factor:
    st = inp.source_type
    if st is SourceType.SCA:
        if inp.kev:
            return Factor("likelihood", "E", 1.0, "kev", "high", "kev=true")
        if inp.epss is not None:
            return Factor(
                "likelihood", "E", epss_to_e(inp.epss), "epss", "high", f"epss={inp.epss:g}"
            )
        note = {"epss_status": inp.epss_status, "kev_status": inp.kev_status}
        if inp.cvss_exploitability is not None:
            value = _clamp(min(0.7, 0.7 * inp.cvss_exploitability / 3.9))
            raw = f"cvss_exploitability={inp.cvss_exploitability:g}"
            return Factor(
                "likelihood", "E", value, "cvss_exploitability", "medium", raw, evidence=note
            )
        value = t.E_BY_SEVERITY[inp.severity]
        return Factor(
            "likelihood", "E", value, "severity", "low", f"severity={inp.severity}", evidence=note
        )
    if st is SourceType.SECRET:
        if inp.live_credential:
            return Factor(
                "likelihood", "E", t.E_SECRET_LIVE, "secret_rule", "high", "live_credential=true"
            )
        return Factor(
            "likelihood", "E", t.E_SECRET_GENERIC, "secret_rule", "medium", "live_credential=false"
        )
    if st is SourceType.SAST:
        value = t.E_SAST[inp.severity]
        raw = f"severity={inp.severity}"
        if (inp.confidence or "").upper() == "HIGH":
            value += t.E_SAST_HIGH_CONFIDENCE_BONUS
            raw += ",confidence=HIGH"
        return Factor("likelihood", "E", _clamp(value), "sast_severity", "medium", raw)
    family = inp.iac_family or "hygiene"
    return Factor(
        "likelihood", "E", t.E_IAC.get(family, 0.25), "iac_family", "medium", f"family={family}"
    )


def _technical_impact(inp: ScoreInput) -> Factor:
    st = inp.source_type
    if st is SourceType.SCA:
        if inp.cvss_impact is not None:
            value = _clamp(inp.cvss_impact / 6.0)
            return Factor(
                "impact", "T", value, "cvss_impact", "high", f"cvss_impact={inp.cvss_impact:g}"
            )
        value = t.T_BY_SEVERITY[inp.severity]
        return Factor("impact", "T", value, "severity", "low", f"severity={inp.severity}")
    if st is SourceType.SECRET:
        return Factor("impact", "T", t.T_SECRET, "secret", "high", "credential")
    if st is SourceType.SAST:
        value = t.T_SAST.get(inp.category, t.T_SAST["other"])
        return Factor("impact", "T", value, "sast_category", "medium", f"category={inp.category}")
    family = inp.iac_family or "hygiene"
    return Factor(
        "impact", "T", t.T_IAC.get(family, 0.2), "iac_family", "medium", f"family={family}"
    )


def priority_for(score: float) -> Priority:
    for threshold, priority in t.BANDS:
        if score >= threshold:
            return priority
    return Priority.LOW


def score(inp: ScoreInput) -> ScoreResult:
    reach_applicable = inp.source_type in (SourceType.SCA, SourceType.SAST)
    likelihood_factors = [
        _exploitability(inp),
        Factor("likelihood", "X", t.UNKNOWN_EXPOSURE, "default_unknown", "low", "exposure=unknown"),
        Factor(
            "likelihood",
            "R",
            t.UNKNOWN_REACHABILITY,
            "default_unknown" if reach_applicable else "not_applicable",
            "low",
            "reachability=unknown" if reach_applicable else "n_a",
            applicable=reach_applicable,
        ),
    ]
    impact_factors = [
        _technical_impact(inp),
        Factor("impact", "D", t.UNKNOWN_DATA, "default_unknown", "low", "data=unknown"),
        Factor("impact", "P", t.UNKNOWN_PRIVILEGE, "default_unknown", "low", "privilege=unknown"),
        Factor("impact", "C", t.DEFAULT_CRITICALITY, "default", "low", "criticality=medium"),
    ]
    applicable = [f.value for f in likelihood_factors if f.applicable]
    likelihood = math.prod(applicable) ** (1 / len(applicable))
    impact = sum(f.value for f in impact_factors) / len(impact_factors)

    agreeing = max(1, len(set(inp.detected_by)))
    k = 1 + t.K_PER_EXTRA_SCANNER * min(agreeing - 1, t.K_MAX_EXTRA)
    k_factor = Factor(
        "adjustment",
        "K",
        k,
        "corroboration",
        "high",
        f"scanners={agreeing}",
        evidence={"detected_by": sorted(set(inp.detected_by))},
    )
    value = round(min(100.0, 100 * likelihood * impact * k), 2)

    priority = priority_for(value)
    overrides: list[dict[str, str]] = []
    if inp.source_type is SourceType.SCA and inp.kev and priority.rank < Priority.HIGH.rank:
        priority = Priority.HIGH
        overrides.append(
            {"rule": "kev_floor_high", "effect": "priority>=high", "reason": "listed in CISA KEV"}
        )
    if (
        inp.source_type is SourceType.SECRET
        and inp.live_credential
        and priority is not Priority.CRITICAL
    ):
        priority = Priority.CRITICAL
        overrides.append(
            {
                "rule": "live_credential_public_repo",
                "effect": "priority=critical",
                "reason": "format-validated credential in a public repository",
            }
        )

    return ScoreResult(
        model_version=t.MODEL_VERSION,
        likelihood=round(likelihood, 4),
        impact=round(impact, 4),
        corroboration=round(k, 3),
        score=value,
        priority=priority,
        overrides=overrides,
        factors=[*likelihood_factors, *impact_factors, k_factor],
    )
