"""Risk model v2: the blueprint's hybrid model (§14) with deployment context.

    L = geomean(applicable likelihood factors)   E, X, R
    I = mean(impact factors)                     T, D, P, C
    K = 1 + 0.05 · min(scanners agreeing - 1, 2)
    score = min(100, 100 · L · I · K)

X, D, P and C come from ``ScoreInput.context`` (manifest, repository visibility), R from
``ScoreInput.reachability`` (L0/L1/L2), and each falls back to the blueprint's "unknown"
value. When the finding is evidence on an attack path, I is raised to the path's
effective impact (§14.4, adjustment factor ``I*``). With no context, no reachability and
K = 1 this is exactly the §14.3 context-free case. v2 (ADR-0024) adds factor rows for
image packages, taint flows, runtime end-of-life and authorization findings; without
those inputs it scores exactly as v1-ctx.3. Pure function: same input, same
output, and every factor is returned with its provenance.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

from riskgraph.modules.context import FindingContext, Observed
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
    # authz (X5): the finding's assurance; a hypothesis is capped at Low (ADR-0023)
    assurance: str | None = None
    # v2 (ADR-0024); each default means "absent", and then the v1 factors apply
    image_package: bool = False  # installed in a container image: R not assessable
    taint_cwe: str | None = None  # CWE class of a tier-1 taint flow at this finding
    taint_confidence: str | None = None  # that taint rule's confidence
    eol_age_days: int | None = None  # runtime EOL: days from end of support to the data
    # deployment context; None means "nothing known" (all defaults)
    context: FindingContext | None = None
    # reachability tier (sca/sast) with provenance; None = not analysed
    reachability: Observed | None = None
    # §14.4: impact implied by an attack path this finding is evidence on
    effective_impact: EffectiveImpact | None = None


@dataclass(frozen=True, slots=True)
class EffectiveImpact:
    value: float  # I(sink) · P(path | this finding's edge = 1)
    path: str  # attack path label, e.g. "internet → app → app-role → users-db"
    sink: str
    probability: float


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
    effective_impact: float | None = None

    def factor(self, name: str) -> Factor | None:
        return next((f for f in self.factors if f.name == name), None)

    @property
    def exploit_likelihood(self) -> float:
        """geomean(E, R) of a code finding: its attack-graph edge probability (§13.1)."""
        e = self.factor("E")
        r = self.factor("R")
        values = [f.value for f in (e, r) if f is not None and f.applicable]
        return math.prod(values) ** (1 / len(values)) if values else 0.0


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
        sast = Factor("likelihood", "E", _clamp(value), "sast_severity", "medium", raw)
        flow = _taint_exploitability(inp)
        return flow if flow is not None and flow.value > sast.value else sast
    if st is SourceType.RUNTIME:
        return _eol_exploitability(inp.eol_age_days)
    if st is SourceType.AUTHZ:
        raw = f"severity={inp.severity},assurance={inp.assurance or 'unknown'}"
        return Factor("likelihood", "E", t.E_AUTHZ_INFERRED[inp.severity], "authz", "low", raw)
    family = inp.iac_family or "hygiene"
    return Factor(
        "likelihood", "E", t.E_IAC.get(family, 0.25), "iac_family", "medium", f"family={family}"
    )


def _taint_exploitability(inp: ScoreInput) -> Factor | None:
    """E of a tier-1 taint flow by CWE class and rule confidence (ADR-0024), if any."""
    if inp.taint_cwe is None:
        return None
    confidence = (inp.taint_confidence or "").upper()
    value = t.E_TAINT.get(inp.taint_cwe, {}).get(confidence)
    if value is None:
        return None
    raw = f"{inp.taint_cwe},analysis=intraprocedural,confidence={confidence}"
    # tier 1 is inferred (a rule applied to parsed code), never verified (ADR-0021)
    return Factor("likelihood", "E", value, "taint_tier1", "medium", raw)


def _eol_exploitability(age_days: int | None) -> Factor:
    """E of an end-of-life runtime by the time since its end of support (ADR-0024)."""
    if age_days is None or age_days < 0:
        return Factor("likelihood", "E", t.E_RUNTIME_EOL, "runtime_eol", "low", "eol=true")
    value = next(v for days, v in t.E_RUNTIME_EOL_BY_AGE if age_days >= days)
    return Factor("likelihood", "E", value, "runtime_eol", "medium", f"eol_age_days={age_days}")


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
    if st is SourceType.RUNTIME:
        return Factor("impact", "T", t.T_RUNTIME_EOL, "runtime_eol", "low", "no security fixes")
    if st is SourceType.AUTHZ:
        value = t.T_SAST[t.AUTHZ_CATEGORY]
        return Factor("impact", "T", value, "authz", "low", f"category={t.AUTHZ_CATEGORY}")
    family = inp.iac_family or "hygiene"
    return Factor(
        "impact", "T", t.T_IAC.get(family, 0.2), "iac_family", "medium", f"family={family}"
    )


def _context_factor(
    group: str,
    name: str,
    observed: Observed | None,
    values: dict[str, float],
    default: tuple[float, str, str],
) -> Factor:
    """A context factor from an observation, or the blueprint default with its label."""
    if observed is not None and observed.label in values:
        evidence = {k: v for k, v in observed.evidence.items() if v is not None}
        return Factor(
            group,
            name,
            values[observed.label],
            observed.source,
            observed.confidence,
            observed.label,
            evidence=evidence,
        )
    value, source, raw = default
    return Factor(group, name, value, source, "low", raw)


def priority_for(score: float) -> Priority:
    for threshold, priority in t.BANDS:
        if score >= threshold:
            return priority
    return Priority.LOW


def score(inp: ScoreInput) -> ScoreResult:
    reach_applicable = inp.source_type in (SourceType.SCA, SourceType.SAST)
    ctx = inp.context or FindingContext()
    exposure = _context_factor(
        "likelihood",
        "X",
        ctx.exposure,
        t.X_VALUES,
        (t.UNKNOWN_EXPOSURE, "default_unknown", "exposure=unknown"),
    )
    likelihood_factors = [
        _exploitability(inp),
        exposure,
        _reachability_factor(inp, reach_applicable),
    ]
    impact_factors = [
        _technical_impact(inp),
        _context_factor(
            "impact",
            "D",
            ctx.data,
            t.D_VALUES,
            (t.UNKNOWN_DATA, "default_unknown", "data=unknown"),
        ),
        _context_factor(
            "impact",
            "P",
            ctx.privilege,
            t.P_VALUES,
            (t.UNKNOWN_PRIVILEGE, "default_unknown", "privilege=unknown"),
        ),
        _context_factor(
            "impact",
            "C",
            ctx.criticality,
            t.C_VALUES,
            (t.DEFAULT_CRITICALITY, "default", "criticality=medium"),
        ),
    ]
    applicable = [f.value for f in likelihood_factors if f.applicable]
    likelihood = math.prod(applicable) ** (1 / len(applicable))
    impact = sum(f.value for f in impact_factors) / len(impact_factors)
    used_impact = impact
    adjustments: list[Factor] = []
    eff = inp.effective_impact
    if eff is not None and eff.value > impact:
        used_impact = min(1.0, eff.value)
        adjustments.append(
            Factor(
                "adjustment",
                "I*",
                used_impact,
                "attack_path",
                "medium",
                f"sink={eff.sink}",
                evidence={"path": eff.path, "path_probability": round(eff.probability, 5)},
            )
        )

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
    value = round(min(100.0, 100 * likelihood * used_impact * k), 2)

    priority = priority_for(value)
    overrides: list[dict[str, str]] = []
    isolated = ctx.exposure is not None and ctx.exposure.label == "isolated"
    if (
        inp.source_type is SourceType.SCA
        and inp.kev
        and not isolated
        and priority.rank < Priority.HIGH.rank
    ):
        priority = Priority.HIGH
        overrides.append(
            {"rule": "kev_floor_high", "effect": "priority>=high", "reason": "listed in CISA KEV"}
        )
    reach = inp.reachability
    if (
        reach is not None
        and reach.label == "L0"
        and reach.confidence == "high"
        and not inp.kev  # a KEV floor wins: exploited in the wild beats "not imported"
        and priority.rank > Priority.MEDIUM.rank
    ):
        priority = Priority.MEDIUM
        overrides.append(
            {
                "rule": "not_imported_ceiling_medium",
                "effect": "priority<=medium",
                "reason": "dependency is never imported (L0, high confidence)",
            }
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

    hypothesis = inp.source_type is SourceType.AUTHZ and inp.assurance == "hypothesis"
    if hypothesis and (value > t.AUTHZ_SCORE_CEILING or priority is not Priority.LOW):
        value = min(value, t.AUTHZ_SCORE_CEILING)
        priority = Priority.LOW
        overrides.append(
            {
                "rule": "hypothesis_ceiling_low",
                "effect": "priority<=low",
                "reason": "a pattern suggests it and no artifact supports it (test it)",
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
        factors=[*likelihood_factors, *impact_factors, k_factor, *adjustments],
        effective_impact=round(used_impact, 4) if adjustments else None,
    )


def _reachability_factor(inp: ScoreInput, applicable: bool) -> Factor:
    if not applicable:
        return Factor(
            "likelihood",
            "R",
            t.UNKNOWN_REACHABILITY,
            "not_applicable",
            "low",
            "n_a",
            applicable=False,
        )
    if inp.image_package:
        # the code that uses an image's packages is not analysed (X2, ADR-0024)
        return Factor("likelihood", "R", t.R_NOT_ASSESSABLE, "not_assessable", "low", "n_a")
    obs = inp.reachability
    if obs is not None and obs.label in t.R_VALUES:
        evidence = {k: v for k, v in obs.evidence.items() if v is not None}
        return Factor(
            "likelihood",
            "R",
            t.R_VALUES[obs.label],
            obs.source,
            obs.confidence,
            obs.label,
            evidence=evidence,
        )
    return Factor(
        "likelihood",
        "R",
        t.UNKNOWN_REACHABILITY,
        "default_unknown" if obs is None else obs.source,
        "low",
        "reachability=unknown",
        evidence=dict(obs.evidence) if obs is not None else {},
    )
