"""Deterministic fallback explanation, built from the same evidence (blueprint §15).

Always available: used when no model is configured, the model is unreachable, or its
answer fails validation twice. It only restates evidence, so it always validates.
"""

from __future__ import annotations

from riskgraph.modules.explain.draft import MAX_REASONS, ExplanationDraft, Reason
from riskgraph.modules.explain.evidence import EvidencePack, FactorEv

DEFAULT_SOURCES = frozenset({"default", "default_unknown", "not_applicable"})
_IMPACT_FACTORS = ("T", "D", "P", "C", "I*")


def _phrase(f: FactorEv) -> str:
    label = (f.label or "").replace("_", " ")
    shown = label if label and "=" not in label else f"{f.value:g}"
    return f"{f.meaning} is {shown}, from {f.source.replace('_', ' ')} ({f.confidence} confidence)"


def explain(pack: EvidencePack) -> ExplanationDraft:
    s, fnd = pack.score, pack.finding
    informative = [f for f in pack.factors if f.applicable and f.source not in DEFAULT_SOURCES]
    defaults = [f for f in pack.factors if f.applicable and f.source in DEFAULT_SOURCES]
    # strongest evidence first: the factors furthest from the neutral 0.5
    informative.sort(key=lambda f: -abs(f.value - 0.5))
    reasons = [
        Reason(claim=_phrase(f)[:400], evidence_ids=[f.id]) for f in informative[: MAX_REASONS - 1]
    ]
    if pack.paths:
        p = pack.paths[0]
        claim = (
            f"It may lie on the attack path {p.label}; that path is a hypothesis to verify."
            if p.assurance == "hypothesis"
            else f"It lies on the attack path {p.label}."
        )
        reasons.append(Reason(claim=claim[:400], evidence_ids=[p.id]))
    if not reasons:
        reasons.append(
            Reason(claim="No deployment context is known for it.", evidence_ids=["SCORE"])
        )

    where = f" in {fnd.file}" if fnd.file else ""
    summary = (
        f"{fnd.title[:160]}{where} has risk {s.risk:g} and is {s.priority} priority "
        f"under model {s.model_version}."
    )
    impact_parts = [_phrase(f) for f in pack.factors if f.name in _IMPACT_FACTORS and f.applicable]
    impact = "; ".join(impact_parts[:3]) + "." if impact_parts else "Impact factors are unknown."
    caveats = (
        "Unknown factors use neutral defaults: " + ", ".join(f.meaning for f in defaults) + "."
        if defaults
        else ""
    )
    return ExplanationDraft(
        summary=summary,
        reasons=reasons[:MAX_REASONS],
        impact=impact[:600],
        remediation_steps=_steps(pack),
        caveats=caveats[:600],
    )


def _steps(pack: EvidencePack) -> list[str]:
    f = pack.finding
    at = f"{f.file}" if f.file else "the reported location"
    if f.source_type == "sca" and f.package:
        if f.fixed_version:
            return [f"Upgrade {f.package} to {f.fixed_version} or later.", "Re-scan to confirm."]
        return [f"Find a fixed release of {f.package} or remove the dependency.", "Re-scan."]
    if f.source_type == "secret":
        return [
            "Revoke and rotate the credential.",
            "Remove it from the repository and its history.",
            "Re-scan to confirm.",
        ]
    if f.source_type == "iac":
        return [f"Change the flagged configuration in {at}.", "Re-scan to confirm."]
    return [f"Fix the flagged code in {at}.", "Re-scan to confirm."]
