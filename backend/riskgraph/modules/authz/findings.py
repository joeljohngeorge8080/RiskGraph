"""Authorization issues as findings (X5 part 2, ADR-0023).

``source_type = authz``, producer ``riskgraph`` (RiskGraph's own analyzer run, like the
runtime EOL findings). The place is the route: file and line, and ``METHOD full path`` as
the resource, so the fingerprint and the merge key survive the route moving a few lines.
The finding stores no evidence of its own; it links the route and guard evidence it rests
on (``attrs.evidence_ids``), and its ``attrs.assurance`` is the issue's (BOLA: hypothesis,
which the interim score caps at Low).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from riskgraph.modules.authz.analysis import AuthzIssue
from riskgraph.modules.authz.service import RouteKey
from riskgraph.modules.normalization import Location, RawFinding
from riskgraph.shared.vocabulary import ScannerName, SourceType

# CWE-862 Missing Authorization; CWE-639 Authorization Bypass Through User-Controlled Key
_CWE = {
    "inconsistent": ("CWE-862",),
    "unguarded-sensitive": ("CWE-862",),
    "policy": ("CWE-862",),
    "bola": ("CWE-639",),
}
_REMEDIATION = {
    "inconsistent": "Add the guard its sibling routes use, or document why this one is public.",
    "unguarded-sensitive": "Require authentication on this route, or document why it is public.",
    "policy": "Add the guard riskgraph.yaml requires, or narrow the rule if the route is public.",
    "bola": (
        "Load the object through the current user (for example filter by owner), or check "
        "ownership before returning or changing it. Confirm with a two-user test."
    ),
}


def issue_findings(
    issues: Iterable[AuthzIssue], evidence_ids: Mapping[RouteKey, tuple[str, ...]]
) -> list[RawFinding]:
    out: list[RawFinding] = []
    for issue in issues:
        r = issue.route
        where = f"{'/'.join(r.methods) or '?'} {r.full_path or r.path or '<dynamic path>'}"
        related = [e for o in issue.related for e in evidence_ids.get(o.key, ())[:1]]
        out.append(
            RawFinding(
                scanner=ScannerName.RISKGRAPH,
                source_type=SourceType.AUTHZ,
                rule_id=f"authz:{issue.rule}",
                title=issue.title[:300],
                severity=issue.severity,
                location=Location(r.file, r.line or None, r.line or None, where[:300]),
                category="auth",
                description=issue.detail[:2000],
                cwe_ids=_CWE[issue.rule],
                remediation=_REMEDIATION[issue.rule],
                attrs={
                    "assurance": issue.assurance.value,
                    "evidence_ids": [*evidence_ids.get(r.key, ()), *related][:12],
                    "missing_evidence": list(issue.missing)[:5],
                    "route": where[:300],
                    "handler": r.handler,
                    "framework": r.framework,
                    "guard_status": r.status,
                },
            )
        )
    return out
