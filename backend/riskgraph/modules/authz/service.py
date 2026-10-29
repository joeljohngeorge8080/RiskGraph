"""Route inventory as evidence, and reading it back (X5 part 1, ADR-0022).

Each route is one ``route`` evidence record: ``verified`` when the framework was told by a
constructor or an import in the file (a declaration we parsed), ``inferred`` when it was
told by the rest of the repository. Each route with a guard or a possible custom guard has
one ``auth_guard`` record, always ``inferred``: a catalogued name says nothing about how
the guard is configured. The records are scan-scoped like all evidence; nothing links
them to a finding yet (authorization findings are X5 part 2).
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections import Counter
from collections.abc import Iterable, Mapping
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from riskgraph.modules.authz.guards import load_catalogue
from riskgraph.modules.authz.inventory import Route
from riskgraph.modules.evidence import Assurance, Evidence, EvidenceRow, make_evidence
from riskgraph.modules.normalization import Location
from riskgraph.shared.vocabulary import FindingStatus, SourceType

PRODUCER = "riskgraph.authz@1"
RouteKey = tuple[str, int, tuple[str, ...], str]


def route_evidence(
    routes: Iterable[Route],
    observed_at: dt.datetime,
    unchecked: Mapping[RouteKey, tuple[str, ...]] | None = None,
) -> list[Evidence]:
    return evidence_by_route(routes, observed_at, unchecked)[0]


def evidence_by_route(
    routes: Iterable[Route],
    observed_at: dt.datetime,
    unchecked: Mapping[RouteKey, tuple[str, ...]] | None = None,
) -> tuple[list[Evidence], dict[RouteKey, tuple[str, ...]]]:
    """The evidence records, and per route the ids of its own (route first, then guard).
    ``unchecked``: manifest rule paths a route could not be checked against (X5 part 2)."""
    catalogue = load_catalogue()
    out: list[Evidence] = []
    ids: dict[RouteKey, tuple[str, ...]] = {}
    for r in routes:
        catalogued = sorted({g.name for g in r.guards if g.catalogued})
        custom = sorted(
            {g.name for g in r.guards if not g.catalogued and catalogue.looks_like_auth(g.name)}
        )
        route = make_evidence(
            producer=PRODUCER,
            kind="route",
            assurance=(
                Assurance.VERIFIED if r.basis in ("constructor", "import") else Assurance.INFERRED
            ),
            confidence="high" if r.basis == "constructor" and r.mounted else "medium",
            observed_at=observed_at,
            locations=[Location(r.file, r.line, r.line)],
            facts={
                "framework": r.framework,
                "basis": r.basis,
                "methods": list(r.methods),
                "path": r.path,
                "full_path": r.full_path,
                "handler": r.handler,
                "params": list(r.params),
                "guard_status": r.status,
                "guards": catalogued,
                "custom_guards": custom,
                "mounted": r.mounted,
                "notes": list(r.notes),
                **(
                    {"policy_unchecked": list(unchecked[r.key])}
                    if unchecked and r.key in unchecked
                    else {}
                ),
            },
        )
        out.append(route)
        ids[r.key] = (route.id,)
        if not catalogued and not custom:
            continue
        used = [g for g in r.guards if g.catalogued or g.name in custom]
        out.append(
            make_evidence(
                producer=PRODUCER,
                kind="auth_guard",
                assurance=Assurance.INFERRED,
                confidence="high" if catalogued else "low",
                observed_at=observed_at,
                locations=sorted(
                    {Location(g.file, g.line or None, g.line or None) for g in used},
                    key=lambda loc: (loc.file, loc.line_start or 0),
                ),
                facts={
                    "route": route.id,
                    "guards": [f"{g.source}:{g.name}" for g in used],
                    "catalogued": bool(catalogued),
                },
            )
        )
        ids[r.key] = (route.id, out[-1].id)
    return out, ids


def summary(routes: list[Route]) -> dict[str, Any]:
    return {
        "routes": len(routes),
        "by_status": dict(sorted(Counter(r.status for r in routes).items())),
        "by_framework": dict(sorted(Counter(r.framework or "unknown" for r in routes).items())),
    }


def list_routes(session: Session, scan_id: uuid.UUID) -> list[EvidenceRow]:
    rows = session.scalars(
        select(EvidenceRow).where(EvidenceRow.scan_job_id == scan_id, EvidenceRow.kind == "route")
    ).all()

    def order(row: EvidenceRow) -> tuple[str, int, str]:
        loc = (row.payload.get("locations") or [{}])[0]
        return (str(loc.get("file", "")), int(loc.get("line_start") or 0), row.id)

    return sorted(rows, key=order)


# --- manual verification list (X5 part 2, plan §4 X5 "manual verification required") ---
MANUAL_ORDER = ("bola", "policy_unchecked", "unresolved", "unknown_framework", "custom")
_WHY = {
    "unresolved": "the framework is known but RiskGraph could not resolve where the route is "
    "mounted, so a guard may sit on a mount it did not see",
    "unknown_framework": "RiskGraph does not recognise the framework, so it cannot say "
    "whether a guard applies",
    "custom": "the only guard is a name that looks like authentication but is not in the "
    "catalogue: check what it does",
}


def manual_checks(session: Session, scan_id: uuid.UUID) -> list[dict[str, Any]]:
    """What a person has to check, because static analysis cannot decide it: every BOLA
    hypothesis, every route a manifest rule could not be checked against, and every route
    whose guard status is undecided or rests on an uncatalogued name."""
    from riskgraph.modules.findings import Finding, FindingOccurrence

    items: list[dict[str, Any]] = []
    bola = session.execute(
        select(Finding, FindingOccurrence.evidence)
        .join(FindingOccurrence, FindingOccurrence.finding_id == Finding.id)
        .where(
            FindingOccurrence.scan_job_id == scan_id,
            FindingOccurrence.rule_id == "authz:bola",
            Finding.source_type == SourceType.AUTHZ,
            Finding.status == FindingStatus.OPEN,
        )
    ).all()
    for finding, evidence in bola:
        loc = finding.location or {}
        missing = (evidence or {}).get("missing_evidence") or []
        items.append(
            {
                "kind": "bola",
                "reason": finding.title,
                "finding_id": finding.id,
                "route_id": None,
                "file": str(loc.get("file") or ""),
                "line": loc.get("line_start"),
                "route": loc.get("resource"),
                "missing": [str(m) for m in missing][:5],
            }
        )
    for row in list_routes(session, scan_id):
        facts = row.payload.get("facts") or {}
        loc = (row.payload.get("locations") or [{}])[0]
        where = f"{'/'.join(facts.get('methods') or []) or '?'} " + str(
            facts.get("full_path") or facts.get("path") or "<dynamic path>"
        )
        base = {
            "finding_id": None,
            "route_id": row.id,
            "file": str(loc.get("file", "")),
            "line": loc.get("line_start"),
            "route": where,
        }
        unchecked = facts.get("policy_unchecked") or []
        if unchecked:
            items.append(
                {
                    **base,
                    "kind": "policy_unchecked",
                    "reason": "riskgraph.yaml has a rule for this route ("
                    + ", ".join(str(u) for u in unchecked)
                    + "), and RiskGraph could not tell whether its guard is there",
                    "missing": [f"the guard on {where}"],
                }
            )
        status = str(facts.get("guard_status") or "unknown_framework")
        if status in _WHY:
            items.append(
                {
                    **base,
                    "kind": status,
                    "reason": _WHY[status],
                    "missing": [", ".join(facts.get("custom_guards") or [])]
                    if status == "custom"
                    else [f"where {where} is mounted and which middleware runs before it"],
                }
            )
    items.sort(key=lambda i: (MANUAL_ORDER.index(i["kind"]), i["file"], i["line"] or 0))
    return items
