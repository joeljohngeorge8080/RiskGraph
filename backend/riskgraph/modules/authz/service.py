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
from collections.abc import Iterable
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from riskgraph.modules.authz.guards import load_catalogue
from riskgraph.modules.authz.inventory import Route
from riskgraph.modules.evidence import Assurance, Evidence, EvidenceRow, make_evidence
from riskgraph.modules.normalization import Location

PRODUCER = "riskgraph.authz@1"


def route_evidence(routes: Iterable[Route], observed_at: dt.datetime) -> list[Evidence]:
    catalogue = load_catalogue()
    out: list[Evidence] = []
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
            },
        )
        out.append(route)
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
    return out


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
