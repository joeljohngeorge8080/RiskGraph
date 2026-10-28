"""API shapes for the route inventory (X5 part 1)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class RouteOut(BaseModel):
    id: str  # the route evidence id, stable across re-analysis of the same code
    file: str
    line: int | None
    framework: str | None
    basis: str  # constructor | import | repository | unknown
    methods: list[str]
    path: str | None  # as declared
    full_path: str | None  # with resolved prefixes, no trailing slash
    handler: str
    params: list[str]
    guard_status: str  # guarded | custom | none_found | unresolved | unknown_framework
    guards: list[str]  # catalogued guards (inferred)
    custom_guards: list[str]  # uncatalogued names that look like authentication
    mounted: bool  # the mount chain reaches an app
    notes: list[str]
    assurance: str  # of the route itself: verified, or inferred when the framework was
    confidence: str

    @classmethod
    def from_payload(cls, evidence_id: str, payload: dict[str, Any]) -> RouteOut:
        facts = payload.get("facts") or {}
        loc = (payload.get("locations") or [{}])[0]

        def strs(key: str) -> list[str]:
            value = facts.get(key)
            return [str(v) for v in value] if isinstance(value, list) else []

        return cls(
            id=evidence_id,
            file=str(loc.get("file", "")),
            line=loc.get("line_start"),
            framework=facts.get("framework"),
            basis=str(facts.get("basis") or "unknown"),
            methods=strs("methods"),
            path=facts.get("path"),
            full_path=facts.get("full_path"),
            handler=str(facts.get("handler") or ""),
            params=strs("params"),
            guard_status=str(facts.get("guard_status") or "unknown_framework"),
            guards=strs("guards"),
            custom_guards=strs("custom_guards"),
            mounted=bool(facts.get("mounted")),
            notes=strs("notes"),
            assurance=str(payload.get("assurance") or ""),
            confidence=str(payload.get("confidence") or ""),
        )


class RoutesOut(BaseModel):
    items: list[RouteOut]
    total: int
    by_status: dict[str, int]
