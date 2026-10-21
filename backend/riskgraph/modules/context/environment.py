"""Deployment context per finding: exposure, data sensitivity, privilege, criticality.

Blueprint §11.2 factors, from two sources in precedence order:

1. what RiskGraph knows about the repository itself: every MVP scan is of a public
   GitHub repository, so a committed secret is exposed to the internet without auth;
2. the repository manifest (``riskgraph.yaml``), mapped to findings by the longest
   service ``path`` prefix of the finding's file.

Anything not covered stays ``None`` and the risk model uses its "unknown" default.
Data sensitivity follows §14.2: the most sensitive data store reachable from the
finding's service within two hops over RUNS_AS → CAN_ACCESS and CONNECTS_TO.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any

from riskgraph.modules.context.manifest import Manifest, ManifestResult, ServiceDecl
from riskgraph.shared.vocabulary import SourceType

SENSITIVITY_RANK = {
    "public": 0,
    "internal": 1,
    "confidential": 2,
    "pii": 3,
    "financial": 3,
    "credentials": 4,
}
MAX_HOPS = 2


@dataclass(frozen=True, slots=True)
class Observed:
    """One context value with its provenance (stored with the risk factor)."""

    label: str
    source: str
    confidence: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class FindingContext:
    service: str | None = None
    exposure: Observed | None = None
    data: Observed | None = None
    privilege: Observed | None = None
    criticality: Observed | None = None


def _clean_file(file: str) -> str:
    f = file.replace("\\", "/")
    while f.startswith("./"):
        f = f[2:]
    return f.lstrip("/")


class ContextResolver:
    """Resolves the context of findings for one scan (pure; built once per analysis)."""

    def __init__(self, manifest: ManifestResult, *, public_repository: bool = True) -> None:
        self.manifest_result = manifest
        self.public_repository = public_repository
        m = manifest.manifest
        self._m: Manifest | None = m
        # longest prefix first, so 'backend/api/' wins over 'backend/'
        self._services = sorted(m.services, key=lambda s: len(s.path), reverse=True) if m else []
        self._cache: dict[str, FindingContext] = {}
        self.mapped: dict[str, int] = {}
        self.unmapped = 0

    def service_for(self, file: str) -> ServiceDecl | None:
        f = _clean_file(file)
        for s in self._services:
            if f.startswith(s.path):
                return s
        return None

    def for_finding(self, file: str, source_type: SourceType) -> FindingContext:
        service = self.service_for(file)
        if service is None:
            self.unmapped += 1
        else:
            self.mapped[service.name] = self.mapped.get(service.name, 0) + 1
        base = self._service_context(service) if service else FindingContext()
        if source_type is SourceType.SECRET and self.public_repository:
            exposure = Observed(
                "internet_noauth",
                "repository_visibility",
                "high",
                {"reason": "committed to a public repository"},
            )
            return FindingContext(
                base.service, exposure, base.data, base.privilege, base.criticality
            )
        return base

    def _service_context(self, s: ServiceDecl) -> FindingContext:
        cached = self._cache.get(s.name)
        if cached is None:
            cached = FindingContext(
                s.name, self._exposure(s), self._data(s), self._privilege(s), self._criticality(s)
            )
            self._cache[s.name] = cached
        return cached

    @staticmethod
    def _exposure(s: ServiceDecl) -> Observed | None:
        ev: dict[str, Any] = {"service": s.name, "exposure": s.exposure, "auth": s.auth}
        if s.exposure is None:
            return None
        if s.exposure != "internet":
            return Observed(s.exposure, "manifest", "high", ev)
        if s.auth == "required":
            return Observed("internet_auth", "manifest", "high", ev)
        # auth not declared on an internet-facing service: assume the worse case
        confidence = "high" if s.auth == "none" else "medium"
        return Observed("internet_noauth", "manifest", confidence, ev)

    def _privilege(self, s: ServiceDecl) -> Observed | None:
        if self._m is None or s.runs_as is None:
            return None
        identity = next(i for i in self._m.identities if i.name == s.runs_as)
        if identity.privilege is None:
            return None
        ev = {"service": s.name, "identity": identity.name}
        return Observed(identity.privilege, "manifest", "high", ev)

    def _criticality(self, s: ServiceDecl) -> Observed | None:
        if self._m is None or s.name not in self._m.criticality:
            return None
        return Observed(self._m.criticality[s.name], "manifest", "high", {"service": s.name})

    def _data(self, s: ServiceDecl) -> Observed | None:
        """Most sensitive data store within MAX_HOPS of the service (breadth-first)."""
        m = self._m
        if m is None:
            return None
        services = {x.name: x for x in m.services}
        identities = {i.name: i for i in m.identities}
        stores = {d.name: d for d in m.data_stores}

        def edges(name: str) -> list[str]:
            if name in services:
                svc = services[name]
                return [*([svc.runs_as] if svc.runs_as else []), *svc.connects_to]
            if name in identities:
                return list(identities[name].can_access)
            return []

        best: tuple[int, int, str, str, list[str]] | None = None  # rank, -hops, label, sink, path
        seen = {s.name}
        queue: deque[tuple[str, list[str]]] = deque([(s.name, [s.name])])
        while queue:
            name, path = queue.popleft()
            hops = len(path) - 1
            store = stores.get(name)
            if store is not None and store.sensitivity is not None:
                cand = (SENSITIVITY_RANK[store.sensitivity], -hops, store.sensitivity, name, path)
                if best is None or cand[:2] > best[:2]:
                    best = cand
            if hops == MAX_HOPS:
                continue
            for nxt in edges(name):
                if nxt not in seen:
                    seen.add(nxt)
                    queue.append((nxt, [*path, nxt]))
        if best is None:
            return None
        _, neg_hops, label, sink, path = best
        confidence = "high" if -neg_hops <= 1 else "medium"
        return Observed(label, "manifest", confidence, {"sink": sink, "path": path})

    def summary(self) -> dict[str, Any]:
        r = self.manifest_result
        services = []
        for s in self._m.services if self._m else ():
            ctx = self._service_context(s)
            services.append(
                {
                    "name": s.name,
                    "path": s.path or "/",
                    "exposure": ctx.exposure.label if ctx.exposure else None,
                    "privilege": ctx.privilege.label if ctx.privilege else None,
                    "data": ctx.data.label if ctx.data else None,
                    "criticality": ctx.criticality.label if ctx.criticality else None,
                    "findings": self.mapped.get(s.name, 0),
                }
            )
        return {
            "manifest": r.status,
            "file": r.file,
            "warnings": list(r.warnings),
            "public_repository": self.public_repository,
            "services": services,
            "unmapped_findings": self.unmapped,
        }
