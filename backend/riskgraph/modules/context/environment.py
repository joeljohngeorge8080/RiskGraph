"""Deployment context per finding: exposure, data sensitivity, privilege, criticality.

Blueprint §11.2 factors, from two sources in precedence order:

1. what RiskGraph knows about the repository itself: every MVP scan is of a public
   GitHub repository, so a committed secret is exposed to the internet without auth;
2. the repository manifest (``riskgraph.yaml``), mapped to findings by the longest
   service ``path`` prefix of the finding's file;
3. where the manifest is silent: Kubernetes (exposure, RBAC privilege), then Compose
   (exposure). A Kubernetes workload reaches findings through a manifest or Compose
   service of the same name; that is an inference, so its confidence is low.

Anything not covered stays ``None`` and the risk model uses its "unknown" default.
Data sensitivity follows §14.2: the most sensitive data store reachable from the
finding's service within two hops over RUNS_AS → CAN_ACCESS and CONNECTS_TO.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from riskgraph.modules.context.iac import IacAsset, KubeContext, kubernetes_context
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

    def __init__(
        self,
        manifest: ManifestResult,
        *,
        public_repository: bool = True,
        iac: Sequence[IacAsset] = (),
    ) -> None:
        self.manifest_result = manifest
        self.public_repository = public_repository
        m = manifest.manifest
        self._m: Manifest | None = m
        # longest prefix first, so 'backend/api/' wins over 'backend/'
        self._services = sorted(m.services, key=lambda s: len(s.path), reverse=True) if m else []
        # Compose services that build a code directory (P7). Used only where the manifest
        # says nothing about exposure, so a manifest always wins (blueprint §11).
        self._iac = sorted(
            (a for a in iac if a.path_prefix is not None and a.exposure is not None),
            key=lambda a: len(a.path_prefix or ""),
            reverse=True,
        )
        self._kube = kubernetes_context(list(iac))
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
        kube = self._kube_for(file, service)
        if kube is not None and (base.exposure is None or base.privilege is None):
            base = FindingContext(
                base.service,
                base.exposure or self._kube_exposure(kube),
                base.data,
                base.privilege or self._kube_privilege(kube),
                base.criticality,
            )
        if base.exposure is None:
            iac_exposure = self._iac_exposure(file)
            if iac_exposure is not None:
                base = FindingContext(
                    base.service, iac_exposure, base.data, base.privilege, base.criticality
                )
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

    def _compose_service(self, file: str) -> IacAsset | None:
        f = _clean_file(file)
        for a in self._iac:
            prefix = (a.path_prefix or "").strip("/")
            if not prefix or f.startswith(prefix + "/") or f == prefix:
                return a  # an empty prefix is the repository root (`build: .`)
        return None

    def _kube_for(self, file: str, service: ServiceDecl | None) -> KubeContext | None:
        """The workload named like the finding's manifest service, else its Compose service."""
        if not self._kube:
            return None
        if service is not None and service.name in self._kube:
            return self._kube[service.name]
        compose = self._compose_service(file)
        return self._kube.get(compose.name) if compose is not None else None

    @staticmethod
    def _kube_exposure(k: KubeContext) -> Observed | None:
        if k.exposure is None:
            return None
        # Kubernetes says nothing about application auth: same worst case as Compose.
        label = "internet_noauth" if k.exposure == "internet" else "internal"
        return Observed(label, "kubernetes", "low", dict(k.evidence))

    @staticmethod
    def _kube_privilege(k: KubeContext) -> Observed | None:
        if k.privilege is None:
            return None
        return Observed(k.privilege, "kubernetes", "low", dict(k.evidence))

    def _iac_exposure(self, file: str) -> Observed | None:
        f = _clean_file(file)
        for a in self._iac:
            prefix = (a.path_prefix or "").strip("/")
            if prefix and not f.startswith(prefix + "/") and f != prefix:
                continue
            if not prefix and not f:
                continue
            if a.exposure == "internal":
                return Observed(
                    "internal", "compose", "medium", {"service": a.name, "file": a.source_path}
                )
            # Published with no auth information: the same worst-case rule as a manifest
            # internet service without `auth:`, but with lower confidence (it is inferred).
            return Observed(
                "internet_noauth",
                "compose",
                "low",
                {
                    "service": a.name,
                    "file": a.source_path,
                    "published": a.attrs.get("published_ports", []),
                },
            )
        return None

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
            "iac_services": [
                {
                    "name": a.name,
                    "path": a.path_prefix,
                    "exposure": a.exposure,
                    "file": a.source_path,
                }
                for a in self._iac
            ],
            "kubernetes_workloads": [
                {
                    "name": k.workload,
                    "file": k.source_path,
                    "exposure": k.exposure,
                    "privilege": k.privilege,
                }
                for k in sorted(self._kube.values(), key=lambda k: k.workload)
            ],
        }
