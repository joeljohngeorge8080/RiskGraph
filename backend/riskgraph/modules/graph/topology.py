"""Services, images and identities from Compose and Kubernetes (expansion X3, ADR-0019).

Pure. Used only when the manifest declares no services: a manifest always wins (blueprint
§11, precedence manifest > Kubernetes > Compose). What each file *states* is kept apart
from what RiskGraph *infers* from it, because the graph edges built from it carry that
difference as their assurance (ADR-0017):

- a Compose service is a service; its build context is its code path; a published port
  is a claim of internet exposure (inferred: the file says nothing about firewalls);
- a Kubernetes workload is a service; a LoadBalancer/NodePort Service or an Ingress
  that selects it is internet exposure (inferred); the ServiceAccount its pod spec names
  is the identity it runs as (verified), the implicit ``default`` one is inferred;
- a Compose service and a Kubernetes workload with the same name are joined. That join
  is a name match, so the identity it gives the Compose service is inferred;
- RBAC bindings that name the ServiceAccount set the identity's privilege;
- an image the Compose or Kubernetes file names is verified; the last ``FROM`` of a
  Dockerfile in the build context is inferred (an earlier stage name is not followed).

Paths come from the files and are only compared and displayed, never opened.
"""

from __future__ import annotations

import posixpath
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from riskgraph.modules.context import IacAsset, kubernetes_context
from riskgraph.modules.evidence import Assurance
from riskgraph.modules.runtime import ImageRef, parse_ref

MAX_SERVICES = 200
MAX_IMAGES_PER_SERVICE = 20
# Graph keys are stored in 160 characters and add a prefix ("identity:sa:"); the IaC
# extractor allows 160-character names, so derived names are cut to leave room.
MAX_NAME = 120


@dataclass(frozen=True, slots=True)
class Declared:
    """A fact one IaC file states: becomes declaration or rbac_binding evidence."""

    file: str
    facts: dict[str, Any]
    kind: str = "declaration"
    line: int | None = None


@dataclass(frozen=True, slots=True)
class ServiceImage:
    ref: str  # canonical reference
    assurance: Assurance
    declared: Declared


@dataclass(frozen=True, slots=True)
class DerivedService:
    name: str
    path_prefix: str | None  # repo-relative code directory ("" is the root), None unknown
    declared: Declared  # where the service itself is declared
    exposure: Declared | None = None  # set when a file claims internet exposure
    images: tuple[ServiceImage, ...] = ()
    identity: str | None = None  # ServiceAccount name
    identity_assurance: Assurance = Assurance.INFERRED
    identity_declared: Declared | None = None
    privilege: str | None = None  # admin | elevated | None (unknown)
    bindings: tuple[Declared, ...] = ()
    sources: tuple[str, ...] = ()  # compose, kubernetes


@dataclass(frozen=True, slots=True)
class Topology:
    services: tuple[DerivedService, ...] = field(default_factory=tuple)

    def service_for(self, file: str | None) -> str | None:
        """The service whose code path holds ``file`` (longest prefix), if any."""
        if not file:
            return None
        f = file.replace("\\", "/").lstrip("/")
        best: tuple[int, str] | None = None
        for s in self.services:
            prefix = s.path_prefix
            if prefix is None:
                continue
            p = prefix.strip("/")
            if p and not (f == p or f.startswith(p + "/")):
                continue
            if best is None or len(p) > best[0]:
                best = (len(p), s.name)
        return best[1] if best else None


def _canonical(raw: object, file: str, origin: str) -> str | None:
    if not isinstance(raw, str):
        return None
    ref = parse_ref(raw, file, None, origin)  # type: ignore[arg-type]
    return ref.canonical if ref.repository else None


def _dockerfile_base(
    prefix: str | None, dockerfiles: Sequence[ImageRef], service: str
) -> ServiceImage | None:
    """The last FROM of the Dockerfile in the build context: what the service runs on."""
    if prefix is None:
        return None
    candidates = [
        r for r in dockerfiles if r.repository and posixpath.dirname(r.file) == prefix.strip("/")
    ]
    if not candidates:
        return None
    last = max(candidates, key=lambda r: (r.file == _default_dockerfile(prefix), r.line or 0))
    facts = {"service": service, "image": last.canonical, "dockerfile": last.file}
    return ServiceImage(
        last.canonical, Assurance.INFERRED, Declared(last.file, facts, line=last.line)
    )


def _default_dockerfile(prefix: str) -> str:
    p = prefix.strip("/")
    return f"{p}/Dockerfile" if p else "Dockerfile"


def _compose_services(assets: Iterable[IacAsset]) -> list[IacAsset]:
    # Compose services carry published_ports; Kubernetes Services carry a selector.
    return [a for a in assets if a.kind == "service" and "published_ports" in a.attrs]


def derive(assets: Sequence[IacAsset], dockerfiles: Sequence[ImageRef] = ()) -> Topology:
    """Services from Compose and Kubernetes, joined by name (see the module docstring)."""
    kube = kubernetes_context(list(assets))
    k8s_services = {a.name: a for a in assets if a.kind == "service" and "selector" in a.attrs}
    ingresses_to: dict[str, list[IacAsset]] = {}
    for a in assets:
        if a.kind == "ingress":
            for backend in a.attrs.get("backends", []):
                ingresses_to.setdefault(str(backend), []).append(a)
    bindings = [a for a in assets if a.kind == "binding"]
    workloads = {a.name: a for a in assets if a.kind == "workload"}
    compose = {a.name: a for a in _compose_services(assets)}

    out: list[DerivedService] = []
    for full in sorted({*compose, *workloads})[:MAX_SERVICES]:
        c, w = compose.get(full), workloads.get(full)
        name = full[:MAX_NAME]
        if any(s.name == name for s in out):
            continue  # two names that only differ after the cut: keep the first
        sources = tuple(s for s, a in (("compose", c), ("kubernetes", w)) if a is not None)
        declared_in = (c or w).source_path  # type: ignore[union-attr]
        declared = Declared(declared_in, {"service": name, "sources": list(sources)})
        prefix = c.path_prefix if c is not None else None

        exposure: Declared | None = None
        k = kube.get(full) if w is not None else None
        if k is not None and k.exposure == "internet":
            by = [str(x) for x in k.evidence.get("exposed_by", [])]
            # the file of the Service (or the Ingress in front of it) that makes it public
            fronts = [
                *(ingresses_to.get(x, []) for x in by),
                *([k8s_services[x]] for x in by if x in k8s_services),
            ]
            files = sorted({a.source_path for group in fronts for a in group}) or [k.source_path]
            exposure = Declared(
                files[0], {"service": name, "exposed_by": by, "source": "kubernetes"}
            )
        elif c is not None and c.exposure == "internet" and (k is None or k.exposure is None):
            exposure = Declared(
                c.source_path,
                {
                    "service": name,
                    "published_ports": list(c.attrs.get("published_ports", [])),
                    "source": "compose",
                },
            )

        images: dict[str, ServiceImage] = {}
        if c is not None and (ref := _canonical(c.attrs.get("image"), c.source_path, "compose")):
            images[ref] = ServiceImage(
                ref,
                Assurance.VERIFIED,
                Declared(c.source_path, {"service": name, "image": ref, "source": "compose"}),
            )
        if w is not None:
            for raw in w.attrs.get("images") or []:
                ref = _canonical(raw, w.source_path, "kubernetes")
                if ref and ref not in images:
                    images[ref] = ServiceImage(
                        ref,
                        Assurance.VERIFIED,
                        Declared(
                            w.source_path,
                            {"service": name, "image": ref, "source": "kubernetes"},
                        ),
                    )
        base = _dockerfile_base(prefix, dockerfiles, name)
        if base is not None and base.ref not in images:
            images[base.ref] = base

        identity, identity_assurance, identity_declared = None, Assurance.INFERRED, None
        privilege: str | None = None
        bound: tuple[Declared, ...] = ()
        if w is not None:
            account = str(w.attrs.get("service_account") or "default")
            identity = account[:MAX_NAME]
            # a named account is stated by the pod spec; "default" may only be implied, and
            # a Compose service gets it through a name match: both are inferences
            stated = identity != "default" and c is None
            identity_assurance = Assurance.VERIFIED if stated else Assurance.INFERRED
            identity_declared = Declared(
                w.source_path,
                {"service": name, "workload": w.name, "service_account": identity},
            )
            privilege = k.privilege if k is not None else None
            bound = tuple(
                Declared(
                    b.source_path,
                    {
                        "binding": b.name,
                        "role": b.attrs.get("role"),
                        "scope": b.attrs.get("scope"),
                        "service_account": identity,
                        "privilege": b.attrs.get("privilege"),
                    },
                    kind="rbac_binding",
                )
                for b in bindings
                if account in b.attrs.get("service_accounts", [])
            )
        out.append(
            DerivedService(
                name=name,
                path_prefix=prefix,
                declared=declared,
                exposure=exposure,
                images=tuple(images.values())[:MAX_IMAGES_PER_SERVICE],
                identity=identity,
                identity_assurance=identity_assurance,
                identity_declared=identity_declared,
                privilege=privilege,
                bindings=bound,
                sources=sources,
            )
        )
    return Topology(tuple(out))
