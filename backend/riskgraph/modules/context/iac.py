"""Environment assets from Kubernetes and Docker Compose files (blueprint §11, P7).

Read-only and bounded: files are read as text, parsed with ``yaml.safe_load_all`` and
never executed, templated or resolved. Every file, document and list is capped, and a file
that fails to parse produces a warning, not a failed scan (blueprint §11.1).

Exposure is only claimed where the file states it. A Service of type LoadBalancer or
NodePort, an Ingress, or a Compose port published on the host is ``internet``; a ClusterIP
Service or a Compose service with no published port is ``internal``. Anything else is left
unknown, which is the blueprint's under-claim rule.

``kubernetes_context`` joins the Kubernetes objects into per-workload facts: a Service
selects a workload by its pod labels, an Ingress routes to a Service, and a workload's
ServiceAccount is granted privilege by the bindings that name it as a subject.
"""

from __future__ import annotations

import os
import posixpath
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

MAX_FILES = 2000
MAX_FILE_BYTES = 512 * 1024
MAX_DOCS_PER_FILE = 200
MAX_LIST = 20
MAX_ANCHORS = 100
SECRET_KEY = re.compile(r"(PASSWORD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY)", re.IGNORECASE)
YAML_SUFFIXES = (".yaml", ".yml")
SKIP_DIRS = frozenset({".git", "node_modules", ".venv", "vendor"})


@dataclass(frozen=True, slots=True)
class IacAsset:
    kind: str  # service | ingress | identity | workload | binding
    name: str
    source_path: str  # repo-relative; displayed, never opened again
    attrs: dict[str, Any] = field(default_factory=dict)
    exposure: str | None = None  # internet | internal | None (unknown)
    path_prefix: str | None = None  # repo-relative code directory this asset runs, if known


@dataclass(frozen=True, slots=True)
class IacResult:
    assets: tuple[IacAsset, ...]
    warnings: tuple[str, ...]
    files_read: int


def _d(value: object) -> dict[str, Any]:
    """A YAML mapping, or an empty one. Untrusted input is never assumed to be the right shape."""
    return value if isinstance(value, dict) else {}


def _l(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _walk(root: Path) -> Iterator[Path]:
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in sorted(filenames):
            if not name.lower().endswith(YAML_SUFFIXES):
                continue
            count += 1
            if count > MAX_FILES:
                return
            yield Path(dirpath) / name


def _text(value: Any, limit: int = 200) -> str | None:
    return value.strip()[:limit] if isinstance(value, str) and value.strip() else None


def _rel(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()[:512]


def _code_dir(compose_dir: str, context: str) -> str | None:
    """A Compose build context, resolved against the compose file's own directory."""
    if context.startswith(("/", "http://", "https://", "git@")) or ".." in context.split("/"):
        return None
    joined = posixpath.normpath(posixpath.join(compose_dir, context))
    if joined in {".", ""}:
        return ""
    return joined if not joined.startswith("..") else None


def _labels(value: object) -> dict[str, str]:
    return {
        str(k)[:100]: str(v)[:100]
        for k, v in list(_d(value).items())[:MAX_LIST]
        if isinstance(k, str) and isinstance(v, (str, int, bool))
    }


def _ingress_backends(spec: dict[str, Any]) -> list[str]:
    """Service names an Ingress routes to (networking.k8s.io/v1 and the old v1beta1 shape)."""
    names: list[str] = []
    backends = [_d(spec.get("defaultBackend")), _d(spec.get("backend"))]
    for rule in _l(spec.get("rules")):
        for path in _l(_d(_d(rule).get("http")).get("paths")):
            backends.append(_d(_d(path).get("backend")))
    for b in backends:
        name = _text(_d(b.get("service")).get("name")) or _text(b.get("serviceName"))
        if name and name not in names:
            names.append(name)
    return names[:MAX_LIST]


def _k8s(doc: dict[str, Any], source: str) -> list[IacAsset]:
    kind = str(doc.get("kind", ""))
    meta = _d(doc.get("metadata"))
    name = _text(meta.get("name"), 160) or "unnamed"
    spec = _d(doc.get("spec"))
    if kind == "Service":
        svc_type = _text(spec.get("type")) or "ClusterIP"
        ports = [p.get("port") for p in _l(spec.get("ports")) if isinstance(p, dict)]
        exposure = "internet" if svc_type in {"LoadBalancer", "NodePort"} else "internal"
        return [
            IacAsset(
                "service",
                name,
                source,
                {
                    "type": svc_type,
                    "ports": [p for p in ports if isinstance(p, int)][:MAX_LIST],
                    "selector": _labels(spec.get("selector")),
                },
                exposure,
            )
        ]
    if kind == "Ingress":
        rules = _l(spec.get("rules"))
        hosts = [_text(r.get("host")) for r in rules if isinstance(r, dict)]
        return [
            IacAsset(
                "ingress",
                name,
                source,
                {
                    "hosts": [h for h in hosts if h][:MAX_LIST],
                    "tls": bool(spec.get("tls")),
                    "backends": _ingress_backends(spec),
                },
                "internet",
            )
        ]
    if kind == "ServiceAccount":
        return [
            IacAsset(
                "identity",
                name,
                source,
                {"automount": doc.get("automountServiceAccountToken", True) is not False},
            )
        ]
    if kind in {"ClusterRoleBinding", "RoleBinding"}:
        role = _d(doc.get("roleRef"))
        role_name = _text(role.get("name")) or ""
        privilege = (
            "admin"
            if role_name == "cluster-admin"
            else "elevated"
            if kind == "ClusterRoleBinding"
            else None
        )
        accounts = [
            n
            for sub in _l(doc.get("subjects"))
            if _d(sub).get("kind") == "ServiceAccount" and (n := _text(_d(sub).get("name"), 160))
        ]
        return [
            IacAsset(
                "binding",
                name,
                source,
                {
                    "role": role_name,
                    "scope": kind,
                    "privilege": privilege,
                    "service_accounts": accounts[:MAX_LIST],
                },
            )
        ]
    if kind in {"Deployment", "StatefulSet", "DaemonSet", "Pod", "Job", "CronJob"}:
        template = _d(spec.get("template"))
        pod = _d(template.get("spec")) or spec
        containers = _l(pod.get("containers"))
        secret_refs = 0
        privileged = False
        for c in containers:
            if not isinstance(c, dict):
                continue
            for env in _l(c.get("env")):
                value_from = _d(env.get("valueFrom")) if isinstance(env, dict) else {}
                if "secretKeyRef" in value_from:
                    secret_refs += 1
            sc = _d(c.get("securityContext"))
            privileged = privileged or sc.get("privileged") is True
        return [
            IacAsset(
                "workload",
                name,
                source,
                {
                    "service_account": _text(pod.get("serviceAccountName")) or "default",
                    "secret_refs": secret_refs,
                    "privileged": privileged,
                    "labels": _labels(_d(template.get("metadata")).get("labels")),
                    "containers": [n for c in containers if (n := _text(_d(c).get("name"), 160))][
                        :MAX_LIST
                    ],
                },
            )
        ]
    return []


@dataclass(frozen=True, slots=True)
class KubeContext:
    """What the Kubernetes objects say about one workload (kubernetes_context)."""

    workload: str
    source_path: str
    exposure: str | None  # internet | internal | None
    privilege: str | None  # admin | elevated | None (unknown)
    evidence: dict[str, Any]


PRIVILEGE_ORDER = ("elevated", "admin")


def _selects(selector: dict[str, str], labels: dict[str, str]) -> bool:
    # An empty selector selects nothing for a Service: its endpoints are managed by hand.
    return bool(selector) and all(labels.get(k) == v for k, v in selector.items())


def kubernetes_context(assets: tuple[IacAsset, ...] | list[IacAsset]) -> dict[str, KubeContext]:
    """Per-workload exposure and privilege, joined from Services, Ingresses and RBAC.

    Exposure: internet if a LoadBalancer or NodePort Service selects the workload, or an
    Ingress routes to a Service that does; internal if only ClusterIP Services select it;
    unknown otherwise. Privilege: the highest privilege bound to the workload's
    ServiceAccount; unknown when nothing binds it (a missing binding is not proof of
    least privilege, since roles can be granted outside the repository).
    """
    services = [a for a in assets if a.kind == "service" and "selector" in a.attrs]
    ingress_targets = {
        b for a in assets if a.kind == "ingress" for b in a.attrs.get("backends", [])
    }
    bindings = [a for a in assets if a.kind == "binding"]
    out: dict[str, KubeContext] = {}
    for w in (a for a in assets if a.kind == "workload"):
        labels = w.attrs.get("labels", {})
        selecting = [s for s in services if _selects(s.attrs.get("selector", {}), labels)]
        internet = sorted(
            s.name for s in selecting if s.exposure == "internet" or s.name in ingress_targets
        )
        exposure = "internet" if internet else "internal" if selecting else None
        account = w.attrs.get("service_account", "default")
        bound = [b for b in bindings if account in b.attrs.get("service_accounts", [])]
        levels = [b.attrs.get("privilege") for b in bound if b.attrs.get("privilege")]
        privilege = max(levels, key=PRIVILEGE_ORDER.index) if levels else None
        out[w.name] = KubeContext(
            w.name,
            w.source_path,
            exposure,
            privilege,
            {
                "workload": w.name,
                "file": w.source_path,
                "exposed_by": internet or sorted(s.name for s in selecting),
                "service_account": account,
                "bindings": sorted(b.name for b in bound),
            },
        )
    return out


def _compose(doc: dict[str, Any], source: str, compose_dir: str) -> list[IacAsset]:
    services = doc.get("services")
    if not isinstance(services, dict):
        return []
    out: list[IacAsset] = []
    for name, svc in list(services.items())[: MAX_LIST * 10]:
        if not isinstance(name, str) or not isinstance(svc, dict):
            continue
        published: list[str] = []
        for p in _l(svc.get("ports")):
            text = str(p) if isinstance(p, (str, int)) else ""
            if not text:
                continue
            # "80:80", "0.0.0.0:80:80", "127.0.0.1:5432:5432" (loopback is not internet)
            host_part = text.rsplit(":", 1)[0] if text.count(":") >= 1 else ""
            if host_part and not host_part.startswith("127.0.0.1"):
                published.append(text[:64])
        build = svc.get("build")
        context = _d(build).get("context") if isinstance(build, dict) else build
        code = _code_dir(compose_dir, context) if isinstance(context, str) else None
        env = svc.get("environment")
        keys = (
            list(env.keys())
            if isinstance(env, dict)
            else [str(e).split("=", 1)[0] for e in env or [] if isinstance(e, str)]
        )
        secret_keys = sorted({k for k in keys if SECRET_KEY.search(k)})[:MAX_LIST]
        exposure = "internet" if published else "internal"
        out.append(
            IacAsset(
                "service",
                name[:160],
                source,
                {
                    "published_ports": published[:MAX_LIST],
                    "privileged": svc.get("privileged") is True,
                    "secret_env_keys": secret_keys,
                },
                exposure,
                code,
            )
        )
    return out


def extract(root: Path) -> IacResult:
    assets: list[IacAsset] = []
    warnings: list[str] = []
    files = 0
    for path in _walk(root):
        source = _rel(root, path)
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                warnings.append(f"{source}: skipped, larger than the size cap")
                continue
            text = path.read_text(encoding="utf-8", errors="strict")
        except (OSError, UnicodeDecodeError):
            warnings.append(f"{source}: skipped, unreadable as UTF-8")
            continue
        files += 1
        # PyYAML expands aliases without a limit ("billion laughs"): refuse files that use
        # many anchors or aliases rather than load them.
        if text.count("&") > MAX_ANCHORS or text.count("*") > MAX_ANCHORS:
            warnings.append(f"{source}: skipped, too many YAML anchors or aliases")
            continue
        try:
            docs = list(yaml.safe_load_all(text))[:MAX_DOCS_PER_FILE]
        except yaml.YAMLError:
            warnings.append(f"{source}: skipped, not valid YAML")
            continue
        compose_dir = posixpath.dirname(source)
        for doc in docs:
            if not isinstance(doc, dict):
                continue
            if "apiVersion" in doc and "kind" in doc:
                assets.extend(_k8s(doc, source))
            elif isinstance(doc.get("services"), dict):
                assets.extend(_compose(doc, source, compose_dir))
    assets.sort(key=lambda a: (a.kind, a.name, a.source_path))
    return IacResult(tuple(assets[: MAX_FILES * 10]), tuple(warnings[:100]), files)
