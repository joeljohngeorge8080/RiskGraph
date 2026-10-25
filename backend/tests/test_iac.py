"""Kubernetes and Compose extraction (P7). Reads only; nothing is executed or resolved."""

from __future__ import annotations

from pathlib import Path

from riskgraph.modules.context import ContextResolver, extract_iac
from riskgraph.modules.context.iac import MAX_FILE_BYTES, kubernetes_context
from riskgraph.modules.context.manifest import ManifestResult, parse_manifest
from riskgraph.shared.vocabulary import SourceType

K8S = """
apiVersion: v1
kind: Service
metadata: {name: web}
spec:
  type: LoadBalancer
  ports: [{port: 443}]
---
apiVersion: v1
kind: Service
metadata: {name: db}
spec: {type: ClusterIP, ports: [{port: 5432}]}
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: front}
spec:
  tls: [{hosts: [a.example]}]
  rules: [{host: a.example}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: super}
roleRef: {kind: ClusterRole, name: cluster-admin}
subjects: [{kind: ServiceAccount, name: api}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: api}
spec:
  template:
    spec:
      serviceAccountName: api
      containers:
        - name: app
          env:
            - name: DB_PASSWORD
              valueFrom: {secretKeyRef: {name: db, key: pw}}
          securityContext: {privileged: true}
"""

COMPOSE = """
services:
  web:
    build: ./frontend
    ports: ["8080:80"]
    environment:
      API_TOKEN: x
  db:
    image: postgres:16
    ports: ["127.0.0.1:5432:5432"]
  cache:
    image: redis:7
    expose: ["6379"]
"""


def _repo(tmp_path: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return tmp_path


def test_kubernetes_assets_and_their_exposure(tmp_path: Path) -> None:
    root = _repo(tmp_path, {"deploy/k8s.yaml": K8S})
    result = extract_iac(root)
    by = {(a.kind, a.name): a for a in result.assets}
    assert by[("service", "web")].exposure == "internet"
    assert by[("service", "db")].exposure == "internal"
    assert by[("ingress", "front")].exposure == "internet"
    assert by[("binding", "super")].attrs["privilege"] == "admin"
    assert by[("workload", "api")].attrs["secret_refs"] == 1
    assert by[("workload", "api")].attrs["privileged"] is True
    assert all(a.source_path == "deploy/k8s.yaml" for a in result.assets)


def test_compose_publishes_only_non_loopback_ports(tmp_path: Path) -> None:
    root = _repo(tmp_path, {"docker-compose.yml": COMPOSE})
    by = {a.name: a for a in extract_iac(root).assets}
    assert by["web"].exposure == "internet"
    assert by["web"].path_prefix == "frontend"
    assert by["db"].exposure == "internal"  # 127.0.0.1 binding is not internet
    assert by["cache"].exposure == "internal"  # expose: only, not published
    assert by["web"].attrs["secret_env_keys"] == ["API_TOKEN"]


def test_compose_build_context_cannot_escape_the_repository(tmp_path: Path) -> None:
    root = _repo(
        tmp_path,
        {"deploy/compose.yml": "services:\n  x:\n    build: ../../outside\n"},
    )
    (asset,) = extract_iac(root).assets
    assert asset.path_prefix is None


def test_invalid_yaml_is_a_warning_not_a_failure(tmp_path: Path) -> None:
    root = _repo(tmp_path, {"broken.yaml": "a: [unclosed\n", "ok.yaml": K8S})
    result = extract_iac(root)
    assert any("not valid YAML" in w for w in result.warnings)
    assert result.assets  # the good file still extracted


def test_alias_bombs_are_refused_before_parsing(tmp_path: Path) -> None:
    bomb = "a: &x [1,2,3]\n" + "\n".join(f"k{i}: *x" for i in range(150))
    root = _repo(tmp_path, {"bomb.yaml": bomb})
    result = extract_iac(root)
    assert result.assets == ()
    assert any("anchors or aliases" in w for w in result.warnings)


def test_oversized_files_are_skipped(tmp_path: Path) -> None:
    root = _repo(tmp_path, {"big.yaml": "x: " + "a" * (MAX_FILE_BYTES + 10)})
    assert any("size cap" in w for w in extract_iac(root).warnings)


def test_compose_exposure_reaches_findings_under_its_build_context(tmp_path: Path) -> None:
    root = _repo(tmp_path, {"docker-compose.yml": COMPOSE})
    iac = extract_iac(root)
    resolver = ContextResolver(ManifestResult("absent"), iac=iac.assets)
    ctx = resolver.for_finding("frontend/app.py", SourceType.SAST)
    assert ctx.exposure is not None and ctx.exposure.source == "compose"
    assert ctx.exposure.label == "internet_noauth" and ctx.exposure.confidence == "low"
    other = resolver.for_finding("backend/app.py", SourceType.SAST)
    assert other.exposure is None  # under-claim: no mapping, no exposure


K8S_TOPOLOGY = """
apiVersion: v1
kind: Service
metadata: {name: api-lb}
spec:
  type: LoadBalancer
  selector: {app: api}
---
apiVersion: v1
kind: Service
metadata: {name: worker-svc}
spec:
  selector: {app: worker}
---
apiVersion: v1
kind: Service
metadata: {name: front-svc}
spec:
  selector: {app: front}
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: edge}
spec:
  rules:
    - http:
        paths:
          - backend: {service: {name: front-svc, port: {number: 80}}}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: api-admin}
roleRef: {kind: ClusterRole, name: cluster-admin}
subjects: [{kind: ServiceAccount, name: api-sa}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: worker-read}
roleRef: {kind: ClusterRole, name: view}
subjects: [{kind: ServiceAccount, name: worker-sa}, {kind: User, name: api}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: api}
spec:
  template:
    metadata: {labels: {app: api, tier: backend}}
    spec:
      serviceAccountName: api-sa
      containers: [{name: app}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: worker}
spec:
  template:
    metadata: {labels: {app: worker}}
    spec:
      serviceAccountName: worker-sa
      containers: [{name: app}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: front}
spec:
  template:
    metadata: {labels: {app: front}}
    spec: {containers: [{name: web}]}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: lonely}
spec:
  template:
    metadata: {labels: {app: lonely}}
    spec: {containers: [{name: x}]}
"""


def test_kubernetes_topology_joins_services_ingress_and_rbac(tmp_path: Path) -> None:
    root = _repo(tmp_path, {"k8s/all.yaml": K8S_TOPOLOGY})
    kube = kubernetes_context(extract_iac(root).assets)
    assert kube["api"].exposure == "internet"  # LoadBalancer selects app=api
    assert kube["api"].privilege == "admin"  # api-sa bound to cluster-admin
    assert kube["api"].evidence["exposed_by"] == ["api-lb"]
    assert kube["worker"].exposure == "internal"  # only a ClusterIP Service
    assert kube["worker"].privilege == "elevated"  # a ClusterRoleBinding, not cluster-admin
    assert kube["front"].exposure == "internet"  # Ingress -> front-svc -> app=front
    assert kube["front"].privilege is None  # default SA, no binding: unknown, not limited
    assert kube["lonely"].exposure is None  # nothing selects it: under-claim


def test_kubernetes_user_subjects_do_not_grant_a_service_account(tmp_path: Path) -> None:
    root = _repo(tmp_path, {"k8s/all.yaml": K8S_TOPOLOGY})
    kube = kubernetes_context(extract_iac(root).assets)
    # worker-read binds a *User* named "api"; it must not reach the api-sa account
    assert kube["api"].evidence["bindings"] == ["api-admin"]


def test_empty_selector_selects_nothing(tmp_path: Path) -> None:
    text = (
        "apiVersion: v1\nkind: Service\nmetadata: {name: s}\nspec: {type: NodePort}\n---\n"
        "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: d}\n"
        "spec: {template: {metadata: {labels: {a: b}}, spec: {containers: []}}}\n"
    )
    kube = kubernetes_context(extract_iac(_repo(tmp_path, {"x.yaml": text})).assets)
    assert kube["d"].exposure is None


def test_kubernetes_context_reaches_findings_by_compose_service_name(tmp_path: Path) -> None:
    compose = "services:\n  api:\n    build: ./api\n  worker:\n    build: ./worker\n"
    root = _repo(tmp_path, {"k8s/all.yaml": K8S_TOPOLOGY, "docker-compose.yml": compose})
    resolver = ContextResolver(ManifestResult("absent"), iac=extract_iac(root).assets)
    api = resolver.for_finding("api/app.py", SourceType.SCA)
    assert api.exposure is not None and api.exposure.source == "kubernetes"
    assert api.exposure.label == "internet_noauth" and api.exposure.confidence == "low"
    assert api.privilege is not None and api.privilege.label == "admin"
    assert api.privilege.source == "kubernetes"
    worker = resolver.for_finding("worker/job.py", SourceType.SCA)
    # Kubernetes outranks Compose: compose says internal (no ports) and so does k8s
    assert worker.exposure is not None and worker.exposure.source == "kubernetes"
    assert worker.exposure.label == "internal"
    assert worker.privilege is not None and worker.privilege.label == "elevated"


def test_manifest_outranks_kubernetes(tmp_path: Path) -> None:
    manifest = parse_manifest(
        "version: 1\nservices:\n  - name: api\n    path: api/\n    exposure: internal\n"
    )
    root = _repo(tmp_path, {"k8s/all.yaml": K8S_TOPOLOGY})
    resolver = ContextResolver(manifest, iac=extract_iac(root).assets)
    ctx = resolver.for_finding("api/app.py", SourceType.SCA)
    assert ctx.exposure is not None and ctx.exposure.source == "manifest"
    # the manifest says nothing about privilege, so Kubernetes fills it in
    assert ctx.privilege is not None and ctx.privilege.source == "kubernetes"
    assert resolver.summary()["kubernetes_workloads"][0]["name"] == "api"
