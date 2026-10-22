"""Kubernetes and Compose extraction (P7). Reads only; nothing is executed or resolved."""

from __future__ import annotations

from pathlib import Path

from riskgraph.modules.context import ContextResolver, extract_iac
from riskgraph.modules.context.iac import MAX_FILE_BYTES
from riskgraph.modules.context.manifest import ManifestResult
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
