"""A graph without a manifest: services from Compose and Kubernetes (X3 part 1, ADR-0019)."""

from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from riskgraph.modules.context import extract_iac
from riskgraph.modules.evidence import Assurance, Relationship
from riskgraph.modules.graph import AttackAnalysis, GraphFinding, analyze
from riskgraph.modules.graph.attack import UNKNOWN_IDENTITY
from riskgraph.modules.graph.topology import Topology, derive
from riskgraph.modules.runtime import dockerfile_refs
from riskgraph.shared.vocabulary import SourceType as S

from tests.test_attack_paths import FINDINGS, _manifest

VER, INF, HYP = Assurance.VERIFIED, Assurance.INFERRED, Assurance.HYPOTHESIS
PY = "docker.io/library/python:3.8-slim"
API_IMAGE = "ghcr.io/acme/api:1.2"

COMPOSE = """
services:
  api:
    build: ./api
    ports: ["8080:8080"]
  worker:
    build: ./worker
  db:
    image: postgres:16
"""
K8S = """
apiVersion: apps/v1
kind: Deployment
metadata: {name: api}
spec:
  template:
    metadata: {labels: {app: api}}
    spec:
      serviceAccountName: api-sa
      containers: [{name: api, image: "ghcr.io/acme/api:1.2"}]
---
apiVersion: v1
kind: Service
metadata: {name: api-lb}
spec: {type: LoadBalancer, selector: {app: api}}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: api-admin}
roleRef: {kind: ClusterRole, name: cluster-admin}
subjects: [{kind: ServiceAccount, name: api-sa}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: jobs}
spec:
  template:
    spec:
      serviceAccountName: jobs-sa
      containers: [{name: jobs, image: "ghcr.io/acme/jobs:1"}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: plain}
spec:
  template:
    spec:
      containers: [{name: plain, image: "ghcr.io/acme/plain:1"}]
"""
DOCKERFILE = "FROM node:14 AS assets\nRUN build\nFROM python:3.8-slim\nCOPY --from=assets . .\n"


def _repo(root: Path, k8s: str = K8S, compose: str = COMPOSE) -> Topology:
    (root / "api").mkdir()
    (root / "api" / "Dockerfile").write_text(DOCKERFILE)
    (root / "docker-compose.yml").write_text(compose)
    (root / "k8s").mkdir()
    (root / "k8s" / "api.yaml").write_text(k8s)
    return derive(extract_iac(root).assets, dockerfile_refs(root))


def _code(index: int, file: str, tier: str = "L2", p: float = 0.5) -> GraphFinding:
    return GraphFinding(
        index, None, S.SAST, p, tier, title=f"f{index}", evidence=(f"ev{index}",), file=file
    )


def _image(index: int, image: str, kev: bool = False, p: float = 0.7) -> GraphFinding:
    return GraphFinding(
        index,
        None,
        S.SCA,
        p,
        "n_a",
        title=f"img{index}",
        evidence=(f"ev{index}",),
        file="api/Dockerfile",
        image=image,
        kev=kev,
    )


def _kind(a: AttackAnalysis, kind: str) -> list[Relationship]:
    return [e for e in a.edges if e.kind == kind]


def test_services_images_and_identities_come_from_compose_and_kubernetes(
    tmp_path: Path,
) -> None:
    topo = _repo(tmp_path)
    by = {s.name: s for s in topo.services}
    assert set(by) == {"api", "db", "worker", "jobs", "plain"}
    api = by["api"]
    assert api.path_prefix == "api" and api.sources == ("compose", "kubernetes")
    # Kubernetes wins over Compose for exposure; the Service file is the evidence
    assert api.exposure is not None and api.exposure.file == "k8s/api.yaml"
    assert api.exposure.facts["exposed_by"] == ["api-lb"]
    images = {i.ref: i.assurance for i in api.images}
    # the pod spec names one image; the Dockerfile's last FROM is what the build runs on
    assert images == {API_IMAGE: VER, PY: INF}
    # the Compose service gets the account through a name match: an inference
    assert (api.identity, api.identity_assurance, api.privilege) == ("api-sa", INF, "admin")
    assert [b.kind for b in api.bindings] == ["rbac_binding"]
    assert by["jobs"].identity_assurance is VER  # named by its own pod spec
    assert (by["plain"].identity, by["plain"].identity_assurance) == ("default", INF)
    assert by["worker"].exposure is None and by["worker"].identity is None
    assert {i.ref for i in by["db"].images} == {"docker.io/library/postgres:16"}
    assert topo.service_for("api/app/main.py") == "api"
    assert topo.service_for("apix/main.py") is None
    assert topo.service_for("worker/run.py") == "worker"


def test_a_repository_without_a_manifest_gets_an_inferred_path(tmp_path: Path) -> None:
    topo = _repo(tmp_path)
    a = analyze(None, [_code(0, "api/app.py")], topology=topo)
    [path] = a.paths
    assert path.nodes == ["internet", "service:api", "identity:sa:api-sa"]
    assert path.assurance is INF and path.findings == [0]
    assert [e.assurance for e in _kind(a, "EXPOSES")] == [INF]
    assert 0 in a.effective  # an inferred path raises the finding's effective impact
    # every edge rests on evidence the builder recorded (or the finding's own)
    for e in a.edges:
        assert e.evidence_ids and set(e.evidence_ids) <= set(a.evidence) | {"ev0"}
    kinds = {ev.kind for ev in a.evidence.values()}
    assert kinds == {"declaration", "rbac_binding"}
    runs_as = {e.source: e for e in _kind(a, "RUNS_AS")}
    assert runs_as["service:api"].assurance is INF
    assert runs_as["service:jobs"].assurance is VER
    assert runs_as["service:worker"].target == UNKNOWN_IDENTITY
    rbac = [a.evidence[i] for i in runs_as["service:api"].evidence_ids]
    assert any(ev.kind == "rbac_binding" and ev.facts["role"] == "cluster-admin" for ev in rbac)
    images = {(e.source, e.target): e.assurance for e in _kind(a, "RUNS_IMAGE")}
    assert images[("service:api", f"container_image:{API_IMAGE}")] is VER
    assert images[("service:api", f"container_image:{PY}")] is INF
    assert a.nodes[f"container_image:{PY}"]["kind"] == "container_image"


def test_exploit_is_never_more_assured_than_the_inferred_exposure(tmp_path: Path) -> None:
    topo = _repo(tmp_path)
    a = analyze(None, [_code(0, "api/app.py", tier="L3")], topology=topo)
    assert [e.assurance for e in _kind(a, "EXPLOIT")] == [INF]


@pytest.mark.parametrize(("kev", "level"), [(False, HYP), (True, INF)])
def test_image_findings_are_hypotheses_unless_exploited_in_the_wild(
    tmp_path: Path, kev: bool, level: Assurance
) -> None:
    topo = _repo(tmp_path)
    a = analyze(None, [_image(0, PY, kev=kev)], topology=topo)
    [exploit] = _kind(a, "EXPLOIT")
    assert exploit.assurance is level and exploit.findings == (0,)
    [path] = a.paths
    assert path.assurance is level
    assert (0 in a.effective) is (level is INF)  # hypotheses never raise a score


def test_the_best_assured_finding_sets_the_exploit_edge(tmp_path: Path) -> None:
    topo = _repo(tmp_path)
    # the image finding is more exploitable, but only a hypothesis
    a = analyze(None, [_code(0, "api/app.py", p=0.2), _image(1, PY, p=0.9)], topology=topo)
    [exploit] = _kind(a, "EXPLOIT")
    assert exploit.assurance is INF and exploit.p == 0.2 and exploit.findings[0] == 0


def test_unexposed_and_unreachable_findings_make_no_path(tmp_path: Path) -> None:
    topo = _repo(tmp_path)
    findings = [
        _code(0, "worker/job.py"),  # worker is not exposed
        _code(1, "api/app.py", tier="L0"),  # not reachable
        _code(2, "elsewhere/x.py"),  # in no service
        _image(3, "docker.io/library/postgres:16"),  # db is internal
    ]
    a = analyze(None, findings, topology=topo)
    assert a.paths == [] and not _kind(a, "EXPLOIT")


def test_secrets_in_a_build_context_belong_to_that_service(tmp_path: Path) -> None:
    topo = _repo(tmp_path)
    secret = GraphFinding(
        5, None, S.SECRET, secret_family="aws", public_secret=True, evidence=("s",),
        file="api/.env",
    )  # fmt: skip
    a = analyze(None, [secret], topology=topo)
    [contains] = _kind(a, "CONTAINS_SECRET")
    assert contains.source == "service:api" and contains.assurance is VER


def test_a_manifest_with_services_ignores_the_topology(tmp_path: Path) -> None:
    topo = _repo(tmp_path)
    plain = analyze(_manifest(), FINDINGS)
    with_topo = analyze(_manifest(), FINDINGS, topology=topo)
    assert [(e.source, e.target, e.kind, e.assurance) for e in with_topo.edges] == [
        (e.source, e.target, e.kind, e.assurance) for e in plain.edges
    ]
    assert [p.label for p in with_topo.paths] == [p.label for p in plain.paths]
    assert set(with_topo.nodes) == set(plain.nodes)


def test_image_findings_never_join_a_manifest_services_exploit() -> None:
    m = _manifest()
    base = analyze(m, FINDINGS)
    service = next(f.service for f in FINDINGS if f.service)
    extra = GraphFinding(99, service, S.SCA, 0.99, "n_a", evidence=("x",), image=PY)
    after = analyze(m, [*FINDINGS, extra])
    assert [(e.source, e.target, e.assurance, e.p) for e in _kind(after, "EXPLOIT")] == [
        (e.source, e.target, e.assurance, e.p) for e in _kind(base, "EXPLOIT")
    ]


_files = st.sampled_from(["app/a.py", "app/b.py", "app/sub/c.py", "app/d.js"])


def _random(i: int, f: str, kind: S, p: float, tier: str, fam: str | None) -> GraphFinding:
    return GraphFinding(
        i,
        None,
        kind,
        p,
        tier,
        secret_family=fam,
        public_secret=kind is S.SECRET,
        evidence=(f"e{i}",),
        file=f,
    )


_finding = st.builds(
    _random,
    st.integers(0, 10_000),
    _files,
    st.sampled_from([S.SCA, S.SAST, S.SECRET, S.IAC]),
    st.floats(0.01, 1.0),
    st.sampled_from(["L3", "L2", "L1", "L0", "unknown"]),
    st.sampled_from([None, "aws", "github"]),
)


@settings(max_examples=150, deadline=None)
@given(st.lists(_finding, max_size=25, unique_by=lambda f: f.index))
def test_co_located_findings_without_edge_rules_make_no_paths(
    findings: list[GraphFinding],
) -> None:
    # no manifest and no Compose/Kubernetes: findings side by side are never a chain
    for topology in (None, Topology()):
        a = analyze(None, findings, topology=topology)
        assert a.paths == [] and a.effective == {}
        assert not {e.kind for e in a.edges} - {"CONTAINS_SECRET"}


@settings(max_examples=60, deadline=None)
@given(st.lists(_finding, max_size=25, unique_by=lambda f: f.index))
def test_derived_services_without_a_sink_make_no_paths(
    tmp_path_factory: pytest.TempPathFactory, findings: list[GraphFinding]
) -> None:
    # Compose only: an exposed service, but nothing privileged or sensitive behind it
    root = tmp_path_factory.mktemp("compose")
    (root / "docker-compose.yml").write_text(
        "services:\n  app:\n    build: ./app\n    ports: ['80:80']\n"
    )
    topo = derive(extract_iac(root).assets)
    a = analyze(None, findings, topology=topo)
    assert a.paths == [] and a.effective == {}


def test_hostile_long_names_still_fit_the_node_key_column(tmp_path: Path) -> None:
    # Compose and Kubernetes names are capped at 160 by the extractor; the graph's keys
    # add a prefix and are stored in a 160-character column
    long = "s" * 160
    sa = "a" * 160
    k8s = (
        "apiVersion: apps/v1\nkind: Deployment\n"
        f"metadata: {{name: {long}}}\n"
        "spec:\n  template:\n    spec:\n"
        f"      serviceAccountName: {sa}\n"
        f"      containers: [{{name: c, image: 'ghcr.io/acme/{'x' * 200}:1'}}]\n"
        "---\napiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\n"
        "metadata: {name: b}\nroleRef: {kind: ClusterRole, name: cluster-admin}\n"
        f"subjects: [{{kind: ServiceAccount, name: {sa}}}]\n"
    )
    compose = f"services:\n  {long}:\n    build: ./api\n    ports: ['80:80']\n"
    topo = _repo(tmp_path, k8s=k8s, compose=compose)
    a = analyze(None, [_code(0, "api/app.py")], topology=topo)
    assert a.paths  # still a path, and nothing is too long to store
    assert all(len(k) <= 160 for k in a.nodes)
    assert all(len(e.source) <= 160 and len(e.target) <= 160 for e in a.edges)
    assert all(len(n["label"]) <= 200 for n in a.nodes.values())


# --- risk v2 (ADR-0024): an image package runs where its image runs --------------------


def test_an_image_takes_the_worst_context_of_the_services_that_run_it(tmp_path: Path) -> None:
    from riskgraph.modules.context import FindingContext, Observed
    from riskgraph.modules.graph import fill_image_context

    index = _repo(tmp_path).image_contexts()

    def image_context(ref: str, base: FindingContext) -> FindingContext:
        return fill_image_context(base, index.get(ref))

    ctx = image_context(API_IMAGE, FindingContext())
    assert ctx.exposure is not None and ctx.privilege is not None
    assert (ctx.exposure.label, ctx.exposure.source, ctx.exposure.confidence) == (
        "internet_noauth",
        "topology",
        "low",
    )
    assert ctx.exposure.evidence == {"image": API_IMAGE, "services": ["api"]}
    assert (ctx.privilege.label, ctx.privilege.evidence["services"]) == ("admin", ["api"])
    # an image nobody exposes or binds adds nothing; an unknown image neither
    jobs = image_context("ghcr.io/acme/jobs:1", FindingContext())
    assert jobs == FindingContext()
    assert image_context("ghcr.io/acme/nothing:9", FindingContext()) == FindingContext()
    # what the finding's own file already says wins (manifest > Kubernetes > Compose)
    stated = FindingContext("api", Observed("internal", "manifest", "high"))
    kept = image_context(API_IMAGE, stated)
    assert kept.exposure is stated.exposure and kept.service == "api"
    assert kept.privilege is not None and kept.privilege.label == "admin"


def test_image_contexts_stay_linear_on_a_large_topology() -> None:
    import time

    from riskgraph.modules.context import FindingContext
    from riskgraph.modules.graph import fill_image_context
    from riskgraph.modules.graph.topology import Declared, DerivedService, ServiceImage

    d = Declared("k8s/x.yaml", {})
    services = tuple(
        DerivedService(
            f"s{i}",
            None,
            d,
            exposure=d if i % 2 else None,
            images=tuple(ServiceImage(f"r/i{i}-{j}:1", VER, d) for j in range(20)),
            privilege="admin" if i % 3 == 0 else None,
        )
        for i in range(200)
    )
    start = time.perf_counter()
    index = Topology(services).image_contexts()
    for k in range(10_000):
        fill_image_context(FindingContext(), index.get(f"r/i{k % 200}-0:1"))
    assert time.perf_counter() - start < 0.5  # was 1.9 s when each finding scanned all
    assert index["r/i3-0:1"].privilege.label == "admin"  # type: ignore[union-attr]
    assert index["r/i3-0:1"].exposure is not None and "r/i2-0:1" not in index
