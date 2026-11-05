"""Graph performance budgets (blueprint §13.3 NFR, roadmap P9/P10). Run: pytest -m perf."""

from __future__ import annotations

import random
import time
from dataclasses import dataclass

import pytest
from riskgraph.modules.graph import to_networkx

pytestmark = pytest.mark.perf

N_NODES = 5_000
N_EDGES = 20_000


@dataclass(frozen=True)
class Row:
    key: str = ""
    kind: str = ""
    source: str = ""
    target: str = ""
    probability: float | None = None


def _rows(seed: int = 7) -> tuple[list[Row], list[Row]]:
    rnd = random.Random(seed)  # noqa: S311 (seeded synthetic graph, not security)
    nodes = [Row(key=f"service:s{i}", kind="service") for i in range(N_NODES)]
    edges = []
    for _ in range(N_EDGES):
        a, b = rnd.randrange(N_NODES), rnd.randrange(N_NODES)
        if a != b:
            edges.append(
                Row(
                    source=f"service:s{a}",
                    target=f"service:s{b}",
                    kind="EXPLOIT",
                    probability=rnd.uniform(0.05, 1.0),
                )
            )
    return nodes, edges


def test_loader_builds_5k_nodes_20k_edges_under_one_second() -> None:
    nodes, edges = _rows()
    start = time.perf_counter()
    g = to_networkx(nodes, edges)
    elapsed = time.perf_counter() - start
    print(f"\nloader: {g.number_of_nodes()} nodes, {g.number_of_edges()} edges, {elapsed:.3f}s")  # noqa: T201 (recorded in the phase chapter)
    assert g.number_of_nodes() == N_NODES and g.number_of_edges() > 0.99 * N_EDGES
    assert elapsed < 1.0


def _attack_graph(seed: int = 11):  # type: ignore[no-untyped-def]
    """A 5k-node service mesh with 20k exploit/control edges, internet exposure, 10 sinks."""
    import math

    import networkx as nx
    from riskgraph.modules.evidence import Assurance
    from riskgraph.modules.graph.attack import _VIRTUAL, INTERNET, AttackAnalysis

    rnd = random.Random(seed)  # noqa: S311 (seeded synthetic graph, not security)
    g: nx.DiGraph[str] = nx.DiGraph()
    out = AttackAnalysis()
    keys = [INTERNET] + [f"service:s{i}" for i in range(N_NODES - 1)]
    for k in keys:
        g.add_node(k)
        out.nodes[k] = {"key": k, "kind": "service", "label": k, "properties": {}}
    while g.number_of_edges() < N_EDGES:
        a, b = rnd.choice(keys), rnd.choice(keys[1:])
        if a == b or g.has_edge(a, b):
            continue
        kind = "EXPLOIT" if rnd.random() < 0.6 else "RUNS_AS"
        p = rnd.uniform(0.05, 0.95) if kind == "EXPLOIT" else 1.0
        g.add_edge(
            a,
            b,
            kind=kind,
            p=p,
            w=-math.log(p),
            findings=[1] if kind == "EXPLOIT" else [],
            assurance=Assurance.INFERRED,  # every analysis edge carries one since X1
        )
    for k in rnd.sample(keys[1:], 50):  # 1 % of services are internet-facing
        if not g.has_edge(INTERNET, k):
            p = rnd.uniform(0.05, 0.95)
            g.add_edge(
                INTERNET,
                k,
                kind="EXPLOIT",
                p=p,
                w=-math.log(p),
                findings=[1],
                assurance=Assurance.INFERRED,
            )
    g.add_edge(_VIRTUAL, INTERNET, kind="VIRTUAL", p=1.0, w=0.0, findings=[])
    sinks = {k: 0.9 for k in rnd.sample(keys[1:], 10)}
    return g, out, sinks


def test_yen_top3_for_10_sinks_on_5k_20k_under_two_seconds() -> None:
    from riskgraph.modules.graph.attack import K_PATHS, _search

    g, out, sinks = _attack_graph()
    start = time.perf_counter()
    _search(g, out, sinks)
    elapsed = time.perf_counter() - start
    print(f"\nsearch: {len(out.paths)} paths for {len(sinks)} sinks, {elapsed:.3f}s")  # noqa: T201
    assert 0 < len(out.paths) <= K_PATHS * len(sinks)
    assert all(p.hops <= 8 for p in out.paths)
    assert elapsed < 2.0


def test_search_with_function_endpoint_nodes_and_hypotheses_under_two_seconds() -> None:
    """X3 part 2: the same budget with the node kinds X4/X5 add and mixed assurance, so
    both searches (assured graph and full graph) run on every sink."""
    from riskgraph.modules.evidence import Assurance
    from riskgraph.modules.graph.attack import K_PATHS, _search

    g, out, sinks = _attack_graph()
    rnd = random.Random(5)  # noqa: S311 (seeded synthetic graph, not security)
    kinds = ("service", "function", "endpoint")
    for i, key in enumerate(list(out.nodes)[1:]):
        out.nodes[key]["kind"] = kinds[i % 3]
    levels = (Assurance.VERIFIED, Assurance.INFERRED, Assurance.HYPOTHESIS)
    for _, _, data in g.edges(data=True):
        if data["kind"] != "VIRTUAL":
            data["assurance"] = rnd.choice(levels)
    start = time.perf_counter()
    _search(g, out, sinks)
    elapsed = time.perf_counter() - start
    hyp = sum(p.assurance is Assurance.HYPOTHESIS for p in out.paths)
    print(f"\nsearch (two passes): {len(out.paths)} paths, {hyp} hypotheses, {elapsed:.3f}s")  # noqa: T201
    assert 0 < len(out.paths) <= 2 * K_PATHS * len(sinks)
    assert elapsed < 2.0


def test_build_and_search_a_5k_node_20k_edge_manifest_graph_under_two_seconds() -> None:
    """``analyze`` end to end: 2.5k services, 2.5k identities, ~20k stored edges, 10 sinks."""
    from riskgraph.modules.context.manifest import IdentityDecl, Manifest, ServiceDecl
    from riskgraph.modules.graph import GraphFinding, analyze
    from riskgraph.shared.vocabulary import SourceType

    rnd = random.Random(13)  # noqa: S311 (seeded synthetic graph, not security)
    n = 2_500
    sink_ids = set(rnd.sample(range(n), 10))
    services = tuple(
        ServiceDecl.model_construct(
            name=f"s{i}",
            path=f"s{i}/",
            exposure="internet" if i % 50 == 0 else "internal",
            runs_as=f"r{i}",
            connects_to=tuple(f"s{j}" for j in rnd.sample(range(n), 4) if j != i),
            auth=None,
            language=None,
            entrypoints=(),
        )
        for i in range(n)
    )
    identities = tuple(
        IdentityDecl.model_construct(
            name=f"r{i}",
            privilege="admin" if i in sink_ids else "limited",
            can_access=(),
            credentials=(),
            owns=(),
        )
        for i in range(n)
    )
    manifest = Manifest.model_construct(
        version=1, services=services, identities=identities, data_stores=(), criticality={}
    )
    tiers = ("L1", "L2", "L3")
    findings = [
        GraphFinding(
            i,
            f"s{i}",
            SourceType.SAST,
            exploit_p=rnd.uniform(0.05, 0.95),
            tier=tiers[i % 3],
            title=f"f{i}",
            evidence=(f"e{i}",),
        )
        for i in range(n)
    ]
    start = time.perf_counter()
    a = analyze(manifest, findings)
    elapsed = time.perf_counter() - start
    sizes = f"{len(a.nodes)} nodes, {len(a.edges)} edges, {len(a.paths)} paths"
    print(f"\nbuild+search: {sizes}, {elapsed:.3f}s")  # noqa: T201
    assert len(a.nodes) > 5_000 and len(a.edges) >= 20_000
    assert a.paths
    assert elapsed < 2.0
