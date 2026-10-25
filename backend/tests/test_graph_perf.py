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
        g.add_edge(a, b, kind=kind, p=p, w=-math.log(p), findings=[1] if kind == "EXPLOIT" else [])
    for k in rnd.sample(keys[1:], 50):  # 1 % of services are internet-facing
        if not g.has_edge(INTERNET, k):
            p = rnd.uniform(0.05, 0.95)
            g.add_edge(INTERNET, k, kind="EXPLOIT", p=p, w=-math.log(p), findings=[1])
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
