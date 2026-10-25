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
