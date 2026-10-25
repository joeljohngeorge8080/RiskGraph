# PHASE 9: Security graph (invariants, neighbourhood queries, loader)

**Status:** done (2026-10-25). Abbreviated chapter. Decisions: ADR-0006 (Postgres + NetworkX) and ADR-0013 (the per-scan graph). The graph builder itself shipped in MVP level 2 extended (`PHASE_MVP2_EXT.md`); this phase closes the roadmap definition of done.

## A. Objective
Roadmap P9 definition of done:
- `graph_nodes/edges` built per scan (already existing);
- invariants tested;
- `GET /graph` (already existing) and neighbour queries working;
- NetworkX loader < 1 s at 5k nodes;
- recursive-CTE queries.

## B. Built
- **Invariants (blueprint §12)**, checked by the builder before it returns. A violation is a bug, so it raises `GraphInvariantError` and never yields a wrong graph. The checks:
  - `internet` has no in-edges;
  - every service has exactly one RUNS_AS. A service without `runs_as` now points to a synthetic `identity:unknown-identity` (privilege unknown, `synthetic: true`);
  - every credential has exactly one CONTAINS_SECRET in-edge. A secret outside every service hangs off a new `repository` node;
  - every edge joins known nodes;
  - every attack edge (EXPLOIT, AUTHENTICATES_AS) carries finding evidence.
- The synthetic nodes are never sources (no virtual edge) or sinks (no privilege or sensitivity), so **no path or score changes**. This is tested.
- **"What can reach X"**: `graph.service.reach`. One recursive CTE over `graph_edges`:
  - upstream (edges reversed) or downstream;
  - depth 1–8 (the path hop limit), with UNION and the depth bound ending cycles;
  - returns the shortest distance per node and the induced subgraph.
  - Endpoint: `GET /scans/{id}/graph/reach?node=&direction=upstream|downstream&depth=` (404 for an unknown node or scan; 422 for a bad direction or depth).
- **Loader**: `graph.to_networkx(nodes, edges)`. Stored rows become a weighted DiGraph:
  - `w = −ln p`;
  - edges without a probability get `w = ∞`, so they serve neighbourhoods but no shortest path;
  - parallel edges keep the most probable one.

## C. Decisions taken here
- **Induced subgraph for `reach` edges,** rather than only the BFS-tree edges: it is simpler to explain and shows alternative links. The node set is still bounded by depth and by `MAX_GRAPH_NODES` (2,000).
- **Raise on an invariant violation** instead of logging. The graph feeds scores (I\*), so a silently broken graph is worse than a failed analysis, which the pipeline already reports as a failed stage.

## M. Testing
- `test_graph_invariants.py` (8):
  - the fixture graph satisfies every invariant;
  - unknown identity; repository-held secret; synthetic nodes create no paths;
  - each violation is reported; the builder refuses a broken graph;
  - `to_networkx` parallel edges;
  - a **Hypothesis property** over 150 random manifests and finding sets: the builder never violates an invariant, and every path starts at the internet or a credential, has 0 < P ≤ 1 and ≤ 8 hops, and never passes through the repository node or ends at the unknown identity.
- `test_graph_db.py` (4, db): upstream of `users-db` (app-role and app at 1, internet and credentials at 2); the depth bound; downstream from the internet; internet has nothing upstream; 404/422; an SQL-looking key is a bound parameter.
- `test_graph_perf.py` (perf): the loader at 5,000 nodes / 19,990 edges took **0.029 s** (budget 1 s).

## O. Validation
```
uv run ruff check . && uv run mypy        → clean (158 files)
pytest -m "not db and not docker and not e2e and not perf" → 261 passed
make test-db                               → 46 passed, 2 skipped (no host scanners)
pytest -m perf tests/test_graph_perf.py    → loader: 5000 nodes, 19990 edges, 0.029s
```

## Not done
- Compose and Kubernetes topology as graph nodes and edges (paths without a manifest): moved to expansion phase X3, where edges also gain an assurance level (`docs/proposals/EXPANSION_A-D.md`).
- A UI for `reach` (the dashboard is P13).
