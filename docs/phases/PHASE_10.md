# PHASE 10: Attack-path engine (scenario E, performance budget)

**Status:** done (2026-10-25). Abbreviated chapter. Decision: ADR-0013. Derivation, Yen's search, scoring and effective impact shipped in MVP level 2 extended; this phase closes the roadmap definition of done and fixes a performance defect it found.

## A. Objective
Roadmap P10 definition of done:
- Scenario E produces the expected path with evidence;
- Dijkstra + Yen top-3 (already existing);
- the performance budget is met (≤ 2 s at 5k nodes / 20k edges, 10 sinks, k = 3; blueprint §13.3);
- `GET /attack-paths` (already existing).

## B. Defect found and fixed
- **What happened:** the first measurement on a 5k/20k mesh took **11.3 s and returned zero paths**. The hop limit (8) was applied *after* Yen produced each candidate. On a large graph the cheapest paths are long, so all 50 candidates per sink were computed and then thrown away.
- **The fix is the pre-filter blueprint §13.2 already prescribes** ("BFS kept as a pre-filter"):
  - hop distances from the virtual source (once) and to each sink (reverse BFS), both cut off at the budget;
  - Yen runs on the subgraph of nodes with `d_source + d_sink ≤ MAX_HOPS + 1`;
  - a sink outside the hop range is skipped immediately.
- **The pruning is exact:** a path within the hop budget can only pass through nodes that satisfy the bound.
- **Result:** 10 sinks, top 3 each, in **0.057 s**, 30 paths.

## M. Testing
- `test_attack_paths.py` (+2):
  - **Scenario E (§14.6):**
    - an SSRF (SAST high, E = 0.7; L3, R = 1.0) on an internet API with `auth: none`;
    - paths Internet → api → api-role → users-db (P = √0.7 = 0.837, score 75.3 with D(pii) = 0.9) and → instance-metadata (score 83.7, credentials = 1.0);
    - the SSRF finding is the only evidence, on the single EXPLOIT hop;
    - an internal worker's CVE is on no path;
    - I_eff(SSRF) = 1.0, because the rest of the chain is control edges.
  - **A Hypothesis property:** on 120 random 8-node graphs with hop limits 1–4, the engine's top-k probabilities per sink equal brute-force enumeration of every simple path within the limit that holds an EXPLOIT edge.
  - **Mutation check:** setting the pre-filter budget one hop short makes this property fail; restoring it passes.
- `test_graph_perf.py` (perf): `search: 30 paths for 10 sinks, 0.057s` and `loader: 5000 nodes, 19990 edges, 0.031s`.

## O. Validation
```
uv run ruff check . && uv run mypy                         → clean (158 files)
pytest -m "not db and not docker and not e2e and not perf"  → 263 passed
make test-db                                               → 46 passed, 2 skipped
pytest -m perf -s                                          → 2 passed (numbers above)
```

## Not done
- The "cheapest edge to fix" and choke-point (betweenness) metrics: stretch, deferred (expansion plan §5).
- Path assurance levels (verified, inferred, hypothesis): expansion phase X1/X3.
