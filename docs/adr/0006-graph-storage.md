# ADR-0006: Graph storage and analysis

Status: accepted · Date: 2026-09-19

## Context
The brief asks for a justified graph technology, not a reflexive Neo4j. Per-scan graphs are 10³–10⁴ nodes; the analyses are shortest/k-shortest likelihood-weighted paths and neighbourhood queries.

## Decision
Store the graph as `graph_nodes`/`graph_edges` tables in PostgreSQL (a projection rebuilt from typed tables per scan) and analyse it in-process with NetworkX (Dijkstra, Yen's `shortest_simple_paths`). Dashboard neighbourhood queries use recursive CTEs.

## Alternatives considered
### Neo4j Community — rejected
Real pros: native traversal, Cypher, browser. Rejected: second stateful service (memory, backup, auth), cross-store consistency, GDS algorithms enterprise-gated, no benefit at our graph size.
### Apache AGE (Postgres extension) — rejected for now
Keeps one store; tooling and Python drivers immature (BELIEVE, re-check at the upgrade trigger).
### igraph instead of NetworkX — rejected
10–100× faster; irrelevant below 10⁵ edges, and NetworkX reads like the thesis pseudocode.

## Consequences
- (+) one store, one backup, full algorithmic control, testable pure functions
- (−) graph is loaded into memory per analysis (bounded by scan size); no cross-scan graph queries beyond CTEs
- (→) trigger: org-wide graph > 10⁶ edges or sub-second cross-scan multi-hop queries → AGE/Neo4j behind `modules/graph/repo.py`
