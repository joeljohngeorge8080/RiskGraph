# Owner decisions

Questions the owner (jojo) answered, with the options offered. Source of truth for each flag is `FLAGS.md`; this file is the short log. Status of the build work: `TODO` until a commit says otherwise.

| Flag | Question | Options | Answer (2026-11-03) | Build work |
|---|---|---|---|---|
| F-1-1 | Compose database images as `data_store` nodes? | (a) yes, confidential; (b) yes, unknown sensitivity; (c) no | **(a)** | TODO: detector in `graph/topology.py`, node and edges in `graph/attack.py::_derive`, NodeGoat-shaped test, scenario G addition, ADR-0019 line |
| F-1-2 | CAN_ACCESS target for RBAC bindings | (a) keep as is; (b) `kubernetes_api` node; (c) secrets to credentials | **(a)** | none |
| F-2-1 | Tier-1 taint rules on by default? | (a) on by default; (b) opt-in | **(b)**, not the recommendation | none (setting stays unset) |
| F-3-1 | Build the Joern adapter now? | (a) yes; (b) skip | **(a)** | TODO: `modules/scanners/joern/`, parser golden tests on `fixtures/joern/`, `deep` profile (one slot), correlation, ADR with spike numbers, L-5 through the runner |
| F-4-1 | Count authz findings in the X0 evaluation? | (a) keep out; (b) label now; (c) keep in unlabelled | **(a)** | TODO later: authz scenario with labels first (X6 or X8) |
| F-4-2 | Declare routes public on purpose | (a) `authz.public`; (b) word list only; (c) `require: none` | **(a)** | TODO: `AuthzDecl.public`, skip in `_inconsistent` and `_unguarded_sensitive`, tests, ADR-0023 line |
| F-5-1 | Which findings take the path's effective impact I*? | (a) own support; (b) own support + foothold category; (c) leading finding; (d) keep | **(b)** | TODO: `category` on `GraphFinding`, filter in `graph/attack.py::_search`, flip F/G pins, property test, X0 re-run, ADR-0024 note |

Earlier, answered on 2026-11-03 by accepting the recommendation: F-L-1 (a) and F-L-2 (a); both are built (commit `6329243`).
