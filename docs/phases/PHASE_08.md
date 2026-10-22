# PHASE 8: Reachability (L0–L3)
**Status:** L3 for Python added (2026-10-23); L2 for JavaScript/TypeScript already existed. Decision: ADR-0015. Abbreviated chapter.

## Built
- The extractor (`ts-imports.2`) records Python aliases, function calls and entry decorators.
- `callgraph.py`: call resolution through aliases, same-module and cross-module edges, breadth-first search from entry points to a vulnerable-symbol call.
- `vulnerable_symbols.yaml`: two PyYAML CVEs with `yaml.load` and friends. Loaded and validated at import.
- Tier `L3` (migration `c4f0a7e2d913`), wired through the classifier and pipeline. Evidence: symbol, sink function, chain.

## Verification
- `test_callgraph.py` (12): direct, aliased and from-imported calls; cross-file calls; module-level calls; a helper nothing reaches; a safe loader; and three blind spots (`getattr`, dict dispatch, call on a call result), each asserted "never L3".
- DB suite passes, including the migration round-trip.

## Not done (blueprint §11.3, §10.2)
- Semgrep findings mapped to their enclosing function (the "Semgrep ↔ functions" correlation). Semgrep findings still get tier from file reachability only.
- JavaScript/TypeScript L3 (blueprint scopes L3 to Python).
- Frontend display of the L3 tier.
- Secrets reported as SAST by Semgrep show `unknown` instead of `n_a` (scoped test; see ADR-0015).
