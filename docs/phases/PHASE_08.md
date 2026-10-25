# PHASE 8: Reachability (L0–L3)
**Status:** done (2026-10-25) within the blueprint's scope (L0–L1 both languages, L2–L3 Python). Decision: ADR-0015; the SAST rule below applies blueprint §11.3 as written. Abbreviated chapter.

## Built
- The extractor (`ts-imports.2`) records Python aliases, function calls and entry decorators.
- `callgraph.py`: call resolution through aliases, same-module and cross-module edges, breadth-first search from entry points to a vulnerable-symbol call.
- `vulnerable_symbols.yaml`: two PyYAML CVEs with `yaml.load` and friends. Loaded and validated at import.
- Tier `L3` (migration `c4f0a7e2d913`), wired through the classifier and pipeline. Evidence: symbol, sink function, chain.

## Verification
- `test_callgraph.py` (12): direct, aliased and from-imported calls; cross-file calls; module-level calls; a helper nothing reaches; a safe loader; and three blind spots (`getattr`, dict dispatch, call on a call result), each asserted "never L3".
- DB suite passes, including the migration round-trip.

## Session 7 additions (2026-10-25)
- **Semgrep findings mapped to their enclosing function (blueprint §10.2, §11.3).**
  - The extractor (`ts-imports.3`) records each Python function's line spans. Up to 8 per name, since methods in different classes can share a name.
  - `enclosing_function` returns the innermost span holding the finding's line, or `<module>` outside every function.
  - `reachable_functions` is the same call-graph breadth-first search as L3, factored out of `find_l3` (`_resolve` / `_bfs`), so both use one resolution.
  - A SAST finding whose enclosing function a resolved call path reaches from an entry point is **L3**, with the chain as evidence. Module-level code of a reachable module counts, because it runs on import.
  - A finding in a reachable file whose function no resolved path reaches stays **L2**, with the reason recorded (under-claim). JavaScript stays file-level.
- **Bug fixed:** Semgrep `generic.secrets.*` rules are now `secret` findings (family from the rule name; `live_credential` false, because a regex is not format validation). Their reachability is `n_a`, and they merge with Gitleaks and Trivy for the same key.
  - Kitchen-sink findings go from 31 to 29.
  - The private key is now one finding from three scanners, so deleting it "fixes" one finding, not two. When Gitleaks fails, the merged finding stays open even though Semgrep and Trivy succeeded.
- **UI:** the L3 tier appears in filters, the scan summary and the drawer ("Called in `fn` → `yaml.load`" / "In function").

## Verification (session 7)
- `test_callgraph.py` (+5): innermost span and nested functions; route → helper is L3 with chain `app.py:run → app.py:helper`; an uncalled function stays L2; no line means file-level; JS is never L3.
- `test_parsers.py` (+1): Semgrep secret typing and families. `test_merge.py`: three-scanner corroboration.
- DB: kitchen-sink Flask SAST is L3; no SAST finding is left `unknown`; history counts updated with the reason above.
- `test_migration.py` now starts from empty tables: the round trip checks the schema, and the L3 downgrade guard stays.

## Not done (out of the blueprint's P8 scope)
- JavaScript/TypeScript L3 and function mapping (the blueprint scopes L3 to Python).
- Function names are not qualified by class. Two methods with the same name in one file share call edges (an existing limitation, now documented).
