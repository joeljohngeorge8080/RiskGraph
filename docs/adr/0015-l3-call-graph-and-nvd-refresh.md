# ADR-0015: L3 reachability by intraprocedural call graph; NVD refreshed by Beat

Status: accepted · Date: 2026-10-23 · Implements: roadmap Phases 7 and 8 (blueprint §11.2, §11.3) · Builds on: ADR-0012

## Context
ADR-0012 stops at L2 ("imported by code reachable from an entry point"). Blueprint §11.3 defines L3 as "a known-vulnerable symbol is called on a call-graph path from an entry point", with a curated `vulnerable_symbols.yaml`. Separately, §11.2 says NVD outranks scanner-reported CVSS, but NVD's rate limit is 5 requests per 30 s without a key, which is too slow to call from a scan.

## Decision
### L3
- **Extraction.** For Python files the extractor (`ts-imports.2`) records the module's import aliases, each function's direct calls (as dotted names, e.g. `yaml.load`), and which functions carry a route or task decorator. Calls on call results, subscripts and `getattr` record nothing.
- **Resolution.** A call resolves through the module's aliases. A bare name resolves to a function in the same module, or, through an import, to a function in another project module (found through the import index). Only those edges exist.
- **Entry points.** Route and task-decorated functions, and the module-level code of any reachable module (it runs on import).
- **Claim.** A breadth-first search from the entry points reports L3 when it reaches a call to a symbol listed for the finding's CVE. The evidence is the symbol, the sink function, and the chain from the entry point. Confidence is medium.
- **Under-claim.** Dynamic dispatch (`getattr`, dict dispatch, calls on results), decorators that rewrite functions, and plugin loading are not resolved, so those findings stay at L2. `test_callgraph.py` pins each of these cases as "never L3".
- **Data.** `vulnerable_symbols.yaml` ships two PyYAML entries (`yaml.load`, `yaml.full_load`, `yaml.unsafe_load`). It is a starting list, not a catalogue. Malformed content is refused at startup.
- **Schema.** `ReachabilityTier` gains `L3`, with a migration that extends the CHECK list (`c4f0a7e2d913`).

### NVD
- NVD is fetched by a Beat job (`riskgraph.context.refresh_feeds`, hourly), one CVE per request, paced to the rate limit (6.5 s without a key, 0.7 s with one), and capped per run. A scan never calls NVD. It uses the cached score, or the scanner's CVSS when none is cached.
- An NVD score stored for a CVE takes precedence over scanner-reported CVSS, so a later scan does not overwrite it.
- A CVE NVD has no score for is still stamped as checked (negative cache), so it is not asked again every run.

## Consequences
- L3 is only as good as the symbol list and the resolution. The call graph covers Python only, as blueprint §11.3 scopes L3. JavaScript findings stay at L2 or below.
- Known gap: Semgrep's `generic.secrets` private-key rule is typed SAST, so its reachability comes out `unknown` where secrets should be `n_a`. It is covered by a scoped test, not fixed here.
- Not done: the Semgrep enclosing-function mapping from blueprint §10.2, and the frontend display of the L3 tier.
