# ADR-0012: Reachability tiers L0–L2 in the MVP (import graph, no call graph)

Status: accepted · Date: 2026-10-22 · Implements part of: roadmap Phase 8 (blueprint §11.3) · Amends: ADR-0011 (R no longer always unknown)

## Context
After ADR-0011, R (reachability) was the last factor still fixed at "unknown" (0.6). As a result:
- a CVE in a package the code never imports scored the same as one in the request path;
- likelihood stayed capped, so findings with full context topped out near 70.

The blueprint (§11.3) defines tiers L0–L3. L3 needs a Python call graph plus a curated `vulnerable_symbols.yaml`, which is out of scope for this slice.

## Decision
- **Extraction.** `modules/reachability/extract.py` parses Python, JavaScript and TypeScript with **tree-sitter**. Repository code is never imported or executed.
  - It runs as a **separate process** started by `SubprocessRunner`: argv list, `-I`, no network, timeout 300 s, RLIMIT_AS 2 GiB, CPU and file-size limits. `RunSpec.memory_limit` was added for this.
  - It is invoked through the `riskgraph-python` alias, the only argv[0] that resolves outside the scanner search path.
  - It walks the checkout without following symlinks; skips vendor and build directories; skips files over 2 MB, binary files and anything past 50k files; and uses iterative tree traversal, so deep nesting cannot overflow the stack.
- **Import graph** (`graph.py`). Internal imports resolve to repository files: Python dotted paths across candidate roots including relative imports; JavaScript relative specifiers with extension and `index` probing. Everything else becomes a third-party import name; the Python stdlib and Node built-ins are dropped.
- **Entry points:**
  - Python: route and task decorators, `__main__` guards, `manage.py` / `wsgi.py` / `asgi.py` / `urls.py`.
  - JavaScript: server constructors and route registrations, Next.js `pages/` and `app/` routes, `package.json` `main` / `bin` / `exports`.
  - Manifest `services[].entrypoints`.
  - The reachable set is a BFS from the entry points over internal imports.
- **Tiers.** For SCA findings the scope is the directory of the manifest file that declared the package:

| Situation | Tier | Confidence |
|---|---|---|
| imported by reachable code | L2 | medium |
| imported, but only by unreachable code | L1 | medium |
| imported, no entry points detected | L2 | low |
| a direct dependency never imported | L0 | high with a lockfile dependency graph, medium for `requirements.txt` |
| indirect dependency (Trivy `Relationship`/`DependsOn`) | the best tier of its direct ancestors | inherited |
| indirect with no known ancestor, unsupported ecosystem, or no parsed sources | unknown | — |

  - **SAST:** L2 if the file is reachable, L1 if it is parsed but unreachable while entry points exist, otherwise unknown.
  - **Secrets and IaC:** not applicable.
- **Never demote on missing evidence.** Packages used without imports (servers, CLIs, test and lint tools, Django apps listed in `INSTALLED_APPS`, Babel/ESLint plugins, and anything invoked from `package.json` scripts) are `unknown`, never L0. PyPI distribution names are mapped to import names through a curated table plus a normalized heuristic.
- **Model `v1-ctx.2`:**
  - R = L2 0.8, L1 0.5, L0 0.1, unknown 0.6 (§14.2), stored with source `reachability` and evidence (importers, entry chain, the ancestor it came via).
  - New §14.5 rule: **L0 with high confidence caps priority at Medium**, unless the CVE is in KEV (exploited in the wild wins).
  - Without reachability, scores equal `v1-ctx.1`.
- **Storage:** `reachability_results` (scan, finding, tier, confidence, evidence, analyzer_version).

## Alternatives considered
- **Python `ast` instead of tree-sitter:** rejected. It handles one language only, its parser recursion can be driven by hostile input, and the blueprint chose tree-sitter.
- **Call graph and L3 now:** deferred. It needs per-CVE vulnerable symbols; without them L3 would be guesswork.
- **Treat every non-imported package as L0:** rejected. Transitive dependencies and tools would be silently demoted; inheritance through the dependency graph and the "used without import" list prevent that.

## Consequences
- (+) **NodeGoat, live:** 92 SCA findings. Express's transitive CVEs (qs, send, path-to-regexp) inherit L2 through express. Packages used only by tooling are unknown. 4 are L0.
- (+) **Kitchen-sink fixture:** django L0 (never imported), requests L1 (only `scripts/legacy.py`), pyyaml L2 (a Flask route).
- (−) Dynamic imports (`importlib`, `require(variable)`), plugin systems and bundler aliases are blind spots. They yield fewer L2 tiers and more unknown, never L0 for imported code.
- (−) Medium-confidence L0 (`requirements.txt` without a graph) still uses R = 0.1. It does not trigger the ceiling.
- (→) L3 (Python call graph plus vulnerable symbols) and per-service scoping by manifest path are the next steps of Phase 8.
