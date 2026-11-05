# Joern spike (X4.0)

**Verdict: GO** for tier 2 on Python, against the gate in `docs/proposals/EXPANSION_A-D.md` §4 (X4).
Run on the owner's machine on 2026-11-02 (L-2). One caveat is not a gate item but must be handled
by the adapter: sanitized negatives (below).

## What was run
- **Image:** `ghcr.io/joernio/joern@sha256:f6b35cd1296f92070305fcc7cbdb2f113d26ea1920abcb303e1a6622c6b1ba2a`
  (the `linux/amd64` manifest of the `master` tag, index `sha256:e00e3def…ee37d7`; the registry has no
  release tags, only `master` and `nightly`). 3.65 GB on disk, 2.4 GB compressed; OpenJDK 17.
- **Profile (ADR-0014):** no network, `--read-only`, `--cap-drop ALL`, `no-new-privileges`, 65534 user,
  6 GB memory cap, pids 512, source mounted read-only, one container per case.
  **One deviation:** `/tmp` cannot be `noexec`. Joern's zstd library unpacks a native file into the
  Java temp dir and fails otherwise (`ZstdWrapper … mounted with noexec`). The runner keeps `/tmp`
  `noexec` and sets `JAVA_TOOL_OPTIONS=-Djava.io.tmpdir=/work/tmp` (the writable work mount).
- **Frontends:** `joern-parse --language pythonsrc` and `jssrc`. No build step.
- **Query:** `taint.sc` here. Sources are request data (Flask for Python, Express for JS). Sinks are
  the calls of the same five classes as `taint_catalogue.yaml`. Flows come from `reachableByFlows`.
  A flow is dropped when a catalogue sanitizer appears in its path.
- **Suite:** the 20 Python cases of the generated 40-case suite (`python -m evaluation.taint_suite
  write`): 5 classes × intraprocedural, cross-function, cross-file, sanitized. Scored with the same
  scorer as tier 1 (`evaluation.taint_suite.score`). Plus NodeGoat at `c5cb68a7084e`.

## Numbers
| Gate (plan §4, X4) | Needed | Measured | |
|---|---|---|---|
| Recall on interprocedural cases (cross-function and cross-file, 10 cases) | ≥ 0.6 | **1.00** (10/10; intraprocedural 5/5 too) | pass |
| Precision | ≥ 0.7 | **0.88** (2 false positives, 15 true) | pass |
| Peak RAM | ≤ 6 GB | **575 MB** worst suite case, **682 MB** worst case in any run (NodeGoat, JS) | pass |
| Time on NodeGoat | ≤ 10 min | **9.5–10.5 s** (parse and query, 50 JS files) | pass |

For comparison, tier 1 (Semgrep CE 1.182.0, own rules; L-4) on the same 20 Python cases scores
intraprocedural 5/5, cross-function **0/5**, cross-file **0/5**. So the "Semgrep CE scores ≈ 0 on
interprocedural cases" premise holds by measurement, and Joern fills exactly that gap.

Per case: 7.5–10 s wall (parse, load, query), 486–655 MB peak (cgroup `memory.peak` sampled while
the container ran).

## Limits and honest caveats
- **Sanitized negatives: 2 of 5 flagged (0.40); the plan §6 target is ≤ 0.2.** Both are allow-list
  lookups (`ALLOWED_URLS.get(request_arg)`, `TRUSTED_BLOBS.get(...)`): Joern's default data-flow
  semantics let taint pass from the key to the value of a lookup. The catalogue lists no sanitizer
  for CWE-502 and CWE-918, so a sanitizer list cannot fix it. The adapter needs either an
  "allow-list lookup" sanitizer class in the catalogue or custom semantics. `int()`, `shlex.quote`
  and `os.path.basename` sanitized correctly once the query looks for the sanitizer anywhere in an
  element's code (the first version missed `str(int(x))`: 3 of 5).
- The suite is synthetic and tiny (about 15 lines a case). It shows that Joern's engine reaches across
  functions and files; it says nothing about large repositories. NodeGoat has 50 JS files and 3
  flows (all `eval`, `contributions.js:32-34`, the same lines Semgrep reports). **Scaling is BELIEVE,
  not measured.**
- JavaScript was only run on NodeGoat for time and memory; it was not scored (the plan keeps tier 2 to
  Python first).
- No JVM tuning was done; Joern started with its defaults inside the 6 GB cap.
- Image pinning: the `master` tag moves. The digest above is what was measured. Pin that, or build an
  image from a Joern release archive with a checksum like the other scanner images.

## Fixtures
`backend/tests/fixtures/joern/master-f6b35cd1296f/`
- `python/<case>/sinks.tsv`: one line per flow, `class<TAB>sink file<TAB>sink line<TAB>steps`, steps
  `file:line;file:line;…` from source to sink (locations only; ADR-0021 stores no code).
- `nodegoat/sinks.tsv`, `python-summary.json` (time, peak MB, exit code per case),
  `python-semgrep-shaped.json` (the same flows as Semgrep-shaped results, for the scorer).
- The real tier-1 run is `backend/tests/fixtures/semgrep_taint/real-1.182.0-suite-run.json`.

## Reproduce
```
cd backend
uv run python -m evaluation.taint_suite write $DIR/suite
uv run python ../docs/auto/spikes/joern/run_spike.py $DIR/suite $DIR/out
```
The image is large; the pull needs about 3.7 GB of free disk.

## What the adapter (X4 part 2) can now build on
- Parse `sinks.tsv`-style lines into `taint_flow` evidence (steps); the flow assurance rule in
  SCHEDULE Day 3 (`verified` only when every step exists in the code graph) still needs its own check.
- Correlate with tier 1 at the same sink line (cross-file flows end in another file, e.g.
  `helper.py:14`, so the key is file and line of the sink).
- Open: how to model allow-list lookups (F-3-1 follow-up).
