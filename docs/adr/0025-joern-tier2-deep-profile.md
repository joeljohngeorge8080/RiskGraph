# ADR-0025: Tier-2 taint with Joern, in an opt-in `deep` scan profile

Status: accepted · Date: 2026-11-05 · Implements: expansion phase X4 part 2 (`docs/proposals/EXPANSION_A-D.md` §3.A, §4 X4, §5 "Joern tier 2 for Python only"), owner answer F-3-1 (a) · Builds on: ADR-0014 (container runner), ADR-0017 (evidence), ADR-0021 (taint catalogue and evidence contract)

## Context
Tier 1 (Semgrep CE, RiskGraph's own rules) sees a flow only inside one function. On the 20 Python cases of the taint suite it finds the intraprocedural 5/5 and the cross-function and cross-file cases 0/10 (L-4). The Joern spike (L-2, `docs/auto/spikes/joern/RESULT.md`) passed every gate: interprocedural recall 1.00, precision 0.88, peak 682 MB, NodeGoat in about 10 s. It failed the sanitized-negative target: 2 of 5 flagged (0.40 against ≤ 0.2). Both were allow-list lookups (`ALLOWED_URLS.get(arg)`).

## Decision
- **Scanner `joern`** (`modules/scanners/joern/`): adapter, parser, and RiskGraph's query `scanners/joern/taint.sc`, vendored into the image `riskgraph/scanner-joern:4.0.671`.
  - The image is built `FROM ghcr.io/joernio/joern@sha256:f6b35cd1…ba2a`, the digest measured in the spike. Upstream has no release tags, only `master` and `nightly`. The build fails unless the base image's `joern-cli` jar is the pinned `JOERN_VERSION`, and it writes `/opt/riskgraph/joern/VERSION`.
  - The image runs as 65534.
  - It is built only by `make scanner-images-deep` (3.6 GB).
- **One command, no shell.** `joern --script taint.sc --param src=… --param out=… --param lookups=… --param lang=py`. The script parses the checkout itself (`importCode`, PYTHONSRC) and writes JSON with locations only.
  - Joern puts its workspace under the working directory, so the scanner seam gains `Command.cwd`, and Joern runs from its private HOME, which is writable and mounted.
  - Joern unpacks a native library into the Java temp dir, so `JAVA_TOOL_OPTIONS=-Djava.io.tmpdir=<HOME>/tmp` is set. That is one more name on the container env allow-list.
  - The container `/tmp` stays `noexec`.
  - `Command.memory` sets its cap: `joern_memory`, default `3g`, validated as a Docker size.
- **Allow-list lookups sanitize** (the F-3-1 follow-up).
  - The catalogue gains `lookup_sanitizers.python`: a regex for a lookup in an UPPER_CASE module constant (`ALLOWED.get(x)`, `ALLOWED[x]`).
  - The query treats a flow that passes **through** such a lookup call (`get` or `<operator>.indexAccess`) as sanitized. The rule is structural: in `CONFIG["base"] + x`, the lookup is not on `x`'s path, and the flow stays.
  - The catalogue is the single source. The adapter passes the regex as one argv parameter, and the loader allows only a small character set.
  - Tier-1 Semgrep rules do not read it: they are unchanged, byte for byte.
- **Findings** are tier-2 SAST findings with the tier-1 rule id of their class (`riskgraph.taint.python.<class>`), severity as tier 1, and `analysis: interprocedural`.
  - There is one finding per (class, sink), keeping the shortest trace. Steps are capped at 50, and the sink is kept.
  - Redaction rebuilds the report from known keys only.
- **Correlation** needs no new code. The same rule id and sink line put a Joern hit in the same merge group as a tier-1 hit, and `merge._join_taint_hits` joins taint-only groups into the generic Semgrep finding at that sink. On the kitchen sink, both Joern hits join an existing Semgrep finding.
- **Evidence** is `taint_flow`, `inferred`, with `analysis: interprocedural` and location-only steps (ADR-0021).
  - SCHEDULE's "verified only when every step exists in the code graph" is not built.
  - Tier 2 is never `verified` here.
- **Scoring is unchanged.** ADR-0024's taint E row reads tier-1 hits only. A tier-2 hit is scored by the SAST row. A tier-2 E row is a risk-model decision that is left to the owner (see Consequences).
- **`deep` profile**, opt-in twice:
  - the deployment sets `RISKGRAPH_DEEP_PROFILE_ENABLED=true` (default off);
  - a scan request sends `"profile": "deep"`. Without the setting, the API answers 409 `deep-profile-disabled`.
  - A deep scan's runs and `enabled_scanners` include `joern`. `start_scan` enqueues the scanners the scan recorded.
  - **One slot:** Joern runs take a Redis lock of their own (`riskgraph:lock:joern`), as Trivy does, so one Joern runs on the machine at a time.
  - A request that deduplicates onto an active scan of the same repository and ref gets that scan, with the profile it was started with.
- Migration `d4e8b2c6f1a3`: `scanner_name` checks accept `joern`.

## Numbers (measured 2026-11-05, Joern 4.0.671, the adapter's exact command, ADR-0014 profile)
| | Plan §6 target | Spike (L-2) | Adapter |
|---|---|---|---|
| Interprocedural recall (10 Python cases) | ≥ 0.6 | 1.00 | **1.00** |
| Precision (Python) | ≥ 0.7 | 0.88 | **1.00** (15 TP, 0 FP) |
| Sanitized negatives flagged | ≤ 0.2 | 0.40 (2/5) | **0.00** (0/5) |
| Per case | | 7.5–10 s, ≤ 655 MB | 6–8 s |
| L-5: one deep scan through the pipeline's DockerRunner (20 cases in one repo) | ≤ 6 GB, ≤ 10 min | | **13.1 s, 592 MB peak**, 15 flows, scan COMPLETED, workspace removed |

There are also two hostile cases written for the lookup rule: `requests.get(CONFIG["base"] + request.args["p"])` is flagged, and `ALLOWED_URLS[request.args["v"]]` is not. Both are golden fixtures.

## Consequences
- (+) It covers the cross-function and cross-file gap that tier 1 cannot reach, with traces, and it adds nothing to default scans.
- (+) No new dependency in `pyproject.toml`. The image is a scanner image, like the others.
- (−) The image is 3.6 GB. Deep scans need it on the scanning host.
- (−) Python only. JavaScript, Java and Go stay deferred (plan §5). A JS-only repository gives an empty, successful run (measured on a JS suite case).
- (−) Sanitizers other than lookups match by name anywhere in an element's code (as in the spike): `"…" + str(int(a)) + b` treats the whole element as sanitized. That can hide a flow of `b`. Structural sanitizers for every class are a follow-up.
- (−) The suite is synthetic and small. Behaviour on large repositories is BELIEVE: one 40-file repository took 13 s.
- (?) For the owner: should a tier-2 flow raise E like a tier-1 flow (ADR-0024 table), or keep the SAST row? Today it keeps the SAST row.

## Rejected
- **`joern-parse` then `joern --script` in `sh -c`.** That builds a shell string, which CLAUDE.md forbids. One script run does both.
- **Pulling `master` at scan time.** The tag moves. The digest pins what was measured.
- **Custom data-flow semantics for `dict.get`.** They would apply to every `.get`, including ones on request data. The constant-receiver rule is narrower, and the catalogue names it.
- **A separate slot pool for deep scans.** A Redis lock per scanner already exists (Trivy) and gives exactly one slot.
