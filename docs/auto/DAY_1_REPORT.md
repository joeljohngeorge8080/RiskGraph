# Day 1 report (Mon 2026-10-26): X2 part 2 + X3 part 1

**Verdict: COMPLETE.** Every planned step is built, tested and pushed. Two items are flagged instead of guessed (F-1-1, F-1-2). Three checks need the owner's machine (L-3, L-8, L-9).

Start `f056a4f`; commits today, in order:

| Commit | What |
|---|---|
| `d701718` | Day 1 plan |
| `1f6f069`, `62e7c50` | `TRIVY_CACHE_DIR` allowed in scanner containers (bug found while reading), and its test type |
| `e82138a` | `trivy image` command, image parser, OS EOL finding, image-scoped keys, `image_package` evidence |
| `86bb13c` | `scan_images` stage, analysis of image results, SBOM `image` (migration `b8d3f1a6c2e9`), fixed detection per image |
| `78cc007` | Graph from Compose and Kubernetes without a manifest; perf test repaired |
| `e657214` | Derived names cut to fit the key column (self-attack) |
| (this commit) | ADR-0019, ADR-0018 amendment, `PHASE_X2.md` part 2, `PHASE_X3.md`, flags, local tasks, handoff |

Note on authorship: `d701718` was committed under the sandbox's default git identity, before I saw that the probe commit used the run book's fallback identity. Every later commit uses `Joel John George <hmacommunicationsteam@gmail.com>`. The plan commit cannot be rewritten without a force push, which the rules forbid.

## Per plan step
| # | Step | Result | Label |
|---|---|---|---|
| 0 | Trivy env in containers | Fixed; a parametrized test over all 5 adapters, which failed for Trivy before the fix | VERIFIED (reproduced, then green) |
| 1 | `trivy image` command | Recorded flags, `--max-image-size 2147MB`, `--timeout 270s`, ref last; option-shaped refs refused | VERIFIED (unit). That 0.76.0 accepts `--max-image-size`: BELIEVE (L-8) |
| 2 | Stage `scan_images` | Canvas `collect → scan_images → analyze` (scan queue), idempotent index, cap 5, no-Trivy skip, cancel stops pulling, per-image progress for the reaper; never fails the scan | VERIFIED with the fake runner. A real pull in a container: UNVERIFIED (needs the owner's machine, L-3) |
| 3 | Parse into `sca` findings | Both fixtures: python:3.8-slim 24 findings (debian + python-pkg), node:14 debian + node-pkg; image in `package`/`attrs`; keys scoped by image; repository keys unchanged; reachability n/a | VERIFIED |
| 4 | SBOM `image` column | Migration up/down/up on a fresh DB, `alembic check` clean; API `image` + `origin`; old fields unchanged | VERIFIED |
| 5 | EOSL base OS | `runtime-eol:os:debian:10.13` for node:14, none for python:3.8-slim; `eol` evidence dated `2026-10-25T12:33:56.623859Z` | VERIFIED |
| 6 | Freshness, history | `image_package` evidence carries the Trivy DB time; a failed pull leaves image findings open. Removing the guard makes that test fail (mutation check) | VERIFIED |
| 7 | Topology | Compose + Kubernetes + Dockerfile → services, images (verified/inferred), accounts, RBAC privilege | VERIFIED |
| 8 | Edge rules | EXPOSES inferred, RUNS_IMAGE, RUNS_AS verified/inferred/unknown, CONTAINS_SECRET; every edge has recorded evidence | VERIFIED |
| 9 | EXPLOIT | Code and image findings; ≤ inferred; image = hypothesis unless KEV; best-assured first; manifest pools untouched | VERIFIED |
| 10 | Pipeline | db test: inferred path internet → app → `identity:sa:app-sa` through the API | VERIFIED |
| 11 | Properties | Co-located findings, no rules → 0 paths (150 examples); derived services without a sink → 0 paths (60) | VERIFIED |

## Test output (run at the end of the day, after the last code commit)
```
$ uv run ruff check . && uv run ruff format --check . && uv run mypy
All checks passed!
223 files already formatted
Success: no issues found in 213 source files
$ uv run pytest -m "not db and not docker and not e2e and not perf and not llm" -q
421 passed, 83 deselected, 1 warning in 10.91s
$ uv run pytest -m "db and not llm" -q
77 passed, 2 skipped, 425 deselected, 1 warning in 99.85s (0:01:39)
$ uv run pytest -m perf -q
2 passed, 502 deselected, 1 warning in 17.21s
$ alembic upgrade head; downgrade -1; upgrade head; check (fresh database)
Running upgrade a7c2e9f4b1d6 -> b8d3f1a6c2e9 … Running downgrade b8d3f1a6c2e9 -> a7c2e9f4b1d6 … Running upgrade a7c2e9f4b1d6 -> b8d3f1a6c2e9
No new upgrade operations detected.
```
- The 2 skipped db tests are e2e tests that need the real scanners (`/opt/scanners/bin`).
- The 1 warning is Starlette's `BlockingPortal` deprecation, which predates today.
- Start of day, for comparison: 386 unit, 66 db.

## Evaluation (X0)
The graph changed, so I re-ran the evaluation.
- Today's report is **byte-identical** to a run of the start-of-day commit `f056a4f`, made in a separate worktree and database.
- The **pooled table is identical to `BASELINE.md`**.
- The only differences from `BASELINE.md` are the ones already recorded:
  - the model line (`v1-ctx.2` → `v1-ctx.3`, X2 part 1);
  - C's AWS key moving from rank 1 to 6 in the M4 top 10 (X1's intended hypothesis change).
- Expected: every X0 scenario has a manifest, so the derived topology never applies. The evaluation's runner has no image fixtures, so no image findings appear. VERIFIED.
- `BASELINE.md` was not touched.

## Self-attack
1. **Hostile input: long names.**
   - A 160-character Compose service name (the extractor's own cap) plus the `service:` or `identity:sa:` prefix overflows `graph_nodes.key VARCHAR(160)`. The analysis of that repository would have failed.
   - Reproduced with a test; fixed by cutting derived names to 120 characters (`e657214`).
   - Lookups still use the full name. That was a second bug the test caught while I fixed the first.
2. **Ordering/state: a pull failure looked like a fix.** Fixed detection only checked that Trivy succeeded, so a failed image pull would have marked every image finding of the previous scan `fixed`. Guarded and mutation-tested.
3. **Cancellation:** a scan cancelled during the image stage kept pulling the remaining images. The progress touch now stops the loop (test).
4. **Assurance inflation:** an L3 finding on a service whose exposure is only inferred would have made a verified path. EXPLOIT is now capped at inferred (test).
5. **Justified, not fixed:**
   - An image named in two files is attributed to the first one (references are deduplicated by canonical name). Display only; the keys stay stable.
   - Multi-stage Dockerfiles ending in `FROM <stage>`: the last named image may be a builder. The edge is only inferred, and this is written in ADR-0019.

## UNVERIFIED (needs the owner's machine)
- A real `trivy image` pull through the docker runner, the 2 GB cap and the overhead per image (L-3).
- `--max-image-size` on Trivy 0.76.0 (L-8).
- Trivy (fs) under the docker runner after the env fix (L-9).

## New flags and local tasks
- **F-1-1 (OPEN):** data stores from Compose and their sensitivity. Needed for NodeGoat's path (plan X3 criterion); recommendation (a).
- **F-1-2 (OPEN):** CAN_ACCESS from RBAC has no target node. Recommendation (a): keep privilege on the identity.
- **L-8, L-9** added; L-3 now has code to run.

## For Day 2
- **X3 part 2** starts from `graph/attack.py`:
  - `analyze(..., topology=)` and `_derive`;
  - `PathResult.assurance`;
  - `out.paths` sorted by score only. Grouping by assurance is the API's job (`graph/router.py`, `list_paths`).
- `missing_evidence[]` needs, per hypothesis edge, what would prove it:
  - AUTHENTICATES_AS: a manifest link;
  - an image-finding EXPLOIT: "reachability of the package in the image is not assessable";
  - L1/unknown EXPLOIT: an L2+ chain.
- The perf test now runs (0.083 s search at 5k/20k). Extend it with derived and image nodes.
- `F-1-1` blocks nothing on Day 2. Do not build data stores from Compose unless it is ANSWERED.
- The test DB is at head `b8d3f1a6c2e9`.
