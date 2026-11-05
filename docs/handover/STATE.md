# Where RiskGraph stands (handover, 2026-11-05)

Branch `extended_phase_auto`, pushed, with PR #3 open to `main` (see "Owner items" below). PR #2 (`mvp-level2-integration`) and #1 were never merged; #3 contains them. Labels: VERIFIED (run and checked), CONFIDENT (read in code), BELIEVE (expected, not measured).

## Verified at handover
- Backend: ruff, format and mypy clean (247 files).
- Tests: **759 unit** (`make test`), **86 db** (`make test-db`; 2 e2e skipped: no host scanners), 4 perf.
- Migrations: up, down to base and up again on a fresh database; `alembic check` clean; head `d4e8b2c6f1a3`.
- Frontend: eslint and tsc clean (one line changed in `types.ts`; no UI work in this handover).
- X0 replay: byte-identical with and without the last scoring change (F-5-1).

## What is built
| Area | Phase chapters | Decisions |
|---|---|---|
| Blueprint P0–P1: spec, threat model, skeleton | `PHASE_00`, `PHASE_01` | ADR-0001…0008 |
| MVP: scan a public GitHub repo, four scanners, merge, score, UI (**no auth**) | `PHASE_MVP` | ADR-0009, 0010 |
| Level 2: manifest context, reachability L0–L2, attack paths, triage, history, CI gate | `PHASE_MVP2`, `PHASE_MVP2_EXT` | ADR-0011…0013 |
| P3–P12: DockerRunner, pinned scanner images, SBOM, IaC/K8s topology, L3, graph invariants, path search, risk API, AI explanations | `PHASE_03`…`PHASE_12` | ADR-0014…0016 |
| X0: baseline evaluation (frozen) | `PHASE_X0`, `docs/evaluation/BASELINE.md` | |
| X1: evidence and assurance on every edge | `PHASE_X1` | ADR-0017 |
| X2: runtime EOL, image scanning | `PHASE_X2` | ADR-0018 |
| X3: graph from Compose/Kubernetes, assurance-aware paths, credential links | `PHASE_X3` | ADR-0019, 0020 |
| X4: tier-1 taint (Semgrep, opt-in) and **tier-2 taint (Joern, opt-in `deep` profile)** | `PHASE_X4` (parts 1–3) | ADR-0021, **0025** |
| X5: route inventory, guards, authorization findings, `authz.public` | `PHASE_X5` | ADR-0022, 0023 |
| X6: risk model v2, foothold-only effective impact | `PHASE_X6` | ADR-0024 |
| X8 (part): evaluation harness and run book; authz scenario I | `docs/evaluation/EVALUATION_RUNBOOK.md` | |

**Not built:** X7 (dashboard/reporting) and the rest of X8. Blueprint P2 (auth) and P13–P19 are also not built. All of these are in `BACKLOG.md`.

## Done in the handover session (2026-11-05)
| Item | Result | Commit |
|---|---|---|
| F-4-2 `authz.public` | Unguarded-sensitive precision 3/5 → 3/3 with the forms declared (the code-only number stays pinned) | `04d0dc0` |
| F-5-1 foothold-only I* | Only findings that are themselves at least inferred **and** a foothold take a path's effective impact. X0 unchanged (measured) | `4295244`, `5333439` |
| F-3-1 Joern adapter | Python tier 2, opt-in `deep` profile, one slot. Suite: recall 1.00, precision 1.00, sanitized FP 0/5. L-5: 13.1 s, 592 MB | `84f0183` |
| F-4-1 authz evaluation | Scenario I, labels committed first; 7 TP / 1 FP / 0 FN | `99ae3ca`, `fd3dbb4` |
| X8 harness | `make eval-expansion(-full)`: 5 PASS, 3 FAIL, 5 NOT RUN, each NOT RUN with what it needs | `24dea05` |
| Tooling | CI actions pinned by SHA; pre-commit aligned with the locked ruff and gitleaks; dependency log filled | `1c82fb3` |

## Evaluation today (`docs/evaluation/EVALUATION_EXPANSION.md`)
- **PASS:** A2 taint precision 0.80; B1 authz precision 0.90; B2 inventory recall 0.968; B3 BOLA always a hypothesis; D2 scenario H 0 paths.
- **FAIL, as measured:**
  - A1, interprocedural recall 0.50: JavaScript has no tier 2. Python alone is 1.00.
  - A3, sanitized FP 0.50: all from tier 1. Its rules lack the allow-list sanitizer that tier 2 has.
  - P1, X0 ranking: pooled nDCG@10 0.991 against 0.162 for M2. But every method ties within each scenario, so the pre-registered paired test gives p = 1.00.
- **NOT RUN:** C1, D1, D3, P2 ablations, O1 overhead. How to build each one is in the run book.

## Owner items (decide; not engineering tasks)
- **Merge PR #3** (`extended_phase_auto` → `main`, opened 2026-11-05). CI is green on all four jobs (backend, frontend, images, security-self-scan), so the SHA pins are verified. #3 contains #1 and #2, which can be closed after the merge.
- **Tier-2 exploitability.** Should a Joern flow raise E the way a tier-1 flow does (ADR-0024 table), or keep the SAST row? Today it keeps the SAST row (ADR-0025, "Consequences").
- **P2 auth** has not started. The MVP has no authentication: keep every deployment on localhost until P2 is built.
- **The nightly cloud routine** (`docs/auto/RUNBOOK.md`) fires next on 2027-10-25. Disable it if nobody wants it.
- **The `graphify-out/` files** are rewritten by a post-commit hook on every commit. They were committed once at handover.

## Machine notes (the previous owner's machine; yours will differ)
- Ports on that machine came from `.env`: 15432/16379/18000/15173, because other projects use the defaults. `.env.example` uses the defaults.
- Images present there: the five scanner images, `riskgraph/scanner-joern:4.0.671` and its 3.6 GB base. The disk was 97 % full.
- The dev DB was migrated to `b8d3f1a6c2e9`. The next `make dev` applies `d4e8b2c6f1a3` (scanner name `joern`).

## Gotchas that cost time before (keep these; full list in `HISTORY.md`)
1. `make dev` and `make test-services` bind the same ports. Run one at a time, or the dev postgres comes up without a network and `migrate` fails to resolve `postgres`.
2. Scanner containers write files as uid 65534. Remove workspaces through `discard_workspace` (it widens modes in a container first), never with `rm`. Joern's workspace is the same.
3. `/tmp` is a small tmpfs on the dev machine. Test temp trees are removed at exit by `conftest`.
4. `make eval-baseline` and `make eval-expansion-full` empty `riskgraph_test`. They refuse any database not named `*_test`.
5. The host `ruff` on PATH is ancient. Always use `uv run ruff` (or `make lint`).
6. Mounting `./backend:/app` shadows the image venv. Compose mounts only `riskgraph/`, `alembic/`, `alembic.ini` and `tests/`; add a mount line per new top-level backend folder.
7. One active scan per repository and ref: a test that leaves a scan `SCANNING` makes later scans dedupe onto it. A deep request also dedupes onto an active default scan.
8. Sourcing the whole `.env` breaks `cors_origins`. Export variables by name when you run scripts against the dev DB.
9. Joern needs `java.io.tmpdir` under its HOME (the container `/tmp` is `noexec`) and a writable cwd. The adapter sets both (ADR-0025).
