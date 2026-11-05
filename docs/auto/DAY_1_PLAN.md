# Day 1 plan (Mon 2026-10-26): X2 part 2 + X3 part 1

Start state: branch `extended_phase_auto` at `f056a4f`, level with origin. Baseline run before any edit (VERIFIED): ruff, format and mypy clean (208 files); 386 unit passed; 66 db passed, 2 skipped (real scanners absent). No earlier day to catch up on; no flags.

## Read
`CLAUDE.md`, `HANDOFF.md` (top), `todo1150.md`, `docs/auto/{RUNBOOK,SCHEDULE,FLAGS,LOCAL_TASKS}.md`, plan `EXPANSION_A-D.md` §3.C, §3.D, §4 rows X2/X3, §8; ADR-0018, ADR-0014 (via `containers.py`), ADR-0017 (via `evidence/contract.py`, `graph/attack.py`); `PHASE_X2.md`; code: `scanners/{base,runner,containers,docker_runner,registry}.py`, `scanners/trivy/{adapter,parser}.py`, `scans/{pipeline,orchestration,tasks,storage,workspace,reaper,finding_evidence}.py`, `runtime/{images,eol,__init__}.py`, `normalization/{merge,fingerprint,canonical}.py`, `findings/history.py`, `sbom/{models,service}.py`, `context/{iac,environment}.py`, `graph/{attack,models}.py`, `tests/pipeline_support.py`, `tests/fixtures/images/record.py` and both recorded reports.

## Found while reading (fix first, it blocks step X2.2 in the container runner)
`TrivyScanner.command()` puts `TRIVY_CACHE_DIR` in the environment (X2 part 1, for freshness), but `containers.ALLOWED_ENV` does not list it, so `build_create_kwargs` raises `ContainerSpecError` and **every Trivy run fails under the docker runner**. Tests only used the subprocess runner. Fix: allow the variable; test: every registered adapter's command env passes the container env check.

## X2 part 2: scan the images the repository names
Acceptance (plan X2 exit criteria 2–3): the recorded fixtures parse (OS and language packages, fixed versions); every image finding has an advisory id, installed/fixed version and `data_as_of`; a failing or refused ref gives a warning and the scan still completes. Criterion 4 (+90 s per image warm) is the owner's L-3.
Out of scope: Syft for images (ADR-0018 amendment), image nodes in manifest graphs, risk factor changes (X6).

Analogs: `run_scanner` (stage shape, runner, lock, classify), `TrivyScanner.command` (argv style), `trivy.parser._vulnerability` (parsing), `runtime.eol.runtime_findings` (own findings), `FixtureRunner` (fake runner), `20261025_1600_runtime_eol.py` (migration).

| # | Step | Proving test |
|---|---|---|
| 0 | `TRIVY_CACHE_DIR` allowed in scanner containers | `test_containers`: every adapter command env passes `build_create_kwargs` |
| 1 | `TrivyScanner.image_command(paths, settings, ref, output)`: the `record.py` flags (`image --image-src remote --format json --list-all-pkgs --scanners vuln --cache-backend memory --skip-db-update --skip-java-db-update --skip-version-check --disable-telemetry --exit-code 0 --quiet`), `--cache-dir`, `--timeout`, `--output`, `--max-image-size` (BELIEVE: flag exists in 0.76; L-3 checks it) and the ref last; network egress | unit: argv golden; ref never parsed as a flag (refs starting with `-` are refused by `parse_ref` already: test it) |
| 2 | Stage `scan_images` between `collect` and `analyze` (canvas, inline runner): only when the Trivy run SUCCEEDED; allowed refs sorted, at most `image_scan_max_refs` (5); each through the runner with the Trivy lock and container fields; reports redacted and stored under `scan_output/<scan>/images/<k>.json` plus `index.json` (ref, status, warning, duration); size cap checked again from `Metadata.Size`; never fails the scan; idempotent (index present → nothing to do); touches `updated_at` per image so the reaper does not take a long image stage for a dead one | db: fixture ref scanned, unknown ref → warning, scan COMPLETED; refused (internal registry) ref never run; cap of 5; trivy failed → stage skipped with a warning; unit: canvas order |
| 3 | `trivy.parser.parse_image(doc, ref, declared_in)`: `sca` findings, `package.image`, `attrs.image {ref, os, target}`, location = declaring file with resource = ref; fingerprint and SCA merge key scoped by image **only when an image is present** (existing keys unchanged); reachability `n_a` for image findings; evidence kind `image_package` | unit: both fixtures (OS + language packages, fixed versions, advisory id, data_as_of); same CVE in two images = two findings; existing fingerprints unchanged (golden) |
| 4 | SBOM: nullable `image` on `sbom_components`, unique key `(scan_job_id, purl, image)` with NULLS NOT DISTINCT; image inventory from `Results[].Packages`; API adds `image` per component and an optional `origin` filter (default all) | migration up/down/up + `alembic check`; db: image packages listed with `image`, old fields unchanged |
| 5 | `Metadata.OS.EOSL == true` → `runtime` finding `runtime-eol:os:<family>:<name>`, high, producer `riskgraph`, evidence `eol`, `data_as_of` = report `CreatedAt`; same interim score | unit: node:14 gives it, python:3.8-slim does not |
| 6 | Freshness: image evidence carries the scan's Trivy DB time; history: an image finding becomes `fixed` only if its image was scanned in this scan | db: pull failure on the 2nd scan does not mark image findings fixed |

## X3 part 1: a graph without a manifest
Acceptance: a repository with Compose/Kubernetes and no `riskgraph.yaml` gets ≥ 1 inferred path (fixture repo in tests); Hypothesis property: co-located findings with no edge rules give 0 paths; existing X1 tests unchanged.
Out of scope: endpoint nodes (the extractor yields entrypoint labels, not routes: X5), assurance-grouped API and `missing_evidence[]` (day 2), image nodes for manifest graphs.

Analog: `graph/attack.py` (one pure `analyze`), its tests `test_attack_paths.py`, `test_graph_assurance.py`.

| # | Step | Proving test |
|---|---|---|
| 7 | Pure `graph/topology.py`: derived services from Compose services and Kubernetes workloads (joined by name, as `environment.py` already does), only when the manifest has no services; code path from the Compose build context; images per service (Compose/K8s `image:` verified; last `FROM` of a Dockerfile under the code path inferred); ServiceAccount and RBAC privilege | unit: compose + k8s fixture assets → expected services, images, accounts |
| 8 | Edges with declaration/`rbac_binding` evidence from the IaC file: EXPOSES (inferred), RUNS_IMAGE (verified/inferred, not traversable), RUNS_AS (ServiceAccount named in the pod spec: verified; implicit `default` or a Compose↔K8s name join: inferred; none: unknown identity, inferred), CONTAINS_SECRET for secrets in the code path; RBAC privilege makes the identity a sink | unit: every edge has evidence; assurance per the table |
| 9 | EXPLOIT onto a derived service from code findings in its path and image findings on its images; edge assurance = min(finding's tier assurance, exposure assurance); image findings: hypothesis, inferred only if KEV; candidate order assurance → p → index. Image findings never join a manifest service's EXPLOIT pool (that would change manifest graphs) | unit: fixture repo → inferred path internet → api → admin SA; KEV vs non-KEV image; manifest graphs byte-identical |
| 10 | Pipeline passes the IaC assets and image refs into the graph | db: fixture repo scan has the path; summary counts |
| 11 | Property test (Hypothesis): random co-located findings, no IaC, no manifest → 0 paths; random derived topology with no sink → 0 paths | unit |

## Close
Lint, types, unit, db; migration up/down/up + `alembic check`; X0 evaluation (all scenarios have a manifest, so I expect no differences: CONFIDENT); self-attack; `DAY_1_REPORT.md`, `PHASE_X2.md` part 2, `PHASE_X3.md`, ADR-0018 amendment (stage details), ADR-0019 (topology-derived graph), HANDOFF, todo1150, LOCAL_TASKS (L-3 plus the `--max-image-size` check).

## Risks and decisions
- `--max-image-size` is not in `record.py`. If Trivy 0.76 lacks it, every image run fails with a warning (never the scan). Post-check on `Metadata.Size` stays either way. Local task.
- The reaper fails scans with no progress for an hour; 5 images × 300 s timeout fits, and the stage touches the scan per image.
- **Flag F-1-1 (expected):** Compose services that run a database image (postgres, mongo, …) as `data_store` nodes, and with what sensitivity: the plan does not say, and sensitivity drives sink impact. Not built; without it a Compose-only repository has no sinks.
- **Flag F-1-2 (expected):** the plan's CAN_ACCESS from RBAC bindings has no target in the graph (a cluster role names API resources, not services or data stores). Not built; the binding sets the identity's privilege (sink), and its evidence rides on RUNS_AS.
