# ADR-0018: Runtime and image intelligence: EOL from a stored feed, image scans behind an allow-list

Status: accepted · Date: 2026-10-25 · Implements: expansion phase X2 (`docs/proposals/EXPANSION_A-D.md` §3.C, §4) · Builds on: ADR-0014 (container runner), ADR-0015 (feeds by Beat), ADR-0017 (evidence) · Interim EOL score replaced by ADR-0024 (risk v2)

## Context
Gaps G4–G6: images were never scanned, runtime versions were never read, and advisory freshness was never recorded. Three questions were open, and the owner decided them on 2026-10-25:
1. Image vulnerabilities: plan §3.C names a new `container` source type, but §2.4 and the X1 migration added only `runtime` and `authz`.
2. Image pulls need network access, and the untrusted repository chooses which images are named.
3. Runtime EOL findings need a score before risk v2 (X6) defines runtime factor tables.

## Decision
**Image references.**
- Image references are collected from Dockerfile `FROM` lines (with line numbers; stage names and `scratch` are skipped), Compose `image:`, and Kubernetes `containers[].image` and `initContainers[].image`.
- Each reference is stored as a `container_image` asset, with its origin, whether it may be scanned, and the reason when it may not.
- A reference is **allowed** only when it is well formed, has no unresolved `$VAR`, and is on a public registry: `docker.io`, `ghcr.io`, `quay.io`, `gcr.io`, `registry.k8s.io`, `mcr.microsoft.com` or `public.ecr.aws`. Any other host (an internal registry, `localhost`, an IP address) is recorded and never pulled. The repository must not be able to make the worker contact the internal network.

**Image scanning (X2.2).**
- `trivy image` runs on at most 5 allowed references per scan, each at most 2 GB. It uses the ADR-0014 runner with its existing `egress` network mode, as the git fetcher does.
  - *Amendment 2026-10-25:* the plan also named a Syft image SBOM. Syft is **not** given network: its image has no CA certificates (a registry pull fails TLS verification), and fixing that would widen a second tool's network access for no gain. `trivy image --list-all-pkgs` already lists every OS and language package with its PURL, so that report is the image inventory. One pull per image, not two. Recorded in `backend/tests/fixtures/images/`.
- A pull failure, a rate limit or the size cap is recorded as a warning and never fails the scan.
  - *Amendment 2026-10-26 (X2 part 2, how it runs):* a stage `scan_images` runs between `collect` and `analyze` on the scan queue, because it starts containers. It is idempotent: its `index.json` is written last, and a redelivered message does nothing.
  - It needs a successful Trivy run in the same scan, for the vulnerability DB and freshness. Without one, every reference is skipped with a warning.
  - References are taken sorted; the first 5 allowed ones are scanned, and the rest are listed as skipped.
  - Each scan takes the Trivy lock and gets `timeout_trivy_image_s` (300 s). No image is started after a budget of 5 × 300 s plus one lock wait. A cancelled scan stops before the next image.
  - Flags are those of `tests/fixtures/images/record.py`, plus `--max-image-size 2147MB` and `--timeout`. `Metadata.Size` is checked again on the report.
  - Reports are redacted like Trivy's own and stored as `scan_output/<scan>/images/<k>.json`.
  - Findings are `sca` with `package.image` and the declaring file as location (the image is the resource). They are fingerprinted and merged per image, so the same CVE in two images is two findings; repository packages keep their keys.
  - Their evidence is `image_package`, with the Trivy DB date and no raw pointer, because the run's stored report is not where they came from.
  - `Metadata.OS.EOSL` gives `runtime-eol:os:<family>:<name>`, dated by the report's creation time.
  - An image finding becomes `fixed` only when its image was scanned again.
  - Image packages are in `sbom_components` with a nullable `image` (migration `b8d3f1a6c2e9`; unique per scan, purl and image, NULLs not distinct). `GET /scans/{id}/sbom` adds `image` and an optional `origin` filter (default `all`).
- Image package vulnerabilities keep `source_type = sca` and are marked with the image (target and reference). They are package-versus-advisory matches like today's SCA, so the EPSS, KEV and CVSS scoring already applies. Reachability is "not assessable" for image packages, because the code that uses an OS package is not analyzed. The plan's separate `container` source type was not adopted.

**Runtimes and EOL.**
- `modules/runtime` reads runtime declarations. **Exact pins** (`.python-version`, `runtime.txt`, `.nvmrc`, an exact `engines.node`, and the tag of an official `python`, `node` or `golang` image) can produce findings.
- **Ranges and minimums** (`requires-python`, an `engines.node` range, the `go` line in `go.mod`) are recorded and never produce a finding. They state what the code supports, not what runs.
- EOL data comes from endoflife.date (`/api/{product}.json` for `python`, `nodejs` and `go`). It is fetched by a daily Beat task (`riskgraph.runtime.refresh_eol`) into `runtime_eol` with its fetch time, and is never fetched on the scan path. `endoflife.date/api/` is added to the outbound allow-list. A failed product keeps its last data.
- A scan reads the stored cycles. An exact declaration of an ended cycle becomes a `runtime` finding: rule `runtime-eol:<product>:<cycle>`, severity high, the advisory `endoflife.date/<product>/<cycle>`, the matched cycle, a fixed version (the oldest cycle still supported), the EOL date and `data_as_of` (the feed's fetch time). With no stored data there is no finding. The scan summary says which products had data.

**Producer for RiskGraph's own findings.**
- A finding must name a scanner and a run (`finding_occurrences.scanner_run_id` is NOT NULL). `ScannerName.RISKGRAPH` (`riskgraph`) is the producer of findings RiskGraph derives itself: runtime EOL now, authorization in X5.
- The analysis stage creates one `riskgraph` run per scan, idempotently, with status SUCCEEDED, version `runtime.1` and no stored report.
- It never appears in the Celery canvas and is never collected or parsed.
- It is **excluded from the scan's final status**, so a scan whose scanners all failed is still FAILED, not PARTIAL. It counts as succeeded for fixed-detection.
- Migration `a7c2e9f4b1d6` adds the value to both `scanner_name` CHECKs and creates `runtime_eol`. Its downgrade refuses while `riskgraph` rows exist.

**Interim score for runtime EOL (model `v1-ctx.3`, replaced in X6).**
- E = 0.5: no security fixes, but no specific exploitable flaw is known from the EOL alone.
- T = 0.6.
- Reachability does not apply. Exposure, data and privilege context apply as for any finding.
- `v1-ctx.3` also records X1's change: effective impact only from paths of at least `inferred` (ADR-0017). No version bump was made in X1; this one covers both.

**Freshness.**
- `TRIVY_CACHE_DIR` is now in Trivy's command environment, so the existing `trivy --version` run reports the vulnerability DB build time. The analysis reads `UpdatedAt` from that run's log in the scan workspace.
- That time becomes `data_as_of` on every Trivy `package_match` evidence, and `summary.freshness.trivy_db`.
- EOL evidence carries the feed's fetch time, and `summary.freshness.eol` is the oldest fetch time used.

## Consequences
- (+) Every known-vulnerability finding from C can say which advisory, which version and as of when.
- (+) An untrusted repository cannot point the worker at internal hosts through image references.
- (−) Runtime EOL scores are a placeholder until X6.
- (−) Declared ranges never produce a finding: "supports 3.8+" on a 3.12 runtime is not a problem, and 3.8 actually running is only known from an exact pin or an image.
- (−) The `riskgraph` run appears in the scan's run list with no report. That is honest, but it is one more row.
- (−) EPSS and KEV fetch times are not yet part of `summary.freshness` (they are on each vulnerability row).
- (+) Trivy's `Metadata.OS.EOSL` flag gives end-of-support for the base OS image with no feed (for example `node:14` on Debian 10).
- (−) Kubernetes CronJob pod specs (under `jobTemplate`) are still not read by the IaC extractor, so their images are missed. This was already the case before X2.

## Rejected
- **A `container` source type** (plan §3.C). It needs one more migration and new scoring before X6, for findings that are package matches like SCA.
- **Pulling any registry the repository names.** That is server-side request forgery into the internal network.
- **Fetching EOL data during the scan.** The scan would wait on, and fail with, a third-party site; Beat plus `data_as_of` is the ADR-0015 pattern.
- **Attributing runtime findings to Trivy.** That claims provenance it does not have.
