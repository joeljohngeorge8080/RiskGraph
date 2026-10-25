# ADR-0018: Runtime and image intelligence: EOL from a stored feed, image scans behind an allow-list

Status: accepted · Date: 2026-10-25 · Implements: expansion phase X2 (`docs/proposals/EXPANSION_A-D.md` §3.C, §4) · Builds on: ADR-0014 (container runner), ADR-0015 (feeds by Beat), ADR-0017 (evidence)

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
- `trivy image` and `syft` run on at most 5 allowed references per scan, each at most 2 GB. They use the ADR-0014 runner with its existing `egress` network mode, as the git fetcher does.
- A pull failure, a rate limit or the size cap is recorded as a warning and never fails the scan.
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
- (−) Kubernetes CronJob pod specs (under `jobTemplate`) are still not read by the IaC extractor, so their images are missed. This was already the case before X2.

## Rejected
- **A `container` source type** (plan §3.C). It needs one more migration and new scoring before X6, for findings that are package matches like SCA.
- **Pulling any registry the repository names.** That is server-side request forgery into the internal network.
- **Fetching EOL data during the scan.** The scan would wait on, and fail with, a third-party site; Beat plus `data_as_of` is the ADR-0015 pattern.
- **Attributing runtime findings to Trivy.** That claims provenance it does not have.
