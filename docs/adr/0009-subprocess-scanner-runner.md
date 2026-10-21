# ADR-0009: MVP runs scanners as subprocesses in the worker

Status: accepted · Date: 2026-10-21 · Amends: blueprint §9.3 (container isolation) for the MVP only

## Context
The MVP slice (scan a GitHub repo with Trivy, Semgrep, Checkov and Gitleaks, normalize, merge, score, show in a web UI) was requested ahead of the roadmap's Phase 3 (DockerRunner, socket proxy, hardened per-scanner images). Building the container sandbox first would delay the first usable increment by about two weeks. The development container used for this work also has no Docker daemon, so a container runner could not be verified there.

## Decision
- The four scanner binaries are installed into the worker image (`docker/backend.Dockerfile`, target `worker`; `/opt/scanners`). The versions are pinned in `docker/scanner-versions.env`, and release tarballs are checksum-verified by `infrastructure/scripts/install-scanners.sh`.
- `modules/scanners/runner.py` (`SubprocessRunner`) runs each scanner with these guarantees:
  - argv is a list and no shell is ever used. A `str` argv raises `TypeError`.
  - The binary name is resolved from a fixed search path.
  - Environment variables come from an allow-list. Proxy and CA variables are passed only to egress commands (`git`, `trivy`).
  - stdin is closed, the child runs in its own session, and it is killed as a process group on timeout.
  - rlimits are set: no core dumps, CPU limit, file-size limit.
  - The working directory is the scan's read-only checkout.
- Adapters only see `ScanPaths` and return a `Command`. The runner is a `ScannerRunner` protocol, so the blueprint's `DockerRunner` can replace it without touching adapters, parsers or the pipeline.
- `git clone` goes through the same runner with these settings:
  - `core.hooksPath=/dev/null`, `core.symlinks=false`, `protocol.allow=never` (https only), no credential helper, no redirects, `--depth 1`, no submodules.
  - The URL is rebuilt from a validated `owner/name`.
  - `.git` is deleted after cloning, then size and file-count caps are checked.
- Trivy runs are serialized with a Redis lock (its cache DB is shared).

## Alternatives considered
### Blueprint DockerRunner now (§9.3): deferred
This is the right end state: no network, read-only root, cap-drop ALL, seccomp, pinned digests. It is the next security step. It was deferred only for schedule reasons, and because it cannot be verified in the current development container.
### bubblewrap / `unshare --net` around each subprocess: deferred
Cheap network isolation, but it needs user namespaces, which are often disabled in containers. It would be another unverified moving part.

## Consequences
- (−) **Residual risk T-01 is higher than in the blueprint.** A scanner exploited by a malicious repository runs as the worker uid. It can read the worker's `/proc/<pid>/environ` (including the database URL and secret key), reach the network and write the data volume. Mitigations: the env allow-list, non-root uid 10001, the read-only checkout, and the API bound to localhost.
- (−) Scanner images are not separately pinned by digest. The worker image pins tool versions instead.
- (+) One worker image; `make dev` works on any Docker host; the pipeline is verifiable without Docker.
- (→) **Trigger:** before RiskGraph is reachable from anything other than localhost, before scanning untrusted repositories on a shared host, or before adding users, implement `DockerRunner` (roadmap Phase 3) behind `ScannerRunner` and remove the binaries from the worker image.
