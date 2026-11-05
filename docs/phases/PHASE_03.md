# PHASE 3: Scanner orchestration engine (hardened DockerRunner)
**Status:** done for the scope below (2026-10-23). Decision: ADR-0014. Abbreviated chapter: the A–S sections are condensed here, the decision record is the ADR.

## A. Objective
Run every scanner as a container under the blueprint §9.3 profile, reach the daemon only through a socket proxy, and support cancel, slot limits and lost-worker recovery.

## B. Why
ADR-0009's subprocess runner gives a hostile repository's tool the worker's privileges. Containers with a fixed profile are the isolation the threat model (T-01…T-05) assumes.

## C–E. Architecture and decisions
- `DockerRunner` implements `ScannerRunner`; `containers.py` is the profile; `slots.py` is the concurrency cap; `docker_runner.make_removable` and `widen_own_directories` handle cleanup of container-owned files.
- Scanner paths are identical inside and outside the container; the worker maps them to host paths (`RISKGRAPH_HOST_DATA_DIR`).
- Trivy DB refresh is a separate, trusted task.
- Socket proxy: pinned `tecnativa/docker-socket-proxy:0.3.0` by digest, `CONTAINERS`, `IMAGES`, `POST` only.

## F. Folder structure
`backend/riskgraph/modules/scanners/{containers,docker_runner,slots,tooldb,tasks}.py`, `scanners/<name>/Dockerfile`, `infrastructure/scripts/build-scanner-images.sh`, `docker-compose.yml` (socket proxy, egress network).

## G. Database
Migration `5c1e0a9d2f47`: `scan_status` gains `CANCELLED`; cancelled scans are a terminal state.

## H. API
- `POST /api/v1/scans/{id}/cancel` → 202; 409 if the scan has already finished.

## I. Algorithms
- Slot acquire: one Lua script over a sorted set with expiry scores, so the check and add are atomic.
- Reaper: runs `RUNNING` longer than twice the longest scanner timeout → `TIMED_OUT`; scans with no progress for an hour → `FAILED`.

## J. Implementation notes
- The SDK surfaces a wait timeout as a generic connection error, so the runner polls container state instead.
- The clone's `rev-parse` step runs in a subdirectory of the mounted workspace; the profile check accepts working directories under a mount.

## K. Commands
`make scanner-images` builds the pinned images. `make dev` creates the egress network and sets the host paths before `docker compose up`.

## L. Configuration
`RISKGRAPH_SCANNER_RUNNER` (`subprocess` | `docker`), `RISKGRAPH_HOST_DATA_DIR`, `RISKGRAPH_HOST_TRIVY_CACHE_DIR`, `RISKGRAPH_SCANNER_MAX_SLOTS` (default 4).

## M. Testing
- `test_containers.py` (16) profile and refusals; `test_docker_runner.py` (7) control flow with a fake daemon; `test_runtime_db.py` cancel, reaper and slots against Postgres and Redis; no live-daemon test is in the repo yet. The smoke test (uid 65534, no capabilities, read-only source, no network, timeout kill) was run by hand against this host's daemon.

## N. Security
Profile in ADR-0014. Residual: `POST /containers/create` binds through the proxy (host-compromise path from a worker compromise); seccomp is Docker's default profile, not an explicit file.

## O. Validation
Live `make dev` on NodeGoat: five scanners ran as containers, COMPLETED, 124 findings, zero residue after cleanup.

## S. Open items
gVisor runtime; Kubernetes runner; `docker-socket-proxy` config tested only on this host's daemon.
