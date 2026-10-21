# Tech stack — dependency log

Decisions and their runner-ups live in `docs/blueprint/04_TECH_STACK.md`. This file is the log of what was actually added, when, and why.

| Date | Component | Version | Where | Why |
|---|---|---|---|---|
| 2026-10-21 | httpx | ≥0.27 (runtime) | backend | Outbound EPSS/KEV client (`shared/http.py`); previously dev-only for TestClient |
| 2026-10-21 | hypothesis | ≥6.100 (dev) | backend | Property tests for risk-model monotonicity (blueprint §07) |
| 2026-10-21 | Trivy | 0.76.0 | worker image `/opt/scanners` | SCA, secrets, IaC misconfig (ADR-0009/0010) |
| 2026-10-21 | Semgrep | 1.182.0 | worker image (uv tool venv) | SAST |
| 2026-10-21 | semgrep-rules | `17e31e11` | worker image | Vendored rule set when the registry is unreachable |
| 2026-10-21 | Checkov | 3.3.30 | worker image (uv tool venv) | IaC misconfig |
| 2026-10-21 | Gitleaks | 8.30.1 | worker image `/opt/scanners` | Secrets |
| 2026-10-21 | git (Debian) | distro | worker image | Shallow clone of the scanned repository |

Scanner versions have a single source of truth, `docker/scanner-versions.env`. Bumping one means re-recording `backend/tests/fixtures/scanners/<tool>/`.
