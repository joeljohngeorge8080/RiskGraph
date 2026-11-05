# Tech stack: dependency log

Decisions and their runner-ups are in `docs/blueprint/04_TECH_STACK.md`. This file logs what was actually added, when, and why. Add a row in the same change that adds a dependency. Backend packages go in `backend/pyproject.toml` and are locked with `uv lock` (commit `uv.lock` with them). Scanner versions have one source of truth, `docker/scanner-versions.env`; bumping one means re-recording `backend/tests/fixtures/scanners/<tool>/`.

| Date | Component | Version | Where | Why |
|---|---|---|---|---|
| 2026-09-19 | FastAPI, SQLAlchemy 2, psycopg 3, Alembic, Celery + Redis, structlog, pydantic-settings | see `pyproject.toml` | backend | The blueprint stack (ADR-0002, ADR-0007, ADR-0008) |
| 2026-10-21 | httpx | ≥0.27 (runtime) | backend | Outbound EPSS/KEV client (`shared/http.py`); before this it was dev-only, for TestClient |
| 2026-10-21 | hypothesis | ≥6.100 (dev) | backend | Property tests for risk-model monotonicity (blueprint §07) |
| 2026-10-21 | pyyaml | ≥6.0 (declared) | backend | `riskgraph.yaml` manifest; already installed through `uvicorn[standard]` |
| 2026-10-21 | Trivy | 0.76.0 | scanner image | SCA, secrets, IaC misconfig (ADR-0009/0010) |
| 2026-10-21 | Semgrep | 1.182.0 | scanner image | SAST |
| 2026-10-21 | semgrep-rules | `17e31e11` | scanner image | Vendored rule set for when the registry is unreachable |
| 2026-10-21 | Checkov | 3.3.30 | scanner image | IaC misconfig |
| 2026-10-21 | Gitleaks | 8.30.1 | scanner image | Secrets |
| 2026-10-21 | git (Debian) | distro | `git-fetcher` image | Shallow clone of the scanned repository |
| 2026-10-22 | tree-sitter (+ python, javascript, typescript grammars) | 0.26 / 0.25 / 0.25 / 0.23 | backend | Reachability import extraction (ADR-0012) |
| 2026-10-22 | networkx | 3.7 | backend | Attack-path search, Yen k-shortest (ADR-0006, ADR-0013) |
| 2026-10-22 | types-networkx | dev | backend | mypy stubs |
| 2026-10-22 | httpx2 | 2.13.1 (dev, exact) | backend | Starlette's TestClient prefers it and warns on httpx. Its transitive `truststore` is held at 0.10.4, because 0.10.5 was under two weeks old |
| 2026-10-22 | certifi | 2026.10.19 | backend (transitive) | Fixes GHSA-6q48-6c7w-9gw2 (critical) found by the CI image scan |
| 2026-10-22 | cytoscape | 3.34.3 (exact) | frontend | Security graph view, lazy-loaded |
| 2026-10-22 | vitest | 5.0.3 (exact) | frontend | Fixes GHSA advisories in @vitest/mocker ≤ 5.0.2 |
| 2026-10-23 | docker (Python SDK) | ≥7.1 | backend | `DockerRunner` talks to the daemon through the socket proxy (ADR-0014) |
| 2026-10-23 | Syft | 1.54.1 | scanner image | SBOM (P5) |
| 2026-10-23 | tecnativa/docker-socket-proxy | 0.3.0, digest-pinned | compose | The worker's only route to the Docker daemon (ADR-0014) |
| 2026-11-05 | Joern | 4.0.671, base digest `f6b35cd1…` | `riskgraph/scanner-joern` (deep profile only) | Tier-2 taint for Python (ADR-0025). 3.6 GB; built only by `make scanner-images-deep` |

## Tooling pins (not runtime dependencies)
- CI actions are pinned by commit SHA, with the tag in a comment. The 2026-11-05 pass pinned the six that still used tags, at the commit their tag pointed to that day. A tag can be moved or removed upstream (it already happened once: `trivy-action@0.28.0`, session 5).
- Pre-commit: ruff matches the version `uv.lock` pins (0.16.8), and gitleaks matches the scanner (8.30.1). `pre-commit-hooks` is still v5.0.0 (v6.0.0 exists, not adopted).
