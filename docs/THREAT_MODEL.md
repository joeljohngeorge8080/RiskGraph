# RiskGraph — Threat Model (living document; v0.1 from blueprint 03, 2026-09-19)

This is the living threat model. `docs/blueprint/03_THREAT_MODEL.md` is the frozen
snapshot. Phase 15 ticks each mitigation with a test id; new threats are appended
with the next T-NN id and never renumbered.
Phase 15 verifies each mitigation with a test.

## Assets (what we protect)

| Asset | Sensitivity | Where |
|---|---|---|
| A1 Findings, secrets metadata, risk scores | Confidential (a map of an org's weaknesses) | Postgres, raw output files |
| A2 Repository contents during scan | Confidential, untrusted | Workspace volume |
| A3 Credentials: DB, Redis, JWT signing key, webhook secrets, LLM API key, GitHub token (Action side) | Critical | env / secret files |
| A4 Host machine (Docker daemon) | Critical | worker's socket proxy |
| A5 User accounts and sessions | High | Postgres, cookies |
| A6 Integrity of the risk model and graph | High (poisoning changes priorities) | DB, manifest |
| A7 Availability of the scan pipeline | Medium | Redis, worker |

## Actors

| Actor | Capability |
|---|---|
| T1 Repository contributor (malicious or compromised) | Controls files, commit history, manifest, Dockerfile, IaC in a scanned repo |
| T2 Anonymous Internet attacker | Reaches Caddy/API, webhook endpoint |
| T3 Authenticated low-privilege user (viewer/developer) | Valid JWT, wants escalation or data exfiltration |
| T4 Compromised scanner tool (upstream supply chain) | Code execution inside a scanner container |
| T5 Malicious webhook sender | Forged GitHub events |
| T6 LLM provider / model | Returns manipulated or hallucinated output |

## Attack surfaces

S1 webhook endpoint · S2 authenticated API · S3 git clone · S4 scanner
containers · S5 result parsers (JSON from untrusted tools processing untrusted
input) · S6 reachability parser (tree-sitter in worker) · S7 manifest parser ·
S8 LLM prompt/response · S9 dashboard (XSS surface for finding text) · S10
Docker socket proxy · S11 outbound HTTP (NVD/EPSS/KEV, Ollama, Anthropic) ·
S12 CI action (token in runner)

## Threats and mitigations

| ID | STRIDE | Threat | Surface | Mitigation (phase) | Residual |
|---|---|---|---|---|---|
| T-01 | E | Malicious repo exploits a scanner (e.g. crafted archive, regex bomb, parser bug) to execute code in the container, then escapes to the host | S4 | Isolation profile §9.3: non-root, cap-drop ALL, no-new-privileges, read-only FS, seccomp default, no network, no socket, pids/memory/cpu limits, pinned digests (P3, P4); gVisor upgrade path (P18) | Kernel 0-day escape; accepted, documented |
| T-02 | T/I | Scanner output is attacker-influenced (file paths with `../`, huge strings, control chars, HTML) → path traversal when the collector reads/writes, log injection, XSS in dashboard | S5, S9 | Collector only reads fixed `/out/<scanner>.json`; all paths from output are normalized and must resolve under the workspace or are stored as opaque strings never used for FS access; size caps (50 MB raw, 64 KB per field); React text rendering only; CSP (P5, P13) | — |
| T-03 | E | Command injection via repo name / ref / commit into git or scanner commands | S3, S2 | Never shell: container args as list; `ref` validated `^[\w./-]+$`, sha `^[0-9a-f]{40}$`; clone URL taken from the registered repository row, never from request/webhook payload (P3) | — |
| T-04 | S/T | Forged webhook creates scans or spoofs commits | S1 | HMAC-SHA256 with per-repo secret, `hmac.compare_digest`; delivery-id idempotency table; event allow-list; repository must already be registered; payload only supplies sha/ref/PR number (P14, P15) | Secret leak → forged scans (low impact: scans are of the registered repo) |
| T-05 | I | SSRF: attacker registers a repository whose clone URL points at internal services / cloud metadata | S3, S11 | Clone URL validated: https only, host allow-list (`github.com`), no IP literals, no redirects followed by our HTTP client; clone happens in the fetcher container on an egress-only network with no route to internal services (P3, P15); outbound HTTP client with fixed hosts for NVD/EPSS/KEV | — |
| T-06 | I | Secrets found by Gitleaks are stored and displayed in plaintext | A1 | Parser stores HMAC + masked form only; raw JSON redacted before persistence; `error_excerpt` redacted; logs never contain finding evidence (P4, P5) | Secret is still in the repo (the point of the finding) |
| T-07 | E/D | tree-sitter parse of hostile source crashes or exploits the worker | S6 | Parse in a subprocess with memory/time limits (`resource` rlimits), file size cap 2 MB, file count cap, timeouts; parsers are pinned versions; upgrade path: run reachability in a container (P8) | Parser memory-safety bug; accepted |
| T-08 | E | Docker socket proxy abuse from a compromised worker → host root | S10 | Proxy allow-list (create/start/wait/logs/kill/remove only); worker runs non-root in its own container; `container_spec.py` is the only mount builder, unit-tested to reject any path outside `/workspaces/<scan_id>` and `/scan_output/<scan_id>`; scan_id validated UUID (P3, P15) | Worker compromise still = host compromise via bind mounts; documented, mitigated by T-07 controls |
| T-09 | E | Privilege escalation via API: viewer changes finding status, developer manages users, IDOR on ids | S2 | RBAC in service layer, not routers; authorization tests per role × endpoint matrix; UUID v7 ids are not guessable enough to rely on — every read checks the caller may see that repository (P15) | — |
| T-10 | S | Credential stuffing / token theft | S2 | argon2id; login rate limit; 15-min access tokens; rotating refresh tokens with reuse detection; `HttpOnly` cookie for refresh; audit log of auth events (P15) | — |
| T-11 | T | Prompt injection via repo content (comments, commit messages, secret names) manipulates the AI explanation to say "safe" | S8 | Score computed before LLM; LLM sees EvidencePack only, snippets ≤ 5 lines in a labelled untrusted block; validator requires evidence ids and rejects unknown numbers/URLs; fallback template; UI plaintext (P12) | Misleading but validated prose; explanation is advisory by design |
| T-12 | T | Graph poisoning: contributor edits `riskgraph.yaml` to declare the service `isolated` / `read_only`, lowering scores | S7 | Manifest is in the repo → visible in PR diff; Action summary lists "context changes in this PR"; dashboard shows factor source (manifest vs IaC) with a conflict flag when IaC extraction disagrees with the manifest (P7, P14) | Social engineering of reviewers |
| T-13 | D | Resource exhaustion: huge repos, zip bombs, thousands of scan requests | S3, S2 | Clone size cap (blob filter + du check, default 500 MB), file count cap, per-container limits, scanner slot semaphore, rate limits, dedup of active scans per commit, queue depth alert (P3, P15) | — |
| T-14 | I | Information disclosure through error messages, logs, OpenAPI in prod | S2 | RFC 7807 with generic detail; structured logs redact known secret fields; `/docs` disabled or auth-gated in prod; `/metrics` internal only (P15) | — |
| T-15 | T | Supply chain: malicious scanner image or Python dependency | S4 | Pinned digests; lockfiles (`uv.lock`, `package-lock.json`); CI dependency + image scanning; Renovate/Dependabot; Semgrep rule packs vendored at a pinned commit (P1, P4, P18) | Upstream compromise before pinning |
| T-16 | R | Actions not attributable (who marked this false positive?) | A6 | `audit_logs` written in the same transaction for every mutation; includes actor, ip, before/after (P15) | — |
| T-17 | I | CI token leakage in the Action | S12 | Action uses `GITHUB_TOKEN` with `pull-requests: write` only; RiskGraph API key stored as GitHub secret; never printed; API key scopes limited to `scans:write scans:read` (P14) | — |
| T-18 | T | Redis/Postgres unauthenticated on the Docker network | infra | Passwords required, services not published to host in prod profile, Caddy the only exposed port (P18) | — |
| T-19 | S | CSRF on cookie-based refresh | S2 | Refresh cookie `SameSite=Strict`, path-scoped; all other auth via bearer header (not cookie) so CSRF does not apply to data endpoints; CORS allow-list (P15) | — |
| T-20 | D | Ollama/LLM unavailable or slow blocks scans | S8 | Explanation is a separate, optional stage; timeouts; scans never wait on it (P12) | — |

## Security invariants (tested in Phase 15/16)

1. No subprocess is ever invoked with a string command; only the Docker API with list args.
2. No file path derived from scanner output or repository content is opened by the worker outside the workspace root.
3. No raw secret value is persisted or logged (test: seed a known fake key, grep DB dump and logs).
4. Every mutating endpoint has an authorization test for all four roles.
5. Every outbound HTTP host is in a static allow-list.
6. Scanner containers cannot reach the network (test: scanner image runs `curl` → fails).
7. The LLM output validator rejects any claim without a valid evidence id (golden tests).

## MVP note (2026-10-21)

The MVP vertical slice (ADR-0009, ADR-0010, `docs/phases/PHASE_MVP.md`) runs scanners as subprocesses in the worker, not in isolated containers, and has no authentication.

- **T-01** residual risk is raised until the DockerRunner lands: scanner compromise = worker compromise.
- **Invariant 1** holds in a weaker form: no string commands; list argv via `SubprocessRunner` instead of the Docker API.
- **Invariant 6** (scanners cannot reach the network) does **not** hold yet.
- **Invariants 2, 3 and 5** are implemented and tested: `test_workspace.py`, `tests/e2e`, `test_context.py`.

Do not expose the API beyond localhost before Phase 2 (auth) and Phase 3 (DockerRunner).

## MVP level 2 note (2026-10-21): manifest context

ADR-0011 makes `riskgraph.yaml` an input to scoring, so the manifest becomes attacker-controlled input (the scanned repository is untrusted).

- **Parsing:** only fixed names at the repository root, read through `safe_resolve` (symlinks out of the checkout are ignored), 64 KiB cap, `yaml.safe_load`, aliases and nesting deeper than 8 refused before construction (billion laughs, recursion), strict schema with list caps, warnings length-capped. Tested in `tests/test_manifest.py`.
- **T-12 (graph poisoning)** is now live: a repository can under-declare its exposure to lower its own scores. Mitigations in place: every context factor shows `source = manifest` in the score breakdown, and the scan's Context panel lists every declared service. Not in place yet: an IaC-vs-manifest conflict flag (Phase 7).
- Manifest content is never logged; only its status and file name are.

## MVP level 2 extended note (2026-10-22)

ADR-0012 and ADR-0013, `docs/phases/PHASE_MVP2_EXT.md`.

- **T-07 (reachability parser):** now implemented as planned. tree-sitter runs in a separate process through `SubprocessRunner` with an address-space limit (RLIMIT_AS 2 GiB), CPU and file-size limits, a timeout, no network and `-I`. Files over 2 MB, binary files and symlinks are skipped. Repository code is never imported or executed.
- **T-12 (graph poisoning):** the manifest can now also link credential families to identities (`identities[].credentials`). Each link creates attack-graph edges, so under-declaring hides paths. Edges and factors carry their source.
- **T-16 (repudiation):** `audit_logs` records every triage change in the same transaction. The actor is `local` until Phase 2.
- **Invariant 3 (no raw secrets):** the e2e test now also covers `graph_nodes`, `graph_edges`, `attack_paths`, `reachability_results` and `audit_logs`.
