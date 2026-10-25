# RiskGraph expansion A–D: architecture decision and phased plan

Status: **proposed, awaiting owner approval** · Date: 2026-10-25 · Branch at writing: `mvp-level2-integration` @ `08d5181`

Scope: four capabilities on top of the unchanged base layer (Trivy, Semgrep, Gitleaks, Checkov, Syft):
- **A** deep code-level analysis;
- **B** business-logic and authorization analysis;
- **C** runtime and vulnerability intelligence;
- **D** evidence-backed chaining.

Nothing here is implemented yet. On approval, the decisions in §2 become ADR-0016 (and later ADRs), following the "do not re-decide an ADR" rule.

Evidence labels: **VERIFIED** (checked in the repo or a primary source this session), **CONFIDENT** (strong inference), **BELIEVE** (memory, unchecked), **GUESS**.

---

## 1. Audit: what exists, and where A–D plug in

### 1.1 Existing functionality (VERIFIED by reading the code at `08d5181`)

| Area | What exists | Where |
|---|---|---|
| Execution | Hardened scanner containers (read-only, no network, caps dropped, uid 65534, mem/pids limits), socket proxy, slot semaphore, reaper, cancel | `scanners/docker_runner.py`, `containers.py`, ADR-0014 |
| Trivy | `trivy fs --scanners vuln,secret,misconfig` on the checkout **only**. DB updates are skipped at scan time | `scanners/trivy/adapter.py` |
| Syft | Repository SBOM → `sbom_components`; Trivy SCA findings attached by canonical purl; `GET /scans/{id}/sbom` | `modules/sbom` |
| Semgrep | Community engine 1.182.0 with the pinned `semgrep-rules` commit | `scanners/semgrep/adapter.py`, `docker/scanner-versions.env` |
| Normalization | Canonical findings, per-scanner fingerprints, curated cross-scanner merge keys (secret families, IaC topics), severity mapping | `modules/normalization` |
| Intel | EPSS and KEV (TTL cache, fetched during analysis); NVD CVSS by hourly Beat job; NVD outranks scanner CVSS | `context/feeds.py`, ADR-0015 |
| Context | `riskgraph.yaml` manifest; Compose exposure; Kubernetes Service/Ingress/RBAC joined per workload (session 7). Precedence manifest > Kubernetes > Compose | `context/{manifest,iac,environment}.py` |
| Reachability | tree-sitter extractor in a sandboxed subprocess; import graph; entry points from route/task decorators; tiers L0–L2 (Python, JS/TS), L3 for Python through a call graph and `vulnerable_symbols.yaml` (2 PyYAML entries) | `modules/reachability`, ADR-0012/0015 |
| Graph | Per-scan `graph_nodes`/`graph_edges` in Postgres plus NetworkX. States: internet, service, identity, data_store, credential. Edges: EXPOSES, RUNS_AS, CAN_ACCESS, CONNECTS_TO, CONTAINS_SECRET, AUTHENTICATES_AS, EXPLOIT | `graph/attack.py`, ADR-0006/0013 |
| Paths | Yen k=3 per sink, ≤ 8 hops, `w = −ln p`, at least one attack edge, `score = 100·∏p·I(sink)`; effective impact I* (two-pass scoring) | `graph/attack.py`, `risk/model.py` |
| Risk | Model `v1-ctx.2`: geomean(E, X, R) × mean(T, D, P, C), §14.5 overrides; every factor stored with source, confidence and evidence | `modules/risk` |
| Provenance | Raw reports kept per scanner run and downloadable; `finding_occurrences` per scanner | `scans/storage.py`, `findings/models.py` |

### 1.2 Gaps that matter for A–D

| # | Gap | Impact on |
|---|---|---|
| G1 | **Graph edges have no assurance level.** An edge carries `probability` and finding ids, but "declared in the manifest" and "guessed from a name match" look the same. The credential-family link and the Kubernetes name mapping are inferences stored like facts | D (blocking) |
| G2 | **No generic evidence record.** Evidence is ad-hoc JSONB per factor, edge or reachability row. There is no stable id, no producer version, no `data_as_of`, and no pointer into the raw report | A, B, C, D |
| G3 | **Paths are built only from the manifest.** Compose and Kubernetes facts reach finding factors but create no graph nodes or edges. Without `riskgraph.yaml`, NodeGoat has an empty graph | D |
| G4 | **No container image or OS package analysis.** Trivy never runs `image` or `rootfs`. Dockerfile `FROM`, Compose `image:` and Kubernetes `containers[].image` are not collected as assets | C |
| G5 | **No runtime/interpreter identification or EOL data.** `.python-version`, `runtime.txt`, `engines.node`, `.nvmrc` and `FROM python:3.x` are not read | C |
| G6 | **Advisory freshness is not recorded.** Trivy's DB build time is not stored with the scan, so a finding cannot say "matched against advisories as of …" | C |
| G7 | **Semgrep taint is intraprocedural** (a Community Edition limit, see §4.A) and the rule set is generic. There is no interprocedural or inter-file data flow anywhere | A |
| G8 | **Semgrep findings are not mapped to their enclosing function** (blueprint §10.2, open since P8). There is no function node to hang a flow on | A, D |
| G9 | **No authorization model.** The extractor records route decorators but not auth decorators, dependencies or middleware. The manifest has `auth: required` per service, not per route | B |
| G10 | **Known bug:** Semgrep's private-key rule is typed SAST, so its reachability is `unknown` instead of `n_a` | scoring hygiene |
| G11 | P9–P11 definition-of-done tests are missing: scenario A–E fixtures, Hypothesis monotonicity, the 5k-node perf budget, graph invariants (`unknown-identity` RUNS_AS) | evaluation baseline |
| G12 | **Licensing exposure in the current base layer.** The pinned `semgrep-rules` content is under the Semgrep Rules License v1.0: internal business use only, no distribution, no offering as a service ([Semgrep licensing](https://semgrep.dev/docs/licensing), [rules license](https://semgrep.dev/legal/rules-license)). Baking it into a distributed image is fine for this self-hosted project and a thesis. It is **not** fine if RiskGraph is ever shipped or hosted for third parties. Rules written for A and B must be RiskGraph's own (Apache-2.0) | A, B, deployment |

Other open items still apply (P2 auth not built, P12 AI not built). The expansion increases the stakes of P2: a deeper analyzer is more attack surface behind an unauthenticated API.

---

## 2. Architecture: options and the decision

### 2.1 Options compared

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| **O1. Extend the modular monolith.** New analyzers run through the existing `ScannerAdapter` + `DockerRunner` (tools) or the sandboxed extractor subprocess (RiskGraph's own analysis). Everything emits one shared evidence contract into the existing pipeline, Postgres and graph | One runtime, one isolation profile, one DB and backup, reuses fingerprints, risk and graph code; testable as pure functions; matches ADR-0001 | Pipeline `analyze` (787 lines) grows; deep analysis lengthens scans | **Chosen** |
| O2. Separate microservices (deep-code service, authz service, intel service) | Independent scaling and failure isolation | A solo developer operating four services; cross-service consistency; contradicts ADR-0001 with no load to justify it | Rejected |
| O3. Adopt an aggregation platform (DefectDojo, or a commercial ASPM) and put RiskGraph on top | Mature dedup and UI | Replaces the part that *is* the thesis (normalization, context, paths); adds a heavy dependency | Rejected |
| O4. LLM-driven analysis ("ask a model to find auth bugs and chains") | Broad coverage on paper | Not reproducible, unverifiable, invents relationships; violates "AI narrates, never decides" (blueprint §15) | Rejected as a detector. AI stays the P12 explanation layer |

### 2.2 Graph storage (re-evaluated, not assumed)

| Option | Fit for A–D | Verdict |
|---|---|---|
| **Postgres tables + NetworkX (current, ADR-0006)** | A–D add node kinds (endpoint, function, image, os_package, runtime) but stay per-scan. Taint flows are stored as evidence on edges, not as the whole CPG. Expected size ≤ 10⁴ nodes per scan (CONFIDENT: the function nodes added are only those on flows or holding findings) | **Keep.** Add an `assurance` column and an evidence join table |
| Neo4j Community | Cypher is nice for exploration | Second stateful service (RAM on a 15 GB host that already runs other stacks), GPLv3 server, no algorithm we need that NetworkX lacks | Rejected (same reasons as ADR-0006, and still true) |
| Apache AGE | One store with Cypher | Needs a custom Postgres image; driver maturity unverified (BELIEVE) | Deferred to the ADR-0006 trigger (cross-scan, org-wide graph) |
| Keeping the Joern CPG as the system graph | Rich code semantics | It is a code graph, not an attack graph; the JVM stays resident; it can't hold IAM, data or network facts | Rejected. The CPG is a transient analysis artifact; only flows leave it |

**Decision:** keep ADR-0006. The re-check trigger stays the same (> 10⁶ edges, or cross-scan multi-hop queries). Phase X3 adds a performance gate.

### 2.3 Recommended architecture

```
                    existing base layer (unchanged)                    new, same runner & sandbox
clone ─► [trivy fs] [semgrep CE] [gitleaks] [checkov] [syft dir]  │  [trivy image ×N]  [syft image ×N]   (C)
         └───────────── chord of hardened containers ─────────────┤  [joern-taint]                     (A, deep profile)
                                                                  │  extractor subprocess (+auth facts) (B)
                                    ▼                             ▼
   normalize ─► fingerprint/dedup ─► correlate ─► EvidenceStore (one contract: Evidence, Relationship, Assurance)
                                                        │
          context (manifest, k8s, compose, runtime EOL) ┤
          reachability (L0–L3) ─────────────────────────┤
          authz analyzer (route inventory, policy diff) ┤
                                                        ▼
                         graph builder (typed facts → nodes + assured edges, invariant: edge ⇒ evidence)
                                                        ▼
                         attack paths (Yen, assurance-aware) ─► risk v2 (I*, only from ≥ inferred paths)
                                                        ▼
                         API / dashboard / CI gate ─► P12 explanation (EvidencePack, read-only narration)
```

The four words below stay separate, in code and in the UI:
- **Normalization:** one tool's output → canonical findings (`normalization/canonical.py`).
- **Deduplication:** the same issue from the same tool, within and across scans (fingerprints).
- **Correlation:** the same issue from different tools, merged with provenance kept (merge keys). For example, a Semgrep intraprocedural taint hit and a Joern flow that end at the same sink line become one finding with two occurrences, and the corroboration factor K applies.
- **Chaining (attack paths):** *different* weaknesses linked by evidenced relationships into a path. A chain never merges findings, and co-occurrence alone never creates an edge.

### 2.4 Module boundaries and interfaces

New modules follow `modules/<domain>/{router,service,repo,schemas,models,tasks}.py`. Cross-module imports go only through `__init__`.

| Module | New or changed | Responsibility | Public interface |
|---|---|---|---|
| `modules/evidence` | **new** | The shared contract and its storage. Owns no analysis | `Evidence`, `Relationship`, `Assurance`, `RawRef`, `persist_evidence()`, `evidence_for(finding_id \| edge_id)` |
| `modules/scanners/joern` | **new adapter** | Joern in a hardened container, `ScannerAdapter` like the other five | `command()`, `parse() → RawFinding[] + Evidence[]` (flow steps) |
| `modules/scanners/trivy` | changed | Adds an `image` target mode next to `fs`; reports DB metadata | `ImageTarget`, `db_metadata()` |
| `modules/runtime` | **new** | Runtime/interpreter identification, EOL matching, image inventory and deployment linkage (C) | `identify_runtimes(workspace) → RuntimeDecl[]`, `image_refs(iac, dockerfiles) → ImageRef[]`, `eol_status()` |
| `modules/authz` | **new** | Route inventory, auth-guard detection, policy diff, BOLA heuristics (B) | `route_inventory(extract) → Route[]`, `analyze(routes, policy) → AuthzFinding[] + Relationship[]` |
| `modules/reachability` | changed | The extractor also emits auth decorators and dependencies, function spans (fixes G8), and route parameters | `ts-imports.3` extraction schema |
| `modules/graph` | changed | New node and edge kinds; every edge carries `assurance` and evidence ids; assurance-aware search | `build(facts) → Graph` (refuses an edge with no evidence), `paths(graph, policy)` |
| `modules/risk` | changed | Model `v2`: runtime, taint and authz factor tables; I* only from paths with assurance ≥ inferred | `score(inputs) → RiskScore` (unchanged signature) |
| `modules/context` | changed | Advisory freshness (Trivy DB time, NVD/EPSS/KEV fetch times) exposed per finding | `freshness(scan) → Freshness` |

**Shared data contract (Python, frozen dataclasses; Pydantic at the API edge):**

```python
class Assurance(StrEnum):
    VERIFIED = "verified"      # stated by an artifact we parsed: a manifest declaration, an RBAC binding,
                               # an exact lockfile version in an advisory range, a taint flow whose every
                               # step exists in the code graph
    INFERRED = "inferred"      # a documented rule applied to verified facts, with a known gap:
                               # name-matched k8s↔compose, published port ⇒ internet, import-level reachability
    HYPOTHESIS = "hypothesis"  # a pattern suggests it; no artifact supports it: a route with an {id} param and
                               # no ownership check, a credential family matching an identity with no link

@dataclass(frozen=True, slots=True)
class RawRef:                  # provenance: where in the stored raw report this came from
    scanner_run_id: UUID
    pointer: str               # RFC 6901 JSON pointer into the raw report, or "extractor:<file>#<span>"

@dataclass(frozen=True, slots=True)
class Evidence:
    id: str                    # sha256(producer, kind, canonical payload), stable across re-analysis
    producer: str              # "trivy@0.76.0", "joern@<pinned>", "riskgraph.authz@1"
    kind: str                  # package_match | taint_flow | route | auth_guard | rbac_binding |
                               # declaration | runtime_version | image_package | eol
    assurance: Assurance
    confidence: Literal["high", "medium", "low"]   # within the assurance tier
    locations: tuple[Location, ...]
    steps: tuple[FlowStep, ...] = ()               # ordered source → sink, for flows and chains
    raw: RawRef | None = None
    observed_at: datetime                          # when RiskGraph produced it
    data_as_of: datetime | None = None             # advisory DB build or feed fetch time (freshness)

@dataclass(frozen=True, slots=True)
class Relationship:
    source: str; target: str; kind: EdgeKind
    assurance: Assurance
    evidence_ids: tuple[str, ...]                  # non-empty: enforced by the graph builder
    p: float | None = None                         # attacker transition probability, attack edges only
```

**Storage (one migration in X1, hand-reviewed):**
- `evidence` (scan-scoped, `id` text PK per scan, JSONB payload, `assurance`, `producer`, `data_as_of`);
- `finding_evidence` and `edge_evidence` link tables;
- `graph_edges.assurance` (NOT NULL; existing rows backfilled by the documented rule);
- the `source_type` CHECK gains `runtime` and `authz` (taint stays `sast`, with `analysis = 'interprocedural'` in properties).

**Secure execution.**
- Joern and `trivy image` run under the ADR-0014 profile. Repository code is parsed, never built or executed: Joern's Python and JS frontends need no build (CONFIDENT); compiled-language frontends that would need a build are out of scope.
- `trivy image` pulls only image references named in the repository, from public registries, through the existing egress network, with a size cap. Trivy reads layers as data and never runs them (CONFIDENT).
- Private registries and credentials are out of scope.

---

## 3. Technical designs

### A. Deep code-level analysis

**Engines evaluated**

| Engine | Detection depth | Languages | License / usage | Integration | Verdict |
|---|---|---|---|---|---|
| Semgrep CE taint mode (already present) | Intraprocedural only: CE "can only analyze interactions within a single function" ([Semgrep docs](https://semgrep.dev/docs/semgrep-code/semgrep-pro-engine-data-flow)). Cross-file is Pro-only (`--pro`, `interfile: true`) | broad | engine LGPL; registry rules internal-use only (G12) | zero new tools | **Keep as tier 1** with RiskGraph-authored taint rules for the frameworks the extractor already knows (Flask, FastAPI, Django, Express) |
| Semgrep Pro (interfile) | Cross-function and cross-file | 8 languages listed ([docs](https://semgrep.dev/docs/semgrep-code/semgrep-pro-engine-intro)) | proprietary, paid, separate binary | easy | Rejected: cost, not redistributable, results not reproducible for examiners without a licence |
| CodeQL | Best-in-class interprocedural taint | many | Permitted for academic research and for open-source codebases. **Prohibited** with a codebase that is not open source; automated/CI database generation only for open-source code hosted on GitHub.com; no sharing or hosting of the software, unless paid GHAS ([CodeQL terms](https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md)) | heavy: ~1 GB bundle; compiled languages need a build (BELIEVE) | **Rejected as an integrated engine**: a self-hosted platform that scans arbitrary repositories cannot meet those terms. **Allowed as an offline research oracle** in X8 evaluation ("academic research") to estimate Joern's recall on the open-source test apps |
| **Joern** | Interprocedural, inter-file taint over a code property graph (`reachableByFlows` returns the flow steps) | C/C++, Java, JS, Python, Kotlin, PHP, Go, Ruby, Swift, C# with varying maturity ([docs.joern.io](https://docs.joern.io/)) | **Apache-2.0** ([repo](https://github.com/joernio/joern), VERIFIED) | JVM container; Scala query scripts; no build for Python/JS | **Chosen as tier 2**, gated by a spike (X4.0) |
| Custom summary-based taint on the existing tree-sitter call graph | Interprocedural for Python; RiskGraph already resolves calls (ADR-0015) | Python first | own code | moderate, fully controllable | **Fallback** if the Joern spike fails its gate, and it stays the L3 engine regardless. As a primary engine it is a research project in itself, and a homemade data-flow engine is the scope trap most likely to swallow the expansion |

**Design.**
1. **Tier 1 (default profile).** Ship `rules/riskgraph-taint/*.yaml`: RiskGraph-authored taint rules for sources (`request.args`, `request.json`, FastAPI params, `req.query`/`req.body`) and sinks (SQL `execute` with string building, `subprocess`/`os.system`, `open`/`send_file` with joined paths, `pickle.loads`/`yaml.load`, SSRF clients). Semgrep runs them in the same container as today.
2. **Tier 2 (`deep` profile, opt-in per repository or via `riskgraph.yaml` `analysis: deep`).**
   - The Joern container runs `joern-parse` and then a pinned script that loads RiskGraph's source/sink catalogue (the same catalogue as tier 1, generated from one YAML so the two tiers cannot drift).
   - It emits JSON flows: `[{sink, source, steps:[{file, line, method}], cwe}]`.
   - Limits: memory 6 GB (GUESS, measured in the spike), 15 min timeout, a file-count cap, and no network.
3. **Normalization.**
   - Each flow becomes one SAST finding with `analysis: interprocedural`, `cwe`, and an `Evidence(kind=taint_flow, steps=…)`.
   - Assurance is `verified` when every step resolves to a function span in the extractor output; otherwise `inferred`.
   - The fingerprint is (rule family, source location, sink location), so a re-scan dedupes.
4. **Correlation.** A tier-1 hit and a tier-2 flow with the same sink line and CWE family merge into one finding with two occurrences (K applies); tier 2 adds the cross-function steps. This also closes G8: every finding gets an enclosing function from the extractor spans.
5. **Confidence.** High: the source is a framework parameter and the sink an exact API. Medium: a sanitizer could not be classified. Low: the flow passes a dynamic call. Sanitizers are listed in the catalogue; a flow through a known sanitizer is dropped and counted.
6. **Claim boundary.** A reports *instances of known vulnerability classes* (CWE-89/78/22/502/918). It does not claim novel bug classes, and a missing flow is never evidence of safety. Reachability L0 does not suppress a taint finding.

### B. Business logic and authorization

| What | Method | Automatic? | Assurance |
|---|---|---|---|
| Route inventory (method, path, handler, params, framework) | Extend the tree-sitter extractor: Flask/FastAPI/Django/Express decorators, routers, `urlpatterns` | yes | verified |
| Auth guard per route (decorator such as `@login_required`; FastAPI `Depends(get_current_user)` or `Security(...)`; Express middleware in the route chain or `app.use` before the router; DRF `permission_classes`) | Extractor and per-framework guard catalogue (`authz/guards.yaml`, own rules) | yes, for listed guards | verified when a guard is found; "no guard found" is **inferred**, because custom guards exist |
| Sensitive endpoint without auth | No guard + (mutating method, or path/handler touches a data store the manifest marks ≥ confidential, or a taint sink in its call graph) | yes | inferred |
| **Inconsistent** authorization | Sibling routes on the same resource prefix where most have a guard and one does not; or GET is guarded but DELETE is not | yes | inferred (a strong signal with few false positives, CONFIDENT) |
| Manifest-declared policy violated | New optional manifest key `authz: [{path: "/admin/**", requires: [admin]}]`; compared with the guards found | yes | verified (a declaration against a parsed guard) |
| BOLA / IDOR | Route has an object-id parameter, the handler loads by that id, and no ownership predicate (`== current_user.id`, `filter(owner=…)`) appears in the handler's call graph | heuristic | **hypothesis**, always; shown as "test this" with the missing evidence listed |
| Privilege escalation | Route that writes a role/permission field reachable without an admin guard; or the attack-graph path identity(limited) → identity(elevated) | partly | inferred / hypothesis |
| Trust-boundary violations | A taint flow from an internet-exposed route to an internal-only service client (SSRF into the mesh) | yes, through A + D | inherits the flow's assurance |
| Insecure multi-step workflows (skipping step 2 of checkout, replaying a token) | Needs application state | **no** | manual or app-specific test only |
| Dynamic confirmation (two-user swap tests, unauthenticated replay) | Optional harness against a *locally deployed* test instance with synthetic users | no (opt-in) | upgrades a hypothesis to verified when the test passes |

Dynamic testing is **deferred** (§5): it needs a running target, credentials and fixtures per application. Running repository code is outside today's isolation model, which never executes it.

### C. Runtime, dependency and vulnerability intelligence

| Need | Source | New component? |
|---|---|---|
| Language dependencies → CVEs, affected ranges, fixed version | Trivy DB (already has GHSA/NVD/vendor ranges and `FixedVersion`) + Syft SBOM | no |
| OS packages and language runtime in images | `trivy image <ref>` for each image the repository names (Dockerfile `FROM`, Compose `image:`, Kubernetes `containers[].image`); `syft <ref>` for the image SBOM | no new tool: a new target mode of two existing tools |
| Runtime/interpreter version declared by the repository | Parse `.python-version`, `runtime.txt`, `pyproject` `requires-python`, `package.json` `engines.node`, `.nvmrc`, `go.mod` `go`, Dockerfile `FROM python:3.8-slim` | `modules/runtime` (own code) |
| Runtime EOL | [endoflife.date](https://endoflife.date) API, refreshed by Beat like NVD (never on the scan path), stored with fetch time | small client, no dependency (httpx) |
| Runtime CVEs (e.g. CPython in an image) | Trivy's image scan of the installed runtime packages; for declared-only runtimes, an EOL finding plus "image not scanned" | no |
| Freshness | Trivy `version --format json` reports the DB build time (BELIEVE: verify the field in X2.0); stored per scan as `data_as_of` | small |
| Second advisory source | OSV ([osv.dev](https://osv.dev)), Apache-2.0 | **deferred**: Trivy already ingests GHSA/OSV-family data (BELIEVE). Adding osv-scanner duplicates Trivy for little gain; an OSV cross-check is an X8 research question ("how often do the two disagree?"), not an MVP need |
| Grype | Duplicate of Trivy+Syft | rejected |

**Design.**
- Image references are collected as `container_image` assets with the declaring file and line (verified).
- Each distinct public ref (cap 5 per scan, size cap 2 GB) is scanned by `trivy image`. Its findings get `source_type=container` and attach to the image node, and from there to the service (`BUILT_FROM`/`RUNS_IMAGE`, verified when Compose or Kubernetes names the image, inferred when only a Dockerfile in the service path does).
- `RuntimeDecl(kind, version, file, line)` is matched against EOL data and produces `runtime` findings ("Python 3.8 is end-of-life since …", fixed version: the oldest supported cycle).
- **Known versus novel.** C only reports *published* advisories matched by version. Every C finding carries the advisory id, the affected range, the matched version and `data_as_of`. The UI labels this "known vulnerability (version match)", distinct from A's code findings.

### D. Evidence-backed chaining

**Edge rules (additions to §13.1 and ADR-0013):**

| Edge | From → to | Requires evidence of kind | Assurance |
|---|---|---|---|
| EXPOSES | internet → service/endpoint | manifest declaration / Kubernetes LB or Ingress / Compose published port | verified / inferred / inferred |
| ROUTES_TO | endpoint → function | route (extractor) | verified |
| TAINT | endpoint/function → service state | taint_flow (A) | verified or inferred, as the flow |
| EXPLOIT | network neighbour → service | finding with R ≠ L0, or a C finding on the service's image | the finding's tier (L3/taint verified; L2 inferred; unknown reachability gives hypothesis) |
| RUNS_IMAGE | service → container_image | Compose/Kubernetes image ref, or Dockerfile in the service path | verified / inferred |
| CONTAINS_SECRET | service → credential | Gitleaks/Trivy secret finding in the service path | verified |
| AUTHENTICATES_AS | credential → identity | manifest `credentials:` link | verified. A family match with no link is now a **hypothesis** (today it is stored as a normal edge: G1) |
| RUNS_AS | service → identity | manifest / Kubernetes ServiceAccount | verified / inferred (name match) |
| CAN_ACCESS | identity → data_store/service | manifest / RBAC binding | verified |
| UNGUARDED | internet → endpoint | B finding "no guard found" | inferred |
| BOLA_SUSPECT | endpoint → data_store | B heuristic | hypothesis |

**Rules that prevent "chains from co-occurrence".**
1. The builder refuses any edge with no evidence ids (an invariant test).
2. Two findings in the same service never connect unless an edge rule above links them.
3. A path's assurance is the **minimum** over its edges.

**Scoring.**
- `P(π) = ∏p_e`, `score = 100·P(π)·I(sink)`, as today.
- Assurance is kept as a **separate, lexicographic dimension**: paths are listed grouped by assurance, then by score.
- Rejected alternative: discounting `p` by assurance. It hides the uncertainty inside a number and makes "verified 40" and "hypothesis 40" look the same.
- **Effective impact I\* (§14.4) is computed only from paths with assurance ≥ inferred.** Hypothesis paths never raise a score. They are listed as "paths to verify", with the missing evidence named (for example, "no manifest link proves this AWS key authenticates as `api-role`").
- Confidence (high/medium/low within a tier) is shown, not multiplied.

**Graph technology:** unchanged (§2.2). Added measurement: build plus search ≤ 2 s at 5k nodes and 20k edges, with 10 sinks and k=3 (the existing NFR), now including function and endpoint nodes.

---

## 4. Phased roadmap

Phases are named **X0–X8** so they cannot be confused with the blueprint's P0–P19. Phases run in order; each one's exit criteria must hold before the next starts.

Proposed order compared with yours:
- **Contracts and D-core move ahead of A.** A's flows and B's guards *are* graph edges. Building A first means inventing an ad-hoc evidence shape and migrating it later.
- **C stays first among the capabilities.** It is the cheapest, reuses Trivy and Syft, and gives D new nodes.
- **B comes after A,** because B's best signals ("unguarded route whose handler reaches a taint sink") need A's flows and the function spans.

| Phase | Objective / scope | Engineering tasks | Modules | Deliverables | Depends on | Tests and acceptance | Risks → mitigation |
|---|---|---|---|---|---|---|---|---|
| **X0 Audit closure and baseline** | Freeze a measured baseline before adding anything | G10 and G11 were closed in P8–P11 (session 7). Remaining: build `datasets/scenarios/` A–E from the blueprint; implement baselines M1/M2 and the metrics; record current RiskGraph metrics | risk, graph, normalization, `datasets/` | `BASELINE.md` with numbers; tests | — | Baseline P@5, P@10, nDCG@10 for M1, M2 and v1-ctx.2 recorded with CIs; regenerating the datasets reproduces them exactly | Scenario repos overfit the model → generate them from templates and freeze them *before* any tuning |
| **X1 Contracts** | One evidence and assurance contract for everything | ADR-0016; `modules/evidence`; migration (`evidence`, link tables, `graph_edges.assurance`, `source_type` values); retrofit current edges with assurance (credential-family edges → hypothesis; Kubernetes name map → inferred); builder invariant | evidence, graph, findings | ADR, migration, typed contract, API `evidence[]` on finding detail | X0 | Migration up/down/up clean and `alembic check` no drift; invariant test (an edge without evidence raises); existing paths unchanged except the credential-family ones, now hypothesis; their I\* contribution drops, as a documented, intended score change | Over-design → contract frozen at the fields in §2.4; new fields need an ADR |
| **X2 C: runtime and image intel** | Known-vulnerability coverage for images and runtimes | Collect image refs (Dockerfile/Compose/Kubernetes); Trivy `image` mode plus Syft image SBOM under ADR-0014 with egress, caps and a 5-image limit; runtime declarations; endoflife.date client plus Beat refresh; freshness per scan | runtime (new), scanners/trivy, scanners/syft, context | `container_image` assets, `runtime` findings, freshness on findings and scans | X1 | Fixture repo `FROM python:3.8-slim` + `node:14` → EOL findings with dates; recorded `trivy image` fixture parsed (OS + runtime packages, fixed versions); every C finding has advisory id, range, matched version, `data_as_of`; scan overhead ≤ +90 s per image warm-cache (measured) | Image pulls are slow or huge → per-ref cache, size cap, refs deduplicated across scans by digest; registry rate limits → skip with a warning, never fail the scan |
| **X3 D-core: assured graph** | Paths from all evidenced facts, not only the manifest | New node kinds (endpoint, function, container_image); edge rules from §3.D; Compose/Kubernetes topology into the graph (closes G3); assurance-aware search; hypothesis-path listing; I\* gating | graph, risk | `/attack-paths` grouped by assurance, with `missing_evidence[]` on hypotheses | X1 (X2 for image nodes) | NodeGoat with no manifest gets ≥ 1 inferred path from Compose; property test: a random graph built only from co-located findings with no edge rules yields 0 paths; hypothesis paths never change any score (test); perf ≤ 2 s at 5k/20k | Path explosion with function nodes → functions only on flows; hop limit 8 kept |
| **X4 A: deep code** | Interprocedural taint with evidence | **X4.0 spike (go/no-go):** Joern in a hardened container on a 20-case Python/JS source-to-sink suite plus NodeGoat; measure recall, precision, RAM, time. **Then:** tier-1 Semgrep taint rules from one catalogue; Joern adapter, script, parser; enclosing-function mapping (G8); correlation of tier 1 + tier 2 | scanners/joern (new), scanners/semgrep rules, reachability (spans), normalization | `deep` profile, taint findings with steps, catalogue YAML | X1, X3 | **Gate:** Joern recall ≥ 0.6 on interprocedural cases where Semgrep CE scores ≈ 0 (by construction); precision ≥ 0.7; peak RAM ≤ 6 GB; ≤ 10 min on NodeGoat. If not met, fall back to custom Python summaries and record an ADR | JVM memory on a 15 GB host → deep profile opt-in, one slot; Joern version churn → pin by digest, fixtures re-recorded per bump |
| **X5 B: authorization** | Static authz findings with honest assurance | Extractor `ts-imports.4` (guards, params, routers); guard catalogue for 4 frameworks; inventory, inconsistency, unguarded-sensitive, manifest `authz:` policy diff, BOLA heuristic; UNGUARDED/BOLA_SUSPECT edges | reachability (extractor), authz (new), context (manifest), graph | Route inventory endpoint, authz findings, UI-ready "manual verification required" list | X3, X4 (taint sinks) | Labeled suite: each framework with guarded, unguarded, inconsistent and custom-guard cases; inconsistency precision ≥ 0.8; zero BOLA findings above `hypothesis`; route inventory recall ≥ 0.95 on the suite | Custom guards cause false positives → catalogue extensible via manifest `authz.guards:`; framework drift → under-claim and say "unknown framework" |
| **X6 Risk v2** | Integrate C, A and B into scoring | Factor tables for runtime EOL, container OS packages (R = 0.5 "not assessable"), taint (E by CWE and confidence), authz (E for inferred unguarded; hypotheses not scored above Low); model `v2` with the reduction property kept; scenarios F–H | risk | Model `v2`, ADR | X2–X5 | All v1 tests still pass when the new inputs are absent (reduction test); scenario ordering for the new cases matches the labels; monotonicity holds | Score inflation from more findings → per-finding model unchanged; a repository is never summed |
| **X7 Dashboard and reporting** | Make evidence and assurance visible | Assurance badges; flow-step viewer; route inventory table; image/runtime panel; "paths to verify"; CI gate options (`--assurance-min`); SARIF export with provenance | frontend, findings router, CLI | UI views, SARIF, gate flag | X6 | Playwright: flow steps render as plain text; a hypothesis is never styled as a finding; a gate with `assurance-min=inferred` ignores hypotheses | UI scope creep → fixed view list; stretch views deferred |
| **X8 Evaluate, optimize, deploy** | Prove improvement, not tool count | Run §6; ablations (−A, −B, −C, −D); overhead profile; CodeQL as a research oracle on open-source apps only; prod compose profile for `deep` | `evaluation/` | `EVALUATION_EXPANSION.md` | X7 | §6 success criteria | Weak results → reported as found; no post-hoc metric changes |


---

## 5. Minimum viable expansion versus deferred

| | MVE | Deferred (advanced) |
|---|---|---|
| X0 / X1 | all | — |
| C | Image refs; `trivy image` and Syft for public images; runtime declarations and EOL; freshness | OSV cross-check; private registries; Terraform AMIs/Lambda runtimes; deployed-cluster live inventory |
| D | Assurance on every edge; Compose/Kubernetes topology; hypothesis paths separated; I\* gating | Choke-point metric (betweenness); cross-scan/org graph (AGE trigger); "cheapest edge to fix" |
| A | Tier-1 own Semgrep taint rules (Python and JS); Joern tier 2 for **Python only**, if the spike passes; enclosing functions | Joern for JS/Java/Go; custom Python summary engine (only as the fallback); sanitizer inference |
| B | Route inventory and guards for Flask, FastAPI and Express; inconsistency; unguarded-sensitive; manifest policy diff; BOLA as hypothesis | Django/DRF; dynamic two-user tests; multi-step workflow tests; GraphQL |
| X6–X8 | Risk v2; badges, flow viewer, paths to verify; evaluation on the scenario suite plus 2 apps | SARIF; CodeQL oracle; full ablation grid |

---

## 6. Testing and evaluation plan

**Datasets** (all run locally in the sandbox; secrets synthetic, built at test time as `kitchen_sink.py` does):

| Purpose | Dataset | Ground truth |
|---|---|---|
| Known vulnerabilities (C) | Synthetic repos: `FROM python:3.8-slim`, `node:14-alpine`, a pinned old `requests`, Compose/Kubernetes image refs | By construction, against a **frozen Trivy DB snapshot** (stored digest), so results are reproducible |
| Source → sink (A) | 40 synthetic cases (Python 20, JS 20). Each CWE (89, 78, 22, 502, 918) appears as an intraprocedural, a cross-function, a cross-file and a sanitized (negative) variant | By construction. The interprocedural cases are the ones Semgrep CE structurally cannot find, which makes them the honest test of A's added value |
| Authorization (B) | Synthetic Flask/FastAPI/Express apps per pattern (guarded, unguarded, inconsistent, custom guard, id param with and without ownership check); OWASP crAPI and VAmPI for BOLA realism (BELIEVE: both are intentionally vulnerable API apps; verify licences and versions in X5) | By construction; published vulnerability lists for crAPI/VAmPI |
| Attack paths (D) | Scenarios A–E plus new F (SSRF → metadata → identity), G (public image CVE on an internet service → DB), H (co-located findings with no relationship: **expected 0 paths**) | By construction: expected node sequences and the assurance of each edge |
| Realism | OWASP NodeGoat, OWASP Juice Shop (JS); one Python vulnerable app chosen in X0 | Published challenge lists; blind-labelled subset (stretch) |

**Metrics and success criteria** (MVE must meet all; numbers are pre-registered here and not changed after seeing results):

| Metric | Target |
|---|---|
| A recall on interprocedural cases (tier 1+2) | ≥ 0.6, against Semgrep CE alone ≈ 0 by construction; overall precision ≥ 0.7; sanitized negatives FP rate ≤ 0.2 |
| B inconsistency/unguarded precision | ≥ 0.8; route-inventory recall ≥ 0.95; BOLA reported only as hypothesis (100 %) |
| C | 100 % of seeded known CVEs/EOLs found against the frozen DB; every finding has range, fixed version (when one exists) and `data_as_of` |
| D path accuracy | Path precision (paths whose every edge is in the ground truth) ≥ 0.9; scenario H yields 0 paths; assurance calibration: verified edges ≥ 0.95 correct, inferred ≥ 0.7 |
| Prioritization | nDCG@10 and P@5/P@10 for RiskGraph-v2 > M2 (CVSS+EPSS) on the scenario suite, paired permutation test p < 0.05; ablation shows which of A–D contributed |
| Overhead | Default profile scan time p50 ≤ +25 % against the X0 baseline; `deep` profile reported separately; peak RAM recorded |
| Reproducibility | `make eval` regenerates every number from pinned images, the frozen DB and fixed seeds |

False positives are analysed per finding class with a written reason ("custom guard not in catalogue", "dynamic dispatch"), which feeds the catalogue rather than a threshold tweak.

---

## 7. First phase: X0, exact definition of done

**Objective:** a frozen, measured baseline, so every later claim is compared with fixed numbers.

Already closed in P8–P11 (session 7, verified there):
- G10, Semgrep secret typing;
- graph invariants;
- scenarios A–E as unit fixtures;
- monotonicity and reduction properties;
- the perf budgets.

Tasks:
1. `datasets/build.py` generates `datasets/scenarios/A…E` as small repositories (code, manifest, pinned dependencies) from templates, with labels by construction.
2. `evaluation/` implements the rankings M1 (CVSS-only) and M2 (CVSS × the EPSS transform), and the metrics P@K, R@K, nDCG@K (K = 5, 10) and MAP, with bootstrap CIs (blueprint §26).
3. `make eval-baseline` runs the scenarios through the pipeline (recorded scanner fixtures, no network) and writes `docs/evaluation/BASELINE.md`.

Definition of done:
- unit tests for every metric against hand-computed values;
- the generator is deterministic (a second run is byte-identical);
- `BASELINE.md` is committed with the generator commit and the numbers;
- lint, unit and db suites green, with output pasted in `docs/phases/PHASE_X0.md`.

## 8. Main risks, scope traps and decisions to finalize early

**Decide before X1:**
1. Adopt the three-level `Assurance` and "edge requires evidence", including that today's credential-family edges become hypotheses (a visible score change).
2. Keep Postgres + NetworkX (ADR-0006) for the expansion.
3. Joern as tier 2 behind a go/no-go gate; CodeQL only as a research oracle. Accept the licence reading in §3.A.
4. The `deep` profile is opt-in. Default scans stay within +25 % time.
5. Image scanning is limited to public refs named in the repository.
6. RiskGraph-authored rules are licensed Apache-2.0 and kept separate from the `semgrep-rules` content (G12).
7. MVE first in each phase; the deferred items stay deferred (§5).

**Scope traps:**
- writing a general data-flow engine;
- dynamic BOLA testing that needs per-app fixtures;
- chasing language coverage;
- an LLM "finding" anything;
- dashboard views per capability before the evidence contract is stable;
- tuning model weights before the baseline is frozen.

**Technical risks:**

| Risk | Mitigation |
|---|---|
| Joern RAM/time on this host | Spike gate, one slot, opt-in |
| Image pulls (size, rate limits) | Caps, digest cache, skip with a warning |
| Guard catalogues miss custom auth | Inferred, never verified; manifest extension |
| Evidence storage growth | Scan-scoped, capped steps per flow (≤ 50), retention follows scans |
| Frozen-DB reproducibility versus fresh advisories | Evaluation uses the snapshot; production uses fresh data, and `data_as_of` says which |
| The unauthenticated API (P2 not done) exposes deeper results | Still localhost-only. P2 should precede any hosted use of `deep` |

---

Sources: [CodeQL terms](https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md) · [Semgrep cross-file analysis](https://semgrep.dev/docs/semgrep-code/semgrep-pro-engine-data-flow) · [Semgrep Pro engine intro](https://semgrep.dev/docs/semgrep-code/semgrep-pro-engine-intro) · [Semgrep licensing](https://semgrep.dev/docs/licensing) · [Semgrep Rules License](https://semgrep.dev/legal/rules-license) · [Joern repository](https://github.com/joernio/joern) · [Joern docs](https://docs.joern.io/) · [endoflife.date](https://endoflife.date) · [OSV.dev](https://osv.dev)
