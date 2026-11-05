# ADR-0011: Context-aware scoring from the repository manifest (MVP level 2)

Status: accepted · Date: 2026-10-21 · Amends: ADR-0010 (score row) · Implements part of: roadmap Phase 7

## Context
ADR-0010 shipped the §14.3 context-free score. Without context the base score tops out around 42–46, so High and Critical were reachable only through overrides, and the 70/45 bands were mostly unused. The owner asked for a "level 2" MVP built on context-aware scoring, RiskGraph's core differentiator. The manifest schema (§11.1), the factor tables (§14.2) and the 2-hop data-sensitivity rule are already designed in the blueprint. Kubernetes, Compose and Terraform extraction, dashboard overrides and reachability are not built yet.

## Decision
- **Source 1, repository visibility.** Every MVP scan is of a public github.com repository (ADR-0010). A committed secret therefore gets `X = internet_noauth` (source `repository_visibility`, confidence high), with or without a manifest. Other finding types do not use visibility: being in a public repository does not expose the running service.
- **Source 2, `riskgraph.yaml` / `riskgraph.yml` at the repository root**, schema v1 as in §11.1.
  - Validation is strict (Pydantic, `extra="forbid"`): enums, unique names across sections, every `runs_as` / `connects_to` / `can_access` / `criticality` name must resolve, and `path` must be relative and stay inside the repository.
  - An invalid manifest is ignored as a whole, recorded as a scan warning in `summary.context`, and never fails the scan.
  - **Hardening:** read only from fixed names through `ScanWorkspace.safe_resolve` (inside the checkout, regular file, so a symlink pointing outside is ignored); 64 KiB cap; UTF-8 only; `yaml.safe_load`; documents containing YAML aliases (billion laughs) or nesting deeper than 8 levels (recursion in PyYAML's composer) are refused from the event stream before construction; at most 200 items per list; at most 20 warnings, each at most 200 characters.
- **Mapping.** A finding belongs to the service with the longest `path` prefix of its file. `path: ""` covers the whole repository. Findings outside every path keep the defaults and are counted as `unmapped_findings`.
- **Factors** (§14.2 tables, `risk/tables.py`):
  - X from `exposure` + `auth`. `internet` with `auth` not declared counts as `internet_noauth` with confidence medium: when in doubt, over-claim exposure rather than hide it.
  - P from the `runs_as` identity's privilege.
  - D is the most sensitive data store within 2 hops over RUNS_AS → CAN_ACCESS and CONNECTS_TO (ties go to fewer hops). Confidence is high at 1 hop, medium at 2.
  - C comes from `criticality`.
  - R stays `unknown` until Phase 8.
  - Each factor stores the label as `raw_value`, its `source`, its `confidence`, and evidence (service, hop path).
- **Model `v1-ctx.1`.** With no context the scores equal `v1-cf.1` exactly (§14.3 still holds and is still tested). One rule changes, as in §14.5: the KEV floor no longer applies when the finding's service is declared `isolated`.
- **No new tables.** Provenance lives in `risk_factors`, and the per-scan context summary lives in `scan_jobs.summary.context`. Phase 7 adds `GET /repositories/{id}/context` and persisted assets when the graph arrives.

## Alternatives considered
- **Compose / Kubernetes extraction now:** deferred. A published Compose port is a development convenience, not evidence of internet exposure. Getting this right needs the asset model from Phase 7/12, and guessing would over- or under-claim silently.
- **Lenient manifest (keep the valid parts):** rejected. Partial context is harder to explain, and the blueprint wants a malformed manifest to be a visible, reviewable failure (T-12, graph poisoning).
- **Visibility for every finding type:** rejected. A public repository exposes its secrets, not its running service.

## Consequences
- (+) Bands become reachable on evidence. On the kitchen-sink fixture (27 findings), the manifest declares the whole repository internet-facing with no auth, running as admin, reaching PII, criticality high. Priorities change as follows:
  - without the manifest: critical 2 / high 1 / medium 15 / low 9 (max 62.26);
  - with it: critical 14 / high 4 / medium 9 / low 0 (max 94.63);
  - no score decreases (asserted in `test_manifest_context_raises_scores`).
  Committed generic secrets move from Medium to High through repository visibility alone.
- (+) Every difference from the context-free ranking is explained by a factor with a source.
- (−) The manifest is self-declared by the repository owner. A repository can under-declare its exposure. This is the T-12 residual, mitigated only by the manifest being a reviewable diff. Lowering exposure must stay visible in the UI (the Context panel shows every service).
- (−) Scores of `v1-cf.1` and `v1-ctx.1` scans are not comparable when a manifest is present. `risk_model_version` is stored per scan.
- (→) Phase 7 adds IaC/Compose/K8s extraction below the manifest in precedence, and Phase 8 makes R real.
