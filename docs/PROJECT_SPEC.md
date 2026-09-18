# RiskGraph — Project Specification (Phase 0, v1.0, 2026-09-19)

Companion to `docs/blueprint/` (the detailed design). This file is the short,
citable statement of what the project is, what it assumes, and how success is judged.

## 1. Problem statement
Teams run several security scanners whose outputs differ in schema, severity
vocabulary and false-positive profile, and whose severities ignore the system
context that decides whether a finding matters. RiskGraph orchestrates five
open-source scanners, normalizes and correlates their findings, enriches them
with exploit likelihood, code reachability, network exposure, identity privilege
and data sensitivity, projects them into a security graph, discovers attack
paths, and scores contextual risk deterministically with an explanation.

## 2. Scope
See `docs/blueprint/00_BLUEPRINT.md` §3 (scope) and §30 (MVP). Non-goals in §4.

## 3. Assumptions
- A1 One self-hosted instance serves one organization (single-tenant).
- A2 Repositories are on GitHub and may contain hostile content.
- A3 Environmental context is supplied by a `riskgraph.yaml` manifest and/or
  Kubernetes, Compose and (stretch) Terraform files in the repository. Absent
  context is represented as `unknown`, never guessed.
- A4 Public vulnerability data (NVD, EPSS, KEV) is reachable from the server
  at least once a day; the system tolerates outages via caches.
- A5 The host has Docker, ≥ 4 cores and ≥ 16 GB RAM (8 GB without Ollama).
- A6 One developer, 7–9 months, no paid services.

## 4. Research question
Does contextual graph-based prioritization rank practically important security
findings higher than CVSS-only and CVSS+EPSS prioritization? Hypotheses,
methods and metrics: `docs/blueprint/07_TESTING_AND_EVALUATION.md` §26.

## 5. Success criteria (project level)
| # | Criterion | Evidence |
|---|---|---|
| S1 | A push to a connected repository produces, without manual steps, normalized findings from all five scanners in isolated containers | E2E test on `datasets/scenarios/kitchen_sink`; demo §28 |
| S2 | Findings carry CVSS, EPSS, KEV, reachability tier, exposure, identity and data-sensitivity factors with provenance | `GET /findings/{id}` schema; Phase 7/8 tests |
| S3 | Scenario E yields the constructed attack path with evidence | Phase 10 test |
| S4 | Risk engine reproduces the §14.6 fixture scores and is monotone in every factor | Phase 11 unit + property tests |
| S5 | RiskGraph beats CVSS-only and CVSS+EPSS on nDCG@10 and Precision@5 on the scenario suite, with 95 % CIs not overlapping the baselines, or the thesis explains why not | Phase 17 report |
| S6 | Every threat in `docs/THREAT_MODEL.md` has a tested mitigation or documented residual | Phase 15 checklist |
| S7 | A hostile repository (`datasets/scenarios/malicious`) cannot escape, crash the worker, or leak a secret | Phase 16 security validation |
| S8 | The full demo runs on one laptop from `make dev` | Phase 18/19 |

## 6. Architecture principles
1. Detection, context, correlation, risk and explanation are separate modules with one-way dependencies.
2. Deterministic before probabilistic: the risk score never depends on an LLM.
3. Untrusted by default: repository content is executed only inside sandboxed containers and parsed only with tree-sitter.
4. Unknown is a value: missing context is represented and shown, never silently defaulted to "safe".
5. Every score is reproducible from its stored factors and model version.
6. Boring technology, one language per tier, one system of record.
7. Every phase ends with a running increment and a written chapter.
