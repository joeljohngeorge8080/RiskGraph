# PHASE 0 — Project Definition & Threat Model

**Status:** done (2026-09-19). Documentation-only phase; no runtime surface.

## A. Objective
Fix what RiskGraph is, what it assumes, what it will not do, how it will be judged, and what it must defend against — before any code exists.

## B. Why
Every later phase reads these documents instead of re-deciding. The threat model in particular decides Phase 3's sandbox profile and Phase 15's test list; deciding it after the scanner runner exists would mean retrofitting security.

## C. Architecture
No runtime components. The document set:
```
docs/
  PROJECT_SPEC.md          problem, assumptions, research question, success criteria S1–S8, principles
  THREAT_MODEL.md          living STRIDE model (T-01…T-20), security invariants
  adr/0001–0008            architecture shape, stack, ids/tenancy, auth, hosting, graph, queue, sync ORM
  blueprint/00–08          frozen detailed design (written before Phase 0)
```

## D. Components
`PROJECT_SPEC.md`, `THREAT_MODEL.md`, eight ADRs with an index, this chapter.

## E. Technical decisions
Recorded as ADRs 0001–0008 (`docs/adr/README.md`). Each names its live alternative with real pros and an upgrade trigger. New decisions during later phases are appended as ADR-0009+; accepted ADRs are never edited, only superseded.

## F. Folder structure
See C. `docs/phases/` receives one chapter per phase.

## G. Database · H. API · I. Algorithms · J. Implementation · K. Commands · L. Configuration
Not applicable in this phase (no runtime). Schema and API are designed in `docs/blueprint/02_DATA_AND_API.md` and implemented from Phase 2.

## M. Testing
Document review only: every threat row has surface, mitigation with owning phase, and residual; every success criterion names its evidence.

## N. Security
The threat model is the deliverable. Key outcomes that bind later phases: scanned repositories are hostile (T-01, T-02, T-07); the worker's Docker access is the crown jewel (T-08); secrets from Gitleaks are never persisted raw (T-06); the LLM never sees raw repository content (T-11); manifest-based context is reviewable in PRs (T-12).

## O. Validation
- `docs/adr/README.md` lists 8 accepted ADRs; each file has Context, Decision, Alternatives, Consequences with an upgrade trigger. VERIFIED by reading.
- `docs/THREAT_MODEL.md` has 20 threats each mapped to a phase. VERIFIED.
- `docs/PROJECT_SPEC.md` has 8 success criteria with evidence sources. VERIFIED.

## P. Expected output
No runtime output. `ls docs/adr` shows `README.md` plus `0001…0008`.

## Q. Definition of done
- [x] Problem statement, scope, non-goals, assumptions written
- [x] Research question and hypotheses fixed
- [x] Success criteria S1–S8 with evidence
- [x] STRIDE threat model with assets, actors, surfaces, threats, mitigations, residuals
- [x] ADRs for the eight day-one decisions
- [x] Architecture principles

## R. Common failure modes
- Re-litigating an ADR in a later phase instead of writing a superseding one.
- Letting the threat model rot: new surfaces (e.g. Terraform extraction) must add threats.
- Treating success criteria as aspirational; each one has a named test or report.

## S. Next phase
Phase 1 builds the development environment that every later phase runs in.
