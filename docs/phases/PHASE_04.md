# PHASE 4: Scanner adapters (five hardened images)
**Status:** done for the five scanners (2026-10-23). Decisions: ADR-0014. Abbreviated chapter.

## Objective
Each of the five scanners runs from a pinned, checksum-verified image under the Phase 3 profile, and produces parsed findings from recorded fixtures.

## Built
- Dockerfiles in `scanners/<name>/` for trivy, gitleaks, syft (new), semgrep, checkov, plus `git-fetcher`. Versions come from `docker/scanner-versions.env`; `test_scanner_images.py` enforces parity with the adapters' `image_tag`.
- **Syft** adapter (new): inventory via CycloneDX; no findings; parser extracts components with purl, ecosystem and first location (`modules/scanners/syft/parser.py`).
- Trivy now runs `--skip-db-update` with no network.
- Fixtures re-recorded from the pinned images (`tests/fixtures/scanners/record.py` runs containers by default): trivy 0.76.0, gitleaks 8.30.1, semgrep 1.182.0, checkov 3.3.30, syft 1.54.1.

## Decisions
- Syft pinned to 1.54.1, the newest release older than two weeks (the hold policy).
- Semgrep rules are vendored at image build (registry pack first, else the pinned commit), not fetched at scan time.

## Verification
- Unit: parser tests, image-pin tests, the Semgrep rule-id normalisation (`clean_rule_id` now drops a repeated last segment).
- DB: the full pipeline on the recorded fixtures (32 db tests pass).
- Live: NodeGoat through all five containers, COMPLETED.

## Known differences from the host-run MVP
- Semgrep's pinned rule set reports three CWE-78 rules on one line where the host install reported four (`test_merge.py` now expects three, with the reason in the test).
- Its `generic.secrets` private-key rule is typed SAST (see ADR-0015).

## Not done
- Per-version fixture history: only the current pins are recorded.
