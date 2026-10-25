# PHASE 5: Normalization, correlation and SBOM
**Status:** done for SBOM and cross-scanner attachment (2026-10-23). Abbreviated chapter.

## Objective
An SBOM per scan, Trivy's CVEs attached to the packages they affect, and the fingerprint and dedup behaviour that already existed kept intact.

## Built
- `modules/sbom/`: `SbomComponent` (one row per purl per scan), `persist_components` (Syft is the inventory owner; Trivy-only purls are added with `discovered_by=trivy`), `attach_findings` (sets `scan_findings.component_id`).
- Join key: the purl with qualifiers and subpath removed.
- Migration `5c1e0a9d2f47` adds `sbom_components` and `scan_findings.component_id`.
- The analysis stage writes the SBOM and attachments in the same transaction as the findings.

## Verification
- Live NodeGoat: 385 components (all from Syft), 92 SCA findings attached, 0 Trivy-only components.
- DB suite passes; the re-scan behaviour (zero new findings for an unchanged commit) is covered by the existing `test_analyze_is_idempotent_and_rescans_reuse_findings`.

## Not done
- `GET /scans/{id}/sbom` endpoint. The data is stored and summarised in `summary.sbom`, but there is no list endpoint yet.
- Container-image fingerprints (blueprint §10.2) are not implemented; the image scan uses Trivy's `fs` mode only.
