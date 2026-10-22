# PHASE 7: Context enrichment (NVD, EPSS, KEV, manifest, Kubernetes and Compose)
**Status:** partly done (2026-10-23). Terraform extraction is out of scope (stretch). Abbreviated chapter. Decision: ADR-0015.

## Built
- **NVD** (new): `parse_nvd_cvss` (v3.1, then v3.0, then v4.0) and `fetch_nvd`; refreshed by Beat (`riskgraph.context.refresh_feeds`, hourly), paced and capped; NVD outranks scanner CVSS.
- **EPSS and KEV** already existed and still refresh on demand, during a scan (TTL-based). The Beat job covers NVD only.
- **Kubernetes and Compose extraction** (`context/iac.py`): Services (LoadBalancer or NodePort → internet, ClusterIP → internal), Ingress, ServiceAccount, RBAC bindings (cluster-admin → admin), workloads (secret refs, privileged). Compose services (published non-loopback ports → internet, build context mapped to code paths, secret-looking env keys). Files are capped; alias bombs are refused before parsing; invalid YAML is a warning.
- Exposure from Compose reaches findings under the service's build directory, through the same precedence as the manifest, at low confidence.
- Migration `9a4d2c7e1b30` (NVD timestamp) and `5c1e0a9d2f47` (`assets`).
- `GET /api/v1/repositories/{id}/context`: the latest finished scan's context and assets.

## Verification
- `test_iac.py` (7) and `test_nvd_and_syft.py` (5) cover parsing, refusal and mapping; `test_nvd` parsers reject malformed input.
- Live NodeGoat: 4 YAML files, 2 assets extracted, no warnings.

## Not done
- Terraform extraction (stretch, dropped by the owner's scope rule).
- K8s assets are listed, but do not feed findings (no code-path mapping for Kubernetes workloads). This is an honest under-claim.
- Identity privilege from RBAC is extracted but not scored.
- The context endpoint is not exercised by a db test yet.
