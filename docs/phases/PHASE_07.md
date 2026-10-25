# PHASE 7: Context enrichment (NVD, EPSS, KEV, manifest, Kubernetes and Compose)
**Status:** done (2026-10-25) except Terraform extraction, a dropped stretch item. Abbreviated chapter. Decision: ADR-0015.

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

## Session 7 additions (2026-10-25)
- **Kubernetes topology** (`kubernetes_context` in `context/iac.py`). It joins the objects per workload:
  - exposure: a Service selects the workload by pod labels (an empty selector selects nothing); an Ingress routes to a Service (v1 and v1beta1 backends);
  - privilege: the highest privilege bound to the workload's ServiceAccount. Only `ServiceAccount` subjects count, so a *User* with the same name does not.
  - No binding means `unknown`, never `limited`, because roles can be granted outside the repository.
- **Kubernetes reaches findings.** A workload maps to findings through a manifest service, or a Compose service with a build path, of the same name. That is inference, so confidence is `low`.
  - Precedence per factor: manifest > Kubernetes > Compose.
  - A manifest that states exposure but not privilege gets its privilege from RBAC.
  - This scores RBAC privilege (P), which was extracted but unused before.
- `summary.context.kubernetes_workloads`, shown in the UI context panel.
- **`GET /scans/{id}/sbom`** (the P5 leftover): paged (`limit` ≤ 500), filtered by `ecosystem` and a `name` prefix, with LIKE metacharacters escaped. Each component has its count of attached findings.

## Verification (session 7)
- `test_iac.py` (+5): topology join, User-vs-ServiceAccount subjects, empty selector, Compose-name mapping and precedence, manifest outranks Kubernetes.
- `test_context_sbom_db.py` (3, db):
  - the context endpoint returns assets and workloads;
  - a pyyaml SCA finding gets `P` = 1.0 from `kubernetes` (cluster-admin);
  - 404 problem+json without a finished scan;
  - the SBOM endpoint's paging, ecosystem filter, finding counts, literal `%`, and 404.

## Not done
- Terraform extraction (stretch, dropped by the owner's scope rule).
- Namespaces are ignored: two workloads with the same name in different namespaces collide (the last file wins, deterministically).
- The Kubernetes → code mapping is by name only. A workload with no same-named manifest or Compose service does not reach findings (under-claim).
