"""Context: vulnerability intelligence and deployment context.

- vulnerability intelligence: CVSS sub-scores, EPSS, CISA KEV;
- deployment context: the repository manifest (``riskgraph.yaml``) and repository
  visibility, resolved per finding into exposure, data sensitivity, privilege and
  criticality (blueprint §11). Reachability lives in ``modules/reachability``.
"""

from riskgraph.modules.context.cvss import CvssSubscores, subscores
from riskgraph.modules.context.environment import ContextResolver, FindingContext, Observed
from riskgraph.modules.context.iac import IacAsset, IacResult, KubeContext, kubernetes_context
from riskgraph.modules.context.iac import extract as extract_iac
from riskgraph.modules.context.manifest import (
    AuthzDecl,
    AuthzRule,
    Manifest,
    ManifestResult,
    load_manifest,
    parse_manifest,
)
from riskgraph.modules.context.models import Vulnerability
from riskgraph.modules.context.service import (
    VulnIntel,
    list_assets,
    nvd_refresh,
    persist_assets,
    refresh_intel,
)

__all__ = [
    "AuthzDecl",
    "AuthzRule",
    "ContextResolver",
    "CvssSubscores",
    "FindingContext",
    "IacAsset",
    "IacResult",
    "KubeContext",
    "Manifest",
    "ManifestResult",
    "Observed",
    "VulnIntel",
    "Vulnerability",
    "extract_iac",
    "kubernetes_context",
    "list_assets",
    "load_manifest",
    "nvd_refresh",
    "parse_manifest",
    "persist_assets",
    "refresh_intel",
    "subscores",
]
