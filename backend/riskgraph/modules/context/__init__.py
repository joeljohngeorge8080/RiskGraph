"""Context: vulnerability intelligence and deployment context.

- vulnerability intelligence: CVSS sub-scores, EPSS, CISA KEV;
- deployment context: the repository manifest (``riskgraph.yaml``) and repository
  visibility, resolved per finding into exposure, data sensitivity, privilege and
  criticality (blueprint §11). Reachability lives in ``modules/reachability``.
"""

from riskgraph.modules.context.cvss import CvssSubscores, subscores
from riskgraph.modules.context.environment import ContextResolver, FindingContext, Observed
from riskgraph.modules.context.manifest import (
    Manifest,
    ManifestResult,
    load_manifest,
    parse_manifest,
)
from riskgraph.modules.context.models import Vulnerability
from riskgraph.modules.context.service import VulnIntel, refresh_intel

__all__ = [
    "ContextResolver",
    "CvssSubscores",
    "FindingContext",
    "Manifest",
    "ManifestResult",
    "Observed",
    "VulnIntel",
    "Vulnerability",
    "load_manifest",
    "parse_manifest",
    "refresh_intel",
    "subscores",
]
