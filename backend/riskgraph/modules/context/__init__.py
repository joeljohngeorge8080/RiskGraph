"""Context: vulnerability intelligence (CVSS sub-scores, EPSS, CISA KEV).

The MVP has no deployment context (exposure, reachability, data sensitivity); those
factors use the blueprint's "unknown" defaults in the risk model.
"""

from riskgraph.modules.context.cvss import CvssSubscores, subscores
from riskgraph.modules.context.models import Vulnerability
from riskgraph.modules.context.service import VulnIntel, refresh_intel

__all__ = ["CvssSubscores", "VulnIntel", "Vulnerability", "refresh_intel", "subscores"]
