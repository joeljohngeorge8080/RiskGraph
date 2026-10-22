"""SBOM: per-scan package inventory from Syft, joined to Trivy's CVE findings (blueprint §10.2)."""

from riskgraph.modules.sbom.models import SbomComponent
from riskgraph.modules.sbom.service import (
    attach_findings,
    canonical_purl,
    clear,
    list_components,
    persist_components,
)

__all__ = [
    "SbomComponent",
    "attach_findings",
    "canonical_purl",
    "clear",
    "list_components",
    "persist_components",
]
