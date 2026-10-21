"""Normalization: canonical finding model, severity mapping, fingerprints, merging."""

from riskgraph.modules.normalization import families, severity
from riskgraph.modules.normalization.canonical import Location, RawFinding
from riskgraph.modules.normalization.families import IacFamily
from riskgraph.modules.normalization.fingerprint import fingerprint, stable_hash
from riskgraph.modules.normalization.merge import MergedFinding, merge
from riskgraph.modules.normalization.paths import normalize_path

__all__ = [
    "IacFamily",
    "Location",
    "MergedFinding",
    "RawFinding",
    "families",
    "fingerprint",
    "merge",
    "normalize_path",
    "severity",
    "stable_hash",
]
