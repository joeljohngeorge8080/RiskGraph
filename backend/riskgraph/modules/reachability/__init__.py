"""Reachability: is the vulnerable code imported and reachable (blueprint §11.3, ADR-0012)."""

from riskgraph.modules.reachability.extract import ANALYZER_VERSION
from riskgraph.modules.reachability.models import ReachabilityResult
from riskgraph.modules.reachability.service import (
    ReachabilityRun,
    clear,
    persist_verdict,
    run_extractor,
)
from riskgraph.modules.reachability.tiers import NOT_APPLICABLE, UNKNOWN, Verdict

__all__ = [
    "ANALYZER_VERSION",
    "NOT_APPLICABLE",
    "UNKNOWN",
    "ReachabilityResult",
    "ReachabilityRun",
    "Verdict",
    "clear",
    "persist_verdict",
    "run_extractor",
]
