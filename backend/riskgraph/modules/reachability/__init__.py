"""Reachability: is the vulnerable code imported and reachable (blueprint §11.3, ADR-0012)."""

from riskgraph.modules.reachability.extract import ANALYZER_VERSION
from riskgraph.modules.reachability.graph import (
    module_of_file,
    python_module_index,
    resolve_js_module,
    resolve_python_name,
)
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
    "module_of_file",
    "persist_verdict",
    "python_module_index",
    "resolve_js_module",
    "resolve_python_name",
    "run_extractor",
]
