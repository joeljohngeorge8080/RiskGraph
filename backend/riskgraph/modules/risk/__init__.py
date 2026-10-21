"""Risk: the deterministic, explainable prioritization model (blueprint §14)."""

from riskgraph.modules.risk.model import Factor, ScoreInput, ScoreResult, priority_for, score
from riskgraph.modules.risk.models import RiskFactor, RiskScore
from riskgraph.modules.risk.service import persist_score, score_finding
from riskgraph.modules.risk.tables import MODEL_VERSION

__all__ = [
    "MODEL_VERSION",
    "Factor",
    "RiskFactor",
    "RiskScore",
    "ScoreInput",
    "ScoreResult",
    "persist_score",
    "priority_for",
    "score",
    "score_finding",
]
