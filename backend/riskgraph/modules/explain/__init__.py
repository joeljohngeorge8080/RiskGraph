"""Explain: evidence-grounded narration of a finding's score (blueprint §15).

AI never decides risk: the score is computed first; the model only words the evidence,
and its answer is used only if a mechanical validator finds nothing invented.
"""

from riskgraph.modules.explain.adapters import AdapterError, LlmAdapter, NullAdapter, OllamaAdapter
from riskgraph.modules.explain.evidence import EvidencePack
from riskgraph.modules.explain.generate import Outcome, generate
from riskgraph.modules.explain.models import AiExplanation

__all__ = [
    "AdapterError",
    "AiExplanation",
    "EvidencePack",
    "LlmAdapter",
    "NullAdapter",
    "OllamaAdapter",
    "Outcome",
    "generate",
]
