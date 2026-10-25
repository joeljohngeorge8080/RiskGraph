"""Evidence: one contract for every fact the graph and the scores rest on (ADR-0017).

Owns no analysis. Producers (scanners, the manifest, the reachability analyzer, the graph
builder) create ``Evidence``; this module validates it, gives it a stable id, stores it
scan-scoped and links it to findings and graph edges.
"""

from riskgraph.modules.evidence.contract import (
    KINDS,
    MAX_STEPS,
    Assurance,
    Evidence,
    FlowStep,
    RawRef,
    Relationship,
    make_evidence,
    min_assurance,
)
from riskgraph.modules.evidence.models import EdgeEvidence, EvidenceRow, FindingEvidence
from riskgraph.modules.evidence.service import (
    clear,
    evidence_for_edges,
    evidence_for_finding,
    link_edge,
    link_finding,
    persist_evidence,
)

__all__ = [
    "KINDS",
    "MAX_STEPS",
    "Assurance",
    "EdgeEvidence",
    "Evidence",
    "EvidenceRow",
    "FindingEvidence",
    "FlowStep",
    "RawRef",
    "Relationship",
    "clear",
    "evidence_for_edges",
    "evidence_for_finding",
    "link_edge",
    "link_finding",
    "make_evidence",
    "min_assurance",
    "persist_evidence",
]
