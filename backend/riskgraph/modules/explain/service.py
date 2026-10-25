"""Build EvidencePacks from stored rows, explain, and cache by evidence hash."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from riskgraph.modules import graph
from riskgraph.modules.explain.adapters import LlmAdapter, OllamaAdapter
from riskgraph.modules.explain.evidence import (
    FACTOR_NAMES,
    MAX_PATHS,
    EvidencePack,
    FactorEv,
    FindingEv,
    PathEv,
    ScoreEv,
    SnippetEv,
    clip_lines,
    factor_evidence,
)
from riskgraph.modules.explain.generate import Outcome, generate
from riskgraph.modules.explain.models import AiExplanation
from riskgraph.modules.explain.prompt import PROMPT_VERSION
from riskgraph.modules.findings import Finding, get_finding_detail
from riskgraph.modules.risk import RiskScore
from riskgraph.modules.risk.repo import EXCLUDED_FROM_RANKING
from riskgraph.shared.config import Settings
from riskgraph.shared.problems import NotFound
from riskgraph.shared.vocabulary import Priority


def build_pack(session: Session, scan_id: uuid.UUID, finding_id: uuid.UUID) -> EvidencePack:
    d = get_finding_detail(session, finding_id, scan_id)
    if d.score is None:
        raise NotFound("this finding has no risk score in that scan")
    f, s = d.finding, d.score
    loc = f.location or {}
    pkg = f.package or {}
    factors = [
        FactorEv(
            id=f"F{i}",
            name=x.name,
            meaning=FACTOR_NAMES.get(x.name, x.name),
            value=round(float(x.value), 4),
            label=x.raw_value,
            source=x.source,
            confidence=x.confidence,
            applicable=x.applicable,
            evidence=factor_evidence(x.evidence or {}),
        )
        for i, x in enumerate(d.factors, 1)
    ]
    paths = [
        PathEv(
            id=f"P{i}",
            label=" → ".join(str(n.get("label", n.get("key"))) for n in p.nodes),
            probability=round(float(p.probability), 4),
            score=float(p.score),
            sink=p.sink,
            hops=p.hops,
            assurance=graph.path_assurance(p.edges),
        )
        for i, p in enumerate(graph.paths_for_finding(session, scan_id, finding_id)[:MAX_PATHS], 1)
    ]
    snippets = [
        SnippetEv(id=f"S{i}", origin=origin, text=text)
        for i, (origin, text) in enumerate(
            (
                (o, t)
                for o, t in (
                    ("scanner title", clip_lines(f.title)),
                    ("scanner description", clip_lines(f.description)),
                    ("scanner remediation", clip_lines(f.remediation)),
                )
                if t
            ),
            1,
        )
    ]
    return EvidencePack(
        finding=FindingEv(
            finding_id=str(f.id),
            title=f.title[:200],
            source_type=f.source_type.value,
            category=f.category,
            severity=f.severity.value,
            scanners=sorted(d.detected_by),
            file=loc.get("file"),
            line=loc.get("line_start"),
            vulnerability_id=f.vulnerability_id,
            package=pkg.get("name"),
            version=pkg.get("version"),
            fixed_version=pkg.get("fixed_version"),
            cwe_ids=list(f.cwe_ids or [])[:5],
        ),
        score=ScoreEv(
            risk=float(s.score),
            priority=s.priority.value,
            model_version=s.model_version,
            likelihood=float(s.likelihood),
            impact=float(s.impact),
            effective_impact=float(s.effective_impact) if s.effective_impact is not None else None,
            overrides=[str(o.get("rule")) for o in s.overrides],
        ),
        factors=factors,
        paths=paths,
        untrusted_snippets=snippets,
    )


def cached(session: Session, finding_id: uuid.UUID, digest: str) -> AiExplanation | None:
    return session.scalars(
        select(AiExplanation).where(
            AiExplanation.finding_id == finding_id, AiExplanation.evidence_hash == digest
        )
    ).first()


def adapter_from_settings(settings: Settings) -> LlmAdapter | None:
    if settings.llm_provider != "ollama":
        return None
    return OllamaAdapter(
        settings.ollama_url,
        settings.ollama_model,
        timeout_s=settings.ollama_timeout_s,
        keep_alive=settings.ollama_keep_alive,
        socket=settings.ollama_socket,
    )


def explain(
    session: Session,
    scan_id: uuid.UUID,
    finding_id: uuid.UUID,
    adapter: LlmAdapter | None,
    *,
    refresh: bool = False,
) -> AiExplanation:
    """The stored explanation for the finding's current evidence, generating it if needed.

    ``refresh`` regenerates a template fallback (for example once the model is back); a
    validated explanation is kept, since the same evidence would only be re-worded.
    """
    pack = build_pack(session, scan_id, finding_id)
    digest = pack.digest()
    row = cached(session, finding_id, digest)
    if row is not None and not (refresh and row.status == "fallback"):
        return row
    outcome = generate(pack, adapter)
    return _store(session, scan_id, finding_id, pack, digest, outcome)


def _store(
    session: Session,
    scan_id: uuid.UUID,
    finding_id: uuid.UUID,
    pack: EvidencePack,
    digest: str,
    outcome: Outcome,
) -> AiExplanation:
    values = {
        "scan_job_id": scan_id,
        "prompt_version": PROMPT_VERSION,
        "generator": outcome.generator[:96],
        "status": outcome.status,
        "draft": outcome.draft.model_dump(),
        "evidence_ids": pack.ids(),
        "validation_errors": [e[:300] for e in outcome.errors[:10]],
        "attempts": outcome.attempts,
        "latency_ms": outcome.latency_ms,
    }
    # two workers explaining the same finding at once: the later write wins, one row stays
    session.execute(
        insert(AiExplanation)
        .values(id=uuid.uuid4(), finding_id=finding_id, evidence_hash=digest, **values)
        .on_conflict_do_update(constraint="uq_ai_explanations_evidence", set_=values)
    )
    session.flush()
    row = cached(session, finding_id, digest)
    if row is None:  # pragma: no cover - the upsert above guarantees it
        raise RuntimeError("explanation row missing after upsert")
    session.refresh(row)
    return row


def top_critical(session: Session, scan_id: uuid.UUID, limit: int) -> list[uuid.UUID]:
    """The scan's highest-scoring Critical findings that are still in the ranking (§15.3)."""
    return list(
        session.scalars(
            select(RiskScore.finding_id)
            .join(Finding, Finding.id == RiskScore.finding_id)
            .where(
                RiskScore.scan_job_id == scan_id,
                RiskScore.priority == Priority.CRITICAL,
                Finding.status.not_in(EXCLUDED_FROM_RANKING),
            )
            .order_by(RiskScore.score.desc(), RiskScore.finding_id)
            .limit(limit)
        )
    )
