"""Evidence → validated explanation, with one retry and a template fallback (blueprint §15).

    attempt 1 ── valid ──▶ stored as "validated"
       │ invalid (feedback = validator errors)
    attempt 2 ── valid ──▶ stored as "validated"
       │ invalid, or the model is unavailable at any point
    template ─────────────▶ stored as "fallback" (always valid)

Pure apart from the adapter call. The model's raw reply is never stored: a rejected reply
may carry text injected by the repository, so only the validator's messages are kept.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field

from pydantic import ValidationError

from riskgraph.modules.explain import template
from riskgraph.modules.explain.adapters import AdapterError, LlmAdapter
from riskgraph.modules.explain.draft import ExplanationDraft, json_schema
from riskgraph.modules.explain.evidence import EvidencePack
from riskgraph.modules.explain.prompt import SYSTEM, user_message
from riskgraph.modules.explain.validator import validate

MAX_ATTEMPTS = 2


@dataclass(frozen=True, slots=True)
class Outcome:
    draft: ExplanationDraft
    status: str  # validated | fallback
    generator: str  # "ollama:<model>" | "template"
    attempts: int
    errors: list[str] = field(default_factory=list)
    latency_ms: int = 0


def _parse(raw: str) -> ExplanationDraft:
    return ExplanationDraft.model_validate(json.loads(raw))


def generate(pack: EvidencePack, adapter: LlmAdapter | None) -> Outcome:
    started = time.monotonic()
    errors: list[str] = []
    attempts = 0
    if adapter is not None:
        feedback: list[str] | None = None
        while attempts < MAX_ATTEMPTS:
            attempts += 1
            try:
                raw = adapter.complete(SYSTEM, user_message(pack, feedback), json_schema())
            except AdapterError as exc:
                errors.append(f"attempt {attempts}: {exc}")
                break  # unavailable: retrying the same call is not feedback
            try:
                draft = _parse(raw)
            except (ValueError, ValidationError) as exc:
                problems = [f"reply is not a valid explanation object ({type(exc).__name__})"]
            else:
                problems = validate(draft, pack)
                if not problems:
                    return Outcome(
                        draft,
                        "validated",
                        adapter.name,
                        attempts,
                        errors,
                        int((time.monotonic() - started) * 1000),
                    )
            errors.extend(f"attempt {attempts}: {p}" for p in problems)
            feedback = problems
    draft = template.explain(pack)
    # the template only restates evidence; a failure here is a bug in this module
    problems = validate(draft, pack)
    if problems:
        raise RuntimeError(f"template explanation failed validation: {problems}")
    return Outcome(
        draft, "fallback", "template", attempts, errors, int((time.monotonic() - started) * 1000)
    )
