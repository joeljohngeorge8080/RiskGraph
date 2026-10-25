"""What an explainer returns (blueprint §15): structured, every claim cites evidence ids."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

MAX_REASONS = 6
MAX_STEPS = 6


class Reason(BaseModel):
    model_config = ConfigDict(extra="forbid")
    claim: str = Field(max_length=400)
    evidence_ids: list[str] = Field(max_length=8)


class ExplanationDraft(BaseModel):
    model_config = ConfigDict(extra="forbid")
    summary: str = Field(max_length=900)
    reasons: list[Reason] = Field(max_length=MAX_REASONS)
    impact: str = Field(max_length=600)
    remediation_steps: list[str] = Field(max_length=MAX_STEPS)
    caveats: str = Field(default="", max_length=600)


def json_schema() -> dict[str, Any]:
    """The structured-output schema handed to the model (Ollama ``format``)."""
    return ExplanationDraft.model_json_schema()
