"""API schemas for scans."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from riskgraph.shared.vocabulary import RunStatus, ScannerName, ScanStatus


class ScanCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repo_url: str = Field(max_length=300, examples=["https://github.com/bridgecrewio/terragoat"])
    ref: str | None = Field(default=None, max_length=255, examples=["master"])


class RepositoryOut(BaseModel):
    id: uuid.UUID
    full_name: str
    url: str


class ScannerRunOut(BaseModel):
    scanner: ScannerName
    status: RunStatus
    version: str | None
    exit_code: int | None
    duration_ms: int | None
    raw_findings_count: int | None
    output_bytes: int | None
    error_excerpt: str | None
    report_available: bool


class ScanOut(BaseModel):
    id: uuid.UUID
    repository: RepositoryOut
    requested_ref: str
    commit_sha: str | None
    status: ScanStatus
    status_reason: str | None
    created_at: dt.datetime
    started_at: dt.datetime | None
    finished_at: dt.datetime | None
    risk_model_version: str | None
    summary: dict[str, Any]
    scanner_runs: list[ScannerRunOut]
    deduplicated: bool = False


class ScanList(BaseModel):
    items: list[ScanOut]
    total: int
