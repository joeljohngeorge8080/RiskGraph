"""The frontend's copies of the shared vocabulary match the backend enums.

`frontend/src/api/types.ts` mirrors these enums by hand. When a phase adds a value (a
source type, a producer, a status), the UI must learn it too, or it renders a blank label
or keeps polling a scan that has ended.
"""

from __future__ import annotations

import re
from enum import StrEnum
from pathlib import Path

import pytest
from riskgraph.shared.vocabulary import (
    FindingChange,
    FindingStatus,
    Priority,
    ReachabilityTier,
    RunStatus,
    ScannerName,
    ScanStatus,
    Severity,
    SourceType,
)

TYPES = Path(__file__).resolve().parents[2] / "frontend" / "src" / "api" / "types.ts"

MIRRORED: dict[str, type[StrEnum]] = {
    "ScanStatus": ScanStatus,
    "RunStatus": RunStatus,
    "Priority": Priority,
    "Severity": Severity,
    "SourceType": SourceType,
    "ScannerName": ScannerName,
    "FindingStatus": FindingStatus,
    "FindingChange": FindingChange,
    "ReachabilityTier": ReachabilityTier,
}


def union_members(source: str, name: str) -> set[str]:
    """The string literals of ``export type <name> = "a" | "b" ...;`` (one statement)."""
    m = re.search(rf"^export type {name} =([^;]*);", source, re.MULTILINE)
    if m is None:
        raise LookupError(f"no string union named {name}")
    body = m.group(1)
    members = re.findall(r'"([^"\\]*)"', body)
    rest = re.sub(r'"[^"\\]*"', "", body)
    if not members or rest.replace("|", "").strip():
        raise ValueError(f"{name} is not a plain union of string literals")
    return set(members)


@pytest.mark.parametrize("name", sorted(MIRRORED))
def test_the_frontend_union_equals_the_backend_enum(name: str) -> None:
    frontend = union_members(TYPES.read_text(), name)
    backend = {v.value for v in MIRRORED[name]}
    assert frontend == backend, (
        f"{name}: missing in the frontend {sorted(backend - frontend)}, "
        f"unknown to the backend {sorted(frontend - backend)}"
    )


def test_the_parser_reads_multi_line_unions() -> None:
    src = 'export type A =\n  | "x"\n  | "y";\nexport type B = "z";\n'
    assert union_members(src, "A") == {"x", "y"}
    assert union_members(src, "B") == {"z"}


def test_the_parser_refuses_what_it_cannot_compare() -> None:
    with pytest.raises(LookupError):
        union_members('export type AB = "x";', "A")
    with pytest.raises(ValueError):
        union_members('export type A = "x" | string;', "A")
    with pytest.raises(ValueError):
        union_members("export type A = string;", "A")
