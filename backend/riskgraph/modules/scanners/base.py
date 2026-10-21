"""Scanner seam (blueprint §9.2, ADR-0009).

A ``Scanner`` knows how to build its command line, redact its own report and parse it
into canonical findings. *How* the command runs is the runner's business: the MVP uses
``SubprocessRunner``; the blueprint's hardened ``DockerRunner`` can replace it without
touching adapters, because adapters only ever see ``ScanPaths``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Protocol

from riskgraph.modules.normalization import RawFinding
from riskgraph.shared.config import Settings
from riskgraph.shared.vocabulary import ScannerName

Network = Literal["none", "egress"]


@dataclass(frozen=True, slots=True)
class ScanPaths:
    src: Path  # read-only checkout; also the working directory
    out: Path  # this scanner's private output directory
    home: Path  # this scanner's private HOME / TMPDIR parent
    cache: Path  # shared tool cache (Trivy DB)


@dataclass(frozen=True, slots=True)
class Command:
    argv: tuple[str, ...]
    env: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class ParseContext:
    repository: str  # "owner/name", part of every fingerprint


class Scanner(Protocol):
    name: ScannerName
    network: Network
    ok_exit_codes: frozenset[int]
    output_name: str  # fixed file name inside ScanPaths.out

    def timeout_s(self, settings: Settings) -> int: ...

    def command(self, paths: ScanPaths, settings: Settings) -> Command: ...

    def version_argv(self) -> tuple[str, ...]: ...

    def redact(self, doc: Any, key: bytes) -> tuple[Any, set[str]]:
        """Return the document with secrets and code snippets removed, plus every raw
        secret value seen (so the collector can scrub them from other reports)."""
        ...

    def count(self, doc: Any) -> int: ...

    def parse(self, doc: Any, ctx: ParseContext) -> list[RawFinding]:
        """Pure: redacted native document in, canonical findings out."""
        ...
