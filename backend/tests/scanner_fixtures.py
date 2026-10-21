"""Helpers to load recorded scanner fixtures (see tests/fixtures/scanners/record.py)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from riskgraph.modules.normalization import RawFinding, fingerprint
from riskgraph.modules.scanners import SCANNERS, ParseContext
from riskgraph.shared.vocabulary import ScannerName

FIXTURES = Path(__file__).parent / "fixtures" / "scanners"
REPO = "acme/kitchen-sink"


def fixture_path(scanner: ScannerName, name: str = "kitchen_sink.json") -> Path:
    matches = sorted((FIXTURES / scanner.value).glob(f"*/{name}"))
    assert matches, f"no fixture for {scanner}"
    return matches[-1]


def load(scanner: ScannerName) -> Any:
    return json.loads(fixture_path(scanner).read_text())


def parse_all() -> list[RawFinding]:
    out: list[RawFinding] = []
    for name, scanner in SCANNERS.items():
        for f in scanner.parse(load(name), ParseContext(REPO)):
            f.fingerprint = fingerprint(f, REPO)
            out.append(f)
    return out
