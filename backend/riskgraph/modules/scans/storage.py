"""Stored (redacted) scanner reports: ``<scan_output_root>/<scan_id>/<scanner>.json``."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import uuid
from pathlib import Path
from typing import Any

from riskgraph.shared.vocabulary import ScannerName


class ReportTooLargeError(Exception):
    pass


def report_relpath(scan_id: uuid.UUID, scanner: ScannerName) -> str:
    return f"{scan_id}/{ScannerName(scanner).value}.json"


def report_path(root: Path, scan_id: uuid.UUID, scanner: ScannerName) -> Path:
    path = (root / report_relpath(scan_id, scanner)).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ValueError("report path escapes the output root")
    return path


def read_json_capped(path: Path, max_bytes: int) -> Any:
    size = path.stat().st_size
    if size > max_bytes:
        raise ReportTooLargeError(f"report is {size} bytes (cap {max_bytes})")
    with path.open("rb") as fh:
        return json.loads(fh.read(max_bytes + 1))


def write_report(
    root: Path, scan_id: uuid.UUID, scanner: ScannerName, doc: Any
) -> tuple[str, str, int]:
    """Atomically write a report; returns (relative path, sha256, size)."""
    path = report_path(root, scan_id, scanner)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(doc, separators=(",", ":"), sort_keys=True).encode()
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return report_relpath(scan_id, scanner), hashlib.sha256(data).hexdigest(), len(data)


def read_report(root: Path, scan_id: uuid.UUID, scanner: ScannerName, max_bytes: int) -> Any:
    return read_json_capped(report_path(root, scan_id, scanner), max_bytes)
