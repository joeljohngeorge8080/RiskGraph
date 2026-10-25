"""Stored (redacted) scanner reports: ``<scan_output_root>/<scan_id>/<scanner>.json``,
and image reports under ``<scan_id>/images/``."""

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
    sha, size = _write_atomic(report_path(root, scan_id, scanner), doc)
    return report_relpath(scan_id, scanner), sha, size


def read_report(root: Path, scan_id: uuid.UUID, scanner: ScannerName, max_bytes: int) -> Any:
    return read_json_capped(report_path(root, scan_id, scanner), max_bytes)


# Image reports (X2, ADR-0018): ``<scan_output_root>/<scan_id>/images/<k>.json`` plus an
# ``index.json`` the image stage writes last. ``k`` is a position, never a reference.


def _image_path(root: Path, scan_id: uuid.UUID, name: str) -> tuple[Path, str]:
    rel = f"{uuid.UUID(str(scan_id))}/images/{name}.json"
    path = (root / rel).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ValueError("report path escapes the output root")
    return path, rel


def write_image_report(root: Path, scan_id: uuid.UUID, index: int, doc: Any) -> str:
    path, rel = _image_path(root, scan_id, str(int(index)))
    _write_atomic(path, doc)
    return rel


def read_image_report(root: Path, scan_id: uuid.UUID, index: int, max_bytes: int) -> Any:
    return read_json_capped(_image_path(root, scan_id, str(int(index)))[0], max_bytes)


def write_image_index(root: Path, scan_id: uuid.UUID, doc: Any) -> None:
    _write_atomic(_image_path(root, scan_id, "index")[0], doc)


def read_image_index(root: Path, scan_id: uuid.UUID) -> Any | None:
    path = _image_path(root, scan_id, "index")[0]
    if not path.is_file():
        return None
    return read_json_capped(path, 1024 * 1024)


def _write_atomic(path: Path, doc: Any) -> tuple[str, int]:
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
    return hashlib.sha256(data).hexdigest(), len(data)
