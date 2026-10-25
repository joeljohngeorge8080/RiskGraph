"""Runtime declarations and end-of-life findings (expansion X2)."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pytest
from riskgraph.modules.runtime import (
    EolCycle,
    declarations,
    eol_status,
    parse_cycles,
    parse_ref,
    runtime_findings,
)
from riskgraph.shared.vocabulary import ScannerName, Severity, SourceType

FIXTURES = Path(__file__).parent / "fixtures" / "eol"
TODAY = dt.date(2026, 10, 25)
FETCHED = dt.datetime(2026, 10, 25, 6, 0, tzinfo=dt.UTC)


def _cycles(product: str) -> dict[str, EolCycle]:
    doc = json.loads((FIXTURES / f"{product}.json").read_text())
    return {c.cycle: c for c in parse_cycles(product, doc, FETCHED)}


def _write(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def test_recorded_feed_parses_dates_and_booleans() -> None:
    py = _cycles("python")
    assert py["3.8"].eol_date == dt.date(2024, 10, 7) and py["3.8"].latest == "3.8.20"
    go = _cycles("go")
    newest = max(go.values(), key=lambda c: c.release_date or dt.date.min)
    assert newest.eol_date is None and newest.eol_flag is False  # "eol": false


def test_malformed_feed_entries_are_skipped_not_fatal() -> None:
    doc = [
        {"cycle": "3.9", "eol": "not-a-date"},
        {"eol": "2020-01-01"},
        "junk",
        {"cycle": "x" * 40},
    ]
    got = parse_cycles("python", doc, FETCHED)
    assert [c.cycle for c in got] == ["3.9"] and got[0].eol_date is None


def test_exact_declarations_from_files_and_images(tmp_path: Path) -> None:
    _write(tmp_path, ".python-version", "# pyenv\n3.8.10\n")
    _write(tmp_path, "runtime.txt", "python-3.11.4\n")
    _write(tmp_path, "web/.nvmrc", "v14.17.0\n")
    _write(tmp_path, "web/package.json", '{"engines": {"node": ">=16"}}')
    _write(tmp_path, "svc/package.json", '{"engines": {"node": "18"}}')
    _write(tmp_path, "pyproject.toml", '[project]\nrequires-python = ">=3.8"\n')
    _write(tmp_path, "tool/go.mod", "module x\n\ngo 1.19\n")
    images = [
        parse_ref("python:3.8-slim", "Dockerfile", 1, "dockerfile"),
        parse_ref("node:14", "Dockerfile", 5, "dockerfile"),
        parse_ref("golang:1.21-alpine", "tool/Dockerfile", 1, "dockerfile"),
        parse_ref("python:latest", "Dockerfile", 9, "dockerfile"),  # no version: nothing
        parse_ref("ghcr.io/acme/python:3.8", "x", 1, "dockerfile"),  # not the official image
    ]
    got = {(d.product, d.cycle, d.file, d.line, d.exact) for d in declarations(tmp_path, images)}
    assert got == {
        ("python", "3.8", ".python-version", 2, True),
        ("python", "3.11", "runtime.txt", 1, True),
        ("nodejs", "14", "web/.nvmrc", 1, True),
        ("nodejs", "16", "web/package.json", None, False),  # a range: recorded only
        ("nodejs", "18", "svc/package.json", None, True),
        ("python", "3.8", "pyproject.toml", None, False),
        ("go", "1.19", "tool/go.mod", 3, False),  # a minimum, not what runs
        ("python", "3.8", "Dockerfile", 1, True),
        ("nodejs", "14", "Dockerfile", 5, True),
        ("go", "1.21", "tool/Dockerfile", 1, True),
    }


@pytest.mark.parametrize(
    ("product", "cycle", "eol", "fix"),
    [
        ("python", "3.8", True, "3.11"),
        ("python", "3.13", False, None),
        ("nodejs", "14", True, "22"),
    ],
)
def test_eol_status_and_the_oldest_supported_cycle(
    product: str, cycle: str, eol: bool, fix: str | None
) -> None:
    status = eol_status(product, cycle, _cycles(product), TODAY)
    assert status is not None and status.eol is eol
    assert status.oldest_supported == (fix if eol else status.oldest_supported)


def test_an_unknown_cycle_has_no_status() -> None:
    assert eol_status("python", "2.9", _cycles("python"), TODAY) is None


def test_findings_only_for_exact_eol_declarations(tmp_path: Path) -> None:
    _write(tmp_path, "pyproject.toml", '[project]\nrequires-python = ">=3.8"\n')
    images = [
        parse_ref("python:3.8-slim", "Dockerfile", 1, "dockerfile"),
        parse_ref("node:14", "Dockerfile", 5, "dockerfile"),
        parse_ref("python:3.13", "web/Dockerfile", 1, "dockerfile"),
    ]
    decls = declarations(tmp_path, images)
    feeds = {"python": _cycles("python"), "nodejs": _cycles("nodejs")}
    found = runtime_findings(decls, feeds, TODAY)
    assert sorted((f.rule_id, f.location.file, f.location.line_start) for f in found) == [
        ("runtime-eol:nodejs:14", "Dockerfile", 5),
        ("runtime-eol:python:3.8", "Dockerfile", 1),
    ]
    py = next(f for f in found if "python" in f.rule_id)
    assert py.scanner is ScannerName.RISKGRAPH and py.source_type is SourceType.RUNTIME
    assert py.severity is Severity.HIGH and "2024-10-07" in py.title
    # a known-vulnerability finding carries its advisory, range, matched version, data date
    assert py.attrs["advisory"] == "endoflife.date/python/3.8"
    assert py.package == {
        "name": "python",
        "version": "3.8",
        "fixed_version": "3.11",
        "ecosystem": "runtime",
    }
    assert py.attrs["eol_date"] == "2024-10-07"
    assert py.attrs["data_as_of"] == FETCHED.isoformat()


def test_no_feed_data_means_no_finding() -> None:
    decls = declarations(Path("/nonexistent"), [parse_ref("python:3.8", "D", 1, "dockerfile")])
    assert runtime_findings(decls, {}, TODAY) == []
