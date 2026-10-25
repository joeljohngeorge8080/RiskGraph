from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest
from riskgraph.modules.context import load_manifest, parse_manifest
from riskgraph.modules.context.manifest import MAX_MANIFEST_BYTES, normalize_service_path
from riskgraph.modules.scans.workspace import ScanWorkspace

VALID = """
version: 1
services:
  - name: api
    path: backend/
    language: python
    entrypoints: [backend/app/main.py]
    exposure: internet
    auth: none
    runs_as: api-role
    connects_to: [customers-db, cache]
  - name: cache
    path: ./cache
    exposure: internal
identities:
  - name: api-role
    privilege: elevated
    can_access: [customers-db, secrets]
data_stores:
  - name: customers-db
    kind: postgres
    sensitivity: pii
  - name: secrets
    kind: vault
    sensitivity: credentials
criticality:
  api: high
"""


def test_valid_manifest_parses_and_normalizes_paths() -> None:
    r = parse_manifest(VALID)
    assert r.status == "valid" and r.warnings == ()
    assert r.manifest is not None
    assert [s.path for s in r.manifest.services] == ["backend/", "cache/"]
    assert r.manifest.criticality == {"api": "high"}


@pytest.mark.parametrize(
    ("text", "needle"),
    [
        ("version: 1\nservices:\n  - name: api\n    exposure: public\n", "exposure"),
        ("version: 1\nservices:\n  - name: api\n    colour: red\n", "colour"),
        ("version: 2\n", "version"),
        ("version: 1\nservices:\n  - name: api\n    runs_as: ghost\n", "ghost"),
        ("version: 1\nservices:\n  - name: api\n    connects_to: [db]\n", "'db'"),
        ("version: 1\ncriticality:\n  nobody: high\n", "nobody"),
        (
            "version: 1\nservices:\n  - name: x\ndata_stores:\n  - name: x\n",
            "unique",
        ),
        ("version: 1\nservices:\n  - name: api\n    path: ../etc\n", "inside"),
        ("version: 1\nservices:\n  - name: api\n    path: /etc\n", "relative"),
        ("version: 1\nservices:\n  - name: '../x'\n", "name"),
    ],
)
def test_strict_validation_rejects_with_a_reason(text: str, needle: str) -> None:
    r = parse_manifest(text)
    assert r.status == "invalid" and r.manifest is None
    assert any(needle in w for w in r.warnings), r.warnings


@pytest.mark.parametrize(
    "text",
    [
        "version: 1\nservices: [\n",  # broken YAML
        "- just\n- a list\n",  # wrong top-level type
        "",  # empty file
        "a: &x [1]\nb: *x\n",  # aliases refused (billion laughs)
        "version: !!python/object:os.system 1\n",  # unsafe tag
    ],
)
def test_hostile_or_broken_documents_never_raise(text: str) -> None:
    r = parse_manifest(text)
    assert r.status == "invalid" and r.warnings


def test_deep_nesting_is_refused_without_crashing() -> None:
    depth = 20_000  # fits in the 64 KiB cap
    r = parse_manifest("[" * depth + "]" * depth)
    assert r.status == "invalid" and r.warnings


def test_warnings_are_bounded() -> None:
    long_key = "k" * 1000  # YAML allows plain keys up to 1024 characters
    r = parse_manifest(f"version: 1\n{long_key}: 1\n" + "".join(f"x{i}: 1\n" for i in range(50)))
    assert r.status == "invalid"
    assert len(r.warnings) <= 20 and all(len(w) <= 200 for w in r.warnings)


def test_alias_bomb_is_refused_before_expansion() -> None:
    lines = ['a0: &a0 ["x","x","x","x","x","x","x","x","x"]']
    lines += [f"a{i}: &a{i} [{','.join([f'*a{i - 1}'] * 9)}]" for i in range(1, 9)]
    r = parse_manifest("\n".join(lines))
    assert r.warnings == ("YAML aliases are not allowed",)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("", ""), (".", ""), ("./", ""), ("backend", "backend/"), ("a//b/./c/", "a/b/c/")],
)
def test_service_paths(raw: str, expected: str) -> None:
    assert normalize_service_path(raw) == expected


def test_documented_example_manifest_is_valid() -> None:
    example = Path(__file__).resolve().parents[2] / "docs" / "examples" / "riskgraph.yaml"
    r = parse_manifest(example.read_text())
    assert r.status == "valid", r.warnings


def _ws(tmp_path: Path) -> ScanWorkspace:
    ws = ScanWorkspace(tmp_path / "ws", uuid.uuid4())
    ws.src.mkdir(parents=True)
    return ws


def test_load_absent_valid_and_yml_fallback(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    assert load_manifest(ws).status == "absent"
    (ws.src / "riskgraph.yml").write_text(VALID)
    r = load_manifest(ws)
    assert r.status == "valid" and r.file == "riskgraph.yml"


def test_load_refuses_oversized_and_non_utf8(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    (ws.src / "riskgraph.yaml").write_text("#" * (MAX_MANIFEST_BYTES + 1))
    assert load_manifest(ws).status == "invalid"
    (ws.src / "riskgraph.yaml").write_bytes(b"version: 1\n\xff\xfe")
    r = load_manifest(ws)
    assert r.status == "invalid" and "UTF-8" in r.warnings[0]


def test_symlink_out_of_the_checkout_is_ignored(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    outside = tmp_path / "outside.yaml"
    outside.write_text(VALID)
    os.symlink(outside, ws.src / "riskgraph.yaml")
    assert load_manifest(ws).status == "absent"
