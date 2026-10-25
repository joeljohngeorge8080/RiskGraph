"""The recorded `trivy image` reports X2 part 2 is built against stay well formed."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parent / "fixtures" / "images"
IMAGES = {
    "python_3.8-slim": "docker.io/library/python:3.8-slim",
    "node_14": "docker.io/library/node:14",
}


def _report(slug: str) -> dict[str, Any]:
    [path] = sorted((ROOT / slug / "trivy").glob("*/report.json"))
    return dict(json.loads(path.read_text()))


@pytest.mark.parametrize(("slug", "name"), IMAGES.items())
def test_each_image_report_has_os_and_language_results(slug: str, name: str) -> None:
    doc = _report(slug)
    assert doc["ArtifactType"] == "container_image" and doc["ArtifactName"] == name
    classes = {r["Class"] for r in doc["Results"]}
    assert classes == {"os-pkgs", "lang-pkgs"}
    for result in doc["Results"]:
        vulns = result["Vulnerabilities"]
        assert 0 < len(vulns) <= 12  # trimmed by the recorder
        assert result["Packages"], "--list-all-pkgs gives the image inventory"
        for v in vulns:
            ident = v["PkgIdentifier"]["PURL"]
            assert ident.startswith("pkg:") and v["VulnerabilityID"] and v["InstalledVersion"]
            assert v["Severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}


def test_fixed_versions_and_the_end_of_support_flag_are_covered() -> None:
    py, node = _report("python_3.8-slim"), _report("node_14")
    fixed = [v for r in py["Results"] for v in r["Vulnerabilities"] if v.get("FixedVersion")]
    assert fixed and any(v["PkgName"] == "pip" for v in fixed)  # a language package with a fix
    assert node["Metadata"]["OS"]["EOSL"] is True  # Debian 10: Trivy itself says end of support
    assert "EOSL" not in py["Metadata"]["OS"] or py["Metadata"]["OS"]["EOSL"] is False


def test_no_secret_or_host_detail_was_committed() -> None:
    for path in ROOT.rglob("*.json"):
        text = path.read_text()
        assert "BEGIN PRIVATE KEY" not in text and "AKIA" not in text, path
        assert "/home/" not in text, path
