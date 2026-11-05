"""Image scanning (X2 part 2, ADR-0018): the command, the parser and the image scoping."""

from __future__ import annotations

import datetime as dt
import json
from itertools import pairwise
from pathlib import Path
from typing import Any

import pytest
from riskgraph.modules.normalization import Location, RawFinding, fingerprint, merge
from riskgraph.modules.runtime import os_eol_finding, parse_ref
from riskgraph.modules.scanners import ScanPaths
from riskgraph.modules.scanners.trivy import TrivyScanner
from riskgraph.modules.scanners.trivy.parser import parse_image
from riskgraph.modules.scans.finding_evidence import finding_evidence
from riskgraph.shared.config import Settings
from riskgraph.shared.vocabulary import ScannerName, Severity, SourceType

ROOT = Path(__file__).parent / "fixtures" / "images"
PY = "docker.io/library/python:3.8-slim"
NODE = "docker.io/library/node:14"
PATHS = ScanPaths(Path("/w/src"), Path("/w/out/trivy-image"), Path("/w/home/i"), Path("/cache"))


def report(slug: str) -> dict[str, Any]:
    [path] = sorted((ROOT / slug / "trivy").glob("*/report.json"))
    return dict(json.loads(path.read_text()))


def test_image_command_uses_the_recorded_flags_and_puts_the_ref_last() -> None:
    cmd = TrivyScanner().image_command(PATHS, Settings(), PY, "/w/out/trivy-image/0.json")
    argv = cmd.argv
    assert argv[:2] == ("trivy", "image") and argv[-1] == PY
    for flag in (
        "--list-all-pkgs",
        "--skip-db-update",
        "--skip-java-db-update",
        "--skip-version-check",
        "--disable-telemetry",
        "--quiet",
    ):
        assert flag in argv
    pairs = dict(pairwise(argv[2:]))
    assert pairs["--image-src"] == "remote"  # a registry pull, never a Docker daemon
    assert pairs["--scanners"] == "vuln"
    assert pairs["--cache-backend"] == "memory"
    assert pairs["--cache-dir"] == "/cache" and pairs["--format"] == "json"
    assert pairs["--output"] == "/w/out/trivy-image/0.json"
    assert pairs["--max-image-size"] == "2147MB"  # 2 GiB, in Trivy's decimal units
    assert pairs["--timeout"] == "270s"
    assert set(cmd.env) == {"HOME", "TMPDIR"}


@pytest.mark.parametrize("ref", ["", "-x", "--config=/etc/passwd"])
def test_image_command_refuses_a_ref_that_looks_like_an_option(ref: str) -> None:
    with pytest.raises(ValueError):
        TrivyScanner().image_command(PATHS, Settings(), ref, "/w/o.json")


@pytest.mark.parametrize("raw", ["-x", "--config=/etc/passwd", "--x.io/a:1"])
def test_an_option_shaped_reference_is_never_allowed(raw: str) -> None:
    assert parse_ref(raw, "Dockerfile", 1, "dockerfile").allowed is False


def test_python_image_parses_os_and_language_packages_with_fixed_versions() -> None:
    r = parse_image(report("python_3.8-slim"), PY, "api/Dockerfile", 1)
    assert (r.os_family, r.os_name, r.eosl) == ("debian", "12.7", False)
    assert r.created_at and r.size == 129651200
    assert len(r.findings) == 24  # 12 OS + 12 language, as recorded
    ecosystems = {f.package["ecosystem"] for f in r.findings if f.package}
    assert ecosystems == {"debian", "python-pkg"}
    for f in r.findings:
        assert f.source_type is SourceType.SCA and f.scanner is ScannerName.TRIVY
        assert f.vulnerability_id and f.package and f.package["version"]
        assert f.package["image"] == PY and f.attrs["image"]["ref"] == PY
        assert f.location == Location("api/Dockerfile", 1, 1, PY)
    pip = [f for f in r.findings if f.package and f.package["name"] == "pip"]
    assert pip and all(f.package and f.package["fixed_version"] for f in pip)
    assert all(f.package and f.package["path"].endswith("METADATA") for f in pip)
    assert {p.purl.split("/", 1)[0] for p in r.packages} == {"pkg:deb", "pkg:pypi"}


def test_node_image_reports_the_end_of_support_os() -> None:
    r = parse_image(report("node_14"), NODE, "docker-compose.yml")
    assert (r.os_family, r.os_name, r.eosl) == ("debian", "10.13", True)
    assert any(f.package and f.package["ecosystem"] == "node-pkg" for f in r.findings)
    assert r.findings[0].location == Location("docker-compose.yml", None, None, NODE)


@pytest.mark.parametrize("doc", [None, [], {"Results": "x"}, {"Metadata": [], "Results": [1]}])
def test_parse_image_never_raises_on_malformed_reports(doc: Any) -> None:
    r = parse_image(doc, PY, "Dockerfile")
    assert r.findings == [] and r.packages == [] and r.eosl is False and r.size is None


def _sca(image: str | None, file: str = "Dockerfile") -> RawFinding:
    pkg = {"name": "pip", "version": "23.0.1", "purl": "pkg:pypi/pip@23.0.1"}
    if image:
        pkg["image"] = image
    return RawFinding(
        scanner=ScannerName.TRIVY,
        source_type=SourceType.SCA,
        rule_id="CVE-2023-5752",
        title="t",
        severity=Severity.MEDIUM,
        location=Location(file),
        category="vuln_dependency",
        vulnerability_id="CVE-2023-5752",
        package=pkg,
    )


def test_the_same_cve_in_two_images_stays_two_findings() -> None:
    a, b, repo = _sca(PY), _sca("docker.io/library/python:3.9"), _sca(None)
    assert len({fingerprint(x, "o/r") for x in (a, b, repo)}) == 3
    assert len(merge([a, b, repo])) == 3


def test_repository_package_fingerprint_and_merge_key_are_unchanged() -> None:
    # pinned before X2 part 2: image scoping must not move existing findings
    f = _sca(None, "requirements.txt")
    assert fingerprint(f, "o/r") == _legacy_sca_fingerprint(f, "o/r")
    assert merge([f])[0].merge_key == _legacy_sca_merge_key(f)


def _legacy_sca_fingerprint(f: RawFinding, repository: str) -> str:
    from riskgraph.modules.normalization.fingerprint import stable_hash

    pkg = f.package or {}
    return stable_hash("sca", repository, f.vulnerability_id, pkg["purl"], f.location.file)


def _legacy_sca_merge_key(f: RawFinding) -> str:
    from riskgraph.modules.normalization.fingerprint import stable_hash

    pkg = f.package or {}
    return stable_hash("sca", f.vulnerability_id, pkg["purl"], f.location.file)


def test_os_end_of_life_finding_shape() -> None:
    f = os_eol_finding(NODE, "debian", "10.13", "docker-compose.yml", None, "2026-10-25T12:33Z")
    assert f.rule_id == "runtime-eol:os:debian:10.13"
    assert f.source_type is SourceType.RUNTIME and f.scanner is ScannerName.RISKGRAPH
    assert f.severity is Severity.HIGH and f.package and f.package["image"] == NODE
    assert f.location.resource == NODE


def test_image_evidence_names_the_image_and_carries_the_data_dates() -> None:
    r = parse_image(report("node_14"), NODE, "docker-compose.yml")
    eol = os_eol_finding(NODE, "debian", "10.13", "docker-compose.yml", None, r.created_at)
    db = dt.datetime(2026, 10, 25, 1, 20, tzinfo=dt.UTC)
    now = dt.datetime(2026, 10, 26, tzinfo=dt.UTC)
    for f in (r.findings[0], eol):
        f.fingerprint = fingerprint(f, "o/r")
    pkg_ev, eol_ev = (
        finding_evidence(m, None, {}, {}, now, {"trivy": db})[0]
        for m in merge([r.findings[0], eol])
    )
    by_kind = {e.kind: e for e in (pkg_ev, eol_ev)}
    assert by_kind["image_package"].facts["image"] == NODE
    assert by_kind["image_package"].data_as_of == db
    assert by_kind["image_package"].facts["vulnerability_id"]
    assert by_kind["eol"].data_as_of == dt.datetime.fromisoformat(str(r.created_at))
    assert by_kind["eol"].raw is None and by_kind["image_package"].raw is None
