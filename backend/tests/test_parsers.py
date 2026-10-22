from __future__ import annotations

import copy

from riskgraph.modules.normalization.paths import INVALID_PATH, normalize_path
from riskgraph.modules.scanners import SCANNERS, ParseContext
from riskgraph.modules.scanners.checkov import parser as checkov_parser
from riskgraph.modules.scanners.semgrep.parser import clean_rule_id
from riskgraph.shared.vocabulary import ScannerName, Severity, SourceType

from tests.scanner_fixtures import REPO, load

CTX = ParseContext(REPO)


def test_counts_match_parsed_findings() -> None:
    for name, scanner in SCANNERS.items():
        doc = load(name)
        if name is ScannerName.SYFT:  # an inventory: no findings, the components are the SBOM
            assert scanner.count(doc) == len(scanner.parse(doc, CTX)) == 0
            continue
        assert scanner.count(doc) == len(scanner.parse(doc, CTX)) > 0, name


def test_trivy_covers_all_three_scanners() -> None:
    found = SCANNERS[ScannerName.TRIVY].parse(load(ScannerName.TRIVY), CTX)
    kinds = {f.source_type for f in found}
    assert kinds == {SourceType.SCA, SourceType.SECRET, SourceType.IAC}
    sca = next(f for f in found if f.source_type is SourceType.SCA)
    assert sca.vulnerability_id and sca.package and sca.package["purl"].startswith("pkg:pypi/")
    assert sca.cvss and sca.cvss["vector"].startswith("CVSS:3")
    aws = next(f for f in found if f.rule_id == "aws-access-key-id")
    assert aws.severity is Severity.CRITICAL and aws.attrs["live_credential"]
    misconf = next(f for f in found if f.rule_id == "AWS-0107")
    assert misconf.attrs["iac_topic"] == "sg-open-ingress"
    assert misconf.location.resource == "aws_security_group.ssh"


def test_semgrep_rule_ids_and_categories() -> None:
    found = SCANNERS[ScannerName.SEMGREP].parse(load(ScannerName.SEMGREP), CTX)
    assert all(not f.rule_id.startswith("root.") for f in found)
    cats = {f.category for f in found if f.source_type is SourceType.SAST}
    assert "command_injection" in cats
    docker = [f for f in found if f.source_type is SourceType.IAC]
    assert docker and docker[0].attrs["iac_topic"] == "dockerfile-root-user"
    assert clean_rule_id("root..opt.scanners.semgrep-rules.python.x.y") == "python.x.y"
    assert clean_rule_id("python.x.y") == "python.x.y"


def test_checkov_shapes_and_resources() -> None:
    doc = load(ScannerName.CHECKOV)
    assert isinstance(doc, list)
    from_list = checkov_parser.parse(doc)
    from_dicts = [f for block in doc for f in checkov_parser.parse(block)]
    assert len(from_list) == len(from_dicts)
    summary_only = {"passed": 0, "failed": 0, "checkov_version": "3"}
    assert checkov_parser.parse(summary_only) == []
    dockerfile = [f for f in from_list if f.location.file == "Dockerfile"]
    assert dockerfile and all(f.location.resource is None for f in dockerfile)


def test_gitleaks_uses_redacted_fields_only() -> None:
    found = SCANNERS[ScannerName.GITLEAKS].parse(load(ScannerName.GITLEAKS), CTX)
    assert {f.rule_id for f in found} >= {"aws-access-token", "private-key"}
    for f in found:
        assert f.attrs["secret_hmac"] and len(f.attrs["secret_hmac"]) == 64
        assert "REDACTED" in str(f.evidence["masked"])


def test_hostile_paths_are_neutralised() -> None:
    doc = copy.deepcopy(load(ScannerName.GITLEAKS))
    doc[0]["File"] = "../../../../etc/passwd"
    found = SCANNERS[ScannerName.GITLEAKS].parse(doc, CTX)
    assert found[0].location.file == INVALID_PATH
    assert normalize_path("./a/./b.py") == "a/b.py"
    assert normalize_path("/main.tf") == "main.tf"
    assert normalize_path("a\x00b") == INVALID_PATH
    assert normalize_path(None) == "<unknown>"


def test_parsers_tolerate_garbage() -> None:
    for scanner in SCANNERS.values():
        for junk in (None, 3, "x", {}, [], [1, "a"], {"Results": "x", "results": 7}):
            assert scanner.parse(junk, CTX) == []
            assert scanner.count(junk) == 0
