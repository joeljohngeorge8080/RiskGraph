from __future__ import annotations

from dataclasses import replace

from riskgraph.modules.normalization import Location, RawFinding, merge
from riskgraph.modules.normalization.families import iac_family, normalize_check_id, secret_family
from riskgraph.shared.vocabulary import ScannerName, Severity, SourceType

from tests.scanner_fixtures import parse_all


def _secret(scanner: ScannerName, rule: str, line: int, end: int | None = None) -> RawFinding:
    return RawFinding(
        scanner=scanner,
        source_type=SourceType.SECRET,
        rule_id=rule,
        title=rule,
        severity=Severity.HIGH,
        location=Location("main.tf", line, end or line),
        category="secrets_exposure",
        attrs={"secret_family": secret_family(rule)},
    )


def test_kitchen_sink_merges_across_scanners() -> None:
    raw = parse_all()
    merged = merge(raw)
    assert len(merged) < len(raw)
    by_topic = {m.attrs.get("iac_topic"): m for m in merged if m.source_type is SourceType.IAC}
    assert by_topic["dockerfile-root-user"].detected_by == ("checkov", "semgrep", "trivy")
    assert by_topic["sg-open-ingress"].detected_by == ("checkov", "trivy")
    assert by_topic["dockerfile-root-user"].representative.scanner is ScannerName.CHECKOV
    secrets = {
        m.attrs.get("secret_family"): m for m in merged if m.source_type is SourceType.SECRET
    }
    assert secrets["aws"].detected_by == ("gitleaks", "trivy")
    assert secrets["private_key"].detected_by == ("gitleaks", "trivy")  # ranges 1-15 vs 2-14
    assert secrets["aws"].representative.scanner is ScannerName.GITLEAKS
    assert secrets["aws"].attrs["live_credential"] is True
    # four semgrep rules flag the same line for CWE-78: one finding
    shell = [m for m in merged if m.source_type is SourceType.SAST and m.location.line_start == 21]
    assert len(shell) == 1 and len(shell[0].members) == 4


def test_merge_is_deterministic() -> None:
    a = [m.merge_key for m in merge(parse_all())]
    b = [m.merge_key for m in merge(list(reversed(parse_all())))]
    assert a == b


def test_secrets_on_different_lines_stay_apart() -> None:
    merged = merge(
        [
            _secret(ScannerName.GITLEAKS, "aws-access-token", 3),
            _secret(ScannerName.TRIVY, "aws-access-key-id", 3),
            _secret(ScannerName.TRIVY, "aws-secret-access-key", 9),
            _secret(ScannerName.GITLEAKS, "github-pat", 3),  # same line, other family
        ]
    )
    assert sorted(len(m.members) for m in merged) == [1, 1, 2]


def test_unmapped_iac_checks_never_merge_across_scanners() -> None:
    base = RawFinding(
        scanner=ScannerName.CHECKOV,
        source_type=SourceType.IAC,
        rule_id="CKV_X_1",
        title="x",
        severity=Severity.LOW,
        location=Location("main.tf", 1, 5, "aws_x.y"),
        category="misconfig",
        attrs={"iac_topic": None},
    )
    other = replace(base, scanner=ScannerName.TRIVY, rule_id="AWS-9999")
    assert len(merge([base, other])) == 2


def test_merged_severity_is_the_highest() -> None:
    a = _secret(ScannerName.GITLEAKS, "aws-access-token", 3)
    b = replace(_secret(ScannerName.TRIVY, "aws-access-key-id", 3), severity=Severity.CRITICAL)
    (m,) = merge([a, b])
    assert m.severity is Severity.CRITICAL


def test_check_id_normalization_and_families() -> None:
    assert normalize_check_id("AVD-AWS-0086") == "AWS-0086"
    assert normalize_check_id("DS002") == "DS-0002"
    assert normalize_check_id("CKV2_AWS_6") == "CKV2_AWS_6"
    assert iac_family(None, "Ensure bucket is not public").value == "public"
    assert iac_family(None, "Something else").value == "hygiene"
    assert secret_family("generic-api-key") == "generic"
