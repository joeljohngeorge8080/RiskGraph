"""A finding's own evidence: one record per scanner that reported it, plus reachability."""

from __future__ import annotations

import datetime as dt
import uuid

from riskgraph.modules.evidence import Assurance
from riskgraph.modules.normalization import Location, RawFinding, merge
from riskgraph.modules.reachability import Verdict
from riskgraph.modules.scans.finding_evidence import finding_evidence
from riskgraph.shared.vocabulary import ReachabilityTier, ScannerName, Severity, SourceType

NOW = dt.datetime(2026, 10, 25, tzinfo=dt.UTC)
RUNS = {"trivy": uuid.uuid4(), "semgrep": uuid.uuid4(), "gitleaks": uuid.uuid4()}
VERSIONS = {"trivy": "0.76.0", "semgrep": "1.182.0", "gitleaks": "8.30.1"}


def _sca() -> RawFinding:
    return RawFinding(
        scanner=ScannerName.TRIVY,
        source_type=SourceType.SCA,
        rule_id="CVE-2020-14343",
        title="PyYAML arbitrary code execution",
        severity=Severity.CRITICAL,
        location=Location("requirements.txt"),
        category="vuln_dependency",
        vulnerability_id="CVE-2020-14343",
        package={"name": "pyyaml", "version": "5.3", "fixed_version": "5.4", "ecosystem": "pip"},
    )


def _evidence(raw: RawFinding, verdict: Verdict | None = None):  # type: ignore[no-untyped-def]
    [m] = merge([raw])
    return finding_evidence(m, verdict, RUNS, VERSIONS, NOW)


def test_a_scanner_match_is_verified_and_points_at_its_raw_report() -> None:
    [ev] = _evidence(_sca())
    assert ev.kind == "package_match" and ev.assurance is Assurance.VERIFIED
    assert ev.producer == "trivy@0.76.0" and ev.confidence == "high"
    assert ev.raw is not None and ev.raw.scanner_run_id == RUNS["trivy"] and ev.raw.pointer == ""
    assert ev.facts["package"] == "pyyaml" and ev.facts["version"] == "5.3"
    assert ev.facts["vulnerability_id"] == "CVE-2020-14343" and ev.facts["fixed_version"] == "5.4"


def test_one_record_per_scanner_that_reported_it() -> None:
    base = RawFinding(
        scanner=ScannerName.SEMGREP,
        source_type=SourceType.SAST,
        rule_id="python.flask.security.injection.ssrf-requests",
        title="SSRF",
        severity=Severity.HIGH,
        location=Location("api/app.py", 9),
        category="ssrf",
        cwe_ids=("CWE-918",),
        attrs={"confidence": "HIGH"},
    )
    other = RawFinding(
        scanner=ScannerName.SEMGREP,
        source_type=SourceType.SAST,
        rule_id="python.django.security.injection.ssrf.ssrf-injection-requests",
        title="SSRF",
        severity=Severity.HIGH,
        location=Location("api/app.py", 9),
        category="ssrf",
        cwe_ids=("CWE-918",),
    )
    [m] = merge([base, other])
    evs = finding_evidence(m, None, RUNS, VERSIONS, NOW)
    assert [e.kind for e in evs] == ["code_match", "code_match"]
    assert {e.facts["rule_id"] for e in evs} == {base.rule_id, other.rule_id}
    assert {e.confidence for e in evs} == {"high", "medium"}  # semgrep's own, else medium


def test_reachability_evidence_follows_the_tier() -> None:
    l3 = Verdict(ReachabilityTier.L3, "medium", {"symbol": "yaml.load", "chain": ["a:f", "b:g"]})
    evs = _evidence(_sca(), l3)
    [reach] = [e for e in evs if e.kind == "reachability"]
    assert reach.assurance is Assurance.VERIFIED and reach.producer.startswith("riskgraph.")
    assert reach.facts["tier"] == "L3" and reach.facts["chain"] == ("a:f", "b:g")
    l2 = Verdict(ReachabilityTier.L2, "medium", {"importers": ["x.py"]})
    assert [e.assurance for e in _evidence(_sca(), l2) if e.kind == "reachability"] == [
        Assurance.INFERRED
    ]


def test_no_reachability_evidence_when_there_is_no_claim() -> None:
    for tier in (ReachabilityTier.UNKNOWN, ReachabilityTier.NOT_APPLICABLE):
        evs = _evidence(_sca(), Verdict(tier, "low"))
        assert [e.kind for e in evs] == ["package_match"]


def test_odd_verdict_evidence_is_dropped_not_fatal() -> None:
    weird = Verdict(ReachabilityTier.L2, "medium", {"nested": {"a": 1}, "importers": ["x.py"]})
    [reach] = [e for e in _evidence(_sca(), weird) if e.kind == "reachability"]
    assert "nested" not in reach.facts and reach.facts["importers"] == ("x.py",)


def test_secrets_never_carry_the_secret() -> None:
    raw = RawFinding(
        scanner=ScannerName.GITLEAKS,
        source_type=SourceType.SECRET,
        rule_id="aws-access-token",
        title="AWS key",
        severity=Severity.CRITICAL,
        location=Location("web/dist/bundle.js", 2),
        category="secrets_exposure",
        evidence={"match": "AKIA****"},
        attrs={"secret_family": "aws", "live_credential": True, "secret_hmac": "abc"},
    )
    [ev] = _evidence(raw)
    assert ev.kind == "secret_match" and ev.confidence == "high"
    assert ev.facts == {"rule_id": "aws-access-token", "severity": "critical", "family": "aws"}
