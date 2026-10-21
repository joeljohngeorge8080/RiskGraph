"""Parse ``trivy fs --format json`` (schema version 2) into canonical findings."""

from __future__ import annotations

from typing import Any

from riskgraph.modules.normalization import Location, RawFinding, families, normalize_path
from riskgraph.modules.normalization.categories import cwe_ids
from riskgraph.modules.normalization.severity import trivy_severity
from riskgraph.modules.scanners.redact import clip
from riskgraph.shared.vocabulary import ScannerName, Severity, SourceType

_CVSS_SOURCES = ("nvd", "ghsa", "redhat")


def _results(doc: Any) -> list[dict[str, Any]]:
    if not isinstance(doc, dict):
        return []
    results = doc.get("Results")
    return [r for r in results if isinstance(r, dict)] if isinstance(results, list) else []


def _list(value: Any) -> list[dict[str, Any]]:
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []


def count(doc: Any) -> int:
    total = 0
    for r in _results(doc):
        total += len(_list(r.get("Vulnerabilities"))) + len(_list(r.get("Secrets")))
        total += sum(1 for m in _list(r.get("Misconfigurations")) if m.get("Status") == "FAIL")
    return total


def parse(doc: Any) -> list[RawFinding]:
    out: list[RawFinding] = []
    for result in _results(doc):
        target = normalize_path(result.get("Target"))
        ecosystem = result.get("Type")
        for v in _list(result.get("Vulnerabilities")):
            out.append(_vulnerability(v, target, ecosystem))
        for s in _list(result.get("Secrets")):
            out.append(_secret(s, target))
        for m in _list(result.get("Misconfigurations")):
            if m.get("Status") == "FAIL":
                out.append(_misconfig(m, target))
    return out


def pick_cvss(cvss: dict[str, Any] | None) -> dict[str, Any] | None:
    if not cvss:
        return None
    order = [*_CVSS_SOURCES, *sorted(k for k in cvss if k not in _CVSS_SOURCES)]
    for source in order:
        entry = cvss.get(source) or {}
        vector = entry.get("V3Vector")
        if vector:
            return {
                "source": source,
                "vector": vector,
                "base": entry.get("V3Score"),
                "version": vector.split("/")[0].removeprefix("CVSS:") or "3.x",
            }
    return None


def _vulnerability(v: dict[str, Any], target: str, ecosystem: str | None) -> RawFinding:
    vid = str(v.get("VulnerabilityID", "UNKNOWN"))
    name = str(v.get("PkgName", "?"))
    version = str(v.get("InstalledVersion", "?"))
    fixed = v.get("FixedVersion") or None
    purl = (v.get("PkgIdentifier") or {}).get("PURL")
    title = f"{vid} in {name} {version}"
    if v.get("Title"):
        title += f": {v['Title']}"
    return RawFinding(
        scanner=ScannerName.TRIVY,
        source_type=SourceType.SCA,
        rule_id=vid,
        title=clip(title, 300) or vid,
        severity=trivy_severity(v.get("Severity")),
        scanner_severity=v.get("Severity"),
        location=Location(target),
        category="vuln_dependency",
        description=clip(v.get("Description")),
        cwe_ids=cwe_ids(v.get("CweIDs")),
        vulnerability_id=vid,
        package={
            "name": name,
            "version": version,
            "purl": purl,
            "ecosystem": ecosystem,
            "fixed_version": fixed,
        },
        cvss=pick_cvss(v.get("CVSS")),
        remediation=f"Upgrade {name} to {fixed}." if fixed else "No fixed version published yet.",
        evidence={"primary_url": v.get("PrimaryURL"), "published": v.get("PublishedDate")},
    )


def _secret(s: dict[str, Any], target: str) -> RawFinding:
    rule = str(s.get("RuleID", "unknown"))
    live = rule in families.LIVE_CREDENTIAL_RULES
    return RawFinding(
        scanner=ScannerName.TRIVY,
        source_type=SourceType.SECRET,
        rule_id=rule,
        title=str(s.get("Title") or rule),
        severity=Severity.CRITICAL if live else trivy_severity(s.get("Severity")),
        scanner_severity=s.get("Severity"),
        location=Location(target, s.get("StartLine"), s.get("EndLine")),
        category="secrets_exposure",
        remediation="Revoke and rotate the credential, then remove it from the repository.",
        evidence={"secret_category": s.get("Category")},
        attrs={"secret_family": families.secret_family(rule), "live_credential": live},
    )


def _misconfig(m: dict[str, Any], target: str) -> RawFinding:
    check = families.normalize_check_id(str(m.get("ID") or m.get("AVDID") or "unknown"))
    cause = m.get("CauseMetadata") or {}
    topic = families.iac_topic(check)
    title = str(m.get("Title") or check)
    return RawFinding(
        scanner=ScannerName.TRIVY,
        source_type=SourceType.IAC,
        rule_id=check,
        title=title,
        severity=trivy_severity(m.get("Severity")),
        scanner_severity=m.get("Severity"),
        location=Location(
            target, cause.get("StartLine"), cause.get("EndLine"), cause.get("Resource")
        ),
        category="misconfig",
        description=clip(m.get("Description")),
        remediation=clip(m.get("Resolution")),
        evidence={"message": clip(m.get("Message"), 500), "primary_url": m.get("PrimaryURL")},
        attrs={"iac_topic": topic, "iac_family": families.iac_family(topic, title).value},
    )
