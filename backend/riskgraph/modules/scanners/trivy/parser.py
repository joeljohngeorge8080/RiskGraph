"""Parse ``trivy fs`` and ``trivy image`` JSON (schema version 2) into canonical findings."""

from __future__ import annotations

from dataclasses import dataclass
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


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


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


def dependency_graph(doc: Any) -> dict[str, dict[str, Any]]:
    """Per manifest target: package relationships from ``Results[].Packages``.

    ``{target: {"has_graph": bool, "packages": {id: {"name", "version", "relationship",
    "depends_on"}}}}``. Lockfiles with a dependency tree (package-lock, poetry, yarn,
    pnpm, go.mod, uv) carry ``Relationship``/``DependsOn``; requirements.txt does not.
    """
    out: dict[str, dict[str, Any]] = {}
    for result in _results(doc):
        packages: dict[str, dict[str, Any]] = {}
        has_graph = False
        for p in _list(result.get("Packages")):
            name = str(p.get("Name") or "")
            version = str(p.get("Version") or "")
            pid = str(p.get("ID") or f"{name}@{version}")
            relationship = p.get("Relationship") if isinstance(p.get("Relationship"), str) else None
            depends = [str(d) for d in p.get("DependsOn") or [] if isinstance(d, str)][:500]
            has_graph = has_graph or relationship is not None or bool(depends)
            packages[pid] = {
                "name": name,
                "version": version,
                "relationship": relationship,
                "depends_on": depends,
            }
        if packages:
            out[normalize_path(result.get("Target"))] = {
                "has_graph": has_graph,
                "packages": packages,
            }
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


MAX_IMAGE_PACKAGES = 5000


@dataclass(frozen=True, slots=True)
class ImagePackage:
    """One package installed in an image (``--list-all-pkgs``), for the SBOM."""

    purl: str
    name: str
    version: str
    location: str | None  # the file Trivy read it from (language packages)


@dataclass(frozen=True, slots=True)
class ImageReport:
    """What one ``trivy image`` report says (X2, ADR-0018)."""

    ref: str
    findings: list[RawFinding]
    packages: list[ImagePackage]
    os_family: str | None
    os_name: str | None
    eosl: bool  # Trivy's own end-of-support flag for the base OS
    created_at: str | None  # when Trivy wrote the report
    size: int | None  # uncompressed image size in bytes, as Trivy reports it


def parse_image(doc: Any, ref: str, declared_in: str, line: int | None = None) -> ImageReport:
    """Image package vulnerabilities as ``sca`` findings marked with the image.

    The location is the repository file that names the image (it is what the repository
    can change), with the image as the resource. Package coordinates carry the image, so
    the same CVE in two images stays two findings (fingerprint and merge key).
    """
    top = _dict(doc)
    meta = _dict(top.get("Metadata"))
    os_info = _dict(meta.get("OS"))
    family = os_info.get("Family") if isinstance(os_info.get("Family"), str) else None
    os_name = os_info.get("Name") if isinstance(os_info.get("Name"), str) else None
    os_label = " ".join(p for p in (family, os_name) if p) or None
    findings: list[RawFinding] = []
    packages: list[ImagePackage] = []
    for result in _results(doc):
        ecosystem = result.get("Type")
        target = clip(str(result.get("Target") or ""), 200)
        for v in _list(result.get("Vulnerabilities")):
            f = _vulnerability(v, declared_in, ecosystem)
            f.location = Location(declared_in, line, line, ref)
            pkg = dict(f.package or {})
            pkg["image"] = ref
            if isinstance(v.get("PkgPath"), str):
                pkg["path"] = clip(v["PkgPath"], 300)
            f.package = pkg
            f.attrs["image"] = {"ref": ref, "os": os_label, "target": target}
            findings.append(f)
        for p in _list(result.get("Packages")):
            purl = _dict(p.get("Identifier")).get("PURL")
            if not isinstance(purl, str) or not purl.startswith("pkg:"):
                continue
            if len(packages) >= MAX_IMAGE_PACKAGES:
                break
            path = p.get("FilePath")
            packages.append(
                ImagePackage(
                    purl=purl,
                    name=str(p.get("Name") or "")[:256],
                    version=str(p.get("Version") or "")[:128],
                    location=clip(path, 512) if isinstance(path, str) else None,
                )
            )
    size = meta.get("Size")
    created = top.get("CreatedAt")
    return ImageReport(
        ref=ref,
        findings=findings,
        packages=packages,
        os_family=family,
        os_name=os_name,
        eosl=os_info.get("EOSL") is True,
        created_at=created if isinstance(created, str) else None,
        size=size if isinstance(size, int) and not isinstance(size, bool) else None,
    )
