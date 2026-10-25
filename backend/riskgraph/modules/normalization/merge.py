"""Merge canonical findings from all scanners into one deduplicated list (ADR-0010).

Merge keys:
- sca:    vulnerability id + package + manifest file (+ the image, for image packages)
- sast:   file + line + primary CWE (several rules flagging the same line for the same
          weakness are one problem)
- secret: file + credential family + overlapping line range (Gitleaks and Trivy report
          the same key with slightly different ranges)
- iac:    file + curated topic + resource; unmapped checks keep a scanner-specific key
          so they never merge across tools

The representative member (whose title/description are shown) follows a fixed scanner
preference per source type; the merged severity is the highest member severity.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from riskgraph.modules.normalization.canonical import Location, RawFinding
from riskgraph.modules.normalization.fingerprint import stable_hash
from riskgraph.shared.vocabulary import ScannerName, Severity, SourceType

_PREFERENCE: dict[SourceType, tuple[ScannerName, ...]] = {
    SourceType.SCA: (ScannerName.TRIVY,),
    SourceType.SAST: (ScannerName.SEMGREP,),
    SourceType.SECRET: (ScannerName.GITLEAKS, ScannerName.TRIVY),
    SourceType.IAC: (ScannerName.CHECKOV, ScannerName.TRIVY, ScannerName.SEMGREP),
    SourceType.RUNTIME: (ScannerName.TRIVY,),
    SourceType.AUTHZ: (),
}
_CONFIDENCE_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}


@dataclass(slots=True)
class MergedFinding:
    merge_key: str
    members: list[RawFinding]
    representative: RawFinding
    severity: Severity
    detected_by: tuple[str, ...]
    cwe_ids: tuple[str, ...]
    attrs: dict[str, Any] = field(default_factory=dict)

    @property
    def source_type(self) -> SourceType:
        return self.representative.source_type

    @property
    def location(self) -> Location:
        return self.representative.location


def merge(findings: list[RawFinding]) -> list[MergedFinding]:
    groups: dict[tuple[object, ...], list[RawFinding]] = defaultdict(list)
    secrets: dict[tuple[str, str], list[RawFinding]] = defaultdict(list)

    for f in findings:
        loc = f.location
        match f.source_type:
            case SourceType.SCA:
                pkg = f.package or {}
                ident = pkg.get("purl") or f"{pkg.get('name')}@{pkg.get('version')}"
                image = pkg.get("image")  # X2: image packages never merge across images
                scope = (image,) if image else ()
                groups[("sca", f.vulnerability_id, ident, loc.file, *scope)].append(f)
            case SourceType.SAST:
                anchor = f.cwe_ids[0] if f.cwe_ids else f.rule_id
                groups[("sast", loc.file, loc.line_start, anchor)].append(f)
            case SourceType.SECRET:
                secrets[(loc.file, str(f.attrs.get("secret_family", "generic")))].append(f)
            case SourceType.IAC:
                topic = f.attrs.get("iac_topic")
                if topic:
                    groups[("iac", loc.file, topic, loc.resource or "")].append(f)
                else:
                    iac_anchor = loc.resource or loc.line_start
                    groups[("iac", f.scanner.value, f.rule_id, loc.file, iac_anchor)].append(f)
            case SourceType.RUNTIME | SourceType.AUTHZ:
                # no cross-tool merge keys yet (X2, X5): same tool, rule and place only
                anchor_x = loc.resource or loc.line_start
                key = (f.source_type.value, f.scanner.value, f.rule_id, loc.file, anchor_x)
                groups[key].append(f)

    for (file, family), members in secrets.items():
        for cluster in _overlap_clusters(members):
            start = min(m.location.line_start or 0 for m in cluster)
            groups[("secret", file, family, start)].extend(cluster)

    merged = [_build(key, members) for key, members in groups.items()]
    merged.sort(key=lambda m: m.merge_key)
    return merged


def _overlap_clusters(members: list[RawFinding]) -> list[list[RawFinding]]:
    ordered = sorted(members, key=lambda m: (m.location.line_start or 0, m.scanner.value))
    clusters: list[list[RawFinding]] = []
    for m in ordered:
        for cluster in clusters:
            if any(m.location.overlaps(c.location) for c in cluster):
                cluster.append(m)
                break
        else:
            clusters.append([m])
    return clusters


def _build(key: tuple[object, ...], members: list[RawFinding]) -> MergedFinding:
    source_type = members[0].source_type
    preference = _PREFERENCE[source_type]

    def rep_order(f: RawFinding) -> tuple[int, int, str]:
        pref = preference.index(f.scanner) if f.scanner in preference else len(preference)
        return (pref, -f.severity.rank, f.rule_id)

    representative = min(members, key=rep_order)
    severity = max((m.severity for m in members), key=lambda s: s.rank)
    cwe_ids = tuple(sorted({c for m in members for c in m.cwe_ids}))
    detected_by = tuple(sorted({m.scanner.value for m in members}))

    attrs: dict[str, Any] = dict(representative.attrs)
    attrs["live_credential"] = any(m.attrs.get("live_credential") for m in members)
    confidences = [str(m.attrs["confidence"]).upper() for m in members if m.attrs.get("confidence")]
    if confidences:
        attrs["confidence"] = max(confidences, key=lambda c: _CONFIDENCE_RANK.get(c, 0))

    return MergedFinding(
        merge_key=stable_hash(*key),
        members=sorted(members, key=lambda m: (m.scanner.value, m.rule_id)),
        representative=representative,
        severity=severity,
        detected_by=detected_by,
        cwe_ids=cwe_ids,
        attrs=attrs,
    )
