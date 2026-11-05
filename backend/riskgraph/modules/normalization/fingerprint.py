"""Per-scanner fingerprints (blueprint §10.2).

A fingerprint identifies one native result of one scanner stably across scans of the
same repository, so re-scanning an unchanged commit produces no new occurrences.
"""

from __future__ import annotations

import hashlib

from riskgraph.modules.normalization.canonical import RawFinding
from riskgraph.shared.vocabulary import SourceType


def stable_hash(*parts: object) -> str:
    joined = "\x1f".join("" if p is None else str(p).strip().lower() for p in parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def fingerprint(f: RawFinding, repository: str) -> str:
    loc = f.location
    match f.source_type:
        case SourceType.SCA:
            pkg = f.package or {}
            purl = (
                pkg.get("purl") or f"{pkg.get('ecosystem')}:{pkg.get('name')}@{pkg.get('version')}"
            )
            # an image package (X2) is scoped by its image; repository packages keep the key
            image = pkg.get("image")
            scope = (image,) if image else ()
            return stable_hash("sca", repository, f.vulnerability_id, purl, loc.file, *scope)
        case SourceType.SAST:
            anchor = f.attrs.get("snippet_sha256") or loc.line_start
            return stable_hash("sast", repository, f.rule_id, loc.file, anchor)
        case SourceType.SECRET:
            anchor = f.attrs.get("secret_hmac") or loc.line_start
            return stable_hash("secret", repository, f.rule_id, loc.file, anchor)
        case SourceType.IAC:
            anchor = loc.resource or loc.line_start
            return stable_hash("iac", repository, f.rule_id, loc.file, anchor)
        case SourceType.RUNTIME | SourceType.AUTHZ:
            anchor = loc.resource or loc.line_start
            return stable_hash(f.source_type.value, repository, f.rule_id, loc.file, anchor)
