"""Parse Checkov's JSON report.

Checkov writes one of three shapes: a single framework block (dict with ``results``),
a list of such blocks (one per framework), or a bare summary dict when nothing matched.
"""

from __future__ import annotations

import re
from typing import Any

from riskgraph.modules.normalization import Location, RawFinding, families, normalize_path
from riskgraph.modules.normalization.severity import checkov_severity
from riskgraph.modules.scanners.redact import clip
from riskgraph.shared.vocabulary import ScannerName, SourceType

# Terraform/K8s style addresses ("aws_s3_bucket.data", "Deployment.default.web").
# Checkov uses file-ish pseudo resources for Dockerfiles ("/Dockerfile."), which are
# dropped so they merge with tools that report no resource at all.
_RESOURCE = re.compile(r"^[A-Za-z0-9_\-]+(\.[A-Za-z0-9_\-\[\]\"]+)+$")


def _blocks(doc: Any) -> list[dict[str, Any]]:
    items = doc if isinstance(doc, list) else [doc]
    return [b for b in items if isinstance(b, dict) and isinstance(b.get("results"), dict)]


def _failed(doc: Any) -> list[tuple[str, dict[str, Any]]]:
    out = []
    for block in _blocks(doc):
        for check in block["results"].get("failed_checks") or []:
            if isinstance(check, dict):
                out.append((str(block.get("check_type") or ""), check))
    return out


def count(doc: Any) -> int:
    return len(_failed(doc))


def _resource(value: Any) -> str | None:
    if not isinstance(value, str) or value.endswith(".") or value.startswith("/"):
        return None
    return value if _RESOURCE.match(value) else None


def parse(doc: Any) -> list[RawFinding]:
    out: list[RawFinding] = []
    for framework, c in _failed(doc):
        check = str(c.get("check_id", "unknown"))
        title = str(c.get("check_name") or check)
        topic = families.iac_topic(check)
        family = families.iac_family(topic, title)
        lines = c.get("file_line_range") or [None, None]
        start, end = [*lines, None, None][:2] if isinstance(lines, list) else (None, None)
        out.append(
            RawFinding(
                scanner=ScannerName.CHECKOV,
                source_type=SourceType.IAC,
                rule_id=check,
                title=title,
                severity=checkov_severity(c.get("severity"), family),
                scanner_severity=c.get("severity"),
                location=Location(
                    normalize_path(c.get("file_path")),
                    start or None,
                    end or None,
                    _resource(c.get("resource")),
                ),
                category="misconfig",
                description=clip(c.get("description")),
                remediation=c.get("guideline"),
                evidence={"framework": framework, "check_class": c.get("check_class")},
                attrs={"iac_topic": topic, "iac_family": family.value},
            )
        )
    return out
