"""Parse a *redacted* Gitleaks JSON report (see ``GitleaksScanner.redact``)."""

from __future__ import annotations

from typing import Any

from riskgraph.modules.normalization import Location, RawFinding, families, normalize_path
from riskgraph.modules.normalization.severity import gitleaks_severity
from riskgraph.modules.scanners.redact import clip
from riskgraph.shared.vocabulary import ScannerName, SourceType


def _items(doc: Any) -> list[dict[str, Any]]:
    return [i for i in doc if isinstance(i, dict)] if isinstance(doc, list) else []


def count(doc: Any) -> int:
    return len(_items(doc))


def parse(doc: Any) -> list[RawFinding]:
    out: list[RawFinding] = []
    for item in _items(doc):
        rule = str(item.get("RuleID", "unknown"))
        live = rule in families.LIVE_CREDENTIAL_RULES
        out.append(
            RawFinding(
                scanner=ScannerName.GITLEAKS,
                source_type=SourceType.SECRET,
                rule_id=rule,
                title=clip(str(item.get("Description") or rule), 300) or rule,
                severity=gitleaks_severity(rule),
                location=Location(
                    normalize_path(item.get("File")), item.get("StartLine"), item.get("EndLine")
                ),
                category="secrets_exposure",
                remediation="Revoke and rotate the credential, then remove it from the repository.",
                evidence={"masked": item.get("SecretMasked"), "entropy": item.get("Entropy")},
                attrs={
                    "secret_hmac": item.get("SecretHMAC"),
                    "secret_family": families.secret_family(rule),
                    "live_credential": live,
                },
            )
        )
    return out
