"""Scanner-native severity → canonical severity (blueprint §10.3).

Canonical severity is for display and filtering. The risk model does not use it for
CVEs (it uses CVSS/EPSS/KEV), only as a fallback where nothing better exists.
"""

from __future__ import annotations

from riskgraph.modules.normalization.families import LIVE_CREDENTIAL_RULES, IacFamily
from riskgraph.shared.vocabulary import Severity

_PLAIN = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}


def trivy_severity(native: str | None) -> Severity:
    # UNKNOWN (no vendor score) maps to medium: unknown is not "safe".
    return _PLAIN.get((native or "").upper(), Severity.MEDIUM)


def semgrep_severity(native: str | None, impact: str | None, confidence: str | None) -> Severity:
    value = (native or "").upper()
    base = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}.get(
        value, _PLAIN.get(value, Severity.MEDIUM)
    )
    if (
        base is Severity.HIGH
        and (impact or "").upper() == "HIGH"
        and (confidence or "").upper() == "HIGH"
    ):
        return Severity.CRITICAL
    return base


def gitleaks_severity(rule_id: str) -> Severity:
    return Severity.CRITICAL if rule_id in LIVE_CREDENTIAL_RULES else Severity.HIGH


_IAC_FAMILY_SEVERITY = {
    IacFamily.PUBLIC: Severity.HIGH,
    IacFamily.IAM: Severity.HIGH,
    IacFamily.SECRETS: Severity.HIGH,
    IacFamily.ENCRYPTION: Severity.MEDIUM,
    IacFamily.LOGGING: Severity.LOW,
    IacFamily.HYGIENE: Severity.LOW,
}


def checkov_severity(native: str | None, family: IacFamily) -> Severity:
    # Checkov only reports severities with a Prisma Cloud API key; without one the
    # check family decides.
    if native and native.upper() in _PLAIN:
        return _PLAIN[native.upper()]
    return _IAC_FAMILY_SEVERITY[family]
