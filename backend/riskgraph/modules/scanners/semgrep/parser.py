"""Parse ``semgrep scan --json`` into canonical findings."""

from __future__ import annotations

from typing import Any

from riskgraph.modules.normalization import Location, RawFinding, families, normalize_path
from riskgraph.modules.normalization.categories import cwe_ids, sast_category
from riskgraph.modules.normalization.severity import semgrep_severity
from riskgraph.modules.scanners.redact import clip
from riskgraph.shared.vocabulary import ScannerName, SourceType

# Rules about infrastructure files are IaC findings, so they can merge with Checkov/Trivy.
_IAC_RULE_PREFIXES = ("dockerfile.", "terraform.", "yaml.kubernetes.", "generic.dockerfile.")
_RULES_DIR_MARKER = "semgrep-rules."
# Rules that match committed credentials are secret findings, so reachability is n_a and they
# merge with Gitleaks/Trivy secrets (blueprint §11.3). Python "hardcoded password" audit
# rules stay SAST: they flag code, not a credential value.
_SECRET_RULE_PREFIX = "generic.secrets."  # noqa: S105 (a rule id prefix, not a secret)


def semgrep_secret_family(rule: str) -> str:
    """``generic.secrets.security.detected-private-key`` -> ``private_key``."""
    name = rule.rsplit(".", 1)[-1].removeprefix("detected-")
    return families.secret_family(name)


def clean_rule_id(check_id: str) -> str:
    """A local rules directory prefixes ids with its path (``root..opt.semgrep-rules.``)."""
    idx = check_id.rfind(_RULES_DIR_MARKER)
    rule = check_id[idx + len(_RULES_DIR_MARKER) :] if idx >= 0 else check_id
    # A rule file named like its directory repeats the last segment (``missing-user.missing-user``).
    parts = rule.split(".")
    if len(parts) >= 2 and parts[-1] == parts[-2]:
        return ".".join(parts[:-1])
    return rule


def _results(doc: Any) -> list[dict[str, Any]]:
    if not isinstance(doc, dict):
        return []
    results = doc.get("results")
    return [r for r in results if isinstance(r, dict)] if isinstance(results, list) else []


def count(doc: Any) -> int:
    return len(_results(doc))


def parse(doc: Any) -> list[RawFinding]:
    out: list[RawFinding] = []
    for r in _results(doc):
        extra = r.get("extra") or {}
        meta = extra.get("metadata") or {}
        rule = clean_rule_id(str(r.get("check_id", "unknown")))
        cwes = cwe_ids(meta.get("cwe"))
        message = str(extra.get("message") or rule)
        location = Location(
            normalize_path(r.get("path")),
            (r.get("start") or {}).get("line"),
            (r.get("end") or {}).get("line"),
        )
        attrs: dict[str, Any] = {
            "confidence": meta.get("confidence"),
            "impact": meta.get("impact"),
            "likelihood": meta.get("likelihood"),
        }
        is_iac = rule.startswith(_IAC_RULE_PREFIXES)
        is_secret = rule.startswith(_SECRET_RULE_PREFIX)
        if is_secret:
            attrs["secret_family"] = semgrep_secret_family(rule)
            attrs["live_credential"] = False
        if is_iac:
            topic = families.iac_topic(rule)
            attrs["iac_topic"] = topic
            attrs["iac_family"] = families.iac_family(topic, message).value
        refs = meta.get("references") or []
        out.append(
            RawFinding(
                scanner=ScannerName.SEMGREP,
                source_type=(
                    SourceType.IAC
                    if is_iac
                    else SourceType.SECRET
                    if is_secret
                    else SourceType.SAST
                ),
                rule_id=rule,
                title=clip(message.splitlines()[0] if message else rule, 200) or rule,
                severity=semgrep_severity(
                    extra.get("severity"), meta.get("impact"), meta.get("confidence")
                ),
                scanner_severity=extra.get("severity"),
                location=location,
                category=(
                    "misconfig"
                    if is_iac
                    else "secrets_exposure"
                    if is_secret
                    else sast_category(cwes)
                ),
                description=clip(message),
                cwe_ids=cwes,
                evidence={
                    "rule_source": meta.get("source"),
                    "references": [str(x) for x in refs[:3]] if isinstance(refs, list) else [],
                    "vulnerability_class": meta.get("vulnerability_class"),
                },
                attrs=attrs,
            )
        )
    return out
