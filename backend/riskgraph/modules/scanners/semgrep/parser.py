"""Parse ``semgrep scan --json`` into canonical findings."""

from __future__ import annotations

from typing import Any

from riskgraph.modules.normalization import Location, RawFinding, families, normalize_path
from riskgraph.modules.normalization.categories import cwe_ids, sast_category
from riskgraph.modules.normalization.families import TAINT_RULE_PREFIX
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
    own = check_id.find(TAINT_RULE_PREFIX)
    if own >= 0:
        return check_id[own:]  # RiskGraph's own taint rules, wherever the file lives
    idx = check_id.rfind(_RULES_DIR_MARKER)
    rule = check_id[idx + len(_RULES_DIR_MARKER) :] if idx >= 0 else check_id
    # A rule file named like its directory repeats the last segment (``missing-user.missing-user``).
    parts = rule.split(".")
    if len(parts) >= 2 and parts[-1] == parts[-2]:
        return ".".join(parts[:-1])
    return rule


# --- taint traces (X4 tier 1, ADR-0021) -----------------------------------------------
MAX_TAINT_STEPS = 50  # plan §8: evidence stays small
TAINT_STEPS_KEY = "riskgraph_taint_steps"  # what redaction leaves of a dataflow trace
_TRACE_PARTS = (("taint_source", "source"), ("intermediate_vars", "step"), ("taint_sink", "sink"))


def _locations(value: Any, depth: int = 0) -> list[tuple[str, int]]:
    """Every ``{path, start: {line}}`` in ``value``, in document order. Semgrep wraps them
    in ``["CliLoc", [loc, code]]`` or nested ``CliCall`` lists; the code is never read."""
    if depth > 8:
        return []
    if isinstance(value, dict):
        path, start = value.get("path"), value.get("start")
        if isinstance(path, str) and isinstance(start, dict):
            line = start.get("line")
            if isinstance(line, int) and not isinstance(line, bool) and line > 0:
                return [(path[:512], line)]
        return [hit for v in value.values() for hit in _locations(v, depth + 1)]
    if isinstance(value, list):
        return [hit for v in value for hit in _locations(v, depth + 1)]
    return []


def taint_steps(trace: Any) -> list[dict[str, Any]]:
    """A dataflow trace as ordered, location-only steps (source, steps, sink), at most
    MAX_TAINT_STEPS (the sink is kept). Malformed traces give fewer steps, never an error."""
    if not isinstance(trace, dict):
        return []
    steps: list[dict[str, Any]] = []
    for key, role in _TRACE_PARTS:
        for path, line in _locations(trace.get(key)):
            if steps and (steps[-1]["file"], steps[-1]["line"]) == (path, line):
                continue  # the same place twice in a row says nothing new
            steps.append({"file": path, "line": line, "role": role})
    if len(steps) > MAX_TAINT_STEPS:
        steps = [*steps[: MAX_TAINT_STEPS - 1], steps[-1]]
    return steps


def keep_taint_steps(doc: Any) -> Any:
    """Before snippets are dropped: give each RiskGraph taint result its trace's steps."""
    for r in _results(doc):
        extra = r.get("extra")
        if isinstance(extra, dict) and TAINT_RULE_PREFIX in str(r.get("check_id", "")):
            extra[TAINT_STEPS_KEY] = taint_steps(extra.get("dataflow_trace"))
    return doc


def _stored_steps(value: Any) -> list[dict[str, Any]]:
    roles = {role for _, role in _TRACE_PARTS}
    out: list[dict[str, Any]] = []
    for step in value[:MAX_TAINT_STEPS] if isinstance(value, list) else []:
        if not isinstance(step, dict):
            continue
        line, role = step.get("line"), step.get("role")
        if isinstance(line, int) and not isinstance(line, bool) and line > 0 and role in roles:
            file = normalize_path(step.get("file") if isinstance(step.get("file"), str) else None)
            out.append({"file": file, "line": line, "role": role})
    return out


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
        if rule.startswith(TAINT_RULE_PREFIX):
            # tier 1: a flow inside one function, as Semgrep CE sees it
            attrs["analysis"] = "intraprocedural"
            attrs["taint_steps"] = _stored_steps(extra.get(TAINT_STEPS_KEY))
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
