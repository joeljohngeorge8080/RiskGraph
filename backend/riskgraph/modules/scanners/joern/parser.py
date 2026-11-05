"""Parse the deep profile's Joern report into tier-2 taint findings (X4 part 2, ADR-0025).

The report is written by RiskGraph's own query (``scanners/joern/taint.sc``): a version,
and per flow the catalogue class, the sink location and the location-only steps from the
source to the sink. Nothing in it is code (ADR-0021). The report still comes from a
container that read untrusted code, so it is checked strictly and capped: an unknown
class, a malformed location or anything past the caps is dropped, never an error.

A finding takes the tier-1 rule id of its class (``riskgraph.taint.python.<class>``), so
the merge joins it with a tier-1 hit and a generic Semgrep finding at the same sink
(``merge._join_taint_hits``). It is marked ``analysis: interprocedural``: Joern follows the
flow across functions and files, which Semgrep CE cannot.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from riskgraph.modules.normalization import Location, RawFinding, normalize_path
from riskgraph.modules.normalization.categories import cwe_ids, sast_category
from riskgraph.modules.normalization.severity import semgrep_severity
from riskgraph.modules.scanners.semgrep.parser import MAX_TAINT_STEPS
from riskgraph.modules.scanners.semgrep.taint import TaintClass, load_catalogue, rule_id
from riskgraph.shared.vocabulary import ScannerName, SourceType

REPORT_VERSION = 1
LANGUAGE = "python"  # tier 2 is Python only (expansion plan §5)
MAX_FLOWS = 2000
MAX_PATH = 512


@lru_cache(maxsize=1)
def _classes() -> dict[str, TaintClass]:
    return {c.id: c for c in load_catalogue().classes}


def _loc(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    file, line = value.get("file"), value.get("line")
    if not isinstance(file, str) or not 0 < len(file) <= MAX_PATH:
        return None
    if not isinstance(line, int) or isinstance(line, bool) or line <= 0:
        return None
    return {"file": file, "line": line}


def clean(doc: Any) -> dict[str, Any]:
    """The report reduced to what RiskGraph reads: known classes, valid locations, at most
    MAX_FLOWS flows of at most MAX_TAINT_STEPS steps (the sink kept). Used as redaction."""
    flows: list[dict[str, Any]] = []
    raw = doc.get("flows") if isinstance(doc, dict) and doc.get("version") == REPORT_VERSION else []
    known = _classes()
    for flow in raw[:MAX_FLOWS] if isinstance(raw, list) else []:
        if not isinstance(flow, dict) or flow.get("class") not in known:
            continue
        sink = _loc(flow.get("sink"))
        if sink is None:
            continue
        steps = [s for s in map(_loc, flow.get("steps") or []) if s is not None]
        if len(steps) > MAX_TAINT_STEPS:
            steps = [*steps[: MAX_TAINT_STEPS - 1], steps[-1]]
        flows.append({"class": flow["class"], "sink": sink, "steps": steps})
    return {"version": REPORT_VERSION, "language": LANGUAGE, "flows": flows}


def count(doc: Any) -> int:
    flows = doc.get("flows") if isinstance(doc, dict) else None
    return len(flows) if isinstance(flows, list) else 0


def _steps(flow: dict[str, Any]) -> list[dict[str, Any]]:
    """Location-only steps with roles: the first is the source, the last the sink."""
    places = [(normalize_path(s["file"]), s["line"]) for s in flow["steps"]] or [
        (normalize_path(flow["sink"]["file"]), flow["sink"]["line"])
    ]
    out: list[dict[str, Any]] = []
    for i, (file, line) in enumerate(places):
        role = "sink" if i == len(places) - 1 else "source" if i == 0 else "step"
        out.append({"file": file, "line": line, "role": role})
    return out


def parse(doc: Any) -> list[RawFinding]:
    """One finding per (class, sink); of several flows into one sink, the shortest."""
    best: dict[tuple[str, str, int], dict[str, Any]] = {}
    for flow in clean(doc)["flows"]:
        key = (flow["class"], normalize_path(flow["sink"]["file"]), flow["sink"]["line"])
        if key not in best or len(flow["steps"]) < len(best[key]["steps"]):
            best[key] = flow
    out: list[RawFinding] = []
    for (cls, file, line), flow in sorted(best.items()):
        c = _classes()[cls]
        confidence = c.languages[LANGUAGE].confidence.upper()
        cwes = cwe_ids([c.cwe])
        message = f"{c.title}: data from an HTTP request reaches this call"
        out.append(
            RawFinding(
                scanner=ScannerName.JOERN,
                source_type=SourceType.SAST,
                rule_id=rule_id(LANGUAGE, cls),
                title=message,
                severity=semgrep_severity("ERROR", "HIGH", confidence),
                scanner_severity="ERROR",
                location=Location(file, line, line),
                category=sast_category(cwes),
                description=f"{message} (followed across functions and files by Joern).",
                cwe_ids=cwes,
                evidence={"rule_source": "riskgraph", "references": [], "engine": "joern"},
                attrs={
                    "confidence": confidence,
                    "impact": "HIGH",
                    "likelihood": "MEDIUM",
                    "analysis": "interprocedural",
                    "taint_steps": _steps(flow),
                    "riskgraph_class": cls,
                },
            )
        )
    return out
