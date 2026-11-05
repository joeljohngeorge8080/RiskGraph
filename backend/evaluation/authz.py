"""Authorization evaluation (F-4-1): scenario I, scored on its own, outside X0.

    uv run python -m evaluation.authz          # used by ``make eval-authz``

Runs the pipeline's own authorization path on ``authz_scenario`` (extractor → route
inventory → ``authz.analyze`` with the manifest's guards, rules and public routes →
authorization findings → merge → context → score), exactly as ``scans.pipeline.analyze``
does for them, without a database: authorization findings need no scanner, and their
reachability is not applicable. Writes ``docs/evaluation/AUTHZ_EVAL.md`` (deterministic).

Two measurements against the labels written first (``authz_scenario``):
- detection: precision and recall over (route, rule) pairs, per rule and pooled;
- prioritization: routes ranked by their best finding's score, against the routes a
  reviewer fixes first; RiskGraph's score against severity order (the baseline).
"""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from riskgraph.modules.authz import RULES, analyze, issue_findings, route_inventory
from riskgraph.modules.context import ContextResolver, parse_manifest
from riskgraph.modules.normalization import fingerprint, merge
from riskgraph.modules.reachability.extract import extract
from riskgraph.modules.risk import input_for, score
from riskgraph.shared.vocabulary import Severity, SourceType

from evaluation import authz_scenario as scenario
from evaluation.metrics import average_precision, ndcg_at, precision_at

REPORT = Path(__file__).resolve().parents[2] / "docs" / "evaluation" / "AUTHZ_EVAL.md"
REPO = f"riskgraph-eval/{scenario.NAME}"


@dataclass(frozen=True, slots=True)
class Scored:
    route: scenario.Route
    rule: str
    severity: Severity
    score: float
    priority: str
    assurance: str
    key: str  # merge key: a neutral tie-break, as in X0


@dataclass(frozen=True, slots=True)
class Result:
    findings: list[Scored]
    expected: dict[scenario.Route, frozenset[str]]
    important: frozenset[scenario.Route]

    def found(self) -> set[tuple[scenario.Route, str]]:
        return {(f.route, f.rule) for f in self.findings}

    def wanted(self) -> set[tuple[scenario.Route, str]]:
        return {(r, rule) for r, rules in self.expected.items() for rule in rules}

    def counts(self, rule: str | None = None) -> tuple[int, int, int]:
        found = {p for p in self.found() if rule is None or p[1] == rule}
        wanted = {p for p in self.wanted() if rule is None or p[1] == rule}
        return len(found & wanted), len(found - wanted), len(wanted - found)

    def ranking(self, key: Callable[[Scored], tuple[object, ...]]) -> list[scenario.Route]:
        """Routes in the order a reviewer would open them: by each route's best finding."""
        best: dict[scenario.Route, Scored] = {}
        for f in sorted(self.findings, key=key):
            best.setdefault(f.route, f)
        return list(best)


def run() -> Result:
    manifest = parse_manifest(scenario.MANIFEST)
    if manifest.status != "valid" or manifest.manifest is None:
        raise RuntimeError(f"scenario manifest is invalid: {manifest.warnings}")
    decl = manifest.manifest.authz
    root = Path(tempfile.mkdtemp(prefix="riskgraph-authz-eval-"))
    try:
        scenario.build(root)
        routes = route_inventory(extract(root), extra_guards=decl.guards if decl else ())
    finally:
        shutil.rmtree(root, ignore_errors=True)
    issues = analyze(
        routes, decl.rules if decl else (), {}, public=decl.public if decl else ()
    ).issues
    raw = issue_findings(issues, {})
    for f in raw:
        f.fingerprint = fingerprint(f, REPO)
    resolver = ContextResolver(manifest, public_repository=True, iac=[])
    out: list[Scored] = []
    for m in merge(raw):
        if m.source_type is not SourceType.AUTHZ:
            raise RuntimeError(f"unexpected {m.source_type} finding in the authz scenario")
        result = score(input_for(m, None, resolver.for_finding(m.location.file, m.source_type)))
        method, _, path = (m.location.resource or "").partition(" ")
        out.append(
            Scored(
                route=(method, path),
                rule=m.representative.rule_id.removeprefix("authz:"),
                severity=m.severity,
                score=float(result.score),
                priority=result.priority.value,
                assurance=str(m.attrs.get("assurance")),
                key=m.merge_key,
            )
        )
    unknown = sorted({f.route for f in out} - set(scenario.EXPECTED))
    if unknown:
        raise RuntimeError(f"findings on routes the labels do not cover: {unknown}")
    return Result(sorted(out, key=lambda f: f.key), scenario.EXPECTED, scenario.IMPORTANT)


def by_score(f: Scored) -> tuple[object, ...]:
    return (-f.score, f.key)


def by_severity(f: Scored) -> tuple[object, ...]:
    return (-f.severity.rank, f.key)


METHODS: dict[str, Callable[[Scored], tuple[object, ...]]] = {
    "RiskGraph v2 score": by_score,
    "Severity only": by_severity,
}


def _ratio(n: int, d: int) -> str:
    return f"{n / d:.2f} ({n}/{d})" if d else "n/a"


def _fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"


def rank_metrics(res: Result, order: Sequence[scenario.Route]) -> dict[str, float | None]:
    rel = [r in res.important for r in order]
    return {
        "nDCG@5": ndcg_at(rel, 5),
        "P@3": precision_at(rel, 3),
        "AP": average_precision(rel),
    }


def report(res: Result) -> str:
    lines = [
        "# Authorization evaluation (scenario I, F-4-1)",
        "",
        "Generated by `make eval-authz` (`backend/evaluation/authz.py`). Do not edit by hand.",
        "",
        "- Outside X0 on purpose (`OUTSIDE_X0`, owner answer F-4-1 (a)): X0's labels predate "
        "authorization findings. This scenario's labels were committed before its first run "
        "(`backend/evaluation/authz_scenario.py`, commit `e4a6e21`).",
        "- The pipeline's own authorization path, no database: extractor, route inventory, "
        "`authz.analyze` (manifest guards, rules, `public`), findings, merge, context, score.",
        f"- Scenario: {scenario.DESCRIPTION}",
        "",
        "## Detection: (route, rule) pairs against the expected issues",
        "",
        "| Rule | TP | FP | FN | Precision | Recall |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for rule in [*RULES, None]:
        tp, fp, fn = res.counts(rule)
        lines.append(
            f"| {rule or '**pooled**'} | {tp} | {fp} | {fn} | "
            f"{_ratio(tp, tp + fp)} | {_ratio(tp, tp + fn)} |"
        )
    wrong = sorted(res.found() - res.wanted())
    missed = sorted(res.wanted() - res.found())
    lines += [
        "",
        "False positives: " + (", ".join(f"`{r[0]} {r[1]}` {k}" for r, k in wrong) or "none") + ".",
        "",
        "Missed: " + (", ".join(f"`{r[0]} {r[1]}` {k}" for r, k in missed) or "none") + ".",
        "",
        "## Prioritization: routes by their best finding, against the routes to fix first",
        "",
        f"{len(res.important)} important routes of {len({f.route for f in res.findings})} "
        "routes with a finding.",
        "",
        "| Method | nDCG@5 | P@3 | AP |",
        "|---|---:|---:|---:|",
    ]
    for name, key in METHODS.items():
        m = rank_metrics(res, res.ranking(key))
        lines.append(f"| {name} | {_fmt(m['nDCG@5'])} | {_fmt(m['P@3'])} | {_fmt(m['AP'])} |")
    lines += [
        "",
        "## Findings, by RiskGraph score",
        "",
        "| # | Important | Route | Rule | Assurance | Severity | Score | Priority |",
        "|---:|---|---|---|---|---|---:|---|",
    ]
    for i, f in enumerate(sorted(res.findings, key=by_score), 1):
        lines.append(
            f"| {i} | {'yes' if f.route in res.important else 'no'} | `{f.route[0]} "
            f"{f.route[1]}` | {f.rule} | {f.assurance} | {f.severity.value} | "
            f"{f.score:.2f} | {f.priority} |"
        )
    lines += [
        "",
        "## Reading it",
        "",
        "- A BOLA finding is always a hypothesis and is scored Low (ADR-0023, ADR-0024): two "
        "of the four important routes are BOLA-only, so they rank last by design. That is the "
        "cost of never presenting an unproven ownership bug as a finding; a two-user test "
        "would settle them.",
        "- Here the score orders routes exactly as severity does: every authorization "
        "finding of one service gets the same context (exposure, data, privilege), so only "
        "the rule's own table separates them. Context would separate findings across "
        "services; this scenario has one.",
        "- The newsletter signup is public on purpose but not declared in `authz.public`; "
        "declaring it would remove that false positive (F-4-2).",
        "- One small synthetic scenario: the numbers describe it, not authorization findings "
        "in general.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    REPORT.write_text(report(run()), encoding="utf-8")
    print(f"wrote {REPORT}")  # noqa: T201


if __name__ == "__main__":
    main()
