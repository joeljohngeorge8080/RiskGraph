"""X8 evaluation harness: the expansion plan's §6 criteria, measured where data exists.

    uv run python -m evaluation.expansion            # offline criteria only
    uv run python -m evaluation.expansion --x0       # also X0 prioritization (needs
                                                      # `make test-services`; empties *_test)

Writes ``docs/evaluation/EVALUATION_EXPANSION.md``. The criteria and thresholds below are
copied from ``docs/proposals/EXPANSION_A-D.md`` §6, which pre-registered them; they are
not changed after seeing results. Every criterion ends PASS, FAIL or NOT RUN, and a NOT
RUN says what it needs: this harness never reports a number it did not measure. The run
book (``docs/evaluation/EVALUATION_RUNBOOK.md``) says how to produce the missing inputs.

Inputs measured offline, all recorded from real tools:
- A (taint): the real Semgrep 1.182.0 tier-1 run on the 40-case suite
  (``tests/fixtures/semgrep_taint/real-1.182.0-suite-run.json``) and the real Joern
  4.0.671 tier-2 run (``tests/fixtures/joern/master-f6b35cd1296f/adapter/``);
- B (authorization): the labelled suite (``tests/test_authz_findings_suite.py``), the
  inventory suite (``tests/test_authz_suite.py``) and scenario I (``evaluation.authz``);
- D (paths): scenario H through the pipeline's scoring order
  (``tests/test_risk_scenarios_v2.py``).
"""

from __future__ import annotations

import itertools
import json
import sys
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from evaluation import authz as authz_eval
from evaluation import taint_suite
from evaluation.metrics import ndcg_at

BACKEND = Path(__file__).resolve().parents[1]
REPORT = BACKEND.parent / "docs" / "evaluation" / "EVALUATION_EXPANSION.md"
TIER1_RUN = BACKEND / "tests" / "fixtures" / "semgrep_taint" / "real-1.182.0-suite-run.json"
TIER2_RUN = BACKEND / "tests" / "fixtures" / "joern" / "master-f6b35cd1296f" / "adapter"
PASS, FAIL, NOT_RUN = "PASS", "FAIL", "NOT RUN"


@dataclass(frozen=True, slots=True)
class Criterion:
    id: str
    area: str
    what: str
    target: str  # as pre-registered in EXPANSION_A-D.md §6


@dataclass(frozen=True, slots=True)
class Outcome:
    criterion: Criterion
    verdict: str
    measured: str
    source: str  # what was measured, or what is missing


CRITERIA: tuple[Criterion, ...] = (
    Criterion("A1", "A", "Recall on interprocedural cases (tier 1+2)", "≥ 0.6"),
    Criterion("A2", "A", "Overall taint precision", "≥ 0.7"),
    Criterion("A3", "A", "Sanitized negatives flagged", "≤ 0.2"),
    Criterion("B1", "B", "Inconsistency / unguarded precision", "≥ 0.8"),
    Criterion("B2", "B", "Route-inventory recall", "≥ 0.95"),
    Criterion("B3", "B", "BOLA reported only as hypothesis", "100 %"),
    Criterion(
        "C1",
        "C",
        "Seeded known CVEs/EOLs found against the frozen DB, each with range, fixed "
        "version (when one exists) and data_as_of",
        "100 %",
    ),
    Criterion("D1", "D", "Path precision (every edge in the ground truth)", "≥ 0.9"),
    Criterion("D2", "D", "Scenario H yields no path", "0 paths"),
    Criterion("D3", "D", "Assurance calibration", "verified ≥ 0.95, inferred ≥ 0.7 correct"),
    Criterion(
        "P1",
        "Prioritization",
        "nDCG@10 of RiskGraph-v2 against M2 (CVSS+EPSS) on the scenario suite",
        "greater, paired permutation p < 0.05",
    ),
    Criterion("P2", "Prioritization", "Ablations -A, -B, -C, -D", "show what each contributed"),
    Criterion("O1", "Overhead", "Default-profile scan time p50 against the X0 baseline", "≤ +25 %"),
)
_BY_ID = {c.id: c for c in CRITERIA}


def _out(cid: str, ok: bool | None, measured: str, source: str) -> Outcome:
    verdict = NOT_RUN if ok is None else PASS if ok else FAIL
    return Outcome(_BY_ID[cid], verdict, measured, source)


# --- A: taint, tiers 1 and 2 -------------------------------------------------------------
def tier2_as_semgrep(root: Path = TIER2_RUN) -> list[dict[str, object]]:
    """The Joern runs as Semgrep-shaped results, so the suite's own scorer scores them."""
    results: list[dict[str, object]] = []
    for case in sorted(p for p in root.iterdir() if p.is_dir()):
        doc = json.loads((case / "joern.json").read_text(encoding="utf-8"))
        for flow in doc.get("flows", []):
            results.append(
                {
                    "check_id": f"riskgraph.taint.python.{flow['class']}",
                    "path": f"{case.name}/{flow['sink']['file']}",
                    "start": {"line": flow["sink"]["line"]},
                }
            )
    return results


def taint_score(python_only: bool = False) -> taint_suite.Score:
    tier1 = json.loads(TIER1_RUN.read_text(encoding="utf-8"))["results"]
    suite = [c for c in taint_suite.cases() if not python_only or c.language == "python"]
    return taint_suite.score({"results": [*tier1, *tier2_as_semgrep()]}, suite)


def check_taint() -> list[Outcome]:
    s, py = taint_score(), taint_score(python_only=True)
    inter = ("cross_function", "cross_file")

    def recall(x: taint_suite.Score) -> tuple[float, int, int]:
        found = sum(x.true_positives.get(v, 0) for v in inter)
        total = sum(x.positives.get(v, 0) for v in inter)
        return found / total, found, total

    r, f, t = recall(s)
    rp, fp_, tp_ = recall(py)
    src = (
        "real Semgrep 1.182.0 tier-1 run + real Joern 4.0.671 tier-2 run on the 40-case "
        f"suite. Python only (tier 2's language, plan §5): {rp:.2f} ({fp_}/{tp_}); "
        "JavaScript has tier 1 only, which cannot see across functions"
    )
    precision = s.precision or 0.0
    rate = s.sanitized_fp_rate or 0.0
    tier1 = json.loads(TIER1_RUN.read_text(encoding="utf-8"))["results"]
    split = []
    for name, results in (("tier 1", tier1), ("tier 2", tier2_as_semgrep())):
        for lang in ("python", "javascript"):
            one = taint_suite.score(
                {"results": results}, [c for c in taint_suite.cases() if c.language == lang]
            )
            split.append(f"{name} {lang} {one.flagged_negatives}/{one.negatives}")
    return [
        _out("A1", r >= 0.6, f"{r:.2f} ({f}/{t})", src),
        _out("A2", precision >= 0.7, f"{precision:.2f} ({s.false_positives} FP)", "same runs"),
        _out(
            "A3",
            rate <= 0.2,
            f"{rate:.2f} ({s.flagged_negatives}/{s.negatives})",
            "same runs; flagged by " + ", ".join(split) + ". Tier 2 uses the catalogue's "
            "allow-list lookup sanitizer (ADR-0025); tier-1 rules do not yet",
        ),
    ]


# --- B: authorization --------------------------------------------------------------------
def check_authz() -> list[Outcome]:
    from tests import test_authz_findings_suite as suite
    from tests import test_authz_suite as inventory

    with tempfile.TemporaryDirectory(prefix="riskgraph-x8-authz-") as tmp:
        found, issues = suite._run(Path(tmp))
    tp = fp = 0
    for rule in ("inconsistent", "unguarded-sensitive"):
        t, f, _ = suite._score(rule, found)
        tp, fp = tp + t, fp + f
    scenario = authz_eval.run()
    s_tp = s_fp = 0
    for rule in ("inconsistent", "unguarded-sensitive"):
        t, f, _ = scenario.counts(rule)
        s_tp, s_fp = s_tp + t, s_fp + f
    precision = (tp + s_tp) / (tp + fp + s_tp + s_fp)
    with tempfile.TemporaryDirectory(prefix="riskgraph-x8-inventory-") as tmp:
        inventory._write(Path(tmp))
        seen = inventory._found(Path(tmp))
    total = len(inventory.LABELS)
    hit = sum(1 for label in inventory.LABELS if label[:3] in seen)
    levels = [i.assurance.value for i in issues if i.rule == "bola"]
    levels += [f.assurance for f in scenario.findings if f.rule == "bola"]
    hypotheses, bola = levels.count("hypothesis"), levels
    return [
        _out(
            "B1",
            precision >= 0.8,
            f"{precision:.2f} ({tp + s_tp} TP, {fp + s_fp} FP)",
            "labelled suite (forms declared public, F-4-2) + scenario I; scenario I's one FP "
            "is an undeclared public signup",
        ),
        _out("B2", hit / total >= 0.95, f"{hit / total:.3f} ({hit}/{total})", "inventory suite"),
        _out(
            "B3",
            hypotheses == len(bola),
            f"{hypotheses}/{len(bola)}",
            "every BOLA finding of the labelled suite and scenario I",
        ),
    ]


# --- D: paths ----------------------------------------------------------------------------
def check_paths() -> list[Outcome]:
    from tests import test_risk_scenarios_v2 as v2

    paths = v2._run(v2.H, v2.H_MANIFEST).analysis.paths
    return [
        _out(
            "D1",
            None,
            "",
            "needs per-edge ground truth for scenarios A-H, written before the run (runbook §D)",
        ),
        _out("D2", len(paths) == 0, f"{len(paths)} paths", "scenario H, pipeline scoring order"),
        _out(
            "D3",
            None,
            "",
            "needs a labelled sample of edges per assurance level (runbook §D)",
        ),
    ]


# --- P: prioritization -------------------------------------------------------------------
def permutation_p(diffs: Sequence[float]) -> float:
    """Exact one-sided paired sign-flip test: P(mean ≥ observed) over all 2^n flips."""
    if not diffs:
        return 1.0
    observed = sum(diffs) / len(diffs)
    flips = list(itertools.product((1, -1), repeat=len(diffs)))
    hits = sum(
        1
        for signs in flips
        if sum(s * d for s, d in zip(signs, diffs, strict=True)) / len(diffs) >= observed - 1e-12
    )
    return hits / len(flips)


def check_prioritization(rows: Sequence[object] | None) -> list[Outcome]:
    ablation = _out(
        "P2",
        None,
        "",
        "needs one switch per component in the pipeline and an X0 replay per switch "
        "(runbook §P2; backlog)",
    )
    if rows is None:
        return [_out("P1", None, "", "run with --x0 (needs `make test-services`)"), ablation]
    from evaluation.baselines import rank

    by_scenario: dict[str, list[object]] = {}
    for r in rows:
        by_scenario.setdefault(r.scenario, []).append(r)  # type: ignore[attr-defined]

    def ndcg(items: Sequence[object], method: str) -> float:
        ranked = rank(items, method)  # type: ignore[type-var]
        return ndcg_at([x.important for x in ranked], 10) or 0.0  # type: ignore[attr-defined]

    diffs = [
        ndcg(items, "M4 RiskGraph") - ndcg(items, "M2 CVSS+EPSS")
        for _, items in sorted(by_scenario.items())
    ]
    pooled_m4, pooled_m2 = ndcg(list(rows), "M4 RiskGraph"), ndcg(list(rows), "M2 CVSS+EPSS")
    p = permutation_p(diffs)
    return [
        _out(
            "P1",
            pooled_m4 > pooled_m2 and p < 0.05,
            f"pooled {pooled_m4:.3f} vs {pooled_m2:.3f}; per-scenario differences "
            f"{', '.join(f'{d:+.3f}' for d in diffs)}; p = {p:.3f}",
            f"X0 replay, {len(by_scenario)} scenarios; exact sign-flip test over scenarios",
        ),
        ablation,
    ]


def check_unmeasured() -> list[Outcome]:
    return [
        _out(
            "C1",
            None,
            "",
            "needs a seeded CVE/EOL list for the image repositories and a frozen Trivy DB "
            "digest (runbook §C)",
        ),
        _out("O1", None, "", "needs real scanner runs of X0 before and after (runbook §O)"),
    ]


def evaluate(x0: bool = False) -> list[Outcome]:
    rows = None
    if x0:
        from evaluation.run import collect

        rows = collect()
    out = [
        *check_taint(),
        *check_authz(),
        *check_unmeasured(),
        *check_paths(),
        *check_prioritization(rows),
    ]
    order = {c.id: i for i, c in enumerate(CRITERIA)}
    return sorted(out, key=lambda o: order[o.criterion.id])


def render(outcomes: Sequence[Outcome]) -> str:
    counts = {v: sum(1 for o in outcomes if o.verdict == v) for v in (PASS, FAIL, NOT_RUN)}
    lines = [
        "# Expansion evaluation (X8)",
        "",
        "Generated by `make eval-expansion` (`backend/evaluation/expansion.py`). Do not edit by "
        "hand. Criteria and thresholds are the ones pre-registered in "
        "`docs/proposals/EXPANSION_A-D.md` §6. A NOT RUN says what it needs; the run book "
        "(`docs/evaluation/EVALUATION_RUNBOOK.md`) says how to get it.",
        "",
        f"**{counts[PASS]} PASS · {counts[FAIL]} FAIL · {counts[NOT_RUN]} NOT RUN**",
        "",
        "| ID | Area | Criterion | Target | Measured | Verdict | Source / what is needed |",
        "|---|---|---|---|---|---|---|",
    ]
    for o in outcomes:
        c = o.criterion
        lines.append(
            f"| {c.id} | {c.area} | {c.what} | {c.target} | {o.measured or '—'} | "
            f"**{o.verdict}** | {o.source} |"
        )
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    REPORT.write_text(render(evaluate(x0="--x0" in argv)), encoding="utf-8")
    print(f"wrote {REPORT}")  # noqa: T201
    return 0


Check = Callable[[], list[Outcome]]

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
