"""X8 harness (evaluation.expansion): pre-registered criteria, honest verdicts."""

from __future__ import annotations

import pytest
from evaluation import expansion as x


def test_every_pre_registered_criterion_is_listed_once() -> None:
    ids = [c.id for c in x.CRITERIA]
    assert ids == ["A1", "A2", "A3", "B1", "B2", "B3", "C1", "D1", "D2", "D3", "P1", "P2", "O1"]


def test_offline_verdicts_as_measured() -> None:
    got = {o.criterion.id: (o.verdict, o.measured) for o in x.evaluate()}
    assert got["A1"] == (x.FAIL, "0.50 (10/20)")  # JavaScript has no tier 2
    assert got["A2"] == (x.PASS, "0.80 (5 FP)")
    assert got["A3"] == (x.FAIL, "0.50 (5/10)")  # all from tier 1
    assert got["B1"] == (x.PASS, "0.90 (9 TP, 1 FP)")
    assert got["B2"] == (x.PASS, "0.968 (30/31)")
    assert got["B3"] == (x.PASS, "10/10")
    assert got["D2"] == (x.PASS, "0 paths")
    for cid in ("C1", "D1", "D3", "P1", "P2", "O1"):
        assert got[cid] == (x.NOT_RUN, ""), cid


def test_a_verdict_always_comes_with_a_measurement_and_a_not_run_with_a_need() -> None:
    for o in x.evaluate():
        assert (o.verdict == x.NOT_RUN) == (o.measured == ""), o
        assert o.source, o


@pytest.mark.parametrize(
    ("diffs", "p"),
    [([], 1.0), ([0.0] * 5, 1.0), ([0.1] * 5, 1 / 32), ([0.2, -0.1], 0.5)],
)
def test_the_exact_sign_flip_test(diffs: list[float], p: float) -> None:
    assert x.permutation_p(diffs) == pytest.approx(p)


def test_tier2_results_are_semgrep_shaped_for_the_suite_scorer() -> None:
    results = x.tier2_as_semgrep()
    assert len(results) == 16  # 15 suite flows + the hostile concat-ssrf case
    assert all(str(r["check_id"]).startswith("riskgraph.taint.python.") for r in results)
