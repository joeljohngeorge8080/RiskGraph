"""Authorization scenario I (F-4-1): outside X0, labels committed before its first run."""

from __future__ import annotations

from evaluation import authz, authz_scenario
from evaluation.run import OUTSIDE_X0
from riskgraph.modules.authz import RULES


def test_authz_stays_outside_x0() -> None:
    assert "authz" in OUTSIDE_X0


def test_every_expected_rule_is_a_real_rule_and_important_routes_are_labelled() -> None:
    assert all(rules <= set(RULES) for rules in authz_scenario.EXPECTED.values())
    assert set(authz_scenario.EXPECTED) >= authz_scenario.IMPORTANT


def test_detection_numbers_as_measured() -> None:
    res = authz.run()
    assert res.counts() == (7, 1, 0)  # pooled TP, FP, FN
    assert sorted(res.found() - res.wanted()) == [
        (("POST", "/newsletter"), "unguarded-sensitive")  # public, not declared (F-4-2)
    ]


def test_no_bola_finding_is_more_than_a_low_hypothesis() -> None:
    bola = [f for f in authz.run().findings if f.rule == "bola"]
    assert bola and all(f.assurance == "hypothesis" and f.priority == "low" for f in bola)


def test_the_committed_report_is_what_the_code_writes() -> None:
    """``make eval-authz`` is deterministic; a change to the rules shows up here."""
    assert authz.REPORT.read_text(encoding="utf-8") == authz.report(authz.run())
