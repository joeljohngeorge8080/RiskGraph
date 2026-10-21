from __future__ import annotations

import math

import pytest
from hypothesis import given
from hypothesis import strategies as st
from riskgraph.modules.risk import ScoreInput, priority_for, score
from riskgraph.modules.risk.model import epss_to_e
from riskgraph.shared.vocabulary import Priority
from riskgraph.shared.vocabulary import Severity as V
from riskgraph.shared.vocabulary import SourceType as S

# Hand-computed in the plan (docs/phases/PHASE_MVP.md chapter H).
CASES = [
    (ScoreInput(S.SCA, V.HIGH, epss=0.05, cvss_impact=5.9), 36.45, Priority.MEDIUM),
    (ScoreInput(S.SCA, V.HIGH, epss=1e-4, cvss_impact=5.9), 15.31, Priority.LOW),
    (ScoreInput(S.SCA, V.HIGH, kev=True, cvss_impact=5.9), 41.56, Priority.HIGH),
    (
        ScoreInput(S.SECRET, V.CRITICAL, live_credential=True, detected_by=("gitleaks",)),
        41.93,
        Priority.CRITICAL,
    ),
    (
        ScoreInput(S.SECRET, V.CRITICAL, live_credential=True, detected_by=("gitleaks", "trivy")),
        44.02,
        Priority.CRITICAL,
    ),
    (ScoreInput(S.SECRET, V.HIGH), 34.23, Priority.MEDIUM),
    (ScoreInput(S.SAST, V.HIGH, category="sql_injection"), 35.66, Priority.MEDIUM),
    (
        ScoreInput(S.SAST, V.HIGH, category="sql_injection", confidence="HIGH"),
        37.29,
        Priority.MEDIUM,
    ),
    (
        ScoreInput(S.IAC, V.HIGH, iac_family="public", detected_by=("checkov", "trivy")),
        34.51,
        Priority.MEDIUM,
    ),
    (ScoreInput(S.IAC, V.LOW, iac_family="logging"), 15.91, Priority.LOW),
]


@pytest.mark.parametrize(("inp", "expected", "priority"), CASES)
def test_fixture_scores(inp: ScoreInput, expected: float, priority: Priority) -> None:
    result = score(inp)
    assert result.score == pytest.approx(expected, abs=0.01)
    assert result.priority is priority


def test_epss_mapping_points() -> None:
    for epss, e in [(1e-5, 0.05), (1e-4, 0.05), (1e-3, 0.25), (1e-2, 0.5), (0.1, 0.75), (1.0, 1.0)]:
        assert epss_to_e(epss) == pytest.approx(e)
    assert epss_to_e(0) == 0.05


def test_k_equal_one_is_the_blueprint_context_free_model() -> None:
    # §14.3: L = geomean(E, 0.5, 0.6), I = mean(T, 0.5, 0.5, 0.5)
    r = score(ScoreInput(S.SCA, V.HIGH, epss=0.02, cvss_impact=3.6))
    e = (math.log10(0.02) + 4) / 4
    expected = 100 * (e * 0.5 * 0.6) ** (1 / 3) * ((3.6 / 6 + 1.5) / 4)
    assert r.corroboration == 1.0
    assert r.score == pytest.approx(expected, abs=0.01)


def test_every_factor_has_provenance() -> None:
    r = score(ScoreInput(S.SECRET, V.HIGH))
    names = [f.name for f in r.factors]
    assert names == ["E", "X", "R", "T", "D", "P", "C", "K"]
    reach = next(f for f in r.factors if f.name == "R")
    assert reach.applicable is False  # n/a for secrets
    assert all(f.source and f.confidence for f in r.factors)


def test_bands() -> None:
    assert priority_for(70) is Priority.CRITICAL
    assert priority_for(69.99) is Priority.HIGH
    assert priority_for(45) is Priority.HIGH
    assert priority_for(20) is Priority.MEDIUM
    assert priority_for(19.99) is Priority.LOW


unit = st.floats(min_value=1e-6, max_value=1.0)


@given(a=unit, b=unit, impact=st.floats(min_value=0.0, max_value=6.0))
def test_monotone_in_epss(a: float, b: float, impact: float) -> None:
    lo, hi = sorted((a, b))
    s_lo = score(ScoreInput(S.SCA, V.HIGH, epss=lo, cvss_impact=impact)).score
    s_hi = score(ScoreInput(S.SCA, V.HIGH, epss=hi, cvss_impact=impact)).score
    assert s_lo <= s_hi


@given(e=unit, a=st.floats(min_value=0.0, max_value=6.0), b=st.floats(min_value=0.0, max_value=6.0))
def test_monotone_in_impact(e: float, a: float, b: float) -> None:
    lo, hi = sorted((a, b))
    assert (
        score(ScoreInput(S.SCA, V.HIGH, epss=e, cvss_impact=lo)).score
        <= score(ScoreInput(S.SCA, V.HIGH, epss=e, cvss_impact=hi)).score
    )


@given(n=st.integers(min_value=1, max_value=4))
def test_agreement_never_lowers_a_score(n: int) -> None:
    scanners = ("checkov", "trivy", "semgrep", "gitleaks")
    one = score(ScoreInput(S.IAC, V.HIGH, iac_family="public", detected_by=scanners[:1])).score
    many = score(ScoreInput(S.IAC, V.HIGH, iac_family="public", detected_by=scanners[:n])).score
    assert many >= one and many <= one * 1.1 + 0.01


def test_kev_overrides_floor_priority_not_score() -> None:
    r = score(ScoreInput(S.SCA, V.LOW, kev=True, cvss_impact=1.4))
    assert r.priority is Priority.HIGH
    assert r.overrides[0]["rule"] == "kev_floor_high"
    assert r.score < 45
