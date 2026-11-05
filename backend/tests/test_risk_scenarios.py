"""Risk model against blueprint §14.6 (scenarios A-E), §14.7 monotonicity, §14.3 reduction."""

from __future__ import annotations

import math

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from riskgraph.modules.context import FindingContext, Observed
from riskgraph.modules.risk import ScoreInput, score
from riskgraph.modules.risk.model import epss_to_e
from riskgraph.shared.vocabulary import Priority
from riskgraph.shared.vocabulary import Severity as V
from riskgraph.shared.vocabulary import SourceType as S


def _ctx(exposure: str | None, data: str | None, privilege: str | None, crit: str | None):  # type: ignore[no-untyped-def]
    def o(label: str | None) -> Observed | None:
        return Observed(label, "manifest", "high") if label else None

    return FindingContext("svc", o(exposure), o(data), o(privilege), o(crit))


def _reach(tier: str, confidence: str = "medium") -> Observed:
    return Observed(tier, "reachability", confidence)


# CVSS impact sub-scores: v3.1 9.8 (AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H) → 5.9; a 6.5 or a
# 7.5 with T = 0.6 in the blueprint table → impact sub-score 3.6.
SCENARIOS = {
    "A": ScoreInput(
        S.SCA,
        V.CRITICAL,
        epss=0.02,
        cvss_impact=5.9,
        context=_ctx("internal", "internal", "limited", None),
        reachability=_reach("L0", "high"),
    ),
    "B": ScoreInput(
        S.SCA,
        V.MEDIUM,
        epss=0.05,
        cvss_impact=3.6,
        context=_ctx("internet_noauth", "pii", "admin", None),
        reachability=_reach("L3"),
    ),
    "C": ScoreInput(
        S.SECRET,
        V.CRITICAL,
        live_credential=True,
        context=_ctx("internet_noauth", "pii", "admin", None),
    ),
    "D": ScoreInput(
        S.SCA,
        V.HIGH,
        epss=0.01,
        cvss_impact=3.6,
        context=_ctx("internal", "internal", "read_only", None),
        reachability=_reach("L2"),
    ),
    "E": ScoreInput(
        S.SAST,
        V.HIGH,
        category="ssrf",
        context=_ctx("internet_noauth", "pii", "elevated", "high"),
        reachability=_reach("L3"),
    ),
}
# Blueprint §14.6, hand-computed: (E, L, I, risk, priority).
EXPECTED = {
    "A": (0.575, 0.284, 0.595, 16.9, Priority.LOW),
    "B": (0.675, 0.877, 0.75, 65.8, Priority.HIGH),
    "C": (0.9, 0.949, 0.85, 80.6, Priority.CRITICAL),
    "D": (0.5, 0.543, 0.45, 24.4, Priority.MEDIUM),
    "E": (0.7, 0.888, 0.875, 77.7, Priority.CRITICAL),
}


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_scenario_matches_blueprint_table(name: str) -> None:
    r = score(SCENARIOS[name])
    e, likelihood, impact, risk, priority = EXPECTED[name]
    assert r.factor("E").value == pytest.approx(e, abs=0.001)  # type: ignore[union-attr]
    assert r.likelihood == pytest.approx(likelihood, abs=0.001)
    assert r.impact == pytest.approx(impact, abs=0.001)
    # the table was hand-computed from rounded intermediates (A: I = 0.595 for 0.5958)
    assert r.score == pytest.approx(risk, abs=0.1)
    assert r.priority is priority
    assert r.corroboration == 1.0  # one scanner: K plays no part in the table


def test_scenario_b_with_high_criticality() -> None:
    b = SCENARIOS["B"]
    ctx = _ctx("internet_noauth", "pii", "admin", "high")
    r = score(ScoreInput(**{**_fields(b), "context": ctx}))
    assert r.score == pytest.approx(74.6, abs=0.05) and r.priority is Priority.CRITICAL


def test_scenarios_order_c_e_b_d_a_and_cvss_only_does_not() -> None:
    ranked = sorted(SCENARIOS, key=lambda n: -score(SCENARIOS[n]).score)
    assert ranked == ["C", "E", "B", "D", "A"]
    cvss_base = {"A": 9.8, "B": 6.5, "D": 7.5}  # C and E have no CVSS
    assert sorted(cvss_base, key=lambda n: -cvss_base[n]) == ["A", "D", "B"]


def _fields(inp: ScoreInput) -> dict[str, object]:
    return {f: getattr(inp, f) for f in inp.__dataclass_fields__}


# --- §14.7 monotonicity: raising any one factor never lowers score or priority ---------

EXPOSURE = ["isolated", "internal", None, "internet_auth", "internet_noauth"]  # None = 0.5
DATA = ["public", "internal", None, "confidential", "pii", "credentials"]
PRIVILEGE = ["read_only", None, "limited", "elevated", "admin"]  # None = 0.5 = limited
CRITICALITY = ["low", None, "high"]  # None = medium
REACH = ["L0", "L1", None, "L2", "L3"]  # None = unknown 0.6


@st.composite
def inputs(draw: st.DrawFn) -> tuple[dict[str, int], float, float, bool, str, int]:
    idx = {
        "exposure": draw(st.integers(0, len(EXPOSURE) - 1)),
        "data": draw(st.integers(0, len(DATA) - 1)),
        "privilege": draw(st.integers(0, len(PRIVILEGE) - 1)),
        "criticality": draw(st.integers(0, len(CRITICALITY) - 1)),
        "reach": draw(st.integers(0, len(REACH) - 1)),
    }
    epss = draw(st.floats(1e-5, 1.0))
    impact = draw(st.floats(0.0, 6.0))
    kev = draw(st.booleans())
    reach_conf = draw(st.sampled_from(["low", "medium", "high"]))
    scanners = draw(st.integers(1, 4))
    return idx, epss, impact, kev, reach_conf, scanners


def _build(
    idx: dict[str, int], epss: float, impact: float, kev: bool, conf: str, n: int
) -> ScoreInput:
    tier = REACH[idx["reach"]]
    return ScoreInput(
        S.SCA,
        V.HIGH,
        epss=epss,
        cvss_impact=impact,
        kev=kev,
        detected_by=tuple(f"s{i}" for i in range(n)),
        context=_ctx(
            EXPOSURE[idx["exposure"]],
            DATA[idx["data"]],
            PRIVILEGE[idx["privilege"]],
            CRITICALITY[idx["criticality"]],
        ),
        reachability=_reach(tier, conf) if tier else None,
    )


LADDERS = {
    "exposure": EXPOSURE,
    "data": DATA,
    "privilege": PRIVILEGE,
    "criticality": CRITICALITY,
    "reach": REACH,
}


@settings(max_examples=1000, deadline=None)
@given(case=inputs(), which=st.sampled_from([*LADDERS, "epss", "impact", "kev", "scanners"]))
def test_raising_any_factor_never_lowers_risk(
    case: tuple[dict[str, int], float, float, bool, str, int], which: str
) -> None:
    idx, epss, impact, kev, conf, n = case
    before = score(_build(idx, epss, impact, kev, conf, n))
    if which in LADDERS:
        if idx[which] == len(LADDERS[which]) - 1:
            return
        idx = {**idx, which: idx[which] + 1}
    elif which == "epss":
        epss = min(1.0, epss * 3)
    elif which == "impact":
        impact = min(6.0, impact + 1.0)
    elif which == "kev":
        kev = True
    else:
        n += 1
    after = score(_build(idx, epss, impact, kev, conf, n))
    assert after.score >= before.score - 1e-9, (which, before.score, after.score)
    assert after.priority.rank >= before.priority.rank, (which, before.priority, after.priority)


# --- §14.3 reduction: with no context, the score is a fixed function of E and T --------


@settings(max_examples=300, deadline=None)
@given(epss=st.floats(1e-5, 1.0), impact=st.floats(0.0, 6.0), sev=st.sampled_from(list(V)))
def test_context_free_score_is_a_function_of_vulnerability_data_only(
    epss: float, impact: float, sev: V
) -> None:
    r = score(ScoreInput(S.SCA, sev, epss=epss, cvss_impact=impact))
    e = epss_to_e(epss)
    t = min(1.0, max(0.05, impact / 6.0))
    expected = 100 * (e * 0.5 * 0.6) ** (1 / 3) * (t + 0.5 + 0.5 + 0.5) / 4
    assert r.score == pytest.approx(round(min(100.0, expected), 2), abs=0.011)
    # every non-default factor is absent: the differences to this ranking are attributable
    defaults = {f.name: f.source for f in r.factors if f.name in "XRDPC"}
    assert set(defaults.values()) <= {"default_unknown", "default"}


def test_context_free_secret_drops_reachability() -> None:
    r = score(ScoreInput(S.SECRET, V.HIGH, live_credential=False))
    assert r.likelihood == pytest.approx(math.sqrt(0.6 * 0.5), abs=1e-4)
    assert not r.factor("R").applicable  # type: ignore[union-attr]
