from __future__ import annotations

import math

import pytest
from hypothesis import given
from hypothesis import strategies as st
from riskgraph.modules.context import FindingContext, Observed
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


# --- deployment context (v1-ctx) --------------------------------------------------------


def _obs(label: str, source: str = "manifest") -> Observed:
    return Observed(label, source, "high", {"service": "api"})


FULL = FindingContext("api", _obs("internet_noauth"), _obs("pii"), _obs("admin"), _obs("high"))


def test_full_context_follows_the_blueprint_formula() -> None:
    r = score(ScoreInput(S.SCA, V.HIGH, epss=0.05, cvss_impact=5.9, context=FULL))
    e = (math.log10(0.05) + 4) / 4
    expected = 100 * (e * 1.0 * 0.6) ** (1 / 3) * ((5.9 / 6 + 0.9 + 1.0 + 0.9) / 4)
    assert r.score == pytest.approx(expected, abs=0.01)
    assert r.priority is Priority.HIGH  # 69.97: R is still unknown until Phase 8
    by_name = {f.name: f for f in r.factors}
    assert (by_name["X"].value, by_name["X"].source, by_name["X"].raw_value) == (
        1.0,
        "manifest",
        "internet_noauth",
    )
    assert by_name["D"].evidence == {"service": "api"}
    assert by_name["R"].source == "default_unknown"


def test_context_reaches_critical_without_overrides() -> None:
    r = score(ScoreInput(S.SAST, V.HIGH, category="ssrf", confidence="HIGH", context=FULL))
    expected = 100 * (0.8 * 1.0 * 0.6) ** (1 / 3) * ((0.9 + 0.9 + 1.0 + 0.9) / 4)
    assert r.score == pytest.approx(expected, abs=0.01)
    assert r.priority is Priority.CRITICAL and r.overrides == []


def test_quiet_context_lowers_the_score() -> None:
    quiet = FindingContext(
        "batch", _obs("isolated"), _obs("public"), _obs("read_only"), _obs("low")
    )
    base = score(ScoreInput(S.SCA, V.HIGH, epss=0.05, cvss_impact=5.9)).score
    r = score(ScoreInput(S.SCA, V.HIGH, epss=0.05, cvss_impact=5.9, context=quiet))
    assert r.score < base and r.priority is Priority.LOW


def test_secret_in_public_repo_scores_high_without_override() -> None:
    ctx = FindingContext(exposure=_obs("internet_noauth", "repository_visibility"))
    r = score(ScoreInput(S.SECRET, V.HIGH, context=ctx))
    assert r.score == pytest.approx(100 * math.sqrt(0.6 * 1.0) * 0.625, abs=0.01)  # 48.41
    assert r.priority is Priority.HIGH and r.overrides == []


def test_kev_floor_does_not_apply_to_isolated_services() -> None:
    isolated = FindingContext("batch", _obs("isolated"))
    r = score(ScoreInput(S.SCA, V.LOW, kev=True, cvss_impact=1.4, context=isolated))
    assert r.overrides == [] and r.priority is not Priority.HIGH
    internal = FindingContext("api", _obs("internal"))
    r2 = score(ScoreInput(S.SCA, V.LOW, kev=True, cvss_impact=1.4, context=internal))
    assert r2.priority is Priority.HIGH


def test_unknown_labels_fall_back_to_defaults() -> None:
    odd = FindingContext("x", _obs("galactic"), None, None, None)
    with_odd = score(ScoreInput(S.SCA, V.HIGH, epss=0.05, cvss_impact=5.9, context=odd))
    plain = score(ScoreInput(S.SCA, V.HIGH, epss=0.05, cvss_impact=5.9))
    assert with_odd.score == plain.score


EXPOSURES = ["isolated", "internal", None, "internet_auth", "internet_noauth"]


@given(i=st.integers(0, 4), j=st.integers(0, 4), e=unit)
def test_monotone_in_exposure(i: int, j: int, e: float) -> None:
    lo, hi = sorted((i, j))

    def at(k: int) -> float:
        label = EXPOSURES[k]
        ctx = FindingContext(exposure=_obs(label)) if label else None
        return score(ScoreInput(S.SCA, V.HIGH, epss=e, cvss_impact=4.0, context=ctx)).score

    assert at(lo) <= at(hi)


# --- v1-ctx.2: reachability, L0 ceiling, effective impact ---------------------------

from riskgraph.modules.risk import EffectiveImpact  # noqa: E402


def _reach(tier: str, confidence: str = "medium") -> Observed:
    return Observed(tier, "reachability", confidence, {"importers": ["app.py"]})


def test_reachability_sets_r() -> None:
    base = ScoreInput(S.SCA, V.HIGH, epss=0.05, cvss_impact=5.9)
    plain = score(base)
    by_tier = {
        t: score(ScoreInput(S.SCA, V.HIGH, epss=0.05, cvss_impact=5.9, reachability=_reach(t)))
        for t in ("L2", "L1", "L0")
    }
    assert by_tier["L2"].score > plain.score > by_tier["L1"].score > by_tier["L0"].score
    r = by_tier["L0"].factor("R")
    assert r is not None and (r.value, r.source, r.raw_value) == (0.1, "reachability", "L0")
    unknown = score(
        ScoreInput(S.SCA, V.HIGH, epss=0.05, cvss_impact=5.9, reachability=_reach("unknown", "low"))
    )
    assert unknown.score == plain.score  # unknown tier = the old default


def test_reachability_ignored_for_secrets_and_iac() -> None:
    s1 = score(ScoreInput(S.SECRET, V.HIGH))
    s2 = score(ScoreInput(S.SECRET, V.HIGH, reachability=_reach("L0", "high")))
    assert s1.score == s2.score


def test_l0_high_confidence_caps_priority_unless_kev() -> None:
    from riskgraph.modules.context import FindingContext

    loud = FindingContext(
        "app",
        Observed("internet_noauth", "manifest", "high"),
        Observed("credentials", "manifest", "high"),
        Observed("admin", "manifest", "high"),
        Observed("high", "manifest", "high"),
    )
    hot = ScoreInput(
        S.SAST, V.CRITICAL, category="command_injection", confidence="HIGH", context=loud
    )
    assert score(hot).priority is Priority.CRITICAL
    sca = ScoreInput(
        S.SCA,
        V.CRITICAL,
        epss=0.9,
        cvss_impact=6.0,
        context=loud,
        reachability=_reach("L0", "high"),
    )
    capped = score(sca)
    assert capped.priority is Priority.MEDIUM
    assert capped.overrides[-1]["rule"] == "not_imported_ceiling_medium"
    medium_conf = score(
        ScoreInput(
            S.SCA,
            V.CRITICAL,
            epss=0.9,
            cvss_impact=6.0,
            context=loud,
            reachability=_reach("L0", "medium"),
        )
    )
    assert not any(o["rule"] == "not_imported_ceiling_medium" for o in medium_conf.overrides)
    kev = score(
        ScoreInput(
            S.SCA,
            V.CRITICAL,
            kev=True,
            cvss_impact=6.0,
            context=loud,
            reachability=_reach("L0", "high"),
        )
    )
    assert kev.priority.rank >= Priority.HIGH.rank  # exploited in the wild wins


def test_effective_impact_raises_never_lowers() -> None:
    base = ScoreInput(S.SAST, V.MEDIUM, category="sql_injection")
    plain = score(base)
    up = score(
        ScoreInput(
            S.SAST,
            V.MEDIUM,
            category="sql_injection",
            effective_impact=EffectiveImpact(0.9, "p", "data_store:db", 0.5),
        )
    )
    assert up.score == pytest.approx(plain.score * 0.9 / plain.impact, abs=0.02)
    assert up.effective_impact == 0.9 and up.factor("I*") is not None
    low = score(
        ScoreInput(
            S.SAST,
            V.MEDIUM,
            category="sql_injection",
            effective_impact=EffectiveImpact(0.1, "p", "x", 0.1),
        )
    )
    assert low.score == plain.score and low.effective_impact is None


def test_exploit_likelihood_is_geomean_of_e_and_r() -> None:
    r = score(ScoreInput(S.SCA, V.HIGH, epss=0.01, cvss_impact=5.9, reachability=_reach("L2")))
    assert r.exploit_likelihood == pytest.approx(math.sqrt(0.5 * 0.8))
