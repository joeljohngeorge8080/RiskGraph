"""Risk model v2 (X6, ADR-0024): the new factor tables, reduction to v1, monotonicity."""

from __future__ import annotations

import math
from itertools import pairwise

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from riskgraph.modules.context import FindingContext, Observed
from riskgraph.modules.risk import EffectiveImpact, ScoreInput, score
from riskgraph.modules.risk import tables as t
from riskgraph.shared.vocabulary import Priority
from riskgraph.shared.vocabulary import Severity as V
from riskgraph.shared.vocabulary import SourceType as S


def _obs(label: str) -> Observed:
    return Observed(label, "manifest", "high")


FULL = FindingContext("api", _obs("internet_noauth"), _obs("pii"), _obs("admin"), _obs("high"))


# --- container image packages: R = 0.5, not assessable --------------------------------


def test_an_image_package_has_r_not_assessable() -> None:
    r = score(ScoreInput(S.SCA, V.HIGH, epss=0.05, cvss_impact=5.9, image_package=True))
    reach = r.factor("R")
    assert reach is not None and reach.applicable
    assert (reach.value, reach.source, reach.raw_value) == (0.5, "not_assessable", "n_a")
    # a repository dependency with nothing known keeps the unknown 0.6
    plain = score(ScoreInput(S.SCA, V.HIGH, epss=0.05, cvss_impact=5.9))
    assert plain.factor("R").value == t.UNKNOWN_REACHABILITY  # type: ignore[union-attr]
    # an observation cannot apply to an image package: its code is not analysed
    seen = ScoreInput(
        S.SCA,
        V.HIGH,
        epss=0.05,
        image_package=True,
        reachability=Observed("L3", "reachability", "high"),
    )
    assert score(seen).factor("R").value == 0.5  # type: ignore[union-attr]


# --- taint: E by CWE and confidence ----------------------------------------------------


@pytest.mark.parametrize("cwe", sorted(t.E_TAINT))
def test_a_tier1_flow_takes_e_from_the_taint_table(cwe: str) -> None:
    for confidence, value in t.E_TAINT[cwe].items():
        r = score(
            ScoreInput(
                S.SAST,
                V.MEDIUM,  # SAST row 0.45 (+0.1 for HIGH): below every taint row
                category="injection",
                confidence=confidence,
                taint_cwe=cwe,
                taint_confidence=confidence,
            )
        )
        e = r.factor("E")
        assert e is not None and e.source == "taint_tier1" and e.value == value
        assert e.raw_value == f"{cwe},analysis=intraprocedural,confidence={confidence}"
        assert e.confidence == "medium"  # inferred: a rule applied to parsed code


def test_a_flow_never_lowers_e_and_an_unknown_class_or_confidence_changes_nothing() -> None:
    for sev in V:
        for conf in (None, "LOW", "MEDIUM", "HIGH"):
            plain = score(ScoreInput(S.SAST, sev, category="ssrf", confidence=conf))
            flow = score(
                ScoreInput(
                    S.SAST,
                    sev,
                    category="ssrf",
                    confidence=conf,
                    taint_cwe="CWE-918",
                    taint_confidence=conf,
                )
            )
            assert flow.score >= plain.score
    # a CWE outside the catalogue, or a LOW-confidence rule: the SAST row stands
    base = score(ScoreInput(S.SAST, V.HIGH, category="xss"))
    for cwe, conf in (("CWE-79", "HIGH"), ("CWE-89", "LOW"), ("CWE-89", None)):
        other = score(
            ScoreInput(S.SAST, V.HIGH, category="xss", taint_cwe=cwe, taint_confidence=conf)
        )
        assert other == base


# --- runtime end-of-life: E by time past the end of support ----------------------------


@pytest.mark.parametrize(
    ("days", "expected"),
    [(None, 0.5), (0, 0.4), (364, 0.4), (365, 0.5), (1094, 0.5), (1095, 0.6), (9000, 0.6)],
)
def test_eol_exploitability_grows_with_time_past_end_of_support(
    days: int | None, expected: float
) -> None:
    r = score(ScoreInput(S.RUNTIME, V.HIGH, category="runtime_eol", eol_age_days=days))
    e, t_ = r.factor("E"), r.factor("T")
    assert e is not None and e.value == expected and e.source == "runtime_eol"
    assert e.raw_value == ("eol=true" if days is None else f"eol_age_days={days}")
    assert t_ is not None and t_.value == t.T_RUNTIME_EOL


def test_eol_without_a_date_scores_as_the_interim_model_did() -> None:
    # ADR-0018's interim factors were E 0.5, T 0.6: an EOL flag with no date keeps them
    r = score(ScoreInput(S.RUNTIME, V.HIGH, category="runtime_eol"))
    assert (r.factor("E").value, r.factor("T").value) == (0.5, 0.6)  # type: ignore[union-attr]


def test_a_negative_age_is_treated_as_unknown() -> None:
    # a feed date after the snapshot time (clock skew, a corrected feed): not "recent"
    r = score(ScoreInput(S.RUNTIME, V.HIGH, eol_age_days=-30))
    assert r.factor("E").value == 0.5  # type: ignore[union-attr]


# --- authorization findings ------------------------------------------------------------


@given(
    severity=st.sampled_from(list(V)),
    context=st.sampled_from([None, FULL]),
    effective=st.floats(0.0, 1.0),
)
def test_an_authz_hypothesis_is_never_above_low_in_v2(
    severity: V, context: FindingContext | None, effective: float
) -> None:
    r = score(
        ScoreInput(
            S.AUTHZ,
            severity,
            assurance="hypothesis",
            context=context,
            effective_impact=EffectiveImpact(effective, "p", "s", effective),
        )
    )
    assert r.priority is Priority.LOW and r.score < 20.0
    assert all(o["rule"] == "hypothesis_ceiling_low" for o in r.overrides)


def test_authz_e_table_is_below_the_sast_row_for_every_severity() -> None:
    for sev in V:
        assert t.FLOOR <= t.E_AUTHZ_INFERRED[sev] <= t.E_SAST[sev]


# --- reduction: without the new inputs, v2 is v1-ctx.3 ---------------------------------

V1_SOURCES = {
    "E": {"kev", "epss", "cvss_exploitability", "severity", "secret_rule", "sast_severity"}
    | {"runtime_eol", "iac_family"},
    "R": {"not_applicable", "default_unknown", "reachability", "manifest"},
}
LEVELS = ["isolated", "internal", "internet_auth", "internet_noauth"]


@st.composite
def v1_inputs(draw: st.DrawFn) -> ScoreInput:
    source = draw(st.sampled_from([S.SCA, S.SAST, S.SECRET, S.IAC, S.RUNTIME]))
    tier = draw(st.sampled_from([None, "L0", "L1", "L2", "L3"]))
    ctx = draw(
        st.sampled_from([None, FULL, FindingContext("x", _obs(draw(st.sampled_from(LEVELS))))])
    )
    return ScoreInput(
        source,
        draw(st.sampled_from(list(V))),
        category=draw(st.sampled_from(["other", "ssrf", "sql_injection", "auth"])),
        detected_by=tuple(draw(st.lists(st.sampled_from(["a", "b", "c"]), max_size=3))),
        cvss_impact=draw(st.none() | st.floats(0.0, 6.0)),
        epss=draw(st.none() | st.floats(1e-5, 1.0)),
        kev=draw(st.none() | st.booleans()),
        live_credential=draw(st.booleans()),
        confidence=draw(st.sampled_from([None, "LOW", "MEDIUM", "HIGH"])),
        iac_family=draw(st.sampled_from([None, "public", "hygiene"])),
        context=ctx,
        reachability=Observed(tier, "reachability", "high") if tier else None,
    )


def _v1_score(inp: ScoreInput) -> float:
    """§14 formula with the v1-ctx.3 tables, written out independently of model.py."""
    r = score(inp)
    by = {f.name: f for f in r.factors}
    likelihood = [by["E"].value, by["X"].value] + ([by["R"].value] if by["R"].applicable else [])
    lv = math.prod(likelihood) ** (1 / len(likelihood))
    iv = sum(by[n].value for n in "TDPC") / 4
    return round(min(100.0, 100 * lv * iv * by["K"].value), 2)


@settings(max_examples=500, deadline=None)
@given(inp=v1_inputs())
def test_reduction_without_new_inputs_v2_uses_only_v1_factors(inp: ScoreInput) -> None:
    r = score(inp)
    for name, allowed in V1_SOURCES.items():
        assert r.factor(name).source in allowed, (name, r.factor(name))  # type: ignore[union-attr]
    if inp.source_type is S.RUNTIME:
        assert (r.factor("E").value, r.factor("T").value) == (0.5, 0.6)  # type: ignore[union-attr]
    assert r.score == _v1_score(inp)


@settings(max_examples=300, deadline=None)
@given(inp=v1_inputs())
def test_absent_new_inputs_are_the_defaults(inp: ScoreInput) -> None:
    from dataclasses import replace

    explicit = replace(
        inp, image_package=False, taint_cwe=None, taint_confidence=None, eol_age_days=None
    )
    assert score(explicit) == score(inp)


# --- monotonicity over the new inputs (§14.7) -------------------------------------------

AGES = [0, 200, 365, 800, 1095, 5000]


@settings(max_examples=400, deadline=None)
@given(
    a=st.integers(0, len(AGES) - 2),
    ctx=st.sampled_from([None, FULL]),
)
def test_older_eol_never_scores_lower(a: int, ctx: FindingContext | None) -> None:
    younger = score(ScoreInput(S.RUNTIME, V.HIGH, eol_age_days=AGES[a], context=ctx))
    older = score(ScoreInput(S.RUNTIME, V.HIGH, eol_age_days=AGES[a + 1], context=ctx))
    assert older.score >= younger.score and older.priority.rank >= younger.priority.rank


@settings(max_examples=400, deadline=None)
@given(
    sev=st.sampled_from(list(V)),
    cwe=st.sampled_from(sorted(t.E_TAINT)),
    ctx=st.sampled_from([None, FULL]),
    tier=st.sampled_from([None, "L1", "L2", "L3"]),
)
def test_taint_confidence_medium_to_high_never_lowers(
    sev: V, cwe: str, ctx: FindingContext | None, tier: str | None
) -> None:
    reach = Observed(tier, "reachability", "medium") if tier else None

    def at(conf: str | None) -> ScoreInput:
        return ScoreInput(
            S.SAST, sev, taint_cwe=cwe, taint_confidence=conf, context=ctx, reachability=reach
        )

    ladder = [score(at(c)) for c in (None, "MEDIUM", "HIGH")]
    for lo, hi in pairwise(ladder):
        assert hi.score >= lo.score and hi.priority.rank >= lo.priority.rank


@settings(max_examples=300, deadline=None)
@given(sev=st.sampled_from(list(V)), ctx=st.sampled_from([None, FULL]), eff=st.floats(0.0, 1.0))
def test_authz_hypothesis_to_inferred_never_lowers(
    sev: V, ctx: FindingContext | None, eff: float
) -> None:
    path = EffectiveImpact(eff, "p", "s", eff)
    hyp = score(
        ScoreInput(S.AUTHZ, sev, assurance="hypothesis", context=ctx, effective_impact=path)
    )
    inf = score(ScoreInput(S.AUTHZ, sev, assurance="inferred", context=ctx, effective_impact=path))
    assert inf.score >= hyp.score and inf.priority.rank >= hyp.priority.rank


# --- wiring: what input_for reads from a merged finding --------------------------------

from riskgraph.modules.normalization import Location, RawFinding, merge  # noqa: E402
from riskgraph.modules.risk.service import input_for  # noqa: E402
from riskgraph.shared.vocabulary import ScannerName  # noqa: E402


def _raw(rule: str, cwe: str, **attrs: object) -> RawFinding:
    return RawFinding(
        scanner=ScannerName.SEMGREP,
        source_type=S.SAST,
        rule_id=rule,
        title=rule,
        severity=V.HIGH,
        location=Location("api/app.py", 12, 12),
        category="ssrf",
        cwe_ids=(cwe,),
        attrs=dict(attrs),
    )


def test_input_for_reads_the_taint_hit_even_under_a_generic_representative() -> None:
    from riskgraph.modules.normalization.families import TAINT_RULE_PREFIX

    generic = _raw("python.flask.security.injection.ssrf-requests", "CWE-918", confidence="LOW")
    flow = _raw(
        f"{TAINT_RULE_PREFIX}ssrf-python",
        "CWE-918",
        confidence="MEDIUM",
        analysis="intraprocedural",
    )
    (merged,) = merge([generic, flow])
    assert merged.representative.attrs.get("analysis") is None  # the generic rule leads
    inp = input_for(merged, None)
    assert (inp.taint_cwe, inp.taint_confidence) == ("CWE-918", "MEDIUM")
    # a related CWE is mapped to its class; no flow means no taint input
    (alone,) = merge([_raw("x", "CWE-77", confidence="HIGH", analysis="intraprocedural")])
    assert input_for(alone, None).taint_cwe == "CWE-78"
    (plain,) = merge([generic])
    assert (input_for(plain, None).taint_cwe, input_for(plain, None).image_package) == (None, False)


def _eol(**attrs: object) -> RawFinding:
    return RawFinding(
        scanner=ScannerName.RISKGRAPH,
        source_type=S.RUNTIME,
        rule_id="runtime-eol:python:3.8",
        title="Python 3.8 is end-of-life",
        severity=V.HIGH,
        location=Location(".python-version", 1, 1),
        category="runtime_eol",
        package={"name": "python", "version": "3.8", "ecosystem": "runtime"},
        attrs=dict(attrs),
    )


@pytest.mark.parametrize(
    ("attrs", "expected"),
    [
        ({"eol_date": "2024-10-07", "data_as_of": "2026-10-25T03:00:00+00:00"}, 748),
        ({"eol_date": None, "data_as_of": "2026-10-25T03:00:00+00:00"}, None),
        ({"eol_date": "2024-10-07"}, None),
        ({"eol_date": "not a date", "data_as_of": "2026-10-25T03:00:00+00:00"}, None),
        ({"eol_date": "2024-10-07", "data_as_of": 12}, None),
    ],
)
def test_input_for_takes_the_eol_age_from_the_feed_snapshot(
    attrs: dict[str, object], expected: int | None
) -> None:
    (merged,) = merge([_eol(**attrs)])
    assert input_for(merged, None).eol_age_days == expected


def test_input_for_marks_image_packages() -> None:
    raw = RawFinding(
        scanner=ScannerName.TRIVY,
        source_type=S.SCA,
        rule_id="CVE-2023-0001",
        title="openssl",
        severity=V.HIGH,
        location=Location("Dockerfile", 1, 1, "python:3.8-slim"),
        category="vulnerable_dependency",
        vulnerability_id="CVE-2023-0001",
        package={"name": "openssl", "version": "1.1", "image": "python:3.8-slim"},
    )
    (merged,) = merge([raw])
    inp = input_for(merged, None)
    assert inp.image_package and score(inp).factor("R").source == "not_assessable"  # type: ignore[union-attr]
