"""Evaluation metrics against hand-computed values, the baselines, and determinism (X0)."""

from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path

import pytest
from evaluation.baselines import m1_key, m2_key, rank
from evaluation.metrics import (
    _percentile,
    average_precision,
    bootstrap,
    effort_at,
    ndcg_at,
    precision_at,
    recall_at,
)
from evaluation.scenarios import FAKE_AWS_KEY_ID, SCENARIOS

T, F = True, False
REL = [T, F, T, F, F]  # important at ranks 1 and 3


def test_precision_divides_by_k_even_past_the_end() -> None:
    assert precision_at(REL, 1) == 1.0
    assert precision_at(REL, 3) == pytest.approx(2 / 3)
    assert precision_at(REL, 5) == 0.4
    assert precision_at(REL, 10) == 0.2
    with pytest.raises(ValueError):
        precision_at(REL, 0)


def test_recall() -> None:
    assert recall_at(REL, 1) == 0.5
    assert recall_at(REL, 3) == 1.0
    assert recall_at([F, F], 5) is None


def test_ndcg_by_hand() -> None:
    # DCG = 1/log2(2) + 1/log2(4) = 1.5; IDCG = 1 + 1/log2(3)
    assert ndcg_at(REL, 5) == pytest.approx(1.5 / (1 + 1 / math.log2(3)))
    assert ndcg_at([T, T, F], 2) == 1.0
    assert ndcg_at([F, F, F, T], 3) == 0.0  # an important finding exists, none in the top 3
    assert ndcg_at([F, F, F, T], 4) == pytest.approx(1 / math.log2(5))
    assert ndcg_at([F, F], 10) is None


def test_average_precision_by_hand() -> None:
    assert average_precision(REL) == pytest.approx((1 / 1 + 2 / 3) / 2)
    assert average_precision([F, F, F, T]) == 0.25
    assert average_precision([F]) is None


def test_effort_to_ninety_percent_recall() -> None:
    assert effort_at(REL) == 3  # ceil(0.9 * 2) = 2 hits
    assert effort_at([T] * 9 + [F] + [T]) == 9  # ceil(0.9 * 10) = 9, exactly
    assert effort_at([F, F, T]) == 3
    assert effort_at([F]) is None


def test_percentile_interpolates_like_numpy() -> None:
    assert _percentile([1.0, 2.0, 3.0, 4.0], 0.5) == 2.5
    assert _percentile([1.0, 2.0, 3.0, 4.0], 0.025) == pytest.approx(1.075)
    assert _percentile([7.0], 0.975) == 7.0


def test_bootstrap_is_seeded_and_reports_undefined_draws() -> None:
    items = [T, F, F, T, F, F, F, F]
    a = bootstrap(items, lambda s: precision_at(s, 2), resamples=200)
    b = bootstrap(items, lambda s: precision_at(s, 2), resamples=200)
    assert a == b and a.value == 0.5
    assert a.low is not None and a.high is not None and a.low <= a.high
    none = bootstrap([F, F], average_precision, resamples=50)
    assert none.value is None and none.low is None and none.undefined == 50


@dataclass(frozen=True)
class _F:
    fingerprint: str
    severity: str = "medium"
    cvss_base: float | None = None
    epss: float | None = None
    score: float = 0.0
    priority_rank: int = 0


def test_m1_uses_cvss_then_severity_equivalent_then_fingerprint() -> None:
    fs = [
        _F("c", severity="critical"),  # 9.0 equivalent
        _F("a", cvss_base=9.8),
        _F("b", severity="high"),  # 7.5
        _F("d", cvss_base=7.5),  # ties with b, loses on fingerprint
    ]
    assert [f.fingerprint for f in rank(fs, "M1 CVSS-only")] == ["a", "c", "b", "d"]
    assert m1_key(_F("x", severity="info")) == (-0.0, "x")


def test_m2_multiplies_by_the_epss_transform_and_treats_missing_epss_as_neutral() -> None:
    likely = _F("a", cvss_base=6.0, epss=0.5)  # E = (log10(0.5) + 4) / 4 ≈ 0.925
    unlikely = _F("b", cvss_base=9.8, epss=0.0001)  # E = floor 0.05
    unknown = _F("c", severity="high")  # 7.5 * 0.5
    assert m2_key(unknown)[0] == pytest.approx(-0.375)
    assert [f.fingerprint for f in rank([unlikely, unknown, likely], "M2 CVSS+EPSS")] == [
        "a",
        "c",
        "b",
    ]


def test_m4_ranks_like_the_product_priority_first() -> None:
    fs = [_F("a", score=90, priority_rank=3), _F("b", score=40, priority_rank=4), _F("c")]
    assert [f.fingerprint for f in rank(fs, "M4 RiskGraph")] == ["b", "a", "c"]


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_scenario_build_is_byte_identical(name: str, tmp_path: Path) -> None:
    first = SCENARIOS[name].build(tmp_path / "one")
    second = SCENARIOS[name].build(tmp_path / "two")
    files = sorted(p.relative_to(first) for p in first.rglob("*") if p.is_file())
    assert files == sorted(p.relative_to(second) for p in second.rglob("*") if p.is_file())
    assert "riskgraph.yaml" in {str(p) for p in files}
    for rel in files:
        assert (first / rel).read_bytes() == (second / rel).read_bytes()


def test_no_recorded_fixture_holds_the_fake_key() -> None:
    fixtures = Path(__file__).resolve().parents[1] / "evaluation" / "fixtures"
    for report in fixtures.rglob("*.json"):
        assert FAKE_AWS_KEY_ID not in report.read_text(), report
