"""The evidence and assurance contract (ADR-0017, expansion X1)."""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from riskgraph.modules.evidence import (
    MAX_STEPS,
    Assurance,
    Evidence,
    FlowStep,
    RawRef,
    Relationship,
    make_evidence,
    min_assurance,
)
from riskgraph.modules.normalization import Location

T0 = dt.datetime(2026, 10, 25, 12, 0, tzinfo=dt.UTC)
T1 = dt.datetime(2026, 10, 26, 9, 30, tzinfo=dt.UTC)


def _ev(**kw: object) -> Evidence:
    args: dict[str, object] = {
        "producer": "riskgraph.manifest@1",
        "kind": "declaration",
        "assurance": Assurance.VERIFIED,
        "confidence": "high",
        "locations": (Location("riskgraph.yaml"),),
        "facts": {"service": "api", "exposure": "internet"},
        "observed_at": T0,
    }
    args.update(kw)
    return make_evidence(**args)  # type: ignore[arg-type]


def test_id_is_a_stable_hash_of_what_was_observed_not_when() -> None:
    a = _ev()
    assert len(a.id) == 64 and int(a.id, 16) >= 0
    assert _ev(observed_at=T1).id == a.id  # re-analysis keeps the id
    assert _ev(data_as_of=T1).id == a.id
    assert _ev(facts={"exposure": "internet", "service": "api"}).id == a.id  # key order
    assert _ev(facts={"service": "web", "exposure": "internet"}).id != a.id
    assert _ev(producer="riskgraph.manifest@2").id != a.id
    assert _ev(kind="rbac_binding").id != a.id
    assert _ev(assurance=Assurance.INFERRED).id != a.id  # a different claim


def test_raw_ref_does_not_change_the_id_but_is_kept() -> None:
    ref = RawRef(uuid.uuid4(), "")
    with_ref = _ev(raw=ref)
    assert with_ref.id == _ev().id and with_ref.raw == ref


def test_facts_accept_scalars_and_short_string_lists_only() -> None:
    ok = _ev(
        facts={
            "tier": "L2",
            "hops": 3,
            "live": True,
            "p": 0.5,
            "none": None,
            "chain": ["a.py", "b.py"],
        }
    )
    assert ok.facts["chain"] == ("a.py", "b.py")  # stored immutably
    with pytest.raises(ValueError, match="fact"):
        _ev(facts={"nested": {"a": 1}})
    with pytest.raises(ValueError, match="fact"):
        _ev(facts={"mixed": ["a", 1]})
    with pytest.raises(ValueError, match="fact"):
        _ev(facts={"x" * 65: 1})


def test_long_values_are_clipped_not_rejected() -> None:
    e = _ev(facts={"chain": [f"f{i}.py" for i in range(100)], "title": "t" * 1000})
    chain = e.facts["chain"]
    assert isinstance(chain, tuple) and len(chain) == 20
    assert len(str(e.facts["title"])) == 200


def test_steps_are_capped() -> None:
    steps = tuple(FlowStep(Location(f"f{i}.py", i), f"step {i}") for i in range(MAX_STEPS + 5))
    assert len(_ev(steps=steps).steps) == MAX_STEPS


def test_confidence_and_kind_are_validated() -> None:
    with pytest.raises(ValueError, match="confidence"):
        _ev(confidence="certain")
    with pytest.raises(ValueError, match="kind"):
        _ev(kind="vibes")


def test_assurance_orders_verified_over_inferred_over_hypothesis() -> None:
    v, i, h = Assurance.VERIFIED, Assurance.INFERRED, Assurance.HYPOTHESIS
    assert v.rank > i.rank > h.rank
    assert min_assurance([v, i, v]) is i
    assert min_assurance([v, h, i]) is h
    with pytest.raises(ValueError):
        min_assurance([])


def test_a_relationship_needs_evidence() -> None:
    Relationship("internet", "service:api", "EXPOSES", Assurance.VERIFIED, ("a" * 64,))
    with pytest.raises(ValueError, match="evidence"):
        Relationship("internet", "service:api", "EXPOSES", Assurance.VERIFIED, ())
