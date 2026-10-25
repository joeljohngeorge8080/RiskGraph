"""Every graph edge rests on evidence and carries an assurance level (ADR-0017, X1)."""

from __future__ import annotations

import datetime as dt

import pytest
from riskgraph.modules.evidence import Assurance, Relationship
from riskgraph.modules.graph import AttackAnalysis, GraphFinding, analyze
from riskgraph.modules.graph.attack import (
    UNKNOWN_IDENTITY,
    GraphInvariantError,
    exploit_assurance,
)
from riskgraph.shared.vocabulary import SourceType as S

from tests.test_attack_paths import FINDINGS, SCENARIO_E, _manifest
from tests.test_graph_invariants import NO_RUNS_AS

VER, INF, HYP = Assurance.VERIFIED, Assurance.INFERRED, Assurance.HYPOTHESIS


def _by_kind(a: AttackAnalysis, kind: str) -> list[Relationship]:
    return [e for e in a.edges if e.kind == kind]


def test_each_edge_kind_gets_the_documented_assurance() -> None:
    a = analyze(_manifest(), FINDINGS)
    for kind in ("EXPOSES", "RUNS_AS", "CONNECTS_TO", "CAN_ACCESS", "CONTAINS_SECRET"):
        assert {e.assurance for e in _by_kind(a, kind)} == {VER}, kind
    # the AWS key's family matches api-role's credentials list: nothing proves the link
    assert {e.assurance for e in _by_kind(a, "AUTHENTICATES_AS")} == {HYP}
    # both EXPLOIT edges rest on L2 findings: import-level reachability
    assert {e.assurance for e in _by_kind(a, "EXPLOIT")} == {INF}


def test_the_unknown_identity_edge_is_inferred() -> None:
    a = analyze(_manifest(NO_RUNS_AS), [])
    unknown = [e for e in _by_kind(a, "RUNS_AS") if e.target == UNKNOWN_IDENTITY]
    assert [e.assurance for e in unknown] == [INF]


@pytest.mark.parametrize(
    ("tier", "level"), [("L3", VER), ("L2", INF), ("L1", HYP), ("unknown", HYP), (None, HYP)]
)
def test_exploit_assurance_follows_the_reachability_tier(
    tier: str | None, level: Assurance
) -> None:
    assert exploit_assurance(tier) is level


def test_every_edge_names_evidence_that_exists() -> None:
    a = analyze(_manifest(), FINDINGS, manifest_file="riskgraph.yml")
    finding_evidence = {e for f in FINDINGS for e in f.evidence}
    for edge in a.edges:
        assert edge.evidence_ids
        assert set(edge.evidence_ids) <= set(a.evidence) | finding_evidence, edge
    for ev in a.evidence.values():
        assert ev.kind == "declaration" and ev.assurance is VER
        assert [loc.file for loc in ev.locations] == ["riskgraph.yml"]


def test_attack_edges_carry_their_findings_evidence() -> None:
    a = analyze(_manifest(), FINDINGS)
    [auth] = _by_kind(a, "AUTHENTICATES_AS")
    assert "e3" in auth.evidence_ids and auth.findings == (3,)
    # internet -> web rests on web's SQLi; the L0 CVE (finding 1) adds no evidence
    [web] = [e for e in _by_kind(a, "EXPLOIT") if e.target == "service:web"]
    assert "e0" in web.evidence_ids and "e1" not in web.evidence_ids


def test_the_builder_refuses_an_attack_edge_without_finding_evidence() -> None:
    bare = GraphFinding(0, "web", S.SAST, exploit_p=0.6, tier="L2", title="no evidence")
    with pytest.raises(GraphInvariantError, match="EXPLOIT internet -> service:web"):
        analyze(_manifest(), [bare])
    secret = GraphFinding(1, "web", S.SECRET, secret_family="aws", credential_p=0.9)
    with pytest.raises(GraphInvariantError, match="CONTAINS_SECRET"):
        analyze(_manifest(), [secret])


def test_a_path_is_as_assured_as_its_weakest_edge() -> None:
    a = analyze(_manifest(), FINDINGS)
    by = {p.label: p for p in a.paths}
    assert by["Internet → web → api → orders-db"].assurance is INF
    assert by["AWS key → api-role → orders-db"].assurance is HYP
    for path in a.paths:
        levels = [Assurance(e["assurance"]) for e in path.edges]
        assert path.assurance is min(levels, key=lambda x: x.rank)
    assert a.summary()["paths_by_assurance"] == {
        "inferred": sum(p.assurance is INF for p in a.paths),
        "hypothesis": sum(p.assurance is HYP for p in a.paths),
    }


def test_hypothesis_exploit_paths_are_listed_but_never_raise_a_score() -> None:
    weak = GraphFinding(
        0, "api", S.SAST, exploit_p=0.8, tier="unknown", title="maybe", evidence=("w",)
    )
    a = analyze(_manifest(SCENARIO_E), [weak])
    assert a.paths and all(p.assurance is HYP for p in a.paths)
    assert a.effective == {}


def test_a_verified_l3_path_still_raises_the_score() -> None:
    strong = GraphFinding(0, "api", S.SAST, exploit_p=0.8, tier="L3", title="ssrf", evidence=("s",))
    a = analyze(_manifest(SCENARIO_E), [strong])
    assert all(p.assurance is VER for p in a.paths)
    assert a.effective[0].value == pytest.approx(1.0)


def test_evidence_ids_are_stable_across_runs() -> None:
    first = analyze(_manifest(), FINDINGS, observed_at=dt.datetime(2026, 1, 1, tzinfo=dt.UTC))
    again = analyze(_manifest(), FINDINGS)
    assert [e.evidence_ids for e in first.edges] == [e.evidence_ids for e in again.edges]
