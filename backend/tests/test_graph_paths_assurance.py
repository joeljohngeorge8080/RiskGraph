"""Assurance-aware paths (X3 part 2, ADR-0020): hypotheses never change a score, a path is
as assured as its weakest edge, and every hypothesis names the evidence it lacks."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from riskgraph.modules.context import parse_manifest
from riskgraph.modules.evidence import Assurance, min_assurance
from riskgraph.modules.graph import GraphFinding, analyze
from riskgraph.modules.risk.tables import P_VALUES
from riskgraph.shared.vocabulary import SourceType as S

from tests.test_attack_paths import _manifest
from tests.test_graph_invariants import manifests

VER, INF, HYP = Assurance.VERIFIED, Assurance.INFERRED, Assurance.HYPOTHESIS

ADMIN_BEHIND_WEB = """
version: 1
services:
  - {name: web, path: web/, exposure: internet, runs_as: ops}
identities:
  - {name: ops, privilege: admin, credentials: [aws]}
"""


def _sqli(index: int = 0, p: float = 0.3, tier: str = "L2") -> GraphFinding:
    return GraphFinding(
        index, "web", S.SAST, exploit_p=p, tier=tier, title=f"sqli {index}", evidence=(f"e{index}",)
    )


def _aws_key(index: int, p: float = 0.9) -> GraphFinding:
    return GraphFinding(
        index,
        None,
        S.SECRET,
        secret_family="aws",
        credential_p=p,
        public_secret=True,
        title=f"aws key {index}",
        evidence=(f"k{index}",),
        file=f"keys/{index}.env",
        line=1,
    )


def test_hypothesis_paths_cannot_crowd_an_inferred_path_out() -> None:
    m = _manifest(ADMIN_BEHIND_WEB)
    alone = analyze(m, [_sqli()])
    assert 0 in alone.effective
    # three family-matched keys make three cheaper hypothesis paths to the same sink
    crowded = analyze(m, [_sqli(), _aws_key(1), _aws_key(2), _aws_key(3)])
    assert crowded.effective.keys() == alone.effective.keys()
    assert crowded.effective[0] == alone.effective[0]
    kept = [p for p in crowded.paths if p.assurance is not HYP]
    assert [p.nodes for p in kept] == [p.nodes for p in alone.paths]
    assert sum(p.assurance is HYP for p in crowded.paths) == 3


def test_a_more_exploitable_hypothesis_does_not_take_the_edge_from_an_inferred_finding() -> None:
    m = _manifest(ADMIN_BEHIND_WEB)
    alone = analyze(m, [_sqli()])
    # an L1 finding with a higher p sets the stored edge (and makes it a hypothesis) ...
    both = analyze(m, [_sqli(), _sqli(1, p=0.9, tier="L1")])
    [edge] = [e for e in both.edges if e.kind == "EXPLOIT"]
    assert edge.assurance is HYP and edge.p == 0.9
    # ... but the inferred finding keeps the effective impact it had without it
    assert both.effective.get(0) == alone.effective.get(0)
    assert 1 not in both.effective


def test_hypothesis_edges_say_what_would_prove_them() -> None:
    m = _manifest(ADMIN_BEHIND_WEB)
    image_pkg = GraphFinding(
        2, "web", S.SCA, exploit_p=0.5, tier="n_a", title="openssl CVE", evidence=("i",)
    )
    a = analyze(m, [_sqli(1, p=0.4, tier="unknown"), _aws_key(0), image_pkg])
    hyp = [p for p in a.paths if p.assurance is HYP]
    needed = {e["kind"]: e["missing"] for p in hyp for e in p.edges if "missing" in e}
    assert needed["AUTHENTICATES_AS"] == (
        "no manifest link proves this aws key authenticates as ops (an `owns:` entry would)"
    )
    assert needed["EXPLOIT"].startswith("no import or call chain shows")
    for p in a.paths:
        for e in p.edges:
            assert ("missing" in e) == (e["assurance"] == "hypothesis"), e


def _random_findings(draw: st.DrawFn, names: set[str], start: int) -> list[GraphFinding]:
    rows = draw(
        st.lists(
            st.tuples(
                st.sampled_from(sorted(names)),
                st.sampled_from([S.SCA, S.SAST]),
                st.floats(0.05, 1.0),
                st.sampled_from(["L2", "L3"]),
            ),
            max_size=5,
        )
    )
    return [
        GraphFinding(i, svc, kind, exploit_p=p, tier=tier, title=f"f{i}", evidence=(f"e{i}",))
        for i, (svc, kind, p, tier) in enumerate(rows, start)
    ]


@st.composite
def scenarios(draw: st.DrawFn) -> tuple[str, list[GraphFinding], list[GraphFinding]]:
    text = draw(manifests())
    m = parse_manifest(text).manifest
    assert m is not None
    names = {s.name for s in m.services}
    base = _random_findings(draw, names, 0)
    extra_rows = draw(
        st.lists(
            st.tuples(
                st.sampled_from([*sorted(names), None]),
                st.booleans(),  # a family-matched public key, or an L1/unknown code finding
                st.floats(0.05, 1.0),
                st.sampled_from(["L1", "unknown"]),
            ),
            min_size=1,
            max_size=6,
        )
    )
    extra = []
    for i, (svc, is_key, p, tier) in enumerate(extra_rows, 100):
        if is_key or svc is None:
            extra.append(_aws_key(i, p))
        else:
            extra.append(
                GraphFinding(i, svc, S.SAST, exploit_p=p, tier=tier, title=f"h{i}", evidence=("h",))
            )
    return text, base, extra


@settings(max_examples=200, deadline=None)
@given(scenario=scenarios())
def test_hypothesis_only_facts_never_change_a_score(
    scenario: tuple[str, list[GraphFinding], list[GraphFinding]],
) -> None:
    text, base, extra = scenario
    m = _manifest(text)
    before = analyze(m, base)
    after = analyze(m, [*base, *extra])
    for f in base:
        assert after.effective.get(f.index) == before.effective.get(f.index), f
    # a key whose only link is a family match never raises its own score either
    for f in extra:
        if f.source_type is S.SECRET:
            assert f.index not in after.effective


@settings(max_examples=150, deadline=None)
@given(scenario=scenarios())
def test_a_path_is_as_assured_as_its_weakest_edge(
    scenario: tuple[str, list[GraphFinding], list[GraphFinding]],
) -> None:
    text, base, extra = scenario
    a = analyze(_manifest(text), [*base, *extra])
    raising = {e.path for e in a.effective.values()}
    for p in a.paths:
        assert p.assurance is min_assurance(Assurance(e["assurance"]) for e in p.edges)
        if p.assurance is HYP:
            assert p.label not in raising or any(
                q.label == p.label and q.assurance is not HYP for q in a.paths
            )


LINKED = """
version: 1
services:
  - {name: web, path: web/, exposure: internet, runs_as: ops}
identities:
  - name: ops
    privilege: admin
    credentials: [aws]
    owns:
      - {file: keys/1.env, family: aws}
      - {file: keys/2.env, line: 7}
"""


def test_a_manifest_link_makes_the_credential_edge_verified() -> None:
    a = analyze(_manifest(LINKED), [_aws_key(1), _aws_key(2), _aws_key(3)])
    auth = {e.source: e for e in a.edges if e.kind == "AUTHENTICATES_AS"}
    # one edge per key and identity: key 1 is linked, key 2's line does not match, key 3
    # only matches the family
    assert {k: e.assurance for k, e in auth.items()} == {
        "credential:1": VER,
        "credential:2": HYP,
        "credential:3": HYP,
    }
    linked = next(a.evidence[i] for i in auth["credential:1"].evidence_ids if i in a.evidence)
    assert linked.facts["owns"] == "keys/1.env" and linked.facts["family"] == "aws"
    # the verified path raises the linked key's score; the others stay paths to verify
    assert a.effective[1].value == pytest.approx(P_VALUES["admin"])  # I(sink) · P / p
    assert 2 not in a.effective and 3 not in a.effective
    verified = [p for p in a.paths if p.assurance is VER]
    assert [p.label for p in verified] == ["aws key 1 → ops"]


def test_a_link_with_the_wrong_family_proves_nothing() -> None:
    text = LINKED.replace("{file: keys/1.env, family: aws}", "{file: keys/1.env, family: github}")
    a = analyze(_manifest(text), [_aws_key(1)])
    [auth] = [e for e in a.edges if e.kind == "AUTHENTICATES_AS"]
    assert auth.assurance is HYP and 1 not in a.effective


@pytest.mark.parametrize(
    "entry",
    [
        "{file: /etc/passwd}",
        "{file: ../outside.env}",
        "{file: keys/}",
        "{file: ''}",
        "{file: keys/1.env, family: nope}",
        "{file: keys/1.env, line: 0}",
        "{file: keys/1.env, owner: me}",
    ],
)
def test_hostile_or_odd_links_are_rejected(entry: str) -> None:
    text = f"""
version: 1
identities:
  - {{name: ops, owns: [{entry}]}}
"""
    assert parse_manifest(text).status == "invalid"


def test_links_are_normalized_like_finding_paths() -> None:
    text = """
version: 1
identities:
  - {name: ops, owns: [{file: ./keys//1.env}]}
"""
    m = parse_manifest(text).manifest
    assert m is not None and m.identities[0].owns[0].file == "keys/1.env"
