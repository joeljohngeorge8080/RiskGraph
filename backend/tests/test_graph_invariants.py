"""Security-graph invariants (blueprint §12), on fixed and on random manifests (P9)."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from riskgraph.modules.context import parse_manifest
from riskgraph.modules.evidence import Assurance, Relationship
from riskgraph.modules.graph import GraphFinding, analyze
from riskgraph.modules.graph.attack import (
    INTERNET,
    REPOSITORY,
    UNKNOWN_IDENTITY,
    GraphInvariantError,
    invariant_violations,
)
from riskgraph.shared.vocabulary import SourceType as S

from tests.test_attack_paths import FINDINGS, MANIFEST, _manifest

NO_RUNS_AS = """
version: 1
services:
  - {name: web, path: web/, exposure: internet}
  - {name: api, path: api/, exposure: internal, runs_as: api-role}
identities:
  - {name: api-role, privilege: admin}
"""


def test_the_fixture_graph_satisfies_every_invariant() -> None:
    a = analyze(_manifest(MANIFEST), FINDINGS)
    assert invariant_violations(a.nodes, a.edges) == []


def test_a_service_without_runs_as_gets_the_unknown_identity() -> None:
    a = analyze(_manifest(NO_RUNS_AS), [])
    runs_as = [e for e in a.edges if e.kind == "RUNS_AS"]
    assert {(e.source, e.target) for e in runs_as} == {
        ("service:web", UNKNOWN_IDENTITY),
        ("service:api", "identity:api-role"),
    }
    unknown = a.nodes[UNKNOWN_IDENTITY]
    assert unknown["properties"]["privilege"] is None and unknown["properties"]["synthetic"]


def test_a_secret_outside_every_service_hangs_off_the_repository() -> None:
    secret = GraphFinding(
        0, None, S.SECRET, secret_family="aws", credential_p=0.9, title="k", evidence=("k",)
    )
    a = analyze(_manifest(NO_RUNS_AS), [secret])
    ins = [e for e in a.edges if e.target == "credential:0"]
    assert [(e.source, e.kind) for e in ins] == [(REPOSITORY, "CONTAINS_SECRET")]
    assert invariant_violations(a.nodes, a.edges) == []


def test_synthetic_nodes_never_create_paths() -> None:
    # neither the unknown identity nor the repository is a source or a sink
    a = analyze(_manifest(NO_RUNS_AS), [])
    assert a.paths == [] and a.exposed_by_design == 0


def test_violations_are_reported() -> None:
    nodes = {
        INTERNET: {"key": INTERNET, "kind": "internet", "label": "Internet", "properties": {}},
        "service:a": {"key": "service:a", "kind": "service", "label": "a", "properties": {}},
        "credential:1": {
            "key": "credential:1",
            "kind": "credential",
            "label": "c",
            "properties": {},
        },
    }
    v = Assurance.VERIFIED
    edges = [
        Relationship("service:a", INTERNET, "CONNECTS_TO", v, ("decl",)),
        Relationship("service:a", "ghost", "EXPLOIT", v, ("decl",), 0.5),  # no finding
    ]
    found = invariant_violations(nodes, edges)
    assert any("internet has in-edges" in v for v in found)
    assert any("service:a has 0 RUNS_AS" in v for v in found)
    assert any("credential:1 has 0 CONTAINS_SECRET" in v for v in found)
    assert any("unknown node ghost" in v for v in found)
    assert any("EXPLOIT service:a -> ghost has no finding evidence" in v for v in found)


def test_the_builder_refuses_a_broken_graph(monkeypatch: pytest.MonkeyPatch) -> None:
    import riskgraph.modules.graph.attack as attack

    monkeypatch.setattr(attack, "invariant_violations", lambda nodes, edges: ["boom"])
    with pytest.raises(GraphInvariantError, match="boom"):
        analyze(_manifest(MANIFEST), FINDINGS)


NAMES = st.sampled_from(["a", "b", "c", "d"])


@st.composite
def manifests(draw: st.DrawFn) -> str:
    services = draw(st.lists(NAMES, min_size=1, max_size=4, unique=True))
    idents = draw(st.lists(st.sampled_from(["r1", "r2"]), max_size=2, unique=True))
    lines = ["version: 1", "services:"]
    for i, s in enumerate(services):
        exposure = draw(st.sampled_from(["internet", "internal", "isolated"]))
        runs = draw(st.sampled_from([None, *idents])) if idents else None
        conn = draw(st.lists(st.sampled_from([*services, "db"]), max_size=2, unique=True))
        conn = [c for c in conn if c != s]
        lines.append(
            f"  - {{name: {s}, path: p{i}/, exposure: {exposure}"
            + (f", runs_as: {runs}" if runs else "")
            + (f", connects_to: [{', '.join(conn)}]" if conn else "")
            + "}"
        )
    if idents:
        lines.append("identities:")
        for r in idents:
            priv = draw(st.sampled_from(["limited", "elevated", "admin"]))
            lines.append(
                f"  - {{name: {r}, privilege: {priv}, can_access: [db], credentials: [aws]}}"
            )
    lines += ["data_stores:", "  - {name: db, sensitivity: pii}"]
    return "\n".join(lines) + "\n"


@settings(max_examples=150, deadline=None)
@given(
    text=manifests(),
    findings=st.lists(
        st.tuples(
            st.sampled_from([None, "a", "b", "c", "d"]),
            st.sampled_from([S.SCA, S.SAST, S.SECRET]),
            st.floats(0.05, 1.0),
            st.sampled_from(["L0", "L1", "L2", "L3"]),
        ),
        max_size=8,
    ),
)
def test_invariants_hold_on_random_manifests(text: str, findings: list[tuple]) -> None:  # type: ignore[type-arg]
    result = parse_manifest(text)
    assert result.status == "valid", (text, result.warnings)
    m = result.manifest
    assert m is not None
    names = {s.name for s in m.services}
    graph_findings = [
        GraphFinding(
            i,
            svc if svc in names else None,
            kind,
            exploit_p=p if kind is not S.SECRET else 0.0,
            tier=tier,
            secret_family="aws" if kind is S.SECRET else None,
            credential_p=0.9 if kind is S.SECRET else 0.0,
            public_secret=kind is S.SECRET,
            title=f"f{i}",
            evidence=(f"e{i}",),
        )
        for i, (svc, kind, p, tier) in enumerate(findings)
    ]
    a = analyze(m, graph_findings)  # raises GraphInvariantError on a violation
    for path in a.paths:
        assert path.nodes[0] in {INTERNET} | {f"credential:{f.index}" for f in graph_findings}
        assert 0 < path.probability <= 1 and path.hops <= 8
        assert REPOSITORY not in path.nodes[1:] and path.sink != UNKNOWN_IDENTITY


def test_to_networkx_keeps_the_most_probable_parallel_edge() -> None:
    from dataclasses import dataclass
    from math import inf, log

    from riskgraph.modules.graph import to_networkx

    @dataclass
    class R:
        key: str = ""
        kind: str = ""
        source: str = ""
        target: str = ""
        probability: float | None = None

    g = to_networkx(
        [R(key="a", kind="service"), R(key="b", kind="service")],
        [
            R(source="a", target="b", kind="EXPLOIT", probability=0.2),
            R(source="a", target="b", kind="EXPLOIT", probability=0.8),
            R(source="b", target="a", kind="CONNECTS_TO", probability=None),
        ],
    )
    assert g.edges["a", "b"]["p"] == 0.8 and g.edges["a", "b"]["w"] == pytest.approx(-log(0.8))
    assert g.edges["b", "a"]["w"] == inf  # kept for neighbourhoods, never on a path
