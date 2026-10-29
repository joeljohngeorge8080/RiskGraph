"""UNGUARDED and BOLA_SUSPECT edges (X5 part 2, ADR-0023): evidence, assurance, and no
effect on any path or score until risk v2 gives them a probability."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st
from riskgraph.modules.evidence import Assurance
from riskgraph.modules.graph import GraphFinding, analyze
from riskgraph.shared.vocabulary import SourceType as S

from tests.test_attack_paths import FINDINGS, _manifest


def _authz(
    index: int, service: str, rule: str, route: str, evidence: tuple[str, ...] = ("r",)
) -> GraphFinding:
    return GraphFinding(
        index,
        service,
        S.AUTHZ,
        title=route,
        evidence=evidence,
        file=f"{service}/app.py",
        line=index,
        authz_rule=rule,
        route=route,
    )


AUTHZ = [
    _authz(10, "web", "unguarded-sensitive", "POST /items", ("route-a",)),
    _authz(11, "web", "inconsistent", "DELETE /items/<id>", ("route-b", "route-c")),
    _authz(12, "api", "unguarded-sensitive", "POST /internal", ("route-d",)),  # not exposed
    _authz(13, "api", "bola", "GET /orders/<id>", ("route-e",)),
    _authz(14, "web", "bola", "GET /me/<id>", ("route-f",)),  # web reaches no data store
    _authz(15, "web", "policy", "GET /admin", ("route-g",)),  # has a guard, not unguarded
    _authz(16, "web", "unguarded-sensitive", "PUT /x", ()),  # no evidence: skipped
]


def _edges(a, kind: str):  # type: ignore[no-untyped-def]
    return [e for e in a.edges if e.kind == kind]


def test_unguarded_edges_come_from_exposed_services_only() -> None:
    a = analyze(_manifest(), [*FINDINGS, *AUTHZ])
    unguarded = _edges(a, "UNGUARDED")
    assert sorted(e.target for e in unguarded) == [
        "endpoint:web:DELETE /items/<id>",
        "endpoint:web:POST /items",
    ]
    for e in unguarded:
        assert e.source == "internet" and e.assurance is Assurance.INFERRED and e.p is None
    by_target = {e.target: e for e in unguarded}
    assert by_target["endpoint:web:DELETE /items/<id>"].evidence_ids == ("route-b", "route-c")
    assert by_target["endpoint:web:POST /items"].findings == (10,)
    endpoint = a.nodes["endpoint:web:POST /items"]
    assert endpoint["kind"] == "endpoint" and endpoint["properties"]["service"] == "web"


def test_bola_suspect_edges_go_to_the_stores_the_service_reaches() -> None:
    a = analyze(_manifest(), [*FINDINGS, *AUTHZ])
    [bola] = _edges(a, "BOLA_SUSPECT")
    assert (bola.source, bola.target) == ("endpoint:api:GET /orders/<id>", "data_store:orders-db")
    assert bola.assurance is Assurance.HYPOTHESIS and bola.p is None
    assert "endpoint:web:GET /me/<id>" not in a.nodes  # no store, so no endpoint either
    assert "endpoint:api:POST /internal" not in a.nodes  # internal: no UNGUARDED edge
    assert not any(k.endswith("PUT /x") for k in a.nodes)


def test_authz_edges_change_no_path_and_no_effective_impact() -> None:
    plain = analyze(_manifest(), FINDINGS)
    with_authz = analyze(_manifest(), [*FINDINGS, *AUTHZ])
    assert [(p.label, p.score, p.assurance) for p in with_authz.paths] == [
        (p.label, p.score, p.assurance) for p in plain.paths
    ]
    assert with_authz.effective == plain.effective


def test_without_a_manifest_or_topology_nothing_is_built() -> None:
    a = analyze(None, AUTHZ)
    assert not _edges(a, "UNGUARDED") and not _edges(a, "BOLA_SUSPECT")


_RULES = st.sampled_from(["unguarded-sensitive", "inconsistent", "policy", "bola"])
_SERVICES = st.sampled_from(["web", "api", "batch", "ghost"])


@settings(max_examples=60, deadline=None)
@given(st.lists(st.tuples(_SERVICES, _RULES, st.integers(0, 5)), max_size=15))
def test_random_authz_findings_never_change_paths_or_scores(
    rows: list[tuple[str, str, int]],
) -> None:
    extra = [
        _authz(100 + i, svc, rule, f"GET /r{n}", (f"ev{i}",))
        for i, (svc, rule, n) in enumerate(rows)
    ]
    plain = analyze(_manifest(), FINDINGS)
    a = analyze(_manifest(), [*FINDINGS, *extra])
    assert [(p.label, p.score) for p in a.paths] == [(p.label, p.score) for p in plain.paths]
    assert a.effective == plain.effective
    for e in a.edges:
        if e.kind in ("UNGUARDED", "BOLA_SUSPECT"):
            assert e.p is None and e.evidence_ids and e.assurance is not Assurance.VERIFIED
