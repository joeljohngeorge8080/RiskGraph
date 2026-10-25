from __future__ import annotations

import math
from itertools import pairwise

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from riskgraph.modules.context import parse_manifest
from riskgraph.modules.evidence import Assurance
from riskgraph.modules.graph import GraphFinding, analyze
from riskgraph.modules.graph.attack import INTERNET, MAX_HOPS
from riskgraph.shared.vocabulary import SourceType as S

from tests.fixtures.repos import kitchen_sink

VERIFIED = Assurance.VERIFIED

MANIFEST = """
version: 1
services:
  - {name: web, path: web/, exposure: internet, auth: none, runs_as: web-role, connects_to: [api]}
  - {name: api, path: api/, exposure: internal, runs_as: api-role, connects_to: [orders-db]}
  - {name: batch, path: batch/, exposure: isolated, runs_as: batch-role}
identities:
  - {name: web-role, privilege: limited}
  - {name: api-role, privilege: elevated, can_access: [orders-db], credentials: [aws]}
  - {name: batch-role, privilege: admin, can_access: [orders-db]}
data_stores:
  - {name: orders-db, sensitivity: financial}
  - {name: cache, sensitivity: internal}
criticality: {api: high}
"""


def _manifest(text: str = MANIFEST):  # type: ignore[no-untyped-def]
    result = parse_manifest(text)
    assert result.status == "valid", result.warnings
    return result.manifest


FINDINGS = [
    GraphFinding(0, "web", S.SAST, exploit_p=0.6, tier="L2", title="SQLi in web", evidence=("e0",)),
    GraphFinding(1, "web", S.SCA, exploit_p=0.9, tier="L0", title="unused CVE", evidence=("e1",)),
    GraphFinding(2, "api", S.SCA, exploit_p=0.5, tier="L2", title="CVE in api", evidence=("e2",)),
    GraphFinding(
        3,
        "web",
        S.SECRET,
        secret_family="aws",
        credential_p=0.9,
        public_secret=True,
        title="AWS key",
        evidence=("e3",),
    ),
    GraphFinding(
        4, "batch", S.SAST, exploit_p=0.99, tier="L2", title="isolated bug", evidence=("e4",)
    ),
]


def test_paths_and_probabilities_match_hand_computation() -> None:
    a = analyze(_manifest(), FINDINGS)
    by = {(p.sink, p.label): p for p in a.paths}
    # exploit chain: web SQLi (.6), then api CVE (.5); api CONNECTS_TO orders-db is control
    exploit = by[("data_store:orders-db", "Internet → web → api → orders-db")]
    assert exploit.probability == pytest.approx(0.6 * 0.5)  # the L0 CVE (.9) is ignored
    assert exploit.score == pytest.approx(100 * 0.3 * 0.9)  # financial = 0.9
    assert exploit.findings == [0, 2]
    # the public AWS key authenticates as api-role (.9), which can access orders-db
    cred = by[("data_store:orders-db", "AWS key → api-role → orders-db")]
    assert cred.probability == pytest.approx(0.9) and cred.findings == [3]
    assert a.paths[0] is cred  # most probable first
    # exploiting web also yields the key it contains: .6 x .9
    via_web = by[("data_store:orders-db", "Internet → web → AWS key → api-role → orders-db")]
    assert via_web.probability == pytest.approx(0.54) and via_web.rank == 2
    # the isolated batch service has no inbound edge: its admin role is not reachable
    assert not any(p.sink == "identity:batch-role" for p in a.paths)


def test_effective_impact_uses_the_rest_of_the_chain() -> None:
    a = analyze(_manifest(), FINDINGS)
    # I_eff(f) = I(sink) * P(path) / p(f's edge), maximised over paths (§14.4), and only
    # over paths of at least `inferred` (ADR-0017). Before X1, finding 0 took 0.9*.54/.6
    # through the AWS key in web; that path crosses AUTHENTICATES_AS, a family match and
    # so a hypothesis, and no longer counts. The exploit chain web -> api is L2 + L2.
    assert a.effective[0].value == pytest.approx(0.9 * 0.3 / 0.6)
    assert a.effective[2].value == pytest.approx(0.9 * 0.3 / 0.5)
    # the key is on hypothesis paths only: listed to verify, no effective impact
    assert 3 not in a.effective
    assert 1 not in a.effective and 4 not in a.effective


def test_k_paths_per_sink_and_hop_limit() -> None:
    a = analyze(_manifest(), FINDINGS)
    for sink in {p.sink for p in a.paths}:
        ranks = [p.rank for p in a.paths if p.sink == sink]
        assert sorted(ranks) == list(range(1, len(ranks) + 1)) and len(ranks) <= 3
    assert all(p.hops <= MAX_HOPS for p in a.paths)
    for p in a.paths:
        weights = sum(-math.log(e["p"]) for e in p.edges)
        assert math.exp(-weights) == pytest.approx(p.probability, rel=1e-3)


def test_control_only_paths_are_not_attacks() -> None:
    manifest = _manifest(
        """
version: 1
services:
  - {name: web, path: "", exposure: internet, auth: none, runs_as: role}
identities:
  - {name: role, privilege: admin, can_access: [db]}
data_stores:
  - {name: db, sensitivity: pii}
"""
    )
    a = analyze(manifest, [])  # exposed, but no exploitable finding and no secret
    assert a.paths == [] and a.effective == {}
    assert any(e.kind == "EXPOSES" for e in a.edges)


def test_no_manifest_means_no_paths_but_credentials_are_nodes() -> None:
    a = analyze(None, FINDINGS)
    assert a.paths == []
    assert INTERNET in a.nodes and "credential:3" in a.nodes


def test_kitchen_sink_manifest_is_valid_and_links_aws_keys() -> None:
    m = _manifest(kitchen_sink.MANIFEST)
    assert m.identities[0].credentials == ("aws",)
    bad = parse_manifest("version: 1\nidentities:\n  - {name: x, credentials: [ftp]}\n")
    assert bad.status == "invalid" and "credential family" in bad.warnings[0]


@settings(max_examples=120, deadline=None)
@given(
    edges=st.lists(
        st.tuples(
            st.integers(0, 7),
            st.integers(1, 7),
            st.sampled_from(["EXPLOIT", "RUNS_AS"]),
            st.floats(0.05, 0.95),
        ),
        min_size=1,
        max_size=24,
    ),
    hop_limit=st.integers(1, 4),
)
def test_search_matches_brute_force_top_k(
    edges: list[tuple[int, int, str, float]], hop_limit: int
) -> None:
    """The hop pre-filter is exact: same top-k probabilities as enumerating every path."""
    import networkx as nx
    from riskgraph.modules.graph import attack

    def key(i: int) -> str:
        return INTERNET if i == 0 else f"service:s{i}"

    g: nx.DiGraph[str] = nx.DiGraph()
    out = attack.AttackAnalysis()
    for i in range(8):
        g.add_node(key(i))
        out.nodes[key(i)] = {"key": key(i), "kind": "service", "label": key(i), "properties": {}}
    for a, b, kind, p in edges:
        if a == b or g.has_edge(key(a), key(b)):
            continue
        p = 1.0 if kind == "RUNS_AS" else p
        g.add_edge(key(a), key(b), kind=kind, p=p, w=-math.log(p), findings=[a], assurance=VERIFIED)
    g.add_edge(attack._VIRTUAL, INTERNET, kind="VIRTUAL", p=1.0, w=0.0, findings=[])
    sinks = {key(i): 1.0 for i in (5, 6, 7)}

    original = attack.MAX_HOPS
    attack.MAX_HOPS = hop_limit
    try:
        attack._search(g, out, sinks)
    finally:
        attack.MAX_HOPS = original

    for sink in sinks:
        expected = sorted(
            (
                math.prod(g.edges[u, v]["p"] for u, v in pairwise(path))
                for path in nx.all_simple_paths(g, INTERNET, sink, cutoff=hop_limit)
                if any(g.edges[u, v]["kind"] == "EXPLOIT" for u, v in pairwise(path))
            ),
            reverse=True,
        )[: attack.K_PATHS]
        got = sorted((p.probability for p in out.paths if p.sink == sink), reverse=True)
        # Yen stops after MAX_CANDIDATES; on 8 nodes that bound is never reached
        assert got == pytest.approx(expected), (sink, got, expected)


SCENARIO_E = """
version: 1
services:
  - {name: api, path: api/, exposure: internet, auth: none, runs_as: api-role}
  - {name: worker, path: worker/, exposure: internal, runs_as: worker-role}
identities:
  - {name: api-role, privilege: elevated, can_access: [instance-metadata, users-db]}
  - {name: worker-role, privilege: limited}
data_stores:
  - {name: instance-metadata, sensitivity: credentials}
  - {name: users-db, sensitivity: pii}
criticality: {api: high}
"""


def test_scenario_e_ssrf_path_to_metadata_and_pii_with_evidence() -> None:
    """Blueprint §14.6 E: SSRF (SAST high) on an internet API → api-role → creds → PII."""
    e_ssrf, r_l3 = 0.7, 1.0  # §14.2: SAST high; L3: the handler calls the sink
    ssrf = GraphFinding(
        0,
        "api",
        S.SAST,
        exploit_p=math.sqrt(e_ssrf * r_l3),
        tier="L3",
        title="SSRF in fetch()",
        evidence=("ssrf",),
    )
    noise = GraphFinding(
        1, "worker", S.SCA, exploit_p=0.9, tier="L2", title="worker CVE", evidence=("cve",)
    )
    a = analyze(_manifest(SCENARIO_E), [ssrf, noise])
    by = {p.label: p for p in a.paths}
    p_exploit = math.sqrt(0.7)
    pii = by["Internet → api → api-role → users-db"]
    creds = by["Internet → api → api-role → instance-metadata"]
    assert pii.probability == pytest.approx(p_exploit)
    assert pii.score == pytest.approx(100 * p_exploit * 0.9, abs=0.01)  # D(pii) = 0.9
    assert creds.score == pytest.approx(100 * p_exploit * 1.0, abs=0.01)  # credentials = 1.0
    # evidence: the SSRF finding is the only attack edge, on the EXPLOIT hop
    for path in (pii, creds):
        assert path.findings == [0]
        exploit = [e for e in path.edges if e["kind"] == "EXPLOIT"]
        assert len(exploit) == 1 and exploit[0]["source"] == INTERNET
        assert exploit[0]["findings"] == [0]
    # the internal worker is not exposed: its CVE is on no path, whatever its p
    assert all(1 not in p.findings for p in a.paths)
    # §14.4: the rest of the chain is control (p = 1), so I_eff = I(sink)
    assert a.effective[0].value == pytest.approx(1.0)
    assert a.paths[0] is creds  # credentials outrank PII
