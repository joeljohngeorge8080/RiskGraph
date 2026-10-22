from __future__ import annotations

import math

import pytest
from riskgraph.modules.context import parse_manifest
from riskgraph.modules.graph import GraphFinding, analyze
from riskgraph.modules.graph.attack import INTERNET, MAX_HOPS
from riskgraph.shared.vocabulary import SourceType as S

from tests.fixtures.repos import kitchen_sink

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
    GraphFinding(0, "web", S.SAST, exploit_p=0.6, tier="L2", title="SQLi in web"),
    GraphFinding(1, "web", S.SCA, exploit_p=0.9, tier="L0", title="unused CVE"),  # L0: no edge
    GraphFinding(2, "api", S.SCA, exploit_p=0.5, tier="L2", title="CVE in api"),
    GraphFinding(
        3,
        "web",
        S.SECRET,
        secret_family="aws",
        credential_p=0.9,
        public_secret=True,
        title="AWS key",
    ),
    GraphFinding(4, "batch", S.SAST, exploit_p=0.99, tier="L2", title="isolated bug"),
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
    # I_eff(f) = I(sink) * P(path) / p(f's edge), maximised over paths (§14.4)
    assert a.effective[0].value == pytest.approx(0.9 * 0.54 / 0.6)  # via the key in web
    assert a.effective[2].value == pytest.approx(0.9 * 0.3 / 0.5)
    assert a.effective[3].value == pytest.approx(0.9)
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
    assert any(e["kind"] == "EXPOSES" for e in a.edges)


def test_no_manifest_means_no_paths_but_credentials_are_nodes() -> None:
    a = analyze(None, FINDINGS)
    assert a.paths == []
    assert INTERNET in a.nodes and "credential:3" in a.nodes


def test_kitchen_sink_manifest_is_valid_and_links_aws_keys() -> None:
    m = _manifest(kitchen_sink.MANIFEST)
    assert m.identities[0].credentials == ("aws",)
    bad = parse_manifest("version: 1\nidentities:\n  - {name: x, credentials: [ftp]}\n")
    assert bad.status == "invalid" and "credential family" in bad.warnings[0]
