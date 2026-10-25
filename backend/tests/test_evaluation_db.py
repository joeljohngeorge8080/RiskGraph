"""The evaluation replays a scenario through the real pipeline, offline (X0)."""

from __future__ import annotations

import os

import pytest
from evaluation.run import collect

pytestmark = pytest.mark.db


def test_replay_labels_every_finding_and_restores_settings(migrated_db: None) -> None:
    before = {k: os.environ.get(k) for k in ("RISKGRAPH_DATA_DIR", "RISKGRAPH_ENRICHMENT_ENABLED")}
    rows = collect(["B_moderate_reachable_exposed", "C_exposed_credential"])
    assert {r.scenario for r in rows} == {"B_moderate_reachable_exposed", "C_exposed_credential"}
    assert not [r for r in rows if r.defaulted]
    secrets = [r for r in rows if r.source_type == "secret"]
    assert secrets and all(r.important and r.priority in {"critical", "high"} for r in secrets)
    # B's PyYAML CVEs carry the frozen EPSS, so intel came from the snapshot, not a feed
    pyyaml = [r for r in rows if r.package == "pyyaml"]
    assert pyyaml and all(r.epss is not None and r.cvss_base for r in pyyaml)
    assert collect(["C_exposed_credential"]) == [r for r in rows if r.scenario.startswith("C")]
    assert {k: os.environ.get(k) for k in before} == before
