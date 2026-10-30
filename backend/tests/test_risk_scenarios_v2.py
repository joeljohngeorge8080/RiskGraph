"""Scenarios F-H (plan §6, X6): risk v2 on the new inputs, through context, graph and score.

Each scenario runs the pipeline's scoring order: context, pass-1 score, attack graph from
the scores, pass-2 rescore with the effective impact. The labels below were written in
`docs/auto/DAY_5_PLAN.md` before any of this was run, and are not changed after it.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path

import pytest
from riskgraph.modules.context import (
    ContextResolver,
    ManifestResult,
    Observed,
    extract_iac,
    parse_manifest,
)
from riskgraph.modules.evidence import Assurance
from riskgraph.modules.graph import (
    AttackAnalysis,
    GraphFinding,
    PathResult,
    analyze,
    fill_image_context,
)
from riskgraph.modules.graph.topology import derive
from riskgraph.modules.risk import ScoreInput, ScoreResult, rescore, score
from riskgraph.modules.runtime import dockerfile_refs
from riskgraph.shared.vocabulary import Priority
from riskgraph.shared.vocabulary import Severity as V
from riskgraph.shared.vocabulary import SourceType as S


@dataclass(frozen=True)
class Case:
    name: str
    important: bool
    file: str
    inp: ScoreInput  # without context: the resolver adds it, as in the pipeline
    tier: str | None = None
    image: str | None = None
    kev: bool = False


@dataclass
class Run:
    results: dict[str, ScoreResult]
    analysis: AttackAnalysis


def _reach(tier: str) -> Observed:
    return Observed(tier, "reachability", "medium")


def _run(cases: list[Case], manifest: str | None = None, root: Path | None = None) -> Run:
    parsed = parse_manifest(manifest) if manifest else ManifestResult("absent")
    if manifest:
        assert parsed.status == "valid", parsed.warnings
    assets = extract_iac(root).assets if root else []
    topology = derive(assets, dockerfile_refs(root)) if root else None
    resolver = ContextResolver(parsed, public_repository=True, iac=assets)
    inputs: list[ScoreInput] = []
    graph: list[GraphFinding] = []
    for i, c in enumerate(cases):
        ctx = resolver.for_finding(c.file, c.inp.source_type)
        if c.image is not None and topology is not None:
            # as the pipeline does (ADR-0024)
            ctx = fill_image_context(ctx, topology.image_contexts().get(c.image))
        inp = replace(c.inp, context=ctx)
        result = score(inp)
        inputs.append(inp)
        graph.append(
            GraphFinding(
                index=i,
                service=ctx.service,
                source_type=inp.source_type,
                exploit_p=result.exploit_likelihood,
                tier=c.tier,
                title=c.name,
                evidence=(f"ev-{c.name}",),
                file=c.file,
                image=c.image if c.inp.source_type is S.SCA else None,
                kev=c.kev,
            )
        )
    analysis = analyze(parsed.manifest, graph, topology=topology)
    results = {c.name: score(inputs[i]) for i, c in enumerate(cases)}
    for i, effective in analysis.effective.items():
        results[cases[i].name] = rescore(inputs[i], effective)
    return Run(results, analysis)


# --- F: SSRF → instance metadata → identity --------------------------------------------

F_MANIFEST = """
version: 1
services:
  - {name: api, path: api/, exposure: internet, auth: none, runs_as: api-role}
identities:
  - {name: api-role, privilege: admin, can_access: [instance-metadata]}
data_stores:
  - {name: instance-metadata, sensitivity: credentials}
"""
F = [
    Case(
        "F1 tier-1 SSRF",
        True,
        "api/fetch.py",
        ScoreInput(
            S.SAST,
            V.HIGH,
            category="ssrf",
            confidence="HIGH",
            taint_cwe="CWE-918",
            taint_confidence="HIGH",
            reachability=_reach("L3"),
        ),
        tier="L3",
    ),
    Case(
        "F2 weak hash",
        False,
        "api/util.py",
        ScoreInput(S.SAST, V.MEDIUM, category="crypto", reachability=_reach("L2")),
        tier="L2",
    ),
    Case(
        "F3 low-EPSS CVE",
        False,
        "api/requirements.txt",
        ScoreInput(S.SCA, V.MEDIUM, epss=0.001, cvss_impact=3.6, reachability=_reach("L1")),
        tier="L1",
    ),
]


# --- G: public image CVE on an internet service → privileged identity -------------------
# The plan's sink is a database. Data stores from Compose are F-1-1 (OPEN), and Kubernetes
# has none, so the derived graph's sink here is the cluster-admin ServiceAccount.

WEB_IMAGE = "ghcr.io/acme/web:1"
G_K8S = f"""
apiVersion: apps/v1
kind: Deployment
metadata: {{name: web}}
spec:
  template:
    metadata: {{labels: {{app: web}}}}
    spec:
      serviceAccountName: web-sa
      containers: [{{name: web, image: "{WEB_IMAGE}"}}]
---
apiVersion: v1
kind: Service
metadata: {{name: web-lb}}
spec: {{type: LoadBalancer, selector: {{app: web}}}}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {{name: web-admin}}
roleRef: {{kind: ClusterRole, name: cluster-admin}}
subjects: [{{kind: ServiceAccount, name: web-sa}}]
"""


def _g_cases(g1_kev: bool = True) -> list[Case]:
    image = {"file": "k8s/web.yaml", "tier": "n_a", "image": WEB_IMAGE}
    return [
        Case(
            "G1 KEV image CVE",
            True,
            inp=ScoreInput(
                S.SCA, V.CRITICAL, epss=0.9, cvss_impact=5.9, kev=g1_kev, image_package=True
            ),
            kev=g1_kev,
            **image,
        ),
        Case(
            "G2 image CVE",
            False,
            inp=ScoreInput(S.SCA, V.MEDIUM, epss=0.0005, cvss_impact=3.6, image_package=True),
            **image,  # type: ignore[arg-type]
        ),
        Case(
            "G3 base OS end-of-life",
            False,
            "k8s/web.yaml",
            ScoreInput(S.RUNTIME, V.HIGH, category="runtime_eol"),
            image=WEB_IMAGE,
        ),
    ]


def _g_repo(root: Path) -> Path:
    (root / "k8s").mkdir()
    (root / "k8s" / "web.yaml").write_text(G_K8S)
    return root


# --- H: co-located findings with no relationship ----------------------------------------

H_MANIFEST = """
version: 1
services:
  - {name: batch, path: batch/, exposure: isolated, runs_as: batch-role}
identities:
  - {name: batch-role, privilege: admin, can_access: [orders-db]}
data_stores:
  - {name: orders-db, sensitivity: financial}
"""
H = [
    Case(
        "H1 SQLi",
        False,
        "batch/jobs.py",
        ScoreInput(S.SAST, V.HIGH, category="sql_injection", reachability=_reach("L2")),
        tier="L2",
    ),
    Case(
        "H2 CVE",
        False,
        "batch/requirements.txt",
        ScoreInput(S.SCA, V.HIGH, epss=0.02, cvss_impact=5.9, reachability=_reach("L2")),
        tier="L2",
    ),
    Case(
        "H3 IaC hygiene",
        False,
        "batch/Dockerfile",
        ScoreInput(S.IAC, V.LOW, iac_family="hygiene"),
    ),
]


def _assured(run: Run, finding: str) -> list[PathResult]:
    index = next(i for i, name in enumerate(run.results) if name == finding)
    return [
        p
        for p in run.analysis.paths
        if p.assurance is not Assurance.HYPOTHESIS and index in p.findings
    ]


def test_f_ssrf_flow_reaches_the_admin_identity_and_the_metadata() -> None:
    run = _run(F, F_MANIFEST)
    sinks = {p.sink for p in _assured(run, "F1 tier-1 SSRF")}
    assert sinks == {"identity:api-role", "data_store:instance-metadata"}
    f1 = run.results["F1 tier-1 SSRF"]
    e = f1.factor("E")
    assert e is not None and e.source == "sast_severity"  # high + HIGH = 0.8 ≥ taint 0.75
    assert f1.priority is Priority.CRITICAL and f1.factor("I*") is not None
    # F-5-1 (OPEN): every code finding of the service is evidence on its EXPLOIT edge and
    # takes the path's effective impact, so the weak hash (F2) and the L1 CVE (F3) inherit
    # I* = 1.0 by co-location. Pinned here so a change to that rule is seen.
    for other in ("F2 weak hash", "F3 low-EPSS CVE"):
        inherited = run.results[other].factor("I*")
        assert inherited is not None and inherited.value == pytest.approx(1.0, abs=1e-5)


def test_g_kev_image_cve_gives_an_inferred_path_and_a_non_kev_one_only_a_hypothesis(
    tmp_path: Path,
) -> None:
    root = _g_repo(tmp_path)
    run = _run(_g_cases(), root=root)
    g1 = run.results["G1 KEV image CVE"]
    assert g1.factor("R").source == "not_assessable"  # type: ignore[union-attr]
    paths = _assured(run, "G1 KEV image CVE")
    assert paths and {p.sink for p in paths} == {"identity:sa:web-sa"}
    assert all(p.assurance is Assurance.INFERRED for p in paths)
    assert g1.priority.rank >= Priority.HIGH.rank  # KEV floor at least

    # the same CVE without KEV: a hypothesis path to verify, and no score moves
    (tmp_path / "plain").mkdir()
    plain = _run(_g_cases(g1_kev=False), root=_g_repo(tmp_path / "plain"))
    assert not _assured(plain, "G1 KEV image CVE")
    assert plain.analysis.effective == {}


def test_h_co_located_findings_with_no_relationship_yield_no_path() -> None:
    run = _run(H, H_MANIFEST)
    assert run.analysis.paths == [] and run.analysis.effective == {}


def test_scenario_ordering_matches_the_labels(tmp_path: Path) -> None:
    runs = [_run(F, F_MANIFEST), _run(_g_cases(), root=_g_repo(tmp_path)), _run(H, H_MANIFEST)]
    labels = {c.name: c.important for c in [*F, *_g_cases(), *H]}
    scores = {name: r.score for run in runs for name, r in run.results.items()}
    ranked = sorted(scores, key=lambda n: -scores[n])
    important = [n for n in ranked if labels[n]]
    rest = [n for n in ranked if not labels[n]]
    assert ranked[: len(important)] == important, [(n, scores[n]) for n in ranked]
    assert min(scores[n] for n in important) > max(scores[n] for n in rest)


@pytest.mark.parametrize("which", ["F", "H"])
def test_v2_inputs_absent_scenarios_score_as_v1(which: str) -> None:
    """Reduction on the new scenarios: without the taint input F1 is the plain SAST row."""
    cases = F if which == "F" else H
    stripped = [
        replace(c, inp=replace(c.inp, taint_cwe=None, taint_confidence=None)) for c in cases
    ]
    a, b = (
        _run(cases, F_MANIFEST if which == "F" else H_MANIFEST),
        _run(stripped, F_MANIFEST if which == "F" else H_MANIFEST),
    )
    for name in a.results:
        assert b.results[name].factor("E").source != "taint_tier1"  # type: ignore[union-attr]
        assert a.results[name].score >= b.results[name].score
