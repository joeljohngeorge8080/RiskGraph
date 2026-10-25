"""Security graph and attack paths for one scan (blueprint §12-§14.4, ADR-0006, ADR-0013).

Pure: manifest + per-finding facts in, graph + ranked paths + effective impacts out.

Attack-graph states: internet, services, identities, data stores, credentials. Edges:

    EXPLOIT          internet → service (service exposed to the internet)
                     service  → service (CONNECTS_TO)
                     p = max geomean(E, R) over the target's code findings that are not L0
    AUTHENTICATES_AS credential → identity, p = E of the secret (manifest links the family)
    RUNS_AS, CAN_ACCESS, CONNECTS_TO (to a data store), CONTAINS_SECRET: control, p = 1

Edge weight w = -ln p, so the minimum-weight path is the most probable one. Yen's
k-shortest simple paths (``networkx.shortest_simple_paths``, Dijkstra underneath) from a
virtual source attached to ``internet`` and to every public credential, per sink:
data stores with sensitivity ≥ confidential, identities with privilege ≥ elevated, and
services declared critical. Paths have at most MAX_HOPS edges and contain at least one
EXPLOIT or AUTHENTICATES_AS edge (pure control paths are architecture, not attacks).

Invariants (blueprint §12), checked before anything is returned: ``internet`` has no
in-edges; every service has exactly one RUNS_AS (a synthetic ``unknown-identity`` when the
manifest names none); every credential has exactly one CONTAINS_SECRET in-edge (from the
``repository`` node when the secret is outside every service); every edge joins known
nodes; every attack edge carries finding evidence.
"""

from __future__ import annotations

import math
from collections.abc import Iterable
from dataclasses import dataclass, field
from itertools import islice, pairwise
from typing import Any, Protocol

import networkx as nx

from riskgraph.modules.context import Manifest
from riskgraph.modules.risk import EffectiveImpact
from riskgraph.modules.risk.tables import C_VALUES, D_VALUES, P_VALUES
from riskgraph.shared.vocabulary import SourceType

K_PATHS = 3
MAX_HOPS = 8
MAX_CANDIDATES = 50
MAX_EVIDENCE = 10
INTERNET = "internet"
REPOSITORY = "repository"
UNKNOWN_IDENTITY = "identity:unknown-identity"
_VIRTUAL = "@source"
ATTACK_EDGES = frozenset({"EXPLOIT", "AUTHENTICATES_AS"})
SINK_SENSITIVITY = frozenset({"confidential", "pii", "financial", "credentials"})
SINK_PRIVILEGE = frozenset({"elevated", "admin"})


class GraphInvariantError(RuntimeError):
    """The builder produced a graph that breaks a §12 invariant: a bug, never input."""


def invariant_violations(
    nodes: dict[str, dict[str, Any]], edges: list[dict[str, Any]]
) -> list[str]:
    out: list[str] = []
    runs_as: dict[str, int] = {}
    contains: dict[str, int] = {}
    for e in edges:
        src, dst, kind = e["source"], e["target"], e["kind"]
        for end in (src, dst):
            if end not in nodes:
                out.append(f"{kind} {src} -> {dst}: unknown node {end}")
        if dst == INTERNET:
            out.append(f"internet has in-edges ({kind} from {src})")
        if kind == "RUNS_AS":
            runs_as[src] = runs_as.get(src, 0) + 1
        if kind == "CONTAINS_SECRET":
            contains[dst] = contains.get(dst, 0) + 1
        if kind in ATTACK_EDGES and not e.get("findings"):
            out.append(f"{kind} {src} -> {dst} has no evidence")
    for key, n in nodes.items():
        if n["kind"] == "service" and runs_as.get(key, 0) != 1:
            out.append(f"{key} has {runs_as.get(key, 0)} RUNS_AS edges, expected 1")
        if n["kind"] == "credential" and contains.get(key, 0) != 1:
            out.append(f"{key} has {contains.get(key, 0)} CONTAINS_SECRET in-edges, expected 1")
    return out


@dataclass(frozen=True, slots=True)
class GraphFinding:
    index: int  # position in the scan's merged list
    service: str | None
    source_type: SourceType
    exploit_p: float = 0.0  # geomean(E, R) for code findings
    tier: str | None = None
    secret_family: str | None = None
    credential_p: float = 0.0
    public_secret: bool = False
    title: str = ""


@dataclass(frozen=True, slots=True)
class PathResult:
    source: str
    sink: str
    rank: int
    nodes: list[str]
    labels: list[str]
    edges: list[dict[str, Any]]
    probability: float
    sink_impact: float
    score: float
    findings: list[int]

    @property
    def hops(self) -> int:
        return len(self.nodes) - 1

    @property
    def label(self) -> str:
        return " → ".join(self.labels)


@dataclass
class AttackAnalysis:
    nodes: dict[str, dict[str, Any]] = field(default_factory=dict)
    edges: list[dict[str, Any]] = field(default_factory=list)
    paths: list[PathResult] = field(default_factory=list)
    effective: dict[int, EffectiveImpact] = field(default_factory=dict)
    exposed_by_design: int = 0

    def summary(self) -> dict[str, Any]:
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "paths": len(self.paths),
            "sinks_reached": len({p.sink for p in self.paths}),
            "max_path_score": max((p.score for p in self.paths), default=0.0),
            "findings_on_paths": len(self.effective),
            "exposed_by_design": self.exposed_by_design,
        }


def _svc(name: str) -> str:
    return f"service:{name}"


def _idn(name: str) -> str:
    return f"identity:{name}"


def _ds(name: str) -> str:
    return f"data_store:{name}"


def analyze(manifest: Manifest | None, findings: list[GraphFinding]) -> AttackAnalysis:
    out = AttackAnalysis()
    g: nx.DiGraph[str] = nx.DiGraph()

    def node(key: str, kind: str, label: str, **props: Any) -> None:
        out.nodes[key] = {"key": key, "kind": kind, "label": label, "properties": props}
        g.add_node(key)

    def edge(
        src: str, dst: str, kind: str, p: float | None, evidence: list[int] | None = None
    ) -> None:
        out.edges.append(
            {
                "source": src,
                "target": dst,
                "kind": kind,
                "probability": p,
                "findings": evidence or [],
            }
        )
        if p is not None and p > 0:
            g.add_edge(src, dst, kind=kind, p=p, w=-math.log(p), findings=evidence or [])

    node(INTERNET, "internet", "Internet")
    by_service: dict[str, list[GraphFinding]] = {}
    for f in findings:
        if f.service:
            by_service.setdefault(f.service, []).append(f)

    sinks: dict[str, float] = {}
    if manifest is not None:
        for d in manifest.data_stores:
            node(_ds(d.name), "data_store", d.name, sensitivity=d.sensitivity, store_kind=d.kind)
            if d.sensitivity in SINK_SENSITIVITY:
                sinks[_ds(d.name)] = D_VALUES[d.sensitivity]
        for i in manifest.identities:
            node(
                _idn(i.name),
                "identity",
                i.name,
                privilege=i.privilege,
                credentials=list(i.credentials),
            )
            if i.privilege in SINK_PRIVILEGE:
                sinks[_idn(i.name)] = P_VALUES[i.privilege]
        for s in manifest.services:
            mine = by_service.get(s.name, [])
            node(
                _svc(s.name),
                "service",
                s.name,
                path=s.path or "/",
                exposure=s.exposure,
                auth=s.auth,
                criticality=manifest.criticality.get(s.name),
                findings=len(mine),
            )
            if manifest.criticality.get(s.name) == "high":
                sinks[_svc(s.name)] = C_VALUES["high"]

        exploit: dict[str, tuple[float, list[int]]] = {}
        for s in manifest.services:
            code = [
                f
                for f in by_service.get(s.name, [])
                if f.source_type in (SourceType.SCA, SourceType.SAST)
                and f.tier != "L0"
                and f.exploit_p > 0
            ]
            if code:
                code.sort(key=lambda f: (-f.exploit_p, f.index))
                exploit[s.name] = (code[0].exploit_p, [f.index for f in code[:MAX_EVIDENCE]])

        for s in manifest.services:
            if s.exposure == "internet":
                edge(INTERNET, _svc(s.name), "EXPOSES", None)
                if s.name in exploit:
                    p, ev = exploit[s.name]
                    edge(INTERNET, _svc(s.name), "EXPLOIT", p, ev)
            if s.runs_as:
                edge(_svc(s.name), _idn(s.runs_as), "RUNS_AS", 1.0)
            else:
                if UNKNOWN_IDENTITY not in out.nodes:
                    # never a sink (no privilege) and never a source: it adds no path
                    node(
                        UNKNOWN_IDENTITY,
                        "identity",
                        "unknown identity",
                        privilege=None,
                        synthetic=True,
                    )
                edge(_svc(s.name), UNKNOWN_IDENTITY, "RUNS_AS", 1.0)
            for target in s.connects_to:
                if any(d.name == target for d in manifest.data_stores):
                    edge(_svc(s.name), _ds(target), "CONNECTS_TO", 1.0)
                elif target in exploit:
                    edge(_svc(s.name), _svc(target), "CONNECTS_TO", None)
                    p, ev = exploit[target]
                    edge(_svc(s.name), _svc(target), "EXPLOIT", p, ev)
                else:
                    edge(_svc(s.name), _svc(target), "CONNECTS_TO", None)
        services = {s.name for s in manifest.services}
        for i in manifest.identities:
            for target in i.can_access:
                key = _svc(target) if target in services else _ds(target)
                edge(_idn(i.name), key, "CAN_ACCESS", 1.0)

    family_to_identity: dict[str, list[str]] = {}
    if manifest is not None:
        for i in manifest.identities:
            for fam in i.credentials:
                family_to_identity.setdefault(fam, []).append(i.name)
    sources = [INTERNET]
    for f in findings:
        if f.source_type is not SourceType.SECRET:
            continue
        key = f"credential:{f.index}"
        node(
            key,
            "credential",
            f.title or "credential",
            family=f.secret_family,
            public=f.public_secret,
            finding=f.index,
        )
        if f.service and _svc(f.service) in out.nodes:
            edge(_svc(f.service), key, "CONTAINS_SECRET", 1.0, [f.index])
        else:
            if REPOSITORY not in out.nodes:
                node(REPOSITORY, "repository", "repository")  # no in-edges: not on any path
            edge(REPOSITORY, key, "CONTAINS_SECRET", 1.0, [f.index])
        for ident in family_to_identity.get(f.secret_family or "", []):
            edge(key, _idn(ident), "AUTHENTICATES_AS", f.credential_p, [f.index])
        if f.public_secret:
            sources.append(key)

    broken = invariant_violations(out.nodes, out.edges)
    if broken:
        raise GraphInvariantError("; ".join(broken[:5]))
    for src in sources:
        g.add_edge(_VIRTUAL, src, kind="VIRTUAL", p=1.0, w=0.0, findings=[])
    _search(g, out, sinks)
    return out


class _NodeRow(Protocol):
    @property
    def key(self) -> str: ...
    @property
    def kind(self) -> str: ...


class _EdgeRow(Protocol):
    @property
    def source(self) -> str: ...
    @property
    def target(self) -> str: ...
    @property
    def kind(self) -> str: ...
    @property
    def probability(self) -> Any: ...  # Decimal | float | None


def to_networkx(nodes: Iterable[_NodeRow], edges: Iterable[_EdgeRow]) -> nx.DiGraph[str]:
    """Stored graph rows into a weighted DiGraph (the analysis shape: w = -ln p).

    Edges without a probability (EXPOSES, CONNECTS_TO between services) are kept for
    neighbourhood questions, with ``w`` = inf so no shortest path ever uses them.
    """
    g: nx.DiGraph[str] = nx.DiGraph()
    for n in nodes:
        g.add_node(n.key, kind=n.kind)
    for e in edges:
        p = float(e.probability) if e.probability is not None else 0.0
        if g.has_edge(e.source, e.target) and g.edges[e.source, e.target]["p"] >= p:
            continue  # parallel edges: keep the most probable one, as the analysis does
        g.add_edge(e.source, e.target, kind=e.kind, p=p, w=-math.log(p) if p > 0 else math.inf)
    return g


def _search(g: nx.DiGraph[str], out: AttackAnalysis, sinks: dict[str, float]) -> None:
    for sink, impact in sorted(sinks.items()):
        if sink not in g or not nx.has_path(g, _VIRTUAL, sink):
            continue
        rank = 0
        try:
            candidates = nx.shortest_simple_paths(g, _VIRTUAL, sink, weight="w")
            for raw in islice(candidates, MAX_CANDIDATES):
                nodes = raw[1:]
                if len(nodes) - 1 > MAX_HOPS or len(nodes) < 2:
                    continue
                hops = list(pairwise(nodes))
                kinds = [g.edges[a, b]["kind"] for a, b in hops]
                if not ATTACK_EDGES & set(kinds):
                    out.exposed_by_design += 1
                    continue
                rank += 1
                out.paths.append(_path(g, out, nodes, hops, sink, impact, rank))
                if rank >= K_PATHS:
                    break
        except nx.NetworkXNoPath:
            continue
    out.paths.sort(key=lambda p: (-p.score, p.sink, p.rank))
    for path in out.paths:
        for e in path.edges:
            if e["kind"] not in ATTACK_EDGES or not e["p"]:
                continue
            conditional = path.probability / e["p"]
            value = path.sink_impact * conditional
            for idx in e["findings"]:
                current = out.effective.get(idx)
                if current is None or value > current.value:
                    out.effective[idx] = EffectiveImpact(
                        value, path.label, path.sink, path.probability
                    )


def _path(
    g: nx.DiGraph[str],
    out: AttackAnalysis,
    nodes: list[str],
    hops: list[tuple[str, str]],
    sink: str,
    impact: float,
    rank: int,
) -> PathResult:
    edges = []
    probability = 1.0
    findings: list[int] = []
    for a, b in hops:
        data = g.edges[a, b]
        probability *= data["p"]
        edges.append(
            {
                "source": a,
                "target": b,
                "kind": data["kind"],
                "p": round(data["p"], 5),
                "findings": list(data["findings"]),
            }
        )
        if data["kind"] in ATTACK_EDGES:
            findings.extend(data["findings"])
    labels = [out.nodes[n]["label"] for n in nodes]
    return PathResult(
        source=nodes[0],
        sink=sink,
        rank=rank,
        nodes=nodes,
        labels=labels,
        edges=edges,
        probability=probability,
        sink_impact=impact,
        score=round(100 * probability * impact, 2),
        findings=sorted(set(findings)),
    )
