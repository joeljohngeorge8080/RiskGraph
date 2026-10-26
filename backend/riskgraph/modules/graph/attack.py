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

Evidence and assurance (ADR-0017): every edge is a ``Relationship`` that names its
evidence, and the builder refuses one without (``GraphInvariantError``). Manifest edges
rest on declaration evidence and are verified, except RUNS_AS to the synthetic unknown
identity (inferred). CONTAINS_SECRET is verified. AUTHENTICATES_AS matches a secret's
family to an identity's ``credentials`` list, which proves nothing about this key: a
hypothesis. EXPLOIT takes the reachability tier of the finding that sets its p (L3
verified, L2 inferred, otherwise hypothesis). A path is as assured as its weakest edge,
and only paths of at least ``inferred`` raise a finding's effective impact.
"""

from __future__ import annotations

import datetime as dt
import math
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from itertools import islice, pairwise
from typing import Any, Protocol

import networkx as nx

from riskgraph.modules.context import Manifest
from riskgraph.modules.evidence import (
    Assurance,
    Evidence,
    Relationship,
    make_evidence,
    min_assurance,
)
from riskgraph.modules.graph.topology import Declared, DerivedService, Topology
from riskgraph.modules.normalization import Location
from riskgraph.modules.normalization.fingerprint import stable_hash
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
FINDING_EDGES = ATTACK_EDGES | {"CONTAINS_SECRET"}  # must rest on a finding's evidence
MANIFEST_PRODUCER = "riskgraph.manifest@1"
IAC_PRODUCER = "riskgraph.iac@1"  # X3: facts stated by Compose and Kubernetes files
SINK_SENSITIVITY = frozenset({"confidential", "pii", "financial", "credentials"})
SINK_PRIVILEGE = frozenset({"elevated", "admin"})


class GraphInvariantError(RuntimeError):
    """The builder produced a graph that breaks a §12 invariant: a bug, never input."""


def invariant_violations(nodes: dict[str, dict[str, Any]], edges: list[Relationship]) -> list[str]:
    out: list[str] = []
    runs_as: dict[str, int] = {}
    contains: dict[str, int] = {}
    for e in edges:
        src, dst, kind = e.source, e.target, e.kind
        for end in (src, dst):
            if end not in nodes:
                out.append(f"{kind} {src} -> {dst}: unknown node {end}")
        if dst == INTERNET:
            out.append(f"internet has in-edges ({kind} from {src})")
        if kind == "RUNS_AS":
            runs_as[src] = runs_as.get(src, 0) + 1
        if kind == "CONTAINS_SECRET":
            contains[dst] = contains.get(dst, 0) + 1
        if kind in FINDING_EDGES and not e.findings:
            out.append(f"{kind} {src} -> {dst} has no finding evidence")
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
    evidence: tuple[str, ...] = ()  # ids of the finding's own evidence (ADR-0017)
    file: str | None = None  # the finding's file: maps it to a derived service (X3)
    image: str | None = None  # a package installed in this image (X2)
    kev: bool = False  # listed as exploited in the wild


def exploit_assurance(tier: str | None) -> Assurance:
    """How well a finding supports "an attacker can exploit this service" (ADR-0017)."""
    if tier == "L3":
        return Assurance.VERIFIED
    if tier == "L2":
        return Assurance.INFERRED
    return Assurance.HYPOTHESIS  # L1 (only unreachable importers) or unknown


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
    assurance: Assurance = Assurance.VERIFIED  # the weakest edge's

    @property
    def hops(self) -> int:
        return len(self.nodes) - 1

    @property
    def label(self) -> str:
        return " → ".join(self.labels)


@dataclass
class AttackAnalysis:
    nodes: dict[str, dict[str, Any]] = field(default_factory=dict)
    edges: list[Relationship] = field(default_factory=list)
    evidence: dict[str, Evidence] = field(default_factory=dict)  # what the builder observed
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
            "paths_by_assurance": {
                a.value: n
                for a in Assurance
                if (n := sum(1 for p in self.paths if p.assurance is a))
            },
        }


def _svc(name: str) -> str:
    return f"service:{name}"


def _idn(name: str) -> str:
    return f"identity:{name}"


def _ds(name: str) -> str:
    return f"data_store:{name}"


def image_assurance(f: GraphFinding) -> Assurance:
    """An image package's reachability is not assessable (X2): a hypothesis, unless the
    advisory is known to be exploited in the wild, which is still only an inference."""
    return Assurance.INFERRED if f.kev else Assurance.HYPOTHESIS


def _image_key(ref: str) -> str:
    key = f"container_image:{ref}"
    return key if len(key) <= 160 else f"container_image:{stable_hash(ref)[:32]}"


def analyze(
    manifest: Manifest | None,
    findings: list[GraphFinding],
    *,
    manifest_file: str = "riskgraph.yaml",
    observed_at: dt.datetime | None = None,
    topology: Topology | None = None,
) -> AttackAnalysis:
    out = AttackAnalysis()
    g: nx.DiGraph[str] = nx.DiGraph()
    now = observed_at or dt.datetime.now(dt.UTC)

    def node(key: str, kind: str, label: str, **props: Any) -> None:
        out.nodes[key] = {"key": key, "kind": kind, "label": label, "properties": props}
        g.add_node(key)

    def declared(**facts: Any) -> str:
        e = make_evidence(
            producer=MANIFEST_PRODUCER,
            kind="declaration",
            assurance=Assurance.VERIFIED,
            confidence="high",
            locations=(Location(manifest_file),),
            facts=facts,
            observed_at=now,
        )
        out.evidence[e.id] = e
        return e.id

    def stated(d: Declared) -> str:
        """Evidence that an IaC file states ``d`` (X3): the file says so, verified."""
        e = make_evidence(
            producer=IAC_PRODUCER,
            kind=d.kind,
            assurance=Assurance.VERIFIED,
            confidence="high",
            locations=(Location(d.file, d.line, d.line),),
            facts=d.facts,
            observed_at=now,
        )
        out.evidence[e.id] = e
        return e.id

    def edge(
        src: str,
        dst: str,
        kind: str,
        p: float | None,
        assurance: Assurance,
        evidence: Iterable[str],
        from_findings: Iterable[GraphFinding] = (),
    ) -> None:
        used = list(from_findings)
        finding_evidence = [e for f in used for e in f.evidence]
        if kind in FINDING_EDGES and not finding_evidence:
            raise GraphInvariantError(f"{kind} {src} -> {dst} has no finding evidence")
        try:
            rel = Relationship(
                src,
                dst,
                kind,
                assurance,
                tuple(dict.fromkeys([*evidence, *finding_evidence])),
                p,
                tuple(f.index for f in used),
            )
        except ValueError as exc:  # no evidence at all
            raise GraphInvariantError(str(exc)) from exc
        out.edges.append(rel)
        if p is not None and p > 0:
            g.add_edge(
                src,
                dst,
                kind=kind,
                p=p,
                w=-math.log(p),
                findings=list(rel.findings),
                assurance=assurance,
            )

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

        # p comes from the most exploitable finding, and so does the edge's assurance: the
        # edge claims "p, because of that finding". The others are kept as evidence.
        exploit: dict[str, list[GraphFinding]] = {}
        for s in manifest.services:
            code = [
                f
                for f in by_service.get(s.name, [])
                if f.source_type in (SourceType.SCA, SourceType.SAST)
                and f.image is None  # image packages only reach derived services (X3)
                and f.tier != "L0"
                and f.exploit_p > 0
            ]
            if code:
                code.sort(key=lambda f: (-f.exploit_p, f.index))
                exploit[s.name] = code[:MAX_EVIDENCE]

        def exploit_edge(src: str, target: str, reason: str) -> None:
            top = exploit[target]
            edge(
                src,
                _svc(target),
                "EXPLOIT",
                top[0].exploit_p,
                exploit_assurance(top[0].tier),
                [reason],
                top,
            )

        verified = Assurance.VERIFIED
        for s in manifest.services:
            if s.exposure == "internet":
                exposed = declared(service=s.name, exposure="internet")
                edge(INTERNET, _svc(s.name), "EXPOSES", None, verified, [exposed])
                if s.name in exploit:
                    exploit_edge(INTERNET, s.name, exposed)
            if s.runs_as:
                ev = declared(service=s.name, runs_as=s.runs_as)
                edge(_svc(s.name), _idn(s.runs_as), "RUNS_AS", 1.0, verified, [ev])
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
                # the manifest names no identity: a rule fills the gap, so inferred
                ev = declared(service=s.name, runs_as=None)
                edge(_svc(s.name), UNKNOWN_IDENTITY, "RUNS_AS", 1.0, Assurance.INFERRED, [ev])
            for target in s.connects_to:
                ev = declared(service=s.name, connects_to=target)
                if any(d.name == target for d in manifest.data_stores):
                    edge(_svc(s.name), _ds(target), "CONNECTS_TO", 1.0, verified, [ev])
                elif target in exploit:
                    edge(_svc(s.name), _svc(target), "CONNECTS_TO", None, verified, [ev])
                    exploit_edge(_svc(s.name), target, ev)
                else:
                    edge(_svc(s.name), _svc(target), "CONNECTS_TO", None, verified, [ev])
        services = {s.name for s in manifest.services}
        for i in manifest.identities:
            for target in i.can_access:
                key = _svc(target) if target in services else _ds(target)
                ev = declared(identity=i.name, can_access=target)
                edge(_idn(i.name), key, "CAN_ACCESS", 1.0, verified, [ev])

    derived: dict[str, DerivedService] = {}
    if topology is not None and (manifest is None or not manifest.services):
        derived = _derive(out, node, edge, stated, topology, findings, sinks)

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
        home = topology.service_for(f.file) if derived and topology is not None else None
        if f.service and _svc(f.service) in out.nodes and manifest is not None:
            path = next((s.path for s in manifest.services if s.name == f.service), "")
            ev = declared(service=f.service, path=path or "/")
            edge(_svc(f.service), key, "CONTAINS_SECRET", 1.0, Assurance.VERIFIED, [ev], [f])
        elif home is not None and home in derived:
            # the file is inside the service's build context, which the Compose file states
            ds = derived[home]
            path = ds.path_prefix or "/"
            ev = stated(Declared(ds.declared.file, {"service": home, "path": path}))
            edge(_svc(home), key, "CONTAINS_SECRET", 1.0, Assurance.VERIFIED, [ev], [f])
        else:
            if REPOSITORY not in out.nodes:
                node(REPOSITORY, "repository", "repository")  # no in-edges: not on any path
            edge(REPOSITORY, key, "CONTAINS_SECRET", 1.0, Assurance.VERIFIED, [], [f])
        for ident in family_to_identity.get(f.secret_family or "", []):
            # a family match: nothing links this key to the identity (ADR-0017)
            ev = declared(identity=ident, credentials=f.secret_family)
            edge(
                key,
                _idn(ident),
                "AUTHENTICATES_AS",
                f.credential_p,
                Assurance.HYPOTHESIS,
                [ev],
                [f],
            )
        if f.public_secret:
            sources.append(key)

    broken = invariant_violations(out.nodes, out.edges)
    if broken:
        raise GraphInvariantError("; ".join(broken[:5]))
    for src in sources:
        g.add_edge(_VIRTUAL, src, kind="VIRTUAL", p=1.0, w=0.0, findings=[])
    _search(g, out, sinks)
    return out


def _derive(
    out: AttackAnalysis,
    node: Callable[..., None],
    edge: Callable[..., None],
    stated: Callable[[Declared], str],
    topology: Topology,
    findings: list[GraphFinding],
    sinks: dict[str, float],
) -> dict[str, DerivedService]:
    """Services from Compose and Kubernetes when the manifest declares none (ADR-0019).

    Edges: EXPOSES and EXPLOIT from the internet only where a file claims exposure
    (inferred); RUNS_IMAGE (not traversable); RUNS_AS to the ServiceAccount (verified when
    the pod spec names it, else inferred) or to the unknown identity; RBAC privilege makes
    the account a sink. Nothing connects two findings unless one of these rules does.
    """
    services = {s.name: s for s in topology.services}
    code: dict[str, list[GraphFinding]] = {}
    images: dict[str, list[GraphFinding]] = {}
    for f in findings:
        if f.source_type not in (SourceType.SCA, SourceType.SAST) or f.exploit_p <= 0:
            continue
        if f.image is not None:
            images.setdefault(f.image, []).append(f)
        elif f.tier != "L0" and (home := topology.service_for(f.file)) is not None:
            code.setdefault(home, []).append(f)

    for s in topology.services:
        key = _svc(s.name)
        node(
            key,
            "service",
            s.name,
            path=s.path_prefix if s.path_prefix is not None else None,
            exposure="internet" if s.exposure else None,
            derived_from=list(s.sources),
            findings=len(code.get(s.name, [])),
        )
        for img in s.images:
            ikey = _image_key(img.ref)
            if ikey not in out.nodes:
                node(ikey, "container_image", img.ref[:200], ref=img.ref)
            edge(key, ikey, "RUNS_IMAGE", None, img.assurance, [stated(img.declared)])

        if s.identity is not None and s.identity_declared is not None:
            ikey = f"identity:sa:{s.identity}"
            if ikey not in out.nodes:
                node(
                    ikey,
                    "identity",
                    f"service account {s.identity}",
                    privilege=s.privilege,
                    service_account=s.identity,
                )
                if s.privilege in SINK_PRIVILEGE:
                    sinks[ikey] = P_VALUES[s.privilege]
            ev = [stated(s.identity_declared), *(stated(b) for b in s.bindings)]
            edge(key, ikey, "RUNS_AS", 1.0, s.identity_assurance, ev)
        else:
            if UNKNOWN_IDENTITY not in out.nodes:
                node(
                    UNKNOWN_IDENTITY, "identity", "unknown identity", privilege=None, synthetic=True
                )
            ev = [stated(Declared(s.declared.file, {"service": s.name, "runs_as": None}))]
            edge(key, UNKNOWN_IDENTITY, "RUNS_AS", 1.0, Assurance.INFERRED, ev)

        if s.exposure is None:
            continue
        exposed = stated(s.exposure)
        edge(INTERNET, key, "EXPOSES", None, Assurance.INFERRED, [exposed])
        # the edge rests on its best-assured finding first, then the most exploitable;
        # it is never more assured than the exposure it starts from
        candidates = [
            *((f, exploit_assurance(f.tier)) for f in code.get(s.name, [])),
            *((f, image_assurance(f)) for img in s.images for f in images.get(img.ref, [])),
        ]
        if not candidates:
            continue
        candidates.sort(key=lambda c: (-c[1].rank, -c[0].exploit_p, c[0].index))
        top, level = candidates[0]
        used = list(dict.fromkeys(f for f, _ in candidates))[:MAX_EVIDENCE]
        edge(
            INTERNET,
            key,
            "EXPLOIT",
            top.exploit_p,
            min_assurance([level, Assurance.INFERRED]),
            [exposed],
            [top, *(f for f in used if f is not top)],
        )
    return services


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
    # Hop pre-filter (blueprint §13.2: BFS kept as the reachable-set computation). A path
    # of at most MAX_HOPS edges (plus the virtual edge) only visits nodes whose hop
    # distance from the source plus to the sink fits the budget, so pruning the others is
    # exact. Without it, Yen enumerates long candidates only to drop them afterwards.
    budget = MAX_HOPS + 1
    from_source = nx.single_source_shortest_path_length(g, _VIRTUAL, cutoff=budget)
    reverse = g.reverse(copy=False)
    for sink, impact in sorted(sinks.items()):
        if sink not in from_source:
            continue  # no path within the hop limit
        to_sink = nx.single_source_shortest_path_length(reverse, sink, cutoff=budget)
        keep = [n for n, d in to_sink.items() if n in from_source and from_source[n] + d <= budget]
        bounded = g.subgraph(keep)
        rank = 0
        try:
            candidates = nx.shortest_simple_paths(bounded, _VIRTUAL, sink, weight="w")
            for raw in islice(candidates, MAX_CANDIDATES):
                nodes = raw[1:]
                if len(nodes) - 1 > MAX_HOPS or len(nodes) < 2:
                    continue
                hops = list(pairwise(nodes))
                kinds = [bounded.edges[a, b]["kind"] for a, b in hops]
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
        if path.assurance is Assurance.HYPOTHESIS:
            continue  # a path to verify: listed, but it never raises a score (ADR-0017)
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
                "assurance": data["assurance"].value,
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
        assurance=min_assurance(g.edges[a, b]["assurance"] for a, b in hops),
    )
