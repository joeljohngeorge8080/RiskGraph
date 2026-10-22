"""Reachability tier per finding (blueprint §11.3; ADR-0012).

Principle: never demote on missing evidence. A tier is only lower than "unknown" when
the import graph positively shows the code is not used.
"""

from __future__ import annotations

import posixpath
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from riskgraph.modules.reachability.callgraph import SYMBOLS, find_l3
from riskgraph.modules.reachability.graph import ModuleGraph
from riskgraph.modules.reachability.package_names import (
    PYTHON_ECOSYSTEMS,
    import_names,
    used_without_import,
)
from riskgraph.shared.vocabulary import ReachabilityTier, SourceType

MAX_EVIDENCE_FILES = 5
_RANK = {ReachabilityTier.L2: 3, ReachabilityTier.L1: 2, ReachabilityTier.L0: 1}


@dataclass(frozen=True, slots=True)
class Verdict:
    tier: ReachabilityTier
    confidence: str
    evidence: dict[str, Any] = field(default_factory=dict)


UNKNOWN = Verdict(ReachabilityTier.UNKNOWN, "low")
NOT_APPLICABLE = Verdict(ReachabilityTier.NOT_APPLICABLE, "high")


def _scope(target: str) -> str:
    d = posixpath.dirname(target)
    return f"{d}/" if d else ""


class TierClassifier:
    def __init__(self, graph: ModuleGraph, deps: dict[str, dict[str, Any]]) -> None:
        self.graph = graph
        self.deps = deps

    def _imported(self, names: tuple[str, ...], scope: str) -> Verdict | None:
        g = self.graph
        importers = sorted({f for n in names for f in g.external.get(n, ()) if f.startswith(scope)})
        if not importers:
            return None
        reachable = [f for f in importers if f in g.parent]
        if reachable:
            ev: dict[str, Any] = {
                "importers": importers[:MAX_EVIDENCE_FILES],
                "chain": g.chain_to(reachable[0]),
            }
            return Verdict(ReachabilityTier.L2, "medium", ev)
        if g.entries_in(scope):
            ev = {
                "importers": importers[:MAX_EVIDENCE_FILES],
                "reason": "no entry point reaches the importing code",
            }
            return Verdict(ReachabilityTier.L1, "medium", ev)
        ev = {"importers": importers[:MAX_EVIDENCE_FILES], "reason": "no entry points detected"}
        return Verdict(ReachabilityTier.L2, "low", ev)

    def _script_command(self, name: str, scope: str) -> bool:
        """Invoked by an npm script (``"start": "forever server.js"``): used, not imported."""
        cmds = self.graph.script_commands.get(scope, set())
        return name in cmds or name.rsplit("/", 1)[-1] in cmds

    def _has_code(self, ecosystem: str | None, scope: str) -> bool:
        lang = "python" if (ecosystem or "").lower() in PYTHON_ECOSYSTEMS else "js"
        return any(
            f.startswith(scope) and i.get("lang") == lang for f, i in self.graph.files.items()
        )

    def sca(
        self,
        ecosystem: str | None,
        name: str,
        version: str,
        target: str,
        vulnerability_id: str | None = None,
    ) -> Verdict:
        names = import_names(ecosystem, name)
        if names is None:
            return Verdict(
                ReachabilityTier.UNKNOWN, "low", {"reason": f"ecosystem {ecosystem} not analysed"}
            )
        scope = _scope(target)
        if not self._has_code(ecosystem, scope):
            return Verdict(
                ReachabilityTier.UNKNOWN,
                "low",
                {"reason": "no parsed source files next to the manifest"},
            )
        if vulnerability_id in SYMBOLS:
            l3 = find_l3(self.graph, SYMBOLS[vulnerability_id].symbols, scope)
            if l3 is not None:
                ev = {
                    "symbol": l3.symbol,
                    "function": l3.function,
                    "file": l3.file,
                    "chain": [f"{f}:{fn}" for f, fn in l3.chain],
                    "cve": vulnerability_id,
                }
                return Verdict(ReachabilityTier.L3, "medium", ev)
        hit = self._imported(names, scope)
        if hit is not None:
            return hit
        if used_without_import(name) or self._script_command(name, scope):
            return Verdict(
                ReachabilityTier.UNKNOWN, "low", {"reason": "tool or plugin used without imports"}
            )

        target_deps = self.deps.get(target) or {}
        packages: dict[str, dict[str, Any]] = target_deps.get("packages") or {}
        entry = next(
            (
                p
                for p in packages.values()
                if p["name"].lower() == name.lower() and p["version"] == version
            ),
            None,
        )
        relationship = entry["relationship"] if entry else None
        if relationship == "indirect":
            return self._via_ancestors(ecosystem, name, version, packages, scope)
        confidence = (
            "high" if target_deps.get("has_graph") and relationship == "direct" else "medium"
        )
        return Verdict(
            ReachabilityTier.L0,
            confidence,
            {
                "searched": list(names),
                "scope": scope or "/",
                "relationship": relationship or "declared",
            },
        )

    def _via_ancestors(
        self,
        ecosystem: str | None,
        name: str,
        version: str,
        packages: dict[str, dict[str, Any]],
        scope: str,
    ) -> Verdict:
        reverse: dict[str, list[str]] = {}
        for pid, p in packages.items():
            for dep in p["depends_on"]:
                reverse.setdefault(dep, []).append(pid)
        start = next(
            (
                pid
                for pid, p in packages.items()
                if p["name"].lower() == name.lower() and p["version"] == version
            ),
            None,
        )
        if start is None:
            return UNKNOWN
        seen, queue, direct = {start}, deque([start]), []
        while queue and len(seen) < 5000:
            for parent in reverse.get(queue.popleft(), []):
                if parent in seen:
                    continue
                seen.add(parent)
                if packages[parent]["relationship"] == "direct":
                    direct.append(parent)
                else:
                    queue.append(parent)
        if not direct:
            return Verdict(
                ReachabilityTier.UNKNOWN,
                "low",
                {"reason": "indirect dependency without a known parent"},
            )
        best: Verdict | None = None
        best_parent = ""
        for pid in direct:
            p = packages[pid]
            names = import_names(ecosystem, p["name"]) or ()
            hit = self._imported(names, scope)
            if hit is None and (
                used_without_import(p["name"]) or self._script_command(p["name"], scope)
            ):
                return Verdict(
                    ReachabilityTier.UNKNOWN,
                    "low",
                    {"via": p["name"], "reason": "parent used without imports"},
                )
            v = hit or Verdict(ReachabilityTier.L0, "medium", {})
            if best is None or _RANK[v.tier] > _RANK[best.tier]:
                best, best_parent = v, p["name"]
        if best is None:
            return UNKNOWN
        conf = "medium" if best.confidence != "low" else "low"
        return Verdict(
            best.tier, conf, {**best.evidence, "via": best_parent, "relationship": "indirect"}
        )

    def sast(self, file: str) -> Verdict:
        g = self.graph
        if file not in g.files:
            return Verdict(ReachabilityTier.UNKNOWN, "low", {"reason": "file not analysed"})
        if file in g.parent:
            return Verdict(ReachabilityTier.L2, "medium", {"chain": g.chain_to(file)})
        if g.entries:
            return Verdict(
                ReachabilityTier.L1, "medium", {"reason": "no entry point reaches this file"}
            )
        return Verdict(ReachabilityTier.UNKNOWN, "low", {"reason": "no entry points detected"})

    def classify(
        self,
        source_type: SourceType,
        file: str,
        package: dict[str, Any] | None,
        vulnerability_id: str | None = None,
    ) -> Verdict:
        if source_type is SourceType.SAST:
            return self.sast(file)
        if source_type is SourceType.SCA and package:
            return self.sca(
                package.get("ecosystem"),
                str(package.get("name") or ""),
                str(package.get("version") or ""),
                file,
                vulnerability_id,
            )
        return NOT_APPLICABLE
