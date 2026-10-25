"""L3: a known-vulnerable symbol called on a path from an entry point (blueprint §11.3, ADR-0015).

The call graph is intraprocedural name resolution only, as the blueprint states: a call is
resolved through the module's import aliases and to functions defined in the same module or
in an imported project module. Nothing is inferred from types, decorators that rewrite
functions, getattr, dict dispatch or plugins: those calls are not recorded, so the finding
stays at L2. That is the under-claim rule: L3 needs a visible call, or it is not claimed.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from pathlib import Path

import yaml

from riskgraph.modules.reachability.graph import ModuleGraph, _python_module_index

SYMBOLS_FILE = Path(__file__).with_name("vulnerable_symbols.yaml")
MAX_NODES = 20_000
MODULE = "<module>"


@dataclass(frozen=True, slots=True)
class SymbolEntry:
    cve: str
    package: str
    symbols: frozenset[str]


def load_symbols(path: Path = SYMBOLS_FILE) -> dict[str, SymbolEntry]:
    """CVE id -> curated symbols. A malformed file is a configuration error, raised at start."""
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or doc.get("version") != 1:
        raise ValueError("vulnerable_symbols.yaml: unsupported version")
    out: dict[str, SymbolEntry] = {}
    for entry in doc.get("entries") or []:
        symbols = frozenset(str(s) for s in entry.get("symbols") or [])
        if not symbols:
            raise ValueError(f"{entry.get('cve')}: no symbols")
        out[str(entry["cve"])] = SymbolEntry(str(entry["cve"]), str(entry["package"]), symbols)
    return out


SYMBOLS = load_symbols()


def _qualify(dotted: str, aliases: dict[str, str]) -> str:
    head, _, rest = dotted.partition(".")
    base = aliases.get(head, head)
    return f"{base}.{rest}" if rest else base


@dataclass(frozen=True, slots=True)
class Path3:
    symbol: str
    file: str
    function: str
    chain: tuple[tuple[str, str], ...]  # (file, function) from entry to the call


Node = tuple[str, str]  # (file, function name or MODULE)


def _resolve(
    graph: ModuleGraph, symbols: frozenset[str], scope: str
) -> tuple[dict[Node, str], dict[Node, set[Node]], list[Node]]:
    """Sink calls, resolved call edges and entry nodes of the Python call graph."""
    py = {f: info for f, info in graph.files.items() if info.get("lang") == "python"}
    index = _python_module_index(set(py))  # module name -> file
    sinks: dict[Node, str] = {}
    edges: dict[Node, set[Node]] = {}
    for f, info in py.items():
        calls = info.get("calls") or {}
        aliases = calls.get("aliases") or {}
        functions = calls.get("functions") or {}
        owners = {
            MODULE: calls.get("module_calls") or [],
            **{name: (data or {}).get("calls") or [] for name, data in functions.items()},
        }
        for owner, raw in owners.items():
            node = (f, owner)
            for dotted in raw:
                qualified = _qualify(dotted, aliases)
                if qualified in symbols and f.startswith(scope):
                    sinks.setdefault(node, qualified)
                    continue
                if "." not in dotted and dotted in functions:  # same-module function
                    edges.setdefault(node, set()).add((f, dotted))
                    continue
                mod, _, func = qualified.rpartition(".")
                target = index.get(mod)
                if target and func in (
                    (py.get(target, {}).get("calls") or {}).get("functions") or {}
                ):
                    edges.setdefault(node, set()).add((target, func))
    starts = [(f, MODULE) for f in py if f in graph.parent]
    starts += [
        (f, name)
        for f in py
        if f in graph.parent
        for name, data in ((py[f].get("calls") or {}).get("functions") or {}).items()
        if (data or {}).get("entry")
    ]
    return sinks, edges, starts


def _bfs(
    edges: dict[Node, set[Node]], starts: list[Node], stop: dict[Node, str] | None = None
) -> tuple[dict[Node, Node | None], Node | None]:
    """Breadth-first parents from the entry nodes; stops at the first node in ``stop``."""
    seen: dict[Node, Node | None] = {}
    queue: deque[Node] = deque()
    for s in starts:
        if s not in seen:
            seen[s] = None
            queue.append(s)
    while queue and len(seen) < MAX_NODES:
        node = queue.popleft()
        if stop is not None and node in stop:
            return seen, node
        for nxt in sorted(edges.get(node, ())):
            if nxt not in seen:
                seen[nxt] = node
                queue.append(nxt)
    return seen, None


def chain_to(parents: dict[Node, Node | None], node: Node) -> tuple[Node, ...]:
    chain = [node]
    while (parent := parents[chain[-1]]) is not None:
        chain.append(parent)
    return tuple(reversed(chain))


def find_l3(graph: ModuleGraph, symbols: frozenset[str], scope: str) -> Path3 | None:
    """Breadth-first from every entry point to the first call of a symbol under ``scope``."""
    sinks, edges, starts = _resolve(graph, symbols, scope)
    seen, hit = _bfs(edges, starts, sinks)
    if hit is None:
        return None
    return Path3(sinks[hit], hit[0], hit[1], chain_to(seen, hit))


def reachable_functions(graph: ModuleGraph) -> dict[Node, Node | None]:
    """Every (file, function) a resolved call path from an entry point reaches, with parents."""
    _, edges, starts = _resolve(graph, frozenset(), "")
    seen, _ = _bfs(edges, starts)
    return seen


def enclosing_function(graph: ModuleGraph, file: str, line: int) -> str | None:
    """The innermost Python function whose span holds ``line``; MODULE outside every function.

    ``None`` when the file has no call data (not Python, or not parsed): no claim is made.
    """
    calls = (graph.files.get(file) or {}).get("calls")
    if not isinstance(calls, dict):
        return None
    best: tuple[int, str] | None = None
    for name, data in (calls.get("functions") or {}).items():
        for start, end in (data or {}).get("spans") or []:
            if start <= line <= end and (best is None or end - start < best[0]):
                best = (end - start, name)
    return best[1] if best else MODULE
