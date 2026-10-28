"""Module import graph, entry points and the reachable set (pure; blueprint §11.3).

Input is the extractor's JSON. Internal imports are resolved to repository files;
everything else is a third-party import name (stdlib / Node built-ins dropped).
"""

from __future__ import annotations

import posixpath
import sys
from collections import deque
from dataclasses import dataclass, field
from typing import Any

NODE_BUILTINS = frozenset(
    {
        "assert", "buffer", "child_process", "cluster", "crypto", "dgram", "dns", "events",
        "fs", "http", "http2", "https", "net", "os", "path", "perf_hooks", "process",
        "querystring", "readline", "stream", "string_decoder", "timers", "tls", "tty", "url",
        "util", "v8", "vm", "worker_threads", "zlib", "module", "async_hooks", "inspector",
    }
)  # fmt: skip
JS_EXTENSIONS = ("", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")
JS_INDEX = tuple(f"/index{ext}" for ext in (".js", ".jsx", ".mjs", ".ts", ".tsx"))


@dataclass
class ModuleGraph:
    files: dict[str, dict[str, Any]]
    edges: dict[str, set[str]] = field(default_factory=dict)  # file -> internal files
    external: dict[str, set[str]] = field(default_factory=dict)  # import name -> files
    entries: dict[str, list[str]] = field(default_factory=dict)  # file -> reasons
    parent: dict[str, str | None] = field(default_factory=dict)  # BFS tree from entries
    script_commands: dict[str, set[str]] = field(default_factory=dict)  # dir -> npm script cmds

    @property
    def reachable(self) -> set[str]:
        return set(self.parent)

    def chain_to(self, file: str, limit: int = 8) -> list[str]:
        """Entry point → … → file, following the BFS tree."""
        chain: list[str] = []
        node: str | None = file
        while node is not None and len(chain) < limit:
            chain.append(node)
            node = self.parent.get(node)
        return list(reversed(chain))

    def entries_in(self, scope: str) -> bool:
        return any(f.startswith(scope) for f in self.entries)


def _python_roots(files: set[str]) -> list[str]:
    """Directories that act as import roots: repo root, src/, parents of top-level packages."""
    roots = {"", "src/"}
    for f in files:
        if f.endswith("/__init__.py"):
            pkg = posixpath.dirname(f)
            parent = posixpath.dirname(pkg)
            if (
                f"{parent}/__init__.py" not in files
                and (parent or "") + "/__init__.py" not in files
            ):
                roots.add(f"{parent}/" if parent else "")
    return sorted(roots, key=len, reverse=True)


def _python_module_index(files: set[str]) -> dict[str, str]:
    index: dict[str, str] = {}
    for root in _python_roots(files):
        for f in files:
            if not f.endswith(".py") or not f.startswith(root):
                continue
            rel = f[len(root) :][:-3]
            if rel.endswith("/__init__"):
                rel = rel[: -len("/__init__")]
            if not rel or rel == "__init__":
                continue
            index.setdefault(rel.replace("/", "."), f)
    return index


def _resolve_python(
    file: str, imp: dict[str, Any], index: dict[str, str], internal_tops: set[str]
) -> tuple[list[str], str | None]:
    """Internal files an import refers to, and its third-party top-level name (if any)."""
    module = str(imp.get("module") or "")
    names = [str(n) for n in imp.get("names") or []]
    level = int(imp.get("level") or 0)
    if level:
        own = next((m for m, f in index.items() if f == file), None)
        parts = own.split(".") if own else []
        package = parts if file.endswith("__init__.py") else parts[:-1]
        package = package[: max(0, len(package) - (level - 1))]
        base = ".".join([*package, *([module] if module else [])])
        candidates = [f"{base}.{n}" if base else n for n in names] + ([base] if base else [])
        return [index[c] for c in candidates if c in index], None
    candidates = [f"{module}.{n}" for n in names] + [module]
    parts = module.split(".")
    candidates += [".".join(parts[:i]) for i in range(len(parts) - 1, 0, -1)]
    hits = [index[c] for c in candidates if c in index]
    top = parts[0]
    if hits or top in internal_tops:
        return hits, None
    if top in sys.stdlib_module_names or not top:
        return [], None
    return [], module


def _resolve_js(file: str, spec: str, files: set[str]) -> tuple[list[str], str | None]:
    if spec.startswith((".", "/")):
        base = posixpath.normpath(posixpath.join(posixpath.dirname(file), spec)).lstrip("/")
        for suffix in (*JS_EXTENSIONS, *JS_INDEX):
            if base + suffix in files:
                return [base + suffix], None
        return [], None
    if spec.startswith("node:"):
        return [], None
    parts = spec.split("/")
    name = "/".join(parts[:2]) if spec.startswith("@") else parts[0]
    if name in NODE_BUILTINS or name.startswith("@/") or name == "@" or name.startswith("~"):
        return [], None  # built-in, or a bundler path alias
    return [], name


def python_module_index(files: set[str]) -> dict[str, str]:
    """Dotted module name -> repository file, for every import root."""
    return _python_module_index(files)


def module_of_file(index: dict[str, str]) -> dict[str, str]:
    """Repository file -> its dotted module name (the first one, as the index has it)."""
    out: dict[str, str] = {}
    for module, file in index.items():
        out.setdefault(file, module)
    return out


def resolve_python_name(
    file: str,
    module: str,
    name: str | None,
    level: int,
    index: dict[str, str],
    modules: dict[str, str] | None = None,
) -> tuple[str | None, str | None]:
    """What ``from <module> import <name>`` (or ``import <module>``) in ``file`` binds:
    (the module file ``module.name``, None) when ``name`` is itself a module, else (the
    file of ``module``, ``name``). (None, None) when it is not a repository file.
    ``modules`` is ``module_of_file(index)``; pass it when resolving many names."""
    base = module
    if level:
        if modules is not None:
            own = modules.get(file)
        else:
            own = next((m for m, f in index.items() if f == file), None)
        parts = own.split(".") if own else []
        package = parts if file.endswith("__init__.py") else parts[:-1]
        package = package[: max(0, len(package) - (level - 1))]
        base = ".".join([*package, *([module] if module else [])])
    if name and (f"{base}.{name}" if base else name) in index:
        return index[f"{base}.{name}" if base else name], None
    if base in index:
        return index[base], name
    return None, None


def resolve_js_module(file: str, spec: str, files: set[str]) -> str | None:
    """The repository file a relative ``require``/``import`` in ``file`` refers to."""
    hits, _ = _resolve_js(file, spec, files)
    return hits[0] if hits else None


def build(extracted: dict[str, Any], manifest_entrypoints: list[str] | None = None) -> ModuleGraph:
    files = {k: v for k, v in (extracted.get("files") or {}).items() if isinstance(v, dict)}
    graph = ModuleGraph(files=files)
    names = set(files)
    index = _python_module_index(names)
    internal_tops = {m.split(".")[0] for m in index}

    for f, info in files.items():
        edges: set[str] = set()
        for imp in info.get("imports") or []:
            if info.get("lang") == "python":
                hits, ext = _resolve_python(f, imp, index, internal_tops)
                if ext:
                    graph.external.setdefault(ext.split(".")[0], set()).add(f)
                    graph.external.setdefault(ext, set()).add(f)
            else:
                hits, ext = _resolve_js(f, str(imp.get("module") or ""), names)
                if ext:
                    graph.external.setdefault(ext, set()).add(f)
            edges.update(h for h in hits if h != f)
        graph.edges[f] = edges
        if info.get("entry"):
            graph.entries[f] = list(info["entry"])

    for pj, info in (extracted.get("package_json") or {}).items():
        root = posixpath.dirname(pj)
        graph.script_commands[f"{root}/" if root else ""] = set(info.get("script_commands") or [])
        for target in [info.get("main"), *(info.get("bin") or []), *(info.get("exports") or [])]:
            if isinstance(target, str):
                hits, _ = _resolve_js(
                    f"{root}/x.js" if root else "x.js", "./" + target.lstrip("./"), names
                )
                for h in hits:
                    graph.entries.setdefault(h, []).append("package.json")
    for ep in manifest_entrypoints or []:
        ep = posixpath.normpath(ep.lstrip("/"))
        if ep in names:
            graph.entries.setdefault(ep, []).append("manifest entrypoint")

    queue: deque[str] = deque()
    for e in sorted(graph.entries):
        graph.parent[e] = None
        queue.append(e)
    while queue:
        cur = queue.popleft()
        for nxt in sorted(graph.edges.get(cur, ())):
            if nxt not in graph.parent:
                graph.parent[nxt] = cur
                queue.append(nxt)
    return graph
