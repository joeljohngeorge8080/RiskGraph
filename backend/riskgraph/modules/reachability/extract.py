"""Import and entry-point extraction with tree-sitter (blueprint §11.3, threat T-07).

Runs as its own process so a hostile file that crashes or exhausts the parser cannot
take the worker down:

    python -I -m riskgraph.modules.reachability.extract SRC_DIR OUT_JSON

The worker starts it through ``SubprocessRunner`` (argv list, no network, rlimits incl.
an address-space cap, timeout). Repository code is parsed, never imported or executed.
Output (JSON):

    {"version": 1, "files": {"app.py": {"lang": "python",
        "imports": [{"module": "yaml", "names": [], "level": 0}],
        "entry": ["route decorator"],
        "http": {"routes": [...], "assigns": {...}, ...}}},   # routes.py, X5
     "package_json": {"web/package.json": {"main": "server.js", "bin": [...]}},
     "skipped": 3, "truncated": false}
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from riskgraph.modules.reachability.routes import js_routes, python_routes
from riskgraph.modules.reachability.syntax import dotted as _dotted
from riskgraph.modules.reachability.syntax import string_value as _string_value
from riskgraph.modules.reachability.syntax import text as _text
from riskgraph.modules.reachability.syntax import walk as _walk

ANALYZER_VERSION = "ts-imports.5"
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_SPANS_PER_NAME = 8  # a name defined in several classes keeps a few spans
MAX_FILES = 50_000
MAX_IMPORTS_PER_FILE = 2_000
SKIP_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        ".venv",
        "venv",
        "env",
        "vendor",
        "dist",
        "build",
        "site-packages",
        "__pycache__",
        ".tox",
        ".mypy_cache",
        "bower_components",
        "coverage",
    }
)
LANG_BY_SUFFIX = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
}
PY_ENTRY_FILES = frozenset({"manage.py", "wsgi.py", "asgi.py", "urls.py", "__main__.py"})
_PY_ROUTE = re.compile(
    r"^@\s*[\w.]+\.(route|get|post|put|delete|patch|head|options|websocket|api_route|task)\b"
)
_PY_TASK = re.compile(r"^@\s*(shared_task|api_view|task)\b")
_JS_SERVER = re.compile(r"^(express|fastify|Koa|createServer|http\.createServer|Hono)$")
_JS_ROUTE = re.compile(r"^\w+\.(get|post|put|delete|patch|all|use|route|listen)$")
_NEXT_ROUTE = re.compile(r"(^|/)(pages|app)/.+\.(js|jsx|ts|tsx)$")


def _parsers() -> dict[str, Any]:
    import tree_sitter_javascript as tsjs
    import tree_sitter_python as tspy
    import tree_sitter_typescript as tsts
    from tree_sitter import Language, Parser

    return {
        "python": Parser(Language(tspy.language())),
        "javascript": Parser(Language(tsjs.language())),
        "typescript": Parser(Language(tsts.language_typescript())),
        "tsx": Parser(Language(tsts.language_tsx())),
    }


def _python(tree: Any, rel: str) -> tuple[list[dict[str, Any]], list[str]]:
    imports: list[dict[str, Any]] = []
    entry: set[str] = set()
    if Path(rel).name in PY_ENTRY_FILES:
        entry.add(f"{Path(rel).name} convention")
    for node in _walk(tree.root_node):
        if node.type == "import_statement":
            for child in node.named_children:
                target = (
                    child.child_by_field_name("name") if child.type == "aliased_import" else child
                )
                if target is not None and target.type == "dotted_name":
                    imports.append({"module": _text(target), "names": [], "level": 0})
        elif node.type == "import_from_statement":
            mod = node.child_by_field_name("module_name")
            level, module = 0, ""
            if mod is not None and mod.type == "relative_import":
                for part in mod.named_children:
                    if part.type == "import_prefix":
                        level = _text(part).count(".")
                    elif part.type == "dotted_name":
                        module = _text(part)
            elif mod is not None:
                module = _text(mod)
            names = []
            for child in node.children_by_field_name("name"):
                target = (
                    child.child_by_field_name("name") if child.type == "aliased_import" else child
                )
                if target is not None:
                    names.append(_text(target))
            imports.append({"module": module, "names": names[:50], "level": level})
        elif node.type == "decorator":
            text = _text(node).strip()
            if _PY_ROUTE.match(text):
                entry.add("route decorator")
            elif _PY_TASK.match(text):
                entry.add("task/view decorator")
        elif node.type == "if_statement":
            cond = node.child_by_field_name("condition")
            if cond is not None and "__name__" in _text(cond) and "__main__" in _text(cond):
                entry.add("__main__ guard")
        if len(imports) >= MAX_IMPORTS_PER_FILE:
            break
    return imports, sorted(entry)


MAX_CALLS_PER_FUNCTION = 500
MAX_FUNCTIONS_PER_FILE = 2_000
MODULE = "<module>"  # the pseudo-function for code that runs when the module is imported


def _python_calls(tree: Any) -> dict[str, Any]:
    """Aliases, functions and their direct calls, for the L3 call graph (ADR-0015).

    Only names are recorded: ``yaml.load(x)`` as "yaml.load"; ``getattr(m, n)(x)`` and calls
    on call results record nothing, so dynamic dispatch is an under-claim, never a finding.
    """
    aliases: dict[str, str] = {}
    functions: dict[str, dict[str, Any]] = {}
    calls_by_owner: dict[str, list[str]] = {MODULE: []}
    entries: set[str] = set()

    def owner_of(node: Any) -> str:
        cur = node.parent
        while cur is not None:
            if cur.type == "function_definition":
                return _text(cur.child_by_field_name("name"))
            cur = cur.parent
        return MODULE

    for node in _walk(tree.root_node):
        if node.type == "import_statement":
            for child in node.named_children:
                if child.type == "aliased_import":
                    name, alias = (
                        child.child_by_field_name("name"),
                        child.child_by_field_name("alias"),
                    )
                    if name is not None and alias is not None:
                        aliases[_text(alias)] = _text(name)
                elif child.type == "dotted_name":
                    head = _text(child).split(".")[0]
                    aliases.setdefault(head, head)
        elif node.type == "import_from_statement":
            mod = node.child_by_field_name("module_name")
            if mod is None or mod.type != "dotted_name":
                continue  # relative imports are resolved by the import graph, not here
            module = _text(mod)
            for child in node.children_by_field_name("name"):
                if child.type == "aliased_import":
                    name, alias = (
                        child.child_by_field_name("name"),
                        child.child_by_field_name("alias"),
                    )
                    if name is not None and alias is not None:
                        aliases[_text(alias)] = f"{module}.{_text(name)}"
                elif child.type == "dotted_name":
                    aliases[_text(child)] = f"{module}.{_text(child)}"
        elif node.type == "function_definition":
            name = _text(node.child_by_field_name("name"))
            if len(functions) < MAX_FUNCTIONS_PER_FILE:
                info = functions.setdefault(name, {"entry": False, "spans": []})
                calls_by_owner.setdefault(name, [])
                if len(info["spans"]) < MAX_SPANS_PER_NAME:
                    # 1-based lines, so a scanner's line number maps to its enclosing function
                    info["spans"].append([node.start_point[0] + 1, node.end_point[0] + 1])
            parent = node.parent
            if parent is not None and parent.type == "decorated_definition":
                for dec in parent.named_children:
                    if dec.type == "decorator" and (
                        _PY_ROUTE.match(_text(dec).strip()) or _PY_TASK.match(_text(dec).strip())
                    ):
                        entries.add(name)
        elif node.type == "call":
            owner = owner_of(node)
            bucket = calls_by_owner.setdefault(owner, [])
            callee = _dotted(node.child_by_field_name("function"))
            if callee and len(bucket) < MAX_CALLS_PER_FUNCTION:
                bucket.append(callee)
    for name in entries:
        if name in functions:
            functions[name]["entry"] = True
    out_functions = {
        name: {
            "entry": info["entry"],
            "calls": calls_by_owner.get(name, [])[:MAX_CALLS_PER_FUNCTION],
            "spans": info["spans"],
        }
        for name, info in functions.items()
    }
    return {
        "aliases": dict(list(aliases.items())[:MAX_IMPORTS_PER_FILE]),
        "functions": out_functions,
        "module_calls": calls_by_owner.get(MODULE, [])[:MAX_CALLS_PER_FUNCTION],
    }


def _js(tree: Any, rel: str) -> tuple[list[dict[str, Any]], list[str]]:
    imports: list[dict[str, Any]] = []
    entry: set[str] = set()
    if _NEXT_ROUTE.search(rel) and "/components/" not in rel:
        entry.add("framework route file")
    for node in _walk(tree.root_node):
        if node.type in ("import_statement", "export_statement"):
            spec = _string_value(node.child_by_field_name("source"))
            if spec:
                imports.append({"module": spec, "names": [], "level": 0})
        elif node.type == "call_expression":
            fn = node.child_by_field_name("function")
            args = node.child_by_field_name("arguments")
            fn_text = _text(fn) if fn is not None else ""
            if (
                fn is not None
                and fn.type in ("identifier", "import")
                and fn_text in ("require", "import")
            ):
                first = args.named_children[0] if args is not None and args.named_children else None
                spec = _string_value(first)
                if spec:
                    imports.append({"module": spec, "names": [], "level": 0})
            elif _JS_SERVER.match(fn_text):
                entry.add("server constructor")
            elif _JS_ROUTE.match(fn_text) and fn_text.split(".")[0] in (
                "app",
                "router",
                "server",
                "fastify",
                "api",
            ):
                entry.add("route registration")
        if len(imports) >= MAX_IMPORTS_PER_FILE:
            break
    return imports, sorted(entry)


def _package_json(path: Path) -> dict[str, Any] | None:
    try:
        if path.stat().st_size > 256 * 1024:
            return None
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(doc, dict):
        return None
    out: dict[str, Any] = {}
    if isinstance(doc.get("main"), str):
        out["main"] = doc["main"]
    bin_ = doc.get("bin")
    if isinstance(bin_, str):
        out["bin"] = [bin_]
    elif isinstance(bin_, dict):
        out["bin"] = [v for v in bin_.values() if isinstance(v, str)][:20]
    scripts = doc.get("scripts")
    if isinstance(scripts, dict):
        # command words of npm scripts ("forever start server.js && grunt test")
        words = set()
        for cmd in list(scripts.values())[:100]:
            if isinstance(cmd, str):
                for part in re.split(r"&&|\|\||;|\|", cmd[:500]):
                    tokens = [t for t in part.split() if "=" not in t]
                    if tokens:
                        words.add(tokens[0].removeprefix("./node_modules/.bin/"))
                    if tokens[:1] == ["npx"] and len(tokens) > 1:
                        words.add(tokens[1])
        out["script_commands"] = sorted(words)[:100]
    exports = doc.get("exports")
    if isinstance(exports, str):
        out["exports"] = [exports]
    elif isinstance(exports, dict):
        out["exports"] = [v for v in exports.values() if isinstance(v, str)][:20]
    return out


def extract(src: Path) -> dict[str, Any]:
    parsers = _parsers()
    files: dict[str, Any] = {}
    package_json: dict[str, Any] = {}
    skipped = 0
    truncated = False
    count = 0
    for dirpath, dirnames, filenames in os.walk(src, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith("."))
        for name in sorted(filenames):
            path = Path(dirpath) / name
            rel = path.relative_to(src).as_posix()
            if path.is_symlink() or not path.is_file():
                continue
            if name == "package.json":
                info = _package_json(path)
                if info is not None:
                    package_json[rel] = info
                continue
            lang = LANG_BY_SUFFIX.get(path.suffix)
            if lang is None or name.endswith(".d.ts"):
                continue
            count += 1
            if count > MAX_FILES:
                truncated = True
                break
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    skipped += 1
                    continue
                data = path.read_bytes()
            except OSError:
                skipped += 1
                continue
            if b"\x00" in data[:8192]:
                skipped += 1
                continue
            tree = parsers[lang].parse(data)
            imports, entry = _python(tree, rel) if lang == "python" else _js(tree, rel)
            files[rel] = {
                "lang": "python" if lang == "python" else "js",
                "imports": imports,
                "entry": entry,
            }
            if lang == "python":
                files[rel]["calls"] = _python_calls(tree)
            http = python_routes(tree) if lang == "python" else js_routes(tree)
            if http:
                files[rel]["http"] = http
        if truncated:
            break
    return {
        "version": 1,
        "analyzer": ANALYZER_VERSION,
        "files": files,
        "package_json": package_json,
        "skipped": skipped,
        "truncated": truncated,
    }


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        sys.stderr.write("usage: extract SRC_DIR OUT_JSON\n")
        return 2
    src, out = Path(argv[1]), Path(argv[2])
    result = extract(src)
    tmp = out.with_suffix(".tmp")
    tmp.write_text(json.dumps(result, separators=(",", ":")), encoding="utf-8")
    os.replace(tmp, out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
