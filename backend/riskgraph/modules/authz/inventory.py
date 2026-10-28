"""Route inventory and guards from the extractor's ``http`` sections (X5, ADR-0022).

Pure: input is the extractor's JSON (``ts-imports.4`` or later), output a sorted list of ``Route``.
For every route it resolves where it is mounted (prefixes, cross-file through relative
imports) and every place a guard can come from:

- Flask: decorators below the route decorator (above it they never run), ``before_request``
  hooks of the blueprint and of the app;
- FastAPI: ``Depends``/``Security`` in the handler, in the route's ``dependencies=``, on the
  router, on ``include_router`` and on the app, resolved transitively by name;
- Express: route middleware, then ``use()`` middleware registered earlier on the same
  receiver, then the middleware of every mount up to the app.

A guard from the catalogue makes a route ``guarded``; an uncatalogued name that looks like
authentication makes it ``custom``. ``none_found`` is said only when the framework is known
and the route's mounting was resolved up to an app, because a guard could sit at any mount;
otherwise ``unresolved``. A route whose framework is not recognised is
``unknown_framework``, never "no guard". None of it is ever ``verified`` (SCHEDULE day 4).
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from riskgraph.modules.authz.guards import Catalogue, load_catalogue
from riskgraph.modules.reachability import (
    module_of_file,
    python_module_index,
    resolve_js_module,
    resolve_python_name,
)

MAX_ROUTES = 5_000
MAX_MOUNT_DEPTH = 6
MAX_DEPENDS_DEPTH = 5
STATUSES = ("guarded", "custom", "none_found", "unresolved", "unknown_framework")
_PARAM = re.compile(r"<(?:[^:<>]+:)?(\w+)>|\{(\w+)(?::[^}]*)?\}|:(\w+)\??")

Key = tuple[str, str]  # (file, receiver name)


@dataclass(frozen=True, slots=True)
class Guard:
    name: str
    source: str  # decorator | dependency | middleware | mount | router | app | hook
    catalogued: bool  # in the catalogue (or a FastAPI security dependency)
    file: str
    line: int


@dataclass(frozen=True, slots=True)
class Route:
    file: str
    line: int
    framework: str | None
    basis: str  # constructor | import | repository | unknown: how the framework was told
    methods: tuple[str, ...]
    path: str | None  # as declared; None when it is not a plain string
    full_path: str | None  # with every resolved prefix
    handler: str
    params: tuple[str, ...]  # path parameters
    guards: tuple[Guard, ...]
    status: str
    mounted: bool  # the mount chain reaches an app
    notes: tuple[str, ...] = ()


@dataclass
class _Receiver:
    framework: str
    role: str  # app | router
    prefix: str | None
    dependencies: list[dict[str, str]]


@dataclass
class _Mount:
    parent: Key
    prefix: str | None
    guards: list[Guard]
    file: str
    line: int


@dataclass
class _Inventory:
    files: dict[str, dict[str, Any]]
    catalogue: Catalogue
    receivers: dict[Key, _Receiver] = field(default_factory=dict)
    mounts: dict[Key, list[_Mount]] = field(default_factory=lambda: defaultdict(list))
    # use() calls with middleware, per receiver (at most 500 per file, the extractor's cap)
    uses: dict[Key, list[dict[str, Any]]] = field(default_factory=lambda: defaultdict(list))
    by_file: dict[str, list[Key]] = field(default_factory=lambda: defaultdict(list))
    app_hooks: list[Guard] = field(default_factory=list)
    router_hooks: dict[Key, list[Guard]] = field(default_factory=lambda: defaultdict(list))
    index: dict[str, str] = field(default_factory=dict)
    modules: dict[str, str] = field(default_factory=dict)  # file -> dotted module
    names: set[str] = field(default_factory=set)
    _py_cache: dict[tuple[str, str], Key | None] = field(default_factory=dict)

    def http(self, file: str) -> dict[str, Any]:
        info = self.files.get(file) or {}
        http = info.get("http")
        return http if isinstance(http, dict) else {}


def params_of(path: str | None) -> tuple[str, ...]:
    if not path:
        return ()
    return tuple(next(g for g in m.groups() if g) for m in _PARAM.finditer(path))[:20]


def _join(*parts: str | None) -> str:
    """Prefixes and path joined, without a trailing slash: ``/orders`` + ``/`` is
    ``/orders`` (Flask and FastAPI declare it as ``/orders/``, Express serves both), so
    sibling routes compare equal. ``Route.path`` keeps the declaration as written."""
    out = ""
    for part in parts:
        if part:
            out = out.rstrip("/") + "/" + part.lstrip("/")
    return out.rstrip("/") or "/"


def _under(path: str | None, prefix: str | None) -> bool:
    """Express: ``use("/admin", mw)`` runs for /admin and /admin/..., not for /administer."""
    if not prefix or prefix == "/":
        return True
    if path is None:
        return False
    p = prefix.rstrip("/")
    return path == p or path.startswith(p + "/")


def route_inventory(extracted: dict[str, Any], catalogue: Catalogue | None = None) -> list[Route]:
    raw = extracted.get("files") if isinstance(extracted, dict) else None
    files = {k: v for k, v in (raw or {}).items() if isinstance(k, str) and isinstance(v, dict)}
    inv = _Inventory(files=files, catalogue=catalogue or load_catalogue())
    inv.names = set(files)
    inv.index = python_module_index({f for f in files if f.endswith(".py")})
    inv.modules = module_of_file(inv.index)
    _collect_receivers(inv)
    _collect_mounts(inv)
    detected = _detected_frameworks(inv)
    routes: list[Route] = []
    for file in sorted(files):
        for raw_route in inv.http(file).get("routes") or []:
            if not isinstance(raw_route, dict):
                continue
            routes.append(_route(inv, file, raw_route, detected))
            if len(routes) >= MAX_ROUTES:
                break
        if len(routes) >= MAX_ROUTES:
            break
    routes.sort(key=lambda r: (r.file, r.line, r.methods, r.path or ""))
    return routes


# --- receivers and resolution ---------------------------------------------------------
def _lang(inv: _Inventory, file: str) -> str:
    return "python" if (inv.files.get(file) or {}).get("lang") == "python" else "js"


def _collect_receivers(inv: _Inventory) -> None:
    for file in inv.files:
        for name, assign in (inv.http(file).get("assigns") or {}).items():
            if not isinstance(assign, dict):
                continue
            kind = inv.catalogue.kind_of(assign.get("call"))
            if kind is None or inv.catalogue.frameworks[kind[0]].language != _lang(inv, file):
                continue
            deps = assign.get("dependencies") or []
            inv.by_file[file].append((file, name))
            inv.receivers[(file, name)] = _Receiver(
                framework=kind[0],
                role=kind[1],
                prefix=assign.get("prefix") if isinstance(assign.get("prefix"), str) else None,
                dependencies=[d for d in deps if isinstance(d, dict)],
            )


def _resolve(inv: _Inventory, file: str, name: str | None) -> Key | None:
    """The (file, name) a receiver or dependency name used in ``file`` refers to."""
    if not name:
        return None
    if _lang(inv, file) == "python":
        return _resolve_python(inv, file, name)
    return _resolve_js(inv, file, {"name": name})


def _resolve_python(inv: _Inventory, file: str, name: str) -> Key | None:
    cached = inv._py_cache.get((file, name), ())
    if cached != ():
        return cached  # type: ignore[return-value]
    http = inv.http(file)
    head, _, rest = name.partition(".")
    out: Key | None = None
    binding = (http.get("bindings") or {}).get(head)
    if not rest and (name in (http.get("assigns") or {}) or name in (http.get("depends") or {})):
        out = (file, name)
    elif isinstance(binding, dict):
        target, attr = resolve_python_name(
            file,
            str(binding.get("module") or ""),
            binding.get("name") if isinstance(binding.get("name"), str) else None,
            int(binding.get("level") or 0),
            inv.index,
            inv.modules,
        )
        if target is not None:
            if attr is None and rest and "." not in rest:
                out = (target, rest)  # from .routers import users; users.router
            elif attr is not None and not rest:
                out = (target, attr)  # from .views import admin_bp
    elif not rest:
        out = (file, name)
    inv._py_cache[(file, name)] = out
    return out


def _routers_in(inv: _Inventory, target: str) -> list[Key]:
    """The router a module exports: its exported routers, else its only router."""
    local = [k for k in inv.by_file.get(target, []) if inv.receivers[k].role == "router"]
    exported = set(inv.http(target).get("exports") or [])
    picked = [k for k in local if k[1] in exported]
    if picked:
        return sorted(picked)
    return local if len(local) == 1 else []


def _resolve_js(inv: _Inventory, file: str, arg: dict[str, Any]) -> Key | None:
    http = inv.http(file)
    spec = arg.get("module")
    name = arg.get("name")
    if isinstance(name, str):
        if (file, name) in inv.receivers or name in (http.get("assigns") or {}):
            return (file, name)
        bound = (http.get("bindings") or {}).get(name)
        spec = bound if isinstance(bound, str) else None
    if not isinstance(spec, str) or not spec.startswith("."):
        return None
    target = resolve_js_module(file, spec, inv.names)
    if target is None:
        return None
    routers = _routers_in(inv, target)
    return routers[0] if routers else None


# --- mounts, uses and hooks ------------------------------------------------------------
def _collect_mounts(inv: _Inventory) -> None:
    for file in sorted(inv.files):
        http = inv.http(file)
        lang = _lang(inv, file)
        for m in http.get("mounts") or []:
            if not isinstance(m, dict):
                continue
            parent = _resolve(inv, file, m.get("receiver")) or (file, str(m.get("receiver")))
            child = _resolve(inv, file, m.get("child"))
            if child is None:
                continue
            line = int(m.get("line") or 0)
            guards = [
                Guard(str(d.get("name")), "mount", False, file, line)
                for d in m.get("dependencies") or []
                if isinstance(d, dict) and d.get("name")
            ]
            inv.mounts[child].append(_Mount(parent, m.get("prefix"), guards, file, line))
        for h in http.get("hooks") or []:
            if not isinstance(h, dict) or not h.get("name"):
                continue
            guard = Guard(str(h["name"]), "hook", False, file, int(h.get("line") or 0))
            owner = _resolve(inv, file, h.get("receiver")) or (file, str(h.get("receiver")))
            hooked = inv.receivers.get(owner)
            if h.get("kind") == "before_app_request" or (hooked and hooked.role == "app"):
                inv.app_hooks.append(guard)
            else:
                inv.router_hooks[owner].append(guard)
        if lang != "js":
            continue
        for use in http.get("uses") or []:
            if not isinstance(use, dict):
                continue
            receiver = str(use.get("receiver"))
            parent = _resolve_js(inv, file, {"name": receiver}) or (file, receiver)
            line = int(use.get("line") or 0)
            middleware: list[dict[str, Any]] = []
            children: list[Key] = []
            for arg in use.get("args") or []:
                if not isinstance(arg, dict):
                    continue
                child = _resolve_js(inv, file, arg)
                rec = inv.receivers.get(child) if child is not None else None
                if child is not None and rec is not None and rec.role == "router":
                    children.append(child)
                else:
                    middleware.append(arg)
            if middleware:  # a use() that only mounts routers guards nothing by itself
                entry = {"prefix": use.get("prefix"), "middleware": middleware, "file": file}
                inv.uses[parent].append({**entry, "line": line})
            for child in children:
                inv.mounts[child].append(
                    _Mount(
                        parent, use.get("prefix"), _js_guards(middleware, file, line), file, line
                    )
                )


def _js_guards(
    args: list[dict[str, Any]], file: str, line: int, source: str = "mount"
) -> list[Guard]:
    return [Guard(str(a["name"]), source, False, file, line) for a in args if a.get("name")]


def _inline(args: list[dict[str, Any]]) -> bool:
    return any(a.get("inline") for a in args)


def _detected_frameworks(inv: _Inventory) -> dict[str, set[str]]:
    """Frameworks seen with certainty per language: by a constructor or an import."""
    seen: dict[str, set[str]] = defaultdict(set)
    for (file, _), receiver in inv.receivers.items():
        seen[_lang(inv, file)].add(receiver.framework)
    for file in inv.files:
        fw = _by_import(inv, file)
        if fw:
            seen[_lang(inv, file)].add(fw)
    return seen


def _by_import(inv: _Inventory, file: str) -> str | None:
    lang = _lang(inv, file)
    modules = set()
    for imp in (inv.files.get(file) or {}).get("imports") or []:
        if isinstance(imp, dict) and isinstance(imp.get("module"), str):
            modules.add(imp["module"].split(".")[0] if lang == "python" else imp["module"])
    found = {
        fw.name
        for fw in inv.catalogue.frameworks.values()
        if fw.language == lang and modules & set(fw.imports)
    }
    return found.pop() if len(found) == 1 else None


# --- one route -------------------------------------------------------------------------
def _route(inv: _Inventory, file: str, raw: dict[str, Any], detected: dict[str, set[str]]) -> Route:
    lang = _lang(inv, file)
    receiver_name = str(raw.get("receiver") or "")
    key = _resolve(inv, file, receiver_name) or (file, receiver_name)
    receiver = inv.receivers.get(key)
    framework, basis = (receiver.framework, "constructor") if receiver else (None, "unknown")
    if framework is None and (fw := _by_import(inv, file)):
        framework, basis = fw, "import"
    if framework is None and len(detected.get(lang, set())) == 1:
        framework, basis = next(iter(detected[lang])), "repository"
    line = int(raw.get("line") or 0)
    path = raw.get("path") if isinstance(raw.get("path"), str) else None
    notes: list[str] = []
    guards: list[Guard] = []

    # mount chain, innermost first: each level adds its mount's prefix, its own prefix
    # (FastAPI routers, Flask blueprints) and every guard a mount or a receiver adds
    levels: list[list[str | None]] = []
    cur, mounted, seen = key, False, {key}
    for _ in range(MAX_MOUNT_DEPTH):
        rec = inv.receivers.get(cur)
        if rec is not None and rec.role == "app":
            mounted = True
            guards += _deps_as(rec.dependencies, cur[0], 0, "app")
            break
        if rec is not None:
            guards += _deps_as(rec.dependencies, cur[0], 0, "router")
        options = sorted(inv.mounts.get(cur, []), key=lambda m: (m.file, m.line))
        if not options:
            levels.append([rec.prefix if rec else None])
            if rec is not None:
                notes.append(f"{cur[1]} is not mounted anywhere RiskGraph could resolve")
            break
        if len(options) > 1:
            notes.append(f"{cur[1]} is mounted {len(options)} times; the first mount is used")
        mount = options[0]
        own = rec.prefix if rec else None
        if rec is not None and rec.framework == "flask" and mount.prefix:
            own = None  # register_blueprint(url_prefix=) replaces the blueprint's own
        levels.append([mount.prefix, own])
        guards += mount.guards
        below = _join(*_flat(levels), path)  # the route's path as the parent sees it
        for use in inv.uses.get(mount.parent, []):
            earlier = use["file"] == mount.file and use["line"] < mount.line
            if earlier and _under(below, use["prefix"]):
                guards += _js_guards(use["middleware"], use["file"], use["line"], "app")
        if mount.parent in seen:
            notes.append("mount cycle")
            break
        seen.add(mount.parent)
        cur = mount.parent
    else:
        notes.append("mount chain too deep")
    full_path = _join(*_flat(levels), path) if path is not None else None

    if lang == "python":
        guards += _python_guards(inv, file, raw, line, key, framework, notes)
    else:
        guards += _express_guards(inv, file, raw, line, key, path, notes)

    classified = [_classify(inv, framework, g) for g in guards]
    status = _status(inv, framework, classified, mounted or framework == "flask")
    return Route(
        file=file,
        line=line,
        framework=framework,
        basis=basis,
        methods=tuple(str(m) for m in raw.get("methods") or [] if isinstance(m, str))[:10],
        path=path,
        full_path=full_path,
        handler=str(raw.get("handler") or "<unknown>")[:200],
        params=params_of(path),
        guards=tuple(classified),
        status=status,
        mounted=mounted,
        notes=tuple(dict.fromkeys(notes))[:10],
    )


def _flat(levels: list[list[str | None]]) -> list[str | None]:
    """Prefixes outermost first."""
    return [p for level in reversed(levels) for p in level]


def _deps_as(deps: list[dict[str, str]], file: str, line: int, source: str) -> list[Guard]:
    return [
        Guard(str(d["name"]), source, d.get("kind") == "Security", file, line)
        for d in deps
        if isinstance(d, dict) and d.get("name")
    ]


def _python_guards(
    inv: _Inventory,
    file: str,
    raw: dict[str, Any],
    line: int,
    key: Key,
    framework: str | None,
    notes: list[str],
) -> list[Guard]:
    guards = [
        Guard(str(n), "decorator", False, file, line)
        for n in raw.get("decorators") or []
        if isinstance(n, str)
    ]
    for name in raw.get("outer") or []:
        if isinstance(name, str) and framework and inv.catalogue.is_guard(framework, name):
            notes.append(f"{name} is above the route decorator, so it does not run for the route")
    guards += _deps_as(
        [d for d in raw.get("dependencies") or [] if isinstance(d, dict)], file, line, "dependency"
    )
    if framework == "flask":
        guards += inv.router_hooks.get(key, []) + inv.app_hooks
    return guards


def _express_guards(
    inv: _Inventory,
    file: str,
    raw: dict[str, Any],
    line: int,
    key: Key,
    path: str | None,
    notes: list[str],
) -> list[Guard]:
    guards: list[Guard] = []
    for name in raw.get("middleware") or []:
        if name == "<inline>":
            notes.append("inline middleware on the route is not classified")
        elif isinstance(name, str) and not name.startswith("require:"):
            guards.append(Guard(name, "middleware", False, file, line))
    for use in inv.uses.get(key, []):
        if use["file"] != file or use["line"] >= line:
            continue  # only earlier use() on the same receiver in the same file runs first
        if _under(path, use["prefix"]):
            guards += _js_guards(use["middleware"], file, use["line"], "router")
            if _inline(use["middleware"]):
                notes.append("inline middleware registered before the route is not classified")
    return guards


def _classify(inv: _Inventory, framework: str | None, g: Guard) -> Guard:
    if g.catalogued or framework is None:
        return g
    bindings = inv.http(g.file).get("bindings") or {}
    if framework == "fastapi" and g.source in ("dependency", "router", "mount", "app"):
        hit = _fastapi_guard(inv, g.file, g.name, 0, set())
    else:
        hit = inv.catalogue.is_guard(framework, g.name, bindings)
    return Guard(g.name, g.source, hit, g.file, g.line) if hit else g


def _fastapi_guard(inv: _Inventory, file: str, name: str, depth: int, seen: set[Key]) -> bool:
    """A dependency is a guard when it is a security scheme instance, or depends (through
    named functions, at most ``MAX_DEPENDS_DEPTH`` deep) on one."""
    if depth > MAX_DEPENDS_DEPTH:
        return False
    key = _resolve_python(inv, file, name)
    if key is None or key in seen:
        return False
    seen.add(key)
    http = inv.http(key[0])
    assign = (http.get("assigns") or {}).get(key[1])
    if isinstance(assign, dict):
        callee = str(assign.get("call") or "")
        if callee.rsplit(".", 1)[-1] in inv.catalogue.fastapi_schemes:
            return True
    for dep in (http.get("depends") or {}).get(key[1]) or []:
        if not isinstance(dep, dict) or not dep.get("name"):
            continue
        if dep.get("kind") == "Security" or _fastapi_guard(
            inv, key[0], str(dep["name"]), depth + 1, seen
        ):
            return True
    return False


def _status(inv: _Inventory, framework: str | None, guards: list[Guard], resolved: bool) -> str:
    """``resolved``: every place a guard could come from was seen (Flask guards never come
    from a mount, so a Flask route is always resolved)."""
    if framework is None:
        return "unknown_framework"
    if any(g.catalogued for g in guards):
        return "guarded"
    if any(inv.catalogue.looks_like_auth(g.name) for g in guards):
        return "custom"
    return "none_found" if resolved else "unresolved"
