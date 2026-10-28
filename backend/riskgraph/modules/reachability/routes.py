"""Route declarations and the places a guard can come from (X5, ADR-0022).

Part of the extractor process (``extract.py``): it records what the code declares and
decides nothing. Which decorator, dependency or middleware is a guard, which framework a
receiver belongs to and how mounts resolve across files is ``modules/authz``'s job, so the
extractor needs no catalogue and a catalogue change needs no re-extraction.

Python (Flask, FastAPI) per file:
    routes:  [{receiver, verb, methods, path, handler, line, decorators, outer, dependencies,
               handler_params, body}]
             ``decorators`` are applied to the handler before the route registers it (below
             the route decorator); ``outer`` ones are above it and never run for the route.
    assigns: {name: {call, prefix, dependencies}}   module names bound to a call result
    bindings:{name: {module, name, level}}          what an imported name refers to
    mounts:  [{receiver, child, prefix, dependencies, line}]  register_blueprint, include_router
    hooks:   [{receiver, kind, name, line}]         before_request and friends
    depends: {function: [{name, kind}]}             Depends/Security in a function's parameters
JavaScript/TypeScript (Express) per file:
    routes:  [{receiver, verb, methods, path, handler, middleware, line, body}]
    uses:    [{receiver, prefix, args: [{name} | {module} | {inline}], line}]
    assigns: {name: {call}}, bindings: {name: module spec}, exports: [names]
    calls:   [{callee | module, args: [name | None], line}]   f(app, db), require("./r")(app)
    params:  {exported function: [parameter names]}          "<module>" for an anonymous one

``body`` (ts-imports.5) describes the handler when its code is in the same file: its
``span`` [first, last line], the route parameters it passes into a call (``loads``) and
whether a comparison or keyword argument in it mentions an owner or the current user
(``ownership``). Words, not semantics: X5's BOLA hypothesis reads it, nothing else.
"""

from __future__ import annotations

import re
from typing import Any

from riskgraph.modules.reachability.syntax import dotted, string_value, text, walk

MAX_ROUTES_PER_FILE = 1_000
MAX_ENTRIES_PER_KIND = 500  # assigns, bindings, mounts, uses, hooks, depends
MAX_NAMES = 20  # decorators, middleware, dependencies, params per route
MAX_NAME = 200
MAX_PATH = 300

MAX_BODY_NODES = 20_000  # nodes of one handler body looked at for its facts
# names that make a comparison an ownership check: owner_id, user_id, current_user, req.user
OWNERSHIP = re.compile(
    r"owner|user_?id|current_?user|request\.user|req\.user|req\.session|\bg\.user|"
    r"author|created_?by|tenant|account_?id",
    re.IGNORECASE,
)
# calls that format or answer, not load: an id passed to them is not a lookup
NOT_LOADS = frozenset(
    {
        "int",
        "str",
        "float",
        "bool",
        "len",
        "print",
        "repr",
        "format",
        "abort",
        "jsonify",
        "render_template",
        "redirect",
        "url_for",
        "parseInt",
        "Number",
        "String",
        "send",
        "json",
        "render",
        "status",
        "log",
        "info",
        "debug",
        "warn",
        "error",
    }
)
_JS_PARAM = re.compile(r":(\w+)")
_PY_COMPARE = frozenset({"comparison_operator", "keyword_argument"})
_JS_COMPARE = frozenset({"binary_expression", "pair"})
_JS_FUNCTIONS = frozenset({"arrow_function", "function_expression", "function"})
ANONYMOUS_EXPORT = "<module>"

PY_VERBS = frozenset({"get", "post", "put", "delete", "patch", "head", "options"})
PY_ROUTE = PY_VERBS | {"route", "api_route"}
PY_HOOKS = frozenset({"before_request", "before_app_request"})
PY_MOUNTS = frozenset({"register_blueprint", "include_router"})
PY_DEPENDS = frozenset({"Depends", "Security"})
JS_VERBS = frozenset({"get", "post", "put", "delete", "patch", "all", "options", "head"})


def _name(value: str | None) -> str | None:
    return value[:MAX_NAME] if value else None


def _path(node: Any) -> str | None:
    value = string_value(node)
    return value[:MAX_PATH] if value is not None else None


def _args(call: Any) -> tuple[list[Any], dict[str, Any]]:
    """Positional argument nodes and keyword argument values of a Python call."""
    positional: list[Any] = []
    keywords: dict[str, Any] = {}
    args = call.child_by_field_name("arguments")
    if args is None:
        return positional, keywords
    for child in args.named_children[:200]:
        if child.type == "keyword_argument":
            key = child.child_by_field_name("name")
            if key is not None:
                keywords[text(key)] = child.child_by_field_name("value")
        elif child.type != "comment":
            positional.append(child)
    return positional, keywords


def _strings(node: Any) -> list[str]:
    """String literals of a Python list or tuple (``methods=["GET", "POST"]``)."""
    if node is None or node.type not in ("list", "tuple", "set"):
        return []
    out = [string_value(c) for c in node.named_children[:MAX_NAMES]]
    return [v.upper()[:16] for v in out if v]


def _callee(node: Any) -> str | None:
    if node is None or node.type != "call":
        return None
    return dotted(node.child_by_field_name("function"))


def _last(name: str | None) -> str:
    return name.rsplit(".", 1)[-1] if name else ""


def _depends_in(node: Any) -> list[dict[str, str]]:
    """``Depends(x)`` / ``Security(x)`` anywhere under ``node`` (defaults and Annotated)."""
    found: list[dict[str, str]] = []
    for sub in walk(node):
        if sub.type != "call":
            continue
        kind = _last(_callee(sub))
        if kind not in PY_DEPENDS:
            continue
        positional, keywords = _args(sub)
        target = positional[0] if positional else keywords.get("dependency")
        name = _name(dotted(target))
        if name and len(found) < MAX_NAMES:
            found.append({"name": name, "kind": kind})
    return found


def _param_names(params: Any) -> list[str]:
    names: list[str] = []
    for p in params.named_children if params is not None else []:
        node = p if p.type == "identifier" else p.child_by_field_name("name")
        if node is None and p.named_children:
            node = p.named_children[0]
        if node is not None and node.type == "identifier":
            names.append(text(node)[:MAX_NAME])
    return names[:MAX_NAMES]


def _decorator_name(dec: Any) -> str | None:
    expr = dec.named_children[0] if dec.named_children else None
    if expr is None:
        return None
    return _name(_callee(expr) if expr.type == "call" else dotted(expr))


def _route_decorator(dec: Any) -> dict[str, Any] | None:
    expr = dec.named_children[0] if dec.named_children else None
    if expr is None or expr.type != "call":
        return None
    fn = expr.child_by_field_name("function")
    if fn is None or fn.type != "attribute":
        return None
    verb = text(fn.child_by_field_name("attribute"))
    receiver = dotted(fn.child_by_field_name("object"))
    if verb not in PY_ROUTE or not receiver:
        return None
    positional, keywords = _args(expr)
    path_node = positional[0] if positional else keywords.get("rule") or keywords.get("path")
    # route / api_route take methods=, with Flask's default
    methods = [verb.upper()] if verb in PY_VERBS else _strings(keywords.get("methods")) or ["GET"]
    return {
        "receiver": _name(receiver),
        "verb": verb,
        "methods": methods,
        "path": _path(path_node),
        "dependencies": _depends_in(keywords["dependencies"]) if "dependencies" in keywords else [],
    }


def _body(fn: Any, ids: list[str], lang: str) -> dict[str, Any]:
    """What a handler's code says about its ids: its span, the ids it passes into a call
    (a lookup, unless the callee only formats), and whether a comparison or keyword
    argument mentions an owner or the current user."""
    wanted = set(ids)
    loads: list[str] = []
    ownership = False
    compare = _PY_COMPARE if lang == "python" else _JS_COMPARE
    call = "call" if lang == "python" else "call_expression"
    for seen, node in enumerate(walk(fn)):
        if seen >= MAX_BODY_NODES:
            break
        if node.type in compare and not ownership:
            if node.type != "binary_expression" or any(
                text(c) in ("==", "===", "!=", "!==") for c in node.children
            ):
                ownership = bool(OWNERSHIP.search(text(node)[:500]))
        elif node.type == call and wanted - set(loads):
            callee = text(node.child_by_field_name("function") or node).rsplit(".", 1)[-1]
            args = node.child_by_field_name("arguments")
            if args is None or callee in NOT_LOADS:
                continue
            for sub in walk(args):
                name = _id_used(sub, lang)
                if name in wanted and name not in loads:
                    loads.append(name)
    return {
        "span": [fn.start_point[0] + 1, fn.end_point[0] + 1],
        "loads": loads[:MAX_NAMES],
        "ownership": ownership,
    }


def _id_used(node: Any, lang: str) -> str | None:
    """A route parameter used here: a bare name, or ``req.params.id`` in JavaScript."""
    if node.type == "identifier":
        parent = node.parent
        # `x.id` names the attribute, not a variable called id
        attribute = parent is not None and parent.type in ("attribute", "member_expression")
        return None if attribute and node != parent.named_children[0] else text(node)
    if lang == "js" and node.type == "member_expression":
        obj = node.child_by_field_name("object")
        prop = node.child_by_field_name("property")
        if obj is not None and prop is not None and text(obj).endswith(".params"):
            return text(prop)
    return None


def python_routes(tree: Any) -> dict[str, Any]:
    routes: list[dict[str, Any]] = []
    assigns: dict[str, dict[str, Any]] = {}
    bindings: dict[str, dict[str, Any]] = {}
    mounts: list[dict[str, Any]] = []
    hooks: list[dict[str, Any]] = []
    depends: dict[str, list[dict[str, str]]] = {}
    decorated: dict[str, list[str]] = {}  # function -> its decorators, for add_*_rule
    defined: dict[str, Any] = {}  # function -> its node, for add_*_rule
    url_rules: list[dict[str, Any]] = []

    for node in walk(tree.root_node):
        kind = node.type
        if kind in ("import_statement", "import_from_statement"):
            _python_bindings(node, bindings)
        elif kind == "assignment" and len(assigns) < MAX_ENTRIES_PER_KIND:
            left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
            callee = _callee(right)
            if left is not None and left.type == "identifier" and callee:
                _, keywords = _args(right)
                prefix = keywords.get("url_prefix") or keywords.get("prefix")
                assigns[text(left)[:MAX_NAME]] = {
                    "call": _name(callee),
                    "prefix": _path(prefix),
                    "dependencies": _depends_in(keywords["dependencies"])
                    if "dependencies" in keywords
                    else [],
                }
        elif kind == "function_definition":
            _python_function(node, routes, hooks, depends, decorated)
            if len(defined) < MAX_ENTRIES_PER_KIND:
                defined.setdefault(text(node.child_by_field_name("name"))[:MAX_NAME], node)
        elif kind == "call":
            callee = _callee(node)
            verb = _last(callee)
            receiver = callee.rsplit(".", 1)[0] if callee and "." in callee else None
            if not receiver:
                continue
            positional, keywords = _args(node)
            if verb in PY_MOUNTS and positional and len(mounts) < MAX_ENTRIES_PER_KIND:
                prefix = keywords.get("url_prefix") or keywords.get("prefix")
                mounts.append(
                    {
                        "receiver": _name(receiver),
                        "child": _name(dotted(positional[0])),
                        "prefix": _path(prefix),
                        "dependencies": _depends_in(keywords["dependencies"])
                        if "dependencies" in keywords
                        else [],
                        "line": node.start_point[0] + 1,
                    }
                )
            elif verb in PY_HOOKS and positional and len(hooks) < MAX_ENTRIES_PER_KIND:
                hooks.append(
                    {
                        "receiver": _name(receiver),
                        "kind": verb,
                        "name": _name(dotted(positional[0])),
                        "line": node.start_point[0] + 1,
                    }
                )
            elif (
                verb in ("add_url_rule", "add_api_route")
                and positional
                and len(url_rules) < MAX_ROUTES_PER_FILE
            ):
                # Flask: (rule, endpoint, view_func); FastAPI: (path, endpoint)
                at, kw = (2, "view_func") if verb == "add_url_rule" else (1, "endpoint")
                view = keywords.get(kw) or (positional[at] if len(positional) > at else None)
                url_rules.append(
                    {
                        "receiver": _name(receiver),
                        "verb": verb,
                        "methods": _strings(keywords.get("methods")) or ["GET"],
                        "path": _path(positional[0]),
                        "handler": _name(dotted(view)),
                        "line": node.start_point[0] + 1,
                        "outer": [],
                        "dependencies": [],
                        "handler_params": [],
                    }
                )
        if len(routes) >= MAX_ROUTES_PER_FILE:
            break
    for rule in url_rules:  # the view function's own decorators and dependencies apply
        rule["decorators"] = decorated.get(rule["handler"] or "", [])
        rule["dependencies"] = depends.get(rule["handler"] or "", [])
        fn = defined.get(rule["handler"] or "")
        if fn is not None:
            ids = _param_names(fn.child_by_field_name("parameters"))
            rule["handler_params"] = ids
            rule["body"] = _body(fn, ids, "python")
        if len(routes) < MAX_ROUTES_PER_FILE:
            routes.append(rule)
    return _non_empty(
        routes=routes,
        assigns=assigns,
        bindings=bindings,
        mounts=mounts,
        hooks=hooks,
        depends=depends,
    )


def _python_bindings(node: Any, bindings: dict[str, dict[str, Any]]) -> None:
    if len(bindings) >= MAX_ENTRIES_PER_KIND:
        return
    if node.type == "import_statement":
        for child in node.named_children:
            if child.type == "aliased_import":
                name, alias = child.child_by_field_name("name"), child.child_by_field_name("alias")
                if name is not None and alias is not None:
                    bindings[text(alias)] = {"module": text(name), "name": None, "level": 0}
        return
    mod = node.child_by_field_name("module_name")
    level, module = 0, ""
    if mod is not None and mod.type == "relative_import":
        for part in mod.named_children:
            if part.type == "import_prefix":
                level = text(part).count(".")
            elif part.type == "dotted_name":
                module = text(part)
    elif mod is not None:
        module = text(mod)
    for child in node.children_by_field_name("name"):
        target, alias = child, child
        if child.type == "aliased_import":
            target, alias = child.child_by_field_name("name"), child.child_by_field_name("alias")
        if target is not None and alias is not None:
            bindings[text(alias)[:MAX_NAME]] = {
                "module": module[:MAX_NAME],
                "name": text(target)[:MAX_NAME],
                "level": level,
            }


def _python_function(
    node: Any,
    routes: list[dict[str, Any]],
    hooks: list[dict[str, Any]],
    depends: dict[str, list[dict[str, str]]],
    decorated: dict[str, list[str]],
) -> None:
    name = text(node.child_by_field_name("name"))[:MAX_NAME]
    params = node.child_by_field_name("parameters")
    deps = _depends_in(params) if params is not None else []
    if deps and len(depends) < MAX_ENTRIES_PER_KIND:
        depends[name] = deps
    parent = node.parent
    if parent is None or parent.type != "decorated_definition":
        return
    decorators = [d for d in parent.named_children if d.type == "decorator"]
    found = [(i, _route_decorator(d)) for i, d in enumerate(decorators)]
    plain = [(i, _decorator_name(d)) for i, d in enumerate(decorators)]
    route_at = {i for i, r in found if r is not None}
    names = [(i, n) for i, n in plain if n and i not in route_at]
    if len(decorated) < MAX_ENTRIES_PER_KIND:
        decorated[name] = [n for _, n in names][:MAX_NAMES]
    for _, n in names:
        if _last(n) in PY_HOOKS and "." in n and len(hooks) < MAX_ENTRIES_PER_KIND:
            hooks.append(
                {
                    "receiver": n.rsplit(".", 1)[0],
                    "kind": _last(n),
                    "name": name,
                    "line": node.start_point[0] + 1,
                }
            )
    for i, route in found:
        if route is None:
            continue
        routes.append(
            {
                **route,
                "handler": name,
                "line": decorators[i].start_point[0] + 1,
                # Python applies decorators bottom-up: the route registers the function as
                # decorated by everything below it; decorators above it never see a request
                "decorators": [n for j, n in names if j > i][:MAX_NAMES],
                "outer": [n for j, n in names if j < i][:MAX_NAMES],
                "dependencies": [*route["dependencies"], *deps][:MAX_NAMES],
                "handler_params": _param_names(params),
                "body": _body(node, _param_names(params), "python"),
            }
        )


def _js_dotted(node: Any) -> str | None:
    """``a.b.c`` for identifiers and member chains; ``require("x")`` reads as ``x``."""
    if node is None:
        return None
    if node.type in ("identifier", "property_identifier", "this"):
        return text(node)
    if node.type == "member_expression":
        head = _js_dotted(node.child_by_field_name("object"))
        prop = node.child_by_field_name("property")
        if head and prop is not None and prop.type == "property_identifier":
            return f"{head}.{text(prop)}"
        return None
    if node.type == "call_expression":
        return _require_spec(node)
    return None


def _require_spec(node: Any) -> str | None:
    if node is None or node.type != "call_expression":
        return None
    fn = node.child_by_field_name("function")
    if fn is None or fn.type != "identifier" or text(fn) != "require":
        return None
    args = node.child_by_field_name("arguments")
    first = args.named_children[0] if args is not None and args.named_children else None
    return string_value(first)


def _js_arg(node: Any) -> dict[str, Any]:
    """What a middleware or router argument is: a name, a required module, or inline code."""
    if node.type in ("arrow_function", "function_expression", "function"):
        return {"inline": True}
    if node.type == "call_expression":
        spec = _require_spec(node)
        if spec is not None:
            return {"module": spec[:MAX_PATH]}
        fn = node.child_by_field_name("function")
        inner = _require_spec(fn) if fn is not None else None
        if inner is not None:  # require("./routes")(app, db)
            return {"module": inner[:MAX_PATH]}
        name = _js_dotted(fn)
        return {"name": name[:MAX_NAME]} if name else {"inline": True}
    name = _js_dotted(node)
    return {"name": name[:MAX_NAME]} if name else {"inline": True}


def _label(arg: dict[str, Any]) -> str:
    return str(arg.get("name") or (f"require:{arg['module']}" if "module" in arg else "<inline>"))


def js_routes(tree: Any) -> dict[str, Any]:
    routes: list[dict[str, Any]] = []
    uses: list[dict[str, Any]] = []
    assigns: dict[str, dict[str, Any]] = {}
    bindings: dict[str, str] = {}
    exports: list[str] = []
    calls: list[dict[str, Any]] = []
    functions: dict[str, Any] = {}  # name -> function node: handlers and exported functions
    handlers: list[tuple[dict[str, Any], Any]] = []  # route -> its handler argument node

    for node in walk(tree.root_node):
        kind = node.type
        if kind == "variable_declarator":
            _js_declarator(node, assigns, bindings)
            value = node.child_by_field_name("value")
            name = node.child_by_field_name("name")
            if (
                value is not None
                and value.type in _JS_FUNCTIONS
                and name is not None
                and name.type == "identifier"
                and len(functions) < MAX_ENTRIES_PER_KIND
            ):
                functions.setdefault(text(name)[:MAX_NAME], value)
        elif kind == "function_declaration" and len(functions) < MAX_ENTRIES_PER_KIND:
            name = node.child_by_field_name("name")
            if name is not None:
                functions.setdefault(text(name)[:MAX_NAME], node)
        elif kind == "import_statement" and len(bindings) < MAX_ENTRIES_PER_KIND:
            spec = string_value(node.child_by_field_name("source"))
            if spec is None:
                continue
            for sub in walk(node):
                if sub.type == "import_clause":
                    for part in sub.named_children:
                        if part.type == "identifier":
                            bindings[text(part)[:MAX_NAME]] = spec[:MAX_PATH]
                elif sub.type in ("import_specifier", "namespace_import"):
                    alias = sub.child_by_field_name("alias") or (
                        sub.child_by_field_name("name")
                        if sub.type == "import_specifier"
                        else next((c for c in sub.named_children if c.type == "identifier"), None)
                    )
                    if alias is not None:
                        bindings[text(alias)[:MAX_NAME]] = spec[:MAX_PATH]
        elif kind == "assignment_expression":
            left = _js_dotted(node.child_by_field_name("left"))
            right = node.child_by_field_name("right")
            if left in ("module.exports", "exports.default") and right is not None:
                exported = _js_dotted(right)
                if right.type in _JS_FUNCTIONS:  # module.exports = function (app) {…}
                    functions[ANONYMOUS_EXPORT] = right
                    exported = ANONYMOUS_EXPORT
                if exported and len(exports) < MAX_NAMES:
                    exports.append(exported[:MAX_NAME])
        elif kind == "export_statement":
            value = node.child_by_field_name("value")
            decl = node.child_by_field_name("declaration")
            if value is not None and value.type == "identifier" and len(exports) < MAX_NAMES:
                exports.append(text(value)[:MAX_NAME])
            elif value is not None and value.type in _JS_FUNCTIONS:
                functions[ANONYMOUS_EXPORT] = value  # export default (app) => {…}
                exports.append(ANONYMOUS_EXPORT)
            elif decl is not None and decl.type == "function_declaration":
                name = decl.child_by_field_name("name")
                if name is not None and len(exports) < MAX_NAMES:
                    exports.append(text(name)[:MAX_NAME])
        elif kind == "call_expression":
            _js_call(node, routes, uses, handlers)
            _js_call_site(node, calls)
        if len(routes) >= MAX_ROUTES_PER_FILE:
            break
    for route, handler in handlers:
        fn = handler if handler.type in _JS_FUNCTIONS else functions.get(text(handler))
        if fn is not None:
            route["body"] = _body(fn, _JS_PARAM.findall(route["path"] or ""), "js")
    params = {name: _js_params(functions[name]) for name in exports if name in functions}
    return _non_empty(
        routes=routes,
        uses=uses,
        assigns=assigns,
        bindings=bindings,
        exports=exports,
        calls=calls,
        params=params,
    )


def _js_params(fn: Any) -> list[str]:
    params = fn.child_by_field_name("parameters") or fn.child_by_field_name("parameter")
    if params is None:
        return []
    if params.type == "identifier":  # app => {…}
        return [text(params)[:MAX_NAME]]
    names: list[str] = []
    for p in params.named_children[:MAX_NAMES]:
        node = p.child_by_field_name("pattern") if p.type != "identifier" else p
        names.append(
            text(node)[:MAX_NAME] if node is not None and node.type == "identifier" else ""
        )
    return names


def _js_call_site(node: Any, calls: list[dict[str, Any]]) -> None:
    """``routes(app, db)`` or ``require("./routes")(app, db)``: a plain function (not a
    method) called with at least one plain name, so a module that registers its routes on
    a passed-in app can be bound to the caller's app."""
    if len(calls) >= MAX_ENTRIES_PER_KIND:
        return
    fn = node.child_by_field_name("function")
    args_node = node.child_by_field_name("arguments")
    if fn is None or args_node is None:
        return
    site: dict[str, Any]
    if fn.type == "identifier" and text(fn) != "require":
        site = {"callee": text(fn)[:MAX_NAME]}
    elif (spec := _require_spec(fn)) is not None:
        site = {"module": spec[:MAX_PATH]}
    else:
        return
    args = [
        text(a)[:MAX_NAME] if a.type == "identifier" else None
        for a in args_node.named_children[:MAX_NAMES]
        if a.type != "comment"
    ]
    if any(args):
        calls.append({**site, "args": args, "line": node.start_point[0] + 1})


def _js_declarator(node: Any, assigns: dict[str, dict[str, Any]], bindings: dict[str, str]) -> None:
    name, value = node.child_by_field_name("name"), node.child_by_field_name("value")
    if name is None or value is None or value.type != "call_expression":
        return
    spec = _require_spec(value)
    if spec is not None and len(bindings) < MAX_ENTRIES_PER_KIND:
        if name.type == "identifier":
            bindings[text(name)[:MAX_NAME]] = spec[:MAX_PATH]
        elif name.type == "object_pattern":
            for part in name.named_children:
                ident = (
                    part
                    if part.type == "shorthand_property_identifier_pattern"
                    else part.child_by_field_name("value")
                )
                if ident is not None:
                    bindings[text(ident)[:MAX_NAME]] = spec[:MAX_PATH]
        return
    callee = _js_dotted(value.child_by_field_name("function"))
    if name.type == "identifier" and callee and len(assigns) < MAX_ENTRIES_PER_KIND:
        assigns[text(name)[:MAX_NAME]] = {"call": callee[:MAX_NAME]}


def _js_call(
    node: Any,
    routes: list[dict[str, Any]],
    uses: list[dict[str, Any]],
    handlers: list[tuple[dict[str, Any], Any]],
) -> None:
    fn = node.child_by_field_name("function")
    if fn is None or fn.type != "member_expression":
        return
    prop = fn.child_by_field_name("property")
    verb = text(prop) if prop is not None else ""
    if verb not in JS_VERBS and verb != "use":
        return
    args_node = node.child_by_field_name("arguments")
    args = [a for a in (args_node.named_children if args_node else []) if a.type != "comment"]
    args = args[:200]
    obj = fn.child_by_field_name("object")
    path: str | None = None
    chained = False
    # router.route("/x").get(a).post(b): walk down the chain to the .route() call
    while (
        obj is not None
        and obj.type == "call_expression"
        and (inner := obj.child_by_field_name("function")) is not None
        and inner.type == "member_expression"
    ):
        inner_prop = text(inner.child_by_field_name("property"))
        if inner_prop in JS_VERBS:
            obj = inner.child_by_field_name("object")
            continue
        if inner_prop == "route":
            route_args = obj.child_by_field_name("arguments")
            first = (
                route_args.named_children[0] if route_args and route_args.named_children else None
            )
            path, chained = _path(first), True
            obj = inner.child_by_field_name("object")
        break
    receiver = _js_dotted(obj)
    if not receiver or (obj is not None and obj.type == "call_expression"):
        return
    line = node.start_point[0] + 1
    if verb == "use":
        if chained or len(uses) >= MAX_ENTRIES_PER_KIND or not args:
            return
        prefix = _path(args[0])
        rest = args[1:] if prefix is not None else args
        uses.append(
            {
                "receiver": receiver[:MAX_NAME],
                "prefix": prefix,
                "args": [_js_arg(a) for a in rest[:MAX_NAMES]],
                "line": line,
            }
        )
        return
    if not chained:
        # app.get("title") reads a setting: a route needs a path and a handler
        if len(args) < 2:
            return
        path = _path(args[0])
        # a template literal like `/${page}` is a route whose path is not known
        dynamic = args[0].type == "template_string" and text(args[0]).startswith("`/")
        if not dynamic and (path is None or not path.startswith(("/", "*"))):
            return
        args = args[1:]
    if not args:
        return
    described = [_js_arg(a) for a in args]
    route = {
        "receiver": receiver[:MAX_NAME],
        "verb": verb,
        "methods": [verb.upper()],
        "path": path,
        "handler": _label(described[-1]),
        "middleware": [_label(a) for a in described[:-1]][:MAX_NAMES],
        "line": line,
    }
    routes.append(route)
    if args[-1].type in _JS_FUNCTIONS or args[-1].type == "identifier":
        handlers.append((route, args[-1]))


def _non_empty(**parts: Any) -> dict[str, Any]:
    return {k: v for k, v in parts.items() if v}
