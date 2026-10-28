"""Extractor ts-imports.4 and .5 (X5, ADR-0022, ADR-0023): route declarations, every place
a guard can come from, and what a handler loads, recorded without deciding anything."""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Any

from riskgraph.modules.reachability.extract import ANALYZER_VERSION, extract
from riskgraph.modules.reachability.routes import MAX_NAMES, MAX_PATH, MAX_ROUTES_PER_FILE


def _http(tmp_path: Path, name: str, code: str) -> dict[str, Any]:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(code), encoding="utf-8")
    out = extract(tmp_path)
    assert out["analyzer"] == ANALYZER_VERSION == "ts-imports.5"
    return out["files"][name].get("http", {})  # type: ignore[no-any-return]


def _route(http: dict[str, Any], path: str, method: str = "GET") -> dict[str, Any]:
    [hit] = [r for r in http["routes"] if r["path"] == path and method in r["methods"]]
    return hit  # type: ignore[no-any-return]


def test_flask_routes_methods_and_decorator_order(tmp_path: Path) -> None:
    http = _http(
        tmp_path,
        "app.py",
        """
        from flask import Flask
        app = Flask(__name__)

        @app.route("/users/<int:user_id>", methods=["GET", "delete"])
        @login_required
        @limiter.limit("5/minute")
        def user(user_id):
            return ""

        @login_required
        @app.route("/oops")
        def oops():
            return ""

        @app.post("/items")
        def create():
            return ""
        """,
    )
    user = _route(http, "/users/<int:user_id>")
    assert user["methods"] == ["GET", "DELETE"] and user["handler"] == "user"
    assert user["decorators"] == ["login_required", "limiter.limit"] and user["outer"] == []
    assert user["handler_params"] == ["user_id"] and user["line"] == 5
    # a guard above the route decorator is not applied to the registered view
    oops = _route(http, "/oops")
    assert oops["decorators"] == [] and oops["outer"] == ["login_required"]
    assert _route(http, "/items", "POST")["verb"] == "post"
    assert http["assigns"]["app"]["call"] == "Flask"


def test_flask_blueprints_mounts_hooks_and_url_rules(tmp_path: Path) -> None:
    http = _http(
        tmp_path,
        "pkg/admin.py",
        """
        from flask import Blueprint
        from .views import panel as p
        admin = Blueprint("admin", __name__, url_prefix="/admin")

        @admin.before_request
        def require_admin():
            pass

        @admin.get("/stats")
        def stats():
            return ""

        @auth.login_required
        def report():
            return ""

        admin.add_url_rule("/report", view_func=report, methods=["POST"])
        app.register_blueprint(admin, url_prefix="/v2")
        app.before_request(check_token)
        """,
    )
    assert http["assigns"]["admin"] == {"call": "Blueprint", "prefix": "/admin", "dependencies": []}
    assert {(h["receiver"], h["kind"], h["name"]) for h in http["hooks"]} == {
        ("admin", "before_request", "require_admin"),
        ("app", "before_request", "check_token"),
    }
    rule = _route(http, "/report", "POST")
    assert rule["handler"] == "report" and rule["decorators"] == ["auth.login_required"]
    assert http["mounts"] == [
        {"receiver": "app", "child": "admin", "prefix": "/v2", "dependencies": [], "line": 19}
    ]
    assert http["bindings"]["p"] == {"module": "views", "name": "panel", "level": 1}


def test_fastapi_dependencies_in_every_place(tmp_path: Path) -> None:
    http = _http(
        tmp_path,
        "main.py",
        """
        from typing import Annotated
        from fastapi import APIRouter, Depends, FastAPI, Security
        from fastapi.security import OAuth2PasswordBearer
        oauth2 = OAuth2PasswordBearer(tokenUrl="token")
        router = APIRouter(prefix="/items", dependencies=[Depends(verify_key)])
        app = FastAPI()

        def current_user(token: str = Depends(oauth2)):
            return token

        @router.get("/{item_id}", dependencies=[Depends(audit)])
        async def read(item_id: int, user: Annotated[User, Depends(current_user)]):
            return {}

        @app.api_route("/scoped", methods=["GET", "POST"])
        def scoped(u=Security(current_user, scopes=["admin"]), db=Depends()):
            return {}

        app.include_router(router, prefix="/v1", dependencies=[Depends(tenant)])
        """,
    )
    read = _route(http, "/{item_id}")
    assert [d["name"] for d in read["dependencies"]] == ["audit", "current_user"]
    assert read["handler_params"] == ["item_id", "user"]
    scoped = _route(http, "/scoped", "POST")
    assert scoped["dependencies"] == [{"name": "current_user", "kind": "Security"}]
    assert http["depends"]["current_user"] == [{"name": "oauth2", "kind": "Depends"}]
    assert http["assigns"]["oauth2"]["call"] == "OAuth2PasswordBearer"
    assert http["assigns"]["router"]["prefix"] == "/items"
    assert http["assigns"]["router"]["dependencies"] == [{"name": "verify_key", "kind": "Depends"}]
    [mount] = http["mounts"]
    assert mount["child"] == "router" and mount["prefix"] == "/v1"
    assert mount["dependencies"] == [{"name": "tenant", "kind": "Depends"}]


def test_express_routes_chains_uses_bindings_and_exports(tmp_path: Path) -> None:
    http = _http(
        tmp_path,
        "server.js",
        """
        const express = require("express");
        const { ensureLoggedIn } = require("connect-ensure-login");
        import users from "./routes/users";
        const app = express();
        const api = express.Router();
        app.use(express.json());
        app.use("/api", passport.authenticate("jwt"), api);
        app.use("/users", require("./routes/users"));
        app.use("/legacy", require("./routes/legacy")(app, db));
        api.get("/orders/:id", ensureLoggedIn(), orders.show);
        api.route("/carts/:cartId").get(carts.show).delete(isAdmin, carts.remove);
        app.post("/login", function (req, res) {});
        app.get("title");
        app.get(dynamicPath, handler);
        cache.get(`key-${id}`, fallback);
        for (const page of pages) { app.get(`/${page}`, render); }
        module.exports = app;
        """,
    )
    show = _route(http, "/orders/:id")
    assert show["receiver"] == "api" and show["handler"] == "orders.show"
    assert show["middleware"] == ["ensureLoggedIn"]
    remove = _route(http, "/carts/:cartId", "DELETE")
    assert remove["middleware"] == ["isAdmin"] and remove["receiver"] == "api"
    assert _route(http, "/carts/:cartId")["middleware"] == []
    assert _route(http, "/login", "POST")["handler"] == "<inline>"
    # a settings read, a variable path and a template key are not routes; a template
    # path that starts with "/" is a route whose path is not known
    assert len(http["routes"]) == 5
    [dynamic] = [r for r in http["routes"] if r["handler"] == "render"]
    assert dynamic["path"] is None
    uses = {(u["prefix"], tuple(map(str, u["args"]))) for u in http["uses"]}
    assert (None, ("{'name': 'express.json'}",)) in uses
    assert ("/api", ("{'name': 'passport.authenticate'}", "{'name': 'api'}")) in uses
    assert ("/users", ("{'module': './routes/users'}",)) in uses
    assert ("/legacy", ("{'module': './routes/legacy'}",)) in uses
    assert http["bindings"] == {
        "express": "express",
        "ensureLoggedIn": "connect-ensure-login",
        "users": "./routes/users",
    }
    assert http["assigns"]["api"] == {"call": "express.Router"}
    assert http["exports"] == ["app"]


def test_typescript_and_passed_in_receivers(tmp_path: Path) -> None:
    http = _http(
        tmp_path,
        "routes/index.ts",
        """
        import { Router, Request, Response } from "express";
        const router: Router = Router();
        router.get("/me", requireAuth, (req: Request, res: Response) => {});
        export default router;
        export const mount = (app: any) => { app.get("/health", ok); };
        """,
    )
    assert {r["path"] for r in http["routes"]} == {"/me", "/health"}
    assert http["assigns"]["router"] == {"call": "Router"} and http["exports"] == ["router"]


def test_files_without_routes_have_no_http_key(tmp_path: Path) -> None:
    (tmp_path / "lib.py").write_text("import os\n\ndef f():\n    return os.getcwd()\n")
    (tmp_path / "util.js").write_text("module.exports = (a) => a + 1;\n")
    files = extract(tmp_path)["files"]
    assert "http" not in files["lib.py"]
    assert files["util.js"].get("http", {}).get("routes") is None


def test_hostile_input_is_capped_and_never_crashes(tmp_path: Path) -> None:
    many = "\n".join(
        f'@app.get("/r{i}")\ndef r{i}():\n    return ""\n' for i in range(MAX_ROUTES_PER_FILE + 50)
    )
    decorators = "".join(f"@d{i}\n" for i in range(100))
    long_path = "/" + "a" * 5000
    code = (
        many
        + f"\n@app.get({long_path!r})\n{decorators}def long():\n    pass\n"
        + "\n@app.get(f'/x/{y}')\ndef dynamic():\n    pass\n"
        + "\n@app.route()\ndef empty():\n    pass\n"
        + "x = (" * 300
        + "1"
        + ")" * 300
        + "\n"
    )
    http = _http(tmp_path, "big.py", code)
    assert len(http["routes"]) == MAX_ROUTES_PER_FILE
    other = _http(
        tmp_path / "sub",
        "small.py",
        f"@app.get({long_path!r})\n{decorators}def long():\n    pass\n"
        "\n@app.get(f'/x/{{y}}')\ndef dynamic():\n    pass\n"
        "\n@app.route()\ndef empty():\n    pass\n",
    )
    long_route, dynamic, empty = other["routes"]
    assert long_route["path"] is not None and len(long_route["path"]) == MAX_PATH
    assert len(long_route["decorators"]) == MAX_NAMES
    assert dynamic["path"] is None and empty["path"] is None
    js = _http(
        tmp_path / "js",
        "x.js",
        "app.get('/a', " + ", ".join(f"m{i}" for i in range(300)) + ", h);\n"
        "app.use(" + "f(" * 200 + ")" * 200 + ");\n",
    )
    [route] = js["routes"]
    assert len(route["middleware"]) == MAX_NAMES


# --- ts-imports.5: handler bodies, call sites, exported functions (X5 part 2) -----------
def test_python_handler_bodies_say_what_they_load_and_whether_they_check_an_owner(
    tmp_path: Path,
) -> None:
    http = _http(
        tmp_path,
        "app.py",
        """
        from flask import Flask
        app = Flask(__name__)

        @app.get("/invoices/<int:invoice_id>")
        @login_required
        def invoice(invoice_id):
            return Invoice.query.get_or_404(invoice_id)

        @app.delete("/documents/<int:doc_id>")
        def delete_document(doc_id):
            doc = Document.query.filter_by(id=doc_id, owner_id=current_user.id).first()
            return jsonify(doc_id)

        @app.get("/echo/<name>")
        def echo(name):
            return jsonify(str(name))

        def view(item_id):
            return Item.query.get(item_id)

        app.add_url_rule("/items/<item_id>", view_func=view)
        """,
    )
    assert _route(http, "/invoices/<int:invoice_id>")["body"] == {
        "span": [7, 8],
        "loads": ["invoice_id"],
        "ownership": False,
    }
    doc = _route(http, "/documents/<int:doc_id>", "DELETE")["body"]
    assert doc["loads"] == ["doc_id"] and doc["ownership"] is True
    # an id that is only formatted or echoed is not a lookup
    assert _route(http, "/echo/<name>")["body"]["loads"] == []
    rule = _route(http, "/items/<item_id>")
    assert rule["handler_params"] == ["item_id"] and rule["body"]["loads"] == ["item_id"]


def test_fastapi_ownership_through_a_dependency_and_an_attribute_named_like_the_id(
    tmp_path: Path,
) -> None:
    http = _http(
        tmp_path,
        "api.py",
        """
        from fastapi import APIRouter, Depends
        router = APIRouter()

        @router.put("/projects/{project_id}")
        def update(project_id: int, user=Depends(current_user), db=Depends(get_db)):
            return db.query(Project).filter(Project.owner_id == user.id).get(project_id)

        @router.get("/things/{id}")
        def thing(id: int, db=Depends(get_db)):
            return db.get(Thing, row.id)
        """,
    )
    update = _route(http, "/projects/{project_id}", "PUT")["body"]
    assert "project_id" in update["loads"] and update["ownership"] is True
    # `row.id` is an attribute, not the parameter `id`
    assert _route(http, "/things/{id}")["body"]["loads"] == []


def test_express_handler_bodies_inline_named_and_unknown(tmp_path: Path) -> None:
    http = _http(
        tmp_path,
        "routes.js",
        """
        const index = (app, db) => {
          app.get("/notes/:noteId", isLoggedIn, (req, res) => {
            Note.findById(req.params.noteId).then(n => res.json(n));
          });
          app.delete("/notes/:id", async function (req, res) {
            const { id } = req.params;
            await Note.deleteOne({ _id: id, owner: req.user.id });
          });
          app.get("/users/:userId", show);
          app.get("/profile/:pid", profile.show);
        };
        function show(req, res) { return User.findById(req.params.userId); }
        module.exports = index;
        """,
    )
    assert _route(http, "/notes/:noteId")["body"]["loads"] == ["noteId"]
    removed = _route(http, "/notes/:id", "DELETE")["body"]
    assert removed["loads"] == ["id"] and removed["ownership"] is True
    assert _route(http, "/users/:userId")["body"]["span"] == [13, 13]
    assert "body" not in _route(http, "/profile/:pid")  # its code is in another file
    assert http["params"] == {"index": ["app", "db"]} and http["exports"] == ["index"]


def test_js_call_sites_and_exported_function_parameters(tmp_path: Path) -> None:
    server = _http(
        tmp_path,
        "server.js",
        """
        const express = require("express");
        const routes = require("./routes");
        const app = express();
        app.use(session());
        routes(app, db);
        require("./other")(app, { strict: true });
        foo.bar(app);
        setup("literal");
        app.get("/", home);
        """,
    )
    assert server["calls"] == [
        {"callee": "routes", "args": ["app", "db"], "line": 6},
        {"module": "./other", "args": ["app", None], "line": 7},
    ]
    anon = _http(
        tmp_path / "a", "r.js", "module.exports = function (app, db) { app.get('/x', h); };"
    )
    assert anon["params"] == {"<module>": ["app", "db"]} and anon["exports"] == ["<module>"]
    arrow = _http(tmp_path / "b", "r.mjs", "export default app => { app.get('/y', h); };")
    assert arrow["params"] == {"<module>": ["app"]}
    named = _http(tmp_path / "c", "r.js", "export function mount(app) { app.get('/z', h); }")
    assert named["params"] == {"mount": ["app"]}


def test_a_huge_handler_body_is_cut_off_and_still_described(tmp_path: Path) -> None:
    lines = "\n".join(f"    x{i} = load(item_id) if {i} else owner_id == 1" for i in range(6000))
    http = _http(
        tmp_path,
        "big.py",
        f'@app.get("/items/<item_id>")\ndef item(item_id):\n{lines}\n    return 1\n',
    )
    body = _route(http, "/items/<item_id>")["body"]
    assert body["span"] == [2, 6003] and body["loads"] == ["item_id"]
