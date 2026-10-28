"""Extractor ts-imports.4 (X5 part 1, ADR-0022): route declarations and every place a guard
can come from, recorded without deciding anything."""

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
    assert out["analyzer"] == ANALYZER_VERSION == "ts-imports.4"
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
