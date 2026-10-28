"""Route inventory and guards (X5 part 1, ADR-0022): resolution, statuses, evidence."""

from __future__ import annotations

import copy
import datetime as dt
import textwrap
from pathlib import Path
from typing import Any

import pytest
import yaml
from riskgraph.modules.authz import Route, route_evidence, route_inventory, summary
from riskgraph.modules.authz.guards import CATALOGUE_FILE, CatalogueError, load_catalogue, parse
from riskgraph.modules.evidence import Assurance
from riskgraph.modules.reachability.extract import extract


def _inventory(tmp_path: Path, files: dict[str, str]) -> list[Route]:
    for name, code in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(code), encoding="utf-8")
    return route_inventory(extract(tmp_path))


def _at(routes: list[Route], full_path: str, method: str = "GET") -> Route:
    [hit] = [r for r in routes if r.full_path == full_path and method in r.methods]
    return hit


# --- catalogue -------------------------------------------------------------------------
def test_the_catalogue_loads_and_matches_names() -> None:
    cat = load_catalogue()
    assert set(cat.frameworks) == {"flask", "fastapi", "express"}
    assert cat.is_guard("flask", "auth.login_required")
    assert not cat.is_guard("flask", "login_required_not")
    assert cat.is_guard("express", "passport.authenticate")
    assert cat.is_guard("express", "jwt", {"jwt": "express-jwt"})
    assert not cat.is_guard("express", "jwt", {"jwt": "jsonwebtoken"})
    assert cat.kind_of("flask.Flask") == ("flask", "app")
    assert cat.kind_of("express.Router") == ("express", "router")
    assert cat.kind_of("Router") == ("express", "router")
    assert cat.kind_of("Thing") is None


@pytest.mark.parametrize(
    "name,expected",
    [
        ("isLoggedIn", True),
        ("requireAuth", True),
        ("get_current_user", True),
        ("require_user", True),
        ("check_admin", True),
        ("verifyToken", True),
        ("get_db", False),
        ("cache.cached", False),
        ("express.json", False),
        ("get_session", False),
        ("current", False),
    ],
)
def test_custom_hints_match_words_not_substrings(name: str, expected: bool) -> None:
    assert load_catalogue().looks_like_auth(name) is expected


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d.update(version=2),
        lambda d: d.update(extra=1),
        lambda d: d["frameworks"].pop("flask"),
        lambda d: d["frameworks"]["flask"].update(language="go"),
        lambda d: d["guards"]["flask"].append({"name": "x; rm -rf /"}),
        lambda d: d["guards"]["express"].append({"name": "x", "module": "../../evil"}),
        lambda d: d["guards"]["flask"].append({"name": "x", "why": "unknown key"}),
        lambda d: d.update(custom_hints=["Auth"]),
        lambda d: d.update(fastapi_schemes="HTTPBearer"),
    ],
)
def test_a_broken_catalogue_is_refused(change: Any) -> None:
    doc = yaml.safe_load(CATALOGUE_FILE.read_text(encoding="utf-8"))
    broken = copy.deepcopy(doc)
    change(broken)
    with pytest.raises(CatalogueError):
        parse(broken)
    parse(doc)


# --- Flask -----------------------------------------------------------------------------
def test_flask_statuses_prefixes_and_hooks(tmp_path: Path) -> None:
    routes = _inventory(
        tmp_path,
        {
            "app.py": """
                from flask import Flask
                from flask_login import login_required
                from .admin import admin
                app = Flask(__name__)

                @app.route("/profile")
                @login_required
                def profile():
                    return ""

                @login_required
                @app.route("/settings", methods=["POST"])
                def settings():
                    return ""

                @app.get("/public")
                def public():
                    return ""

                @app.get("/staff")
                @staff_only
                @require_role("admin")
                def staff():
                    return ""

                app.register_blueprint(admin, url_prefix="/backoffice")
                """,
            "__init__.py": "",
            "admin.py": """
                from flask import Blueprint
                admin = Blueprint("admin", __name__, url_prefix="/admin")
                reports = Blueprint("reports", __name__, url_prefix="/reports")

                @admin.before_request
                def require_admin():
                    pass

                @admin.get("/users/<int:user_id>")
                def users(user_id):
                    return ""

                @reports.get("/daily")
                def daily():
                    return ""
                """,
        },
    )
    assert _at(routes, "/profile").status == "guarded"
    settings = _at(routes, "/settings", "POST")
    assert settings.status == "none_found"
    assert settings.notes == (
        "login_required is above the route decorator, so it does not run for the route",
    )
    assert _at(routes, "/public").status == "none_found"
    assert _at(routes, "/staff").status == "custom"
    # register_blueprint(url_prefix=) replaces the blueprint's own; the hook is the guard
    users = _at(routes, "/backoffice/users/<int:user_id>")
    assert users.status == "custom" and users.params == ("user_id",) and users.mounted
    assert [g.source for g in users.guards] == ["hook"]
    # a blueprint nobody registers keeps its own prefix and says so
    daily = _at(routes, "/reports/daily")
    assert daily.status == "none_found" and not daily.mounted
    assert any("not mounted" in n for n in daily.notes)
    assert all(r.basis == "constructor" and r.framework == "flask" for r in routes)


def test_an_app_level_hook_reaches_every_flask_route(tmp_path: Path) -> None:
    routes = _inventory(
        tmp_path,
        {
            "app.py": """
                from flask import Flask
                app = Flask(__name__)
                app.before_request(check_token)

                @app.get("/a")
                def a():
                    return ""
                """,
        },
    )
    assert _at(routes, "/a").status == "custom"


def test_unknown_and_inferred_frameworks(tmp_path: Path) -> None:
    alone = _inventory(
        tmp_path / "one",
        {"views.py": "@thing.get('/x')\ndef x():\n    return ''\n"},
    )
    assert [(r.framework, r.status, r.basis) for r in alone] == [
        (None, "unknown_framework", "unknown")
    ]
    together = _inventory(
        tmp_path / "two",
        {
            "app.py": "from flask import Flask\napp = Flask(__name__)\n",
            "views.py": "@site.get('/x')\ndef x():\n    return ''\n",
        },
    )
    [x] = together
    assert (x.framework, x.basis) == ("flask", "repository")


# --- FastAPI ---------------------------------------------------------------------------
FASTAPI_APP = {
    "app/__init__.py": "",
    "app/security.py": """
        from fastapi import Depends
        from fastapi.security import OAuth2PasswordBearer
        oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

        def get_current_user(token: str = Depends(oauth2_scheme)):
            return token

        def get_admin(user=Depends(get_current_user)):
            return user

        def loop_a(x=Depends(loop_b)):
            return x

        def loop_b(x=Depends(loop_a)):
            return x
        """,
    "app/db.py": "def get_db():\n    yield None\n",
    "app/routers/__init__.py": "",
    "app/routers/items.py": """
        from typing import Annotated
        from fastapi import APIRouter, Depends
        from ..db import get_db
        from ..security import get_admin, loop_a
        router = APIRouter(prefix="/items")

        @router.get("/{item_id}")
        def read(item_id: int, db=Depends(get_db)):
            return {}

        @router.delete("/{item_id}")
        def delete(item_id: int, admin: Annotated[dict, Depends(get_admin)]):
            return {}

        @router.get("/loop")
        def loop(x=Depends(loop_a)):
            return {}
        """,
    "app/routers/orphan.py": """
        from fastapi import APIRouter
        router = APIRouter()

        @router.get("/orphan")
        def orphan():
            return {}
        """,
    "app/main.py": """
        from fastapi import Depends, FastAPI, Security
        from .routers import items
        from .security import get_current_user
        app = FastAPI()
        app.include_router(items.router, prefix="/v1")

        @app.get("/health")
        def health():
            return {}

        @app.get("/me", dependencies=[Depends(get_current_user)])
        def me():
            return {}

        @app.get("/scoped")
        def scoped(u=Security(lookup, scopes=["x"])):
            return {}
        """,
}


def test_fastapi_dependencies_resolve_across_files(tmp_path: Path) -> None:
    routes = _inventory(tmp_path, FASTAPI_APP)
    read = _at(routes, "/v1/items/{item_id}")
    assert read.status == "none_found" and read.mounted and read.params == ("item_id",)
    assert _at(routes, "/v1/items/{item_id}", "DELETE").status == "guarded"  # get_admin → oauth2
    assert _at(routes, "/v1/items/loop").status == "none_found"  # a cycle is no guard
    assert _at(routes, "/health").status == "none_found"
    assert _at(routes, "/me").status == "guarded"
    assert _at(routes, "/scoped").status == "guarded"  # Security() is a security dependency
    orphan = _at(routes, "/orphan")
    assert orphan.status == "unresolved" and not orphan.mounted


def test_fastapi_include_router_dependencies_guard_the_router(tmp_path: Path) -> None:
    files = dict(FASTAPI_APP)
    files["app/main.py"] = files["app/main.py"].replace(
        'prefix="/v1")', 'prefix="/v1", dependencies=[Depends(get_current_user)])'
    )
    routes = _inventory(tmp_path, files)
    read = _at(routes, "/v1/items/{item_id}")
    assert read.status == "guarded"
    assert {g.source for g in read.guards if g.catalogued} == {"mount"}


# --- Express ---------------------------------------------------------------------------
def test_express_order_prefixes_and_mounts(tmp_path: Path) -> None:
    routes = _inventory(
        tmp_path,
        {
            "server.js": """
                const express = require("express");
                const passport = require("passport");
                const jwt = require("express-jwt");
                const admin = require("./routes/admin");
                const app = express();
                app.get("/early", h);
                app.use(express.json());
                app.use("/secure", passport.authenticate("jwt"));
                app.get("/secure/data", h);
                app.get("/securely", h);
                app.use("/admin", jwt({ secret: s }), admin);
                app.use(requireLogin);
                app.get("/late", h);
                """,
            "routes/admin.js": """
                const router = require("express").Router();
                const users = require("./users");
                router.get("/stats", h);
                router.use("/users", users);
                module.exports = router;
                """,
            "routes/users.js": """
                const express = require("express");
                const router = express.Router();
                router.delete("/:id", h);
                module.exports = router;
                """,
            "routes/index.js": """
                module.exports = (app) => {
                  app.get("/passed", h);
                  app.get("/passed-guarded", isAuthenticated, h);
                };
                """,
        },
    )
    assert _at(routes, "/early").status == "none_found"  # registered before any use()
    assert _at(routes, "/secure/data").status == "guarded"
    assert _at(routes, "/securely").status == "none_found"  # /secure does not cover it
    assert _at(routes, "/admin/stats").status == "guarded"  # the mount's express-jwt
    nested = _at(routes, "/admin/users/:id", "DELETE")
    assert nested.status == "guarded" and nested.mounted and nested.params == ("id",)
    assert _at(routes, "/late").status == "custom"  # requireLogin, registered before it
    passed = _at(routes, "/passed")
    assert passed.status == "unresolved" and passed.basis == "repository"
    assert _at(routes, "/passed-guarded").status == "custom"


def test_express_inline_middleware_is_noted_not_guessed(tmp_path: Path) -> None:
    routes = _inventory(
        tmp_path,
        {
            "app.js": """
                const express = require("express");
                const app = express();
                app.use((req, res, next) => next());
                app.get("/x", (req, res, next) => next(), h);
                """,
        },
    )
    x = _at(routes, "/x")
    assert x.status == "none_found"
    assert set(x.notes) == {
        "inline middleware on the route is not classified",
        "inline middleware registered before the route is not classified",
    }


# --- hostile and empty input -----------------------------------------------------------
@pytest.mark.parametrize(
    "doc",
    [
        {},
        {"files": None},
        {"files": {"a.py": None, "b.js": {"http": "nope"}}},
        {"files": {"a.py": {"lang": "python", "http": {"routes": [None, 1, "x"]}}}},
        {"files": {"a.py": {"lang": "python", "http": {"routes": [{}], "mounts": [None, {}]}}}},
        {"files": {"a.js": {"lang": "js", "http": {"uses": [{"args": [None, {}]}], "routes": []}}}},
    ],
)
def test_malformed_extracts_give_routes_or_nothing_and_never_raise(doc: dict[str, Any]) -> None:
    for r in route_inventory(doc):
        assert r.status in ("unknown_framework", "unresolved", "none_found")


def test_a_mount_cycle_ends(tmp_path: Path) -> None:
    routes = _inventory(
        tmp_path,
        {
            "a.js": """
                const express = require("express");
                const a = express.Router();
                const b = express.Router();
                a.use("/b", b);
                b.use("/a", a);
                a.get("/x", h);
                """,
        },
    )
    x = _at(routes, "/b/a/x")
    assert x.status == "unresolved" and "mount cycle" in x.notes


# --- evidence --------------------------------------------------------------------------
def test_routes_become_route_and_auth_guard_evidence(tmp_path: Path) -> None:
    routes = _inventory(tmp_path, FASTAPI_APP)
    now = dt.datetime(2026, 10, 28, tzinfo=dt.UTC)
    evidence = route_evidence(routes, now)
    by_kind: dict[str, list[Any]] = {}
    for e in evidence:
        by_kind.setdefault(e.kind, []).append(e)
    assert len(by_kind["route"]) == len(routes)
    assert all(e.assurance is Assurance.VERIFIED for e in by_kind["route"])
    assert all(e.assurance is Assurance.INFERRED for e in by_kind["auth_guard"])
    me = next(e for e in by_kind["route"] if e.facts["full_path"] == "/me")
    assert me.facts["guard_status"] == "guarded" and me.facts["guards"] == ("get_current_user",)
    [guard] = [e for e in by_kind["auth_guard"] if e.facts["route"] == me.id]
    assert guard.confidence == "high" and guard.facts["guards"] == ("dependency:get_current_user",)
    assert route_evidence(routes, now) == evidence  # stable ids
    assert summary(routes)["by_status"] == {"guarded": 3, "none_found": 3, "unresolved": 1}


def test_a_repository_inferred_framework_gives_inferred_route_evidence(tmp_path: Path) -> None:
    routes = _inventory(
        tmp_path,
        {
            "app.py": "from flask import Flask\napp = Flask(__name__)\n",
            "views.py": "@site.get('/x')\n@admin_required\ndef x():\n    return ''\n",
        },
    )
    [route, guard] = route_evidence(routes, dt.datetime(2026, 10, 28, tzinfo=dt.UTC))
    assert route.assurance is Assurance.INFERRED and route.confidence == "medium"
    assert route.facts["custom_guards"] == ("admin_required",)
    assert guard.confidence == "low" and guard.facts["catalogued"] is False


def test_the_pipeline_step_reports_instead_of_failing_the_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import uuid

    from riskgraph.modules.reachability import ReachabilityRun
    from riskgraph.modules.scans import pipeline

    sid = uuid.uuid4()
    assert pipeline._routes(sid, ReachabilityRun("failed")) == (
        [],
        {"status": "unavailable", "routes": 0},
    )
    ok = ReachabilityRun("ok", extracted={"files": {}})
    assert pipeline._routes(sid, ok) == ([], {"status": "ok", **summary([])})

    def boom(_: object) -> list[Route]:
        raise RuntimeError("bug")

    monkeypatch.setattr(pipeline, "route_inventory", boom)
    assert pipeline._routes(sid, ok) == ([], {"status": "failed", "routes": 0})
