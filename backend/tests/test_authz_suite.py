"""Labelled route suite (X5 part 1; plan §6 "Authorization (B)", SCHEDULE day 4).

One small app per framework with every pattern the plan names: guarded, unguarded,
inconsistent (a router where all routes but one are guarded), custom guard, and an id
parameter with and without an ownership check. Each route is labelled by hand with its
method, full path, guard status and path parameters. The real extractor and inventory run
on the written files.

Two constructs are in the suite on purpose although the extractor does not handle them,
so the recall is an honest number and not 1.0 by construction: an Express route on a
computed member (``app[verb](…)``) and a Flask class-based view's handler name. The
ownership check itself is X5 part 2's BOLA heuristic; here only the parameter is labelled.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from riskgraph.modules.authz import route_inventory
from riskgraph.modules.reachability.extract import extract

RECALL_TARGET = 0.95  # plan X5 row: route inventory recall ≥ 0.95

FLASK = {
    "flaskapp/__init__.py": "",
    "flaskapp/app.py": """
        from flask import Flask
        from flask_login import login_required
        from .orders import orders
        from .views import ReportView
        app = Flask(__name__)

        @app.route("/")
        def index():
            return ""

        @app.route("/account", methods=["GET", "POST"])
        @login_required
        def account():
            return ""

        @app.get("/team")
        @team_member_required
        def team():
            return ""

        @app.delete("/documents/<int:doc_id>")
        @login_required
        def delete_document(doc_id):
            doc = Document.query.filter_by(id=doc_id, owner_id=current_user.id).first_or_404()
            return ""

        @app.get("/invoices/<int:invoice_id>")
        @login_required
        def invoice(invoice_id):
            return Invoice.query.get_or_404(invoice_id)

        app.add_url_rule("/reports", view_func=ReportView.as_view("reports"))
        app.register_blueprint(orders, url_prefix="/orders")
        """,
    "flaskapp/orders.py": """
        from flask import Blueprint
        from flask_login import login_required
        orders = Blueprint("orders", __name__)

        @orders.get("/")
        @login_required
        def list_orders():
            return ""

        @orders.get("/<int:order_id>")
        @login_required
        def show(order_id):
            return ""

        @orders.post("/")
        @login_required
        def create():
            return ""

        @orders.delete("/<int:order_id>")
        def remove(order_id):
            return ""
        """,
}
FLASK_LABELS = [
    ("flaskapp/app.py", "GET", "/", "none_found", ()),
    ("flaskapp/app.py", "GET", "/account", "guarded", ()),
    ("flaskapp/app.py", "POST", "/account", "guarded", ()),
    ("flaskapp/app.py", "GET", "/team", "custom", ()),
    ("flaskapp/app.py", "DELETE", "/documents/<int:doc_id>", "guarded", ("doc_id",)),
    ("flaskapp/app.py", "GET", "/invoices/<int:invoice_id>", "guarded", ("invoice_id",)),
    ("flaskapp/app.py", "GET", "/reports", "none_found", ()),
    ("flaskapp/orders.py", "GET", "/orders", "guarded", ()),
    ("flaskapp/orders.py", "GET", "/orders/<int:order_id>", "guarded", ("order_id",)),
    ("flaskapp/orders.py", "POST", "/orders", "guarded", ()),
    ("flaskapp/orders.py", "DELETE", "/orders/<int:order_id>", "none_found", ("order_id",)),
]

FASTAPI = {
    "api/__init__.py": "",
    "api/deps.py": """
        from fastapi import Depends
        from fastapi.security import HTTPBearer
        bearer = HTTPBearer()

        def current_user(credentials=Depends(bearer)):
            return credentials

        def get_db():
            yield None
        """,
    "api/projects.py": """
        from typing import Annotated
        from fastapi import APIRouter, Depends
        from .deps import current_user, get_db
        router = APIRouter(prefix="/projects")

        @router.get("/")
        def list_projects(user=Depends(current_user)):
            return []

        @router.get("/{project_id}")
        def get_project(project_id: int, user: Annotated[dict, Depends(current_user)]):
            return {}

        @router.put("/{project_id}")
        def update_project(project_id: int, user=Depends(current_user), db=Depends(get_db)):
            return db.query(Project).filter(Project.owner_id == user.id).first()

        @router.delete("/{project_id}")
        def delete_project(project_id: int, db=Depends(get_db)):
            return {}
        """,
    "api/main.py": """
        from fastapi import Depends, FastAPI
        from . import projects
        from .deps import get_db
        app = FastAPI()
        app.include_router(projects.router, prefix="/v1")

        @app.get("/status")
        def status(db=Depends(get_db)):
            return {}

        @app.api_route("/webhook", methods=["POST", "PUT"])
        def webhook(sig=Depends(verify_signature)):
            return {}

        def metrics():
            return {}

        app.add_api_route("/metrics", metrics, methods=["GET"])
        """,
}
FASTAPI_LABELS = [
    ("api/projects.py", "GET", "/v1/projects", "guarded", ()),
    ("api/projects.py", "GET", "/v1/projects/{project_id}", "guarded", ("project_id",)),
    ("api/projects.py", "PUT", "/v1/projects/{project_id}", "guarded", ("project_id",)),
    ("api/projects.py", "DELETE", "/v1/projects/{project_id}", "none_found", ("project_id",)),
    ("api/main.py", "GET", "/status", "none_found", ()),
    ("api/main.py", "POST", "/webhook", "custom", ()),
    ("api/main.py", "PUT", "/webhook", "custom", ()),
    ("api/main.py", "GET", "/metrics", "none_found", ()),
]

EXPRESS = {
    "web/server.js": """
        const express = require("express");
        const passport = require("passport");
        const notes = require("./routes/notes");
        const app = express();
        app.use(express.json());
        app.get("/", home);
        app.post("/login", passport.authenticate("local"), loggedIn);
        app.use("/notes", passport.authenticate("session"), notes);
        app.get("/profile/:userId", isLoggedIn, profile.show);
        for (const verb of ["get", "post"]) { app[verb]("/echo", echo); }
        app.get("/health", (req, res) => res.send("ok"));
        """,
    "web/routes/notes.js": """
        const express = require("express");
        const router = express.Router();
        router.get("/", notes.list);
        router.route("/:noteId")
          .get(notes.show)
          .delete(notes.remove);
        module.exports = router;
        """,
    "web/routes/admin.js": """
        const { Router } = require("express");
        const admin = Router();
        admin.get("/users", requireAdmin, users.list);
        admin.get("/users/:id", requireAdmin, users.show);
        admin.post("/users", requireAdmin, users.create);
        admin.delete("/users/:id", users.remove);
        module.exports = admin;
        """,
}
EXPRESS_LABELS = [
    ("web/server.js", "GET", "/", "none_found", ()),
    ("web/server.js", "POST", "/login", "guarded", ()),
    ("web/server.js", "GET", "/profile/:userId", "custom", ("userId",)),
    ("web/server.js", "GET", "/echo", "none_found", ()),  # app[verb]: not extracted
    ("web/server.js", "GET", "/health", "none_found", ()),
    ("web/routes/notes.js", "GET", "/notes", "guarded", ()),
    ("web/routes/notes.js", "GET", "/notes/:noteId", "guarded", ("noteId",)),
    ("web/routes/notes.js", "DELETE", "/notes/:noteId", "guarded", ("noteId",)),
    # admin is never mounted in this app: its routes are seen, their guard sources are not
    ("web/routes/admin.js", "GET", "/users", "custom", ()),
    ("web/routes/admin.js", "GET", "/users/:id", "custom", ("id",)),
    ("web/routes/admin.js", "POST", "/users", "custom", ()),
    ("web/routes/admin.js", "DELETE", "/users/:id", "unresolved", ("id",)),
]

LABELS = FLASK_LABELS + FASTAPI_LABELS + EXPRESS_LABELS


def _write(root: Path) -> None:
    for name, code in {**FLASK, **FASTAPI, **EXPRESS}.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(code), encoding="utf-8")


def _found(root: Path) -> dict[tuple[str, str, str], tuple[str, tuple[str, ...], str]]:
    found = {}
    for r in route_inventory(extract(root)):
        for method in r.methods:
            found[(r.file, method, r.full_path or "")] = (r.status, r.params, r.handler)
    return found


def test_the_suite_has_every_pattern_for_every_framework() -> None:
    for labels in (FLASK_LABELS, FASTAPI_LABELS, EXPRESS_LABELS):
        statuses = {label[3] for label in labels}
        assert {"guarded", "none_found", "custom"} <= statuses
        assert any(label[4] for label in labels if label[3] == "guarded")  # id, guarded
        assert any(label[4] for label in labels if label[3] != "guarded")  # id, not guarded


def test_route_inventory_recall_on_the_labelled_suite(tmp_path: Path) -> None:
    _write(tmp_path)
    found = _found(tmp_path)
    hits = [label for label in LABELS if label[:3] in found]
    recall = len(hits) / len(LABELS)
    missed = sorted(set(LABELS) - set(hits))
    assert recall >= RECALL_TARGET, missed
    # the one miss is the computed-member route the docstring names
    assert [m[2] for m in missed] == ["/echo"]
    # nothing is found that is not labelled (precision of the inventory itself)
    assert set(found) <= {label[:3] for label in LABELS}


def test_guard_status_and_parameters_match_the_labels(tmp_path: Path) -> None:
    _write(tmp_path)
    found = _found(tmp_path)
    wrong = [
        (label, found[label[:3]][:2])
        for label in LABELS
        if label[:3] in found and found[label[:3]][:2] != (label[3], label[4])
    ]
    assert wrong == []


def test_no_route_is_ever_called_unguarded_without_a_resolved_mount(tmp_path: Path) -> None:
    _write(tmp_path)
    for r in route_inventory(extract(tmp_path)):
        if r.status == "none_found":
            assert r.mounted or r.framework == "flask"


def test_the_class_based_view_is_found_without_a_handler_name(tmp_path: Path) -> None:
    _write(tmp_path)
    assert _found(tmp_path)[("flaskapp/app.py", "GET", "/reports")][2] == "<unknown>"
