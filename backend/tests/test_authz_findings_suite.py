"""Labelled authorization suite (X5 part 2; plan §6 "Authorization (B)", SCHEDULE day 5).

One small app per framework, written to look like ordinary code rather than like the
rules. Every route is labelled by hand with the issues a careful reviewer would raise
(ground truth, not what the rules happen to say): a write left open among guarded
siblings, a sensitive route without a guard, a manifest policy broken, an id looked up
without an ownership check. Routes that are public on purpose (a catalogue, a contact
form, a public post list next to guarded writes) are labelled with no issue, so a rule
that fires on them counts as a false positive.

The real extractor, inventory and analysis run on the written files. A line marked
``# code finding`` stands for an injection-like SAST finding there (the real scanners do
not run in tests). Targets from the plan: inconsistency precision ≥ 0.8; no BOLA finding
above ``hypothesis``; the inventory's own recall is pinned by ``test_authz_suite.py``.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from riskgraph.modules.authz import analyze, route_inventory
from riskgraph.modules.context import parse_manifest
from riskgraph.modules.evidence import Assurance
from riskgraph.modules.reachability.extract import extract
from riskgraph.shared.vocabulary import Severity

PRECISION_TARGET = 0.8  # plan X5 row and §6: inconsistency / unguarded precision ≥ 0.8
MARK = "# code finding"

FLASK = {
    "shop/__init__.py": "",
    "shop/app.py": """
        from flask import Flask, request
        from flask_login import login_required, current_user
        from .orders import orders
        from .admin import admin
        app = Flask(__name__)

        @app.get("/products")
        def products():
            return Product.query.all()

        @app.get("/products/<int:product_id>")
        def product(product_id):
            return Product.query.get_or_404(product_id)

        @app.post("/contact")
        def contact():
            send_mail(request.form["message"])
            return ""

        @app.route("/login", methods=["GET", "POST"])
        def login():
            return ""

        @app.get("/invoices/<int:invoice_id>")
        @login_required
        def invoice(invoice_id):
            return Invoice.query.get_or_404(invoice_id)

        @app.get("/account")
        @login_required
        def account():
            return current_user

        @app.post("/account/delete")
        def delete_account():
            db.session.delete(User.query.get(request.form["id"]))
            return ""

        @app.get("/posts")
        def posts():
            return Post.query.all()

        @app.post("/posts")
        @login_required
        def new_post():
            return ""

        @app.delete("/posts/<int:post_id>")
        @login_required
        def delete_post(post_id):
            Post.query.filter_by(id=post_id, author_id=current_user.id).delete()
            return ""

        @app.get("/search")
        def search():
            q = request.args["q"]
            return db.engine.execute("SELECT * FROM items WHERE name = '" + q + "'")  # code finding

        app.register_blueprint(orders, url_prefix="/orders")
        app.register_blueprint(admin, url_prefix="/admin")
        """,
    "shop/orders.py": """
        from flask import Blueprint
        from flask_login import login_required, current_user
        orders = Blueprint("orders", __name__)

        @orders.get("/")
        @login_required
        def list_orders():
            return Order.query.filter_by(user_id=current_user.id).all()

        @orders.get("/<int:order_id>")
        @login_required
        def show(order_id):
            return Order.query.filter_by(id=order_id, user_id=current_user.id).first_or_404()

        @orders.post("/")
        @login_required
        def create():
            return ""

        @orders.delete("/<int:order_id>")
        def remove(order_id):
            Order.query.filter_by(id=order_id).delete()
            return ""
        """,
    "shop/admin.py": """
        from flask import Blueprint
        from flask_login import login_required
        admin = Blueprint("admin", __name__)

        @admin.get("/stats")
        @login_required
        def stats():
            return ""

        @admin.get("/users")
        @login_required
        @admin_required
        def users():
            return ""
        """,
}
FLASK_MANIFEST = """
version: 1
authz:
  guards: [admin_required]
  rules:
    - path: /admin/**
      require: [admin_required]
"""
FLASK_LABELS: dict[tuple[str, str, str], set[str]] = {
    ("shop/app.py", "GET", "/products"): set(),
    ("shop/app.py", "GET", "/products/<int:product_id>"): set(),  # a public catalogue
    ("shop/app.py", "POST", "/contact"): set(),  # a public contact form
    ("shop/app.py", "GET", "/login"): set(),
    ("shop/app.py", "POST", "/login"): set(),
    ("shop/app.py", "GET", "/invoices/<int:invoice_id>"): {"bola"},
    ("shop/app.py", "GET", "/account"): set(),
    ("shop/app.py", "POST", "/account/delete"): {"unguarded-sensitive"},
    ("shop/app.py", "GET", "/posts"): set(),  # anyone may read the posts
    ("shop/app.py", "POST", "/posts"): set(),
    ("shop/app.py", "DELETE", "/posts/<int:post_id>"): set(),
    ("shop/app.py", "GET", "/search"): {"unguarded-sensitive"},  # SQL built from input
    ("shop/orders.py", "GET", "/orders"): set(),
    ("shop/orders.py", "GET", "/orders/<int:order_id>"): set(),
    ("shop/orders.py", "POST", "/orders"): set(),
    ("shop/orders.py", "DELETE", "/orders/<int:order_id>"): {"inconsistent", "bola"},
    ("shop/admin.py", "GET", "/admin/stats"): {"policy"},
    ("shop/admin.py", "GET", "/admin/users"): set(),
}

FASTAPI = {
    "api/__init__.py": "",
    "api/deps.py": """
        from fastapi import Depends
        from fastapi.security import OAuth2PasswordBearer
        oauth2 = OAuth2PasswordBearer(tokenUrl="token")

        def current_user(token=Depends(oauth2)):
            return decode(token)

        def get_db():
            yield session()
        """,
    "api/projects.py": """
        from fastapi import APIRouter, Depends
        from .deps import current_user, get_db
        router = APIRouter(prefix="/projects")

        @router.get("/")
        def list_projects(user=Depends(current_user), db=Depends(get_db)):
            return db.query(Project).filter(Project.owner_id == user.id).all()

        @router.get("/{project_id}")
        def get_project(project_id: int, user=Depends(current_user), db=Depends(get_db)):
            return db.query(Project).filter(
                Project.id == project_id, Project.owner_id == user.id
            ).first()

        @router.put("/{project_id}")
        def update_project(project_id: int, user=Depends(current_user), db=Depends(get_db)):
            return db.get(Project, project_id)

        @router.delete("/{project_id}")
        def delete_project(project_id: int, db=Depends(get_db)):
            db.delete(db.get(Project, project_id))
        """,
    "api/main.py": """
        import subprocess
        from fastapi import Depends, FastAPI
        from . import projects
        from .deps import current_user, get_db
        app = FastAPI()
        app.include_router(projects.router, prefix="/v1")

        @app.get("/status")
        def status():
            return {"ok": True}

        @app.get("/teams")
        def teams(db=Depends(get_db)):
            return db.query(Team).all()

        @app.get("/teams/{team_id}")
        def team(team_id: int, user=Depends(current_user), db=Depends(get_db)):
            return db.query(Team).filter(Team.id == team_id, Team.owner_id == user.id).one()

        @app.post("/teams")
        def create_team(user=Depends(current_user)):
            return {}

        @app.post("/reports/export")
        def export(fmt: str):
            return subprocess.run("convert --to " + fmt, shell=True)  # code finding

        @app.post("/webhook/github")
        def github_hook():
            return {}
        """,
}
FASTAPI_LABELS: dict[tuple[str, str, str], set[str]] = {
    ("api/projects.py", "GET", "/v1/projects"): set(),
    ("api/projects.py", "GET", "/v1/projects/{project_id}"): set(),
    ("api/projects.py", "PUT", "/v1/projects/{project_id}"): {"bola"},
    ("api/projects.py", "DELETE", "/v1/projects/{project_id}"): {"inconsistent", "bola"},
    ("api/main.py", "GET", "/status"): set(),
    # a team list anyone can read next to a guarded team page: a reviewer asks
    ("api/main.py", "GET", "/teams"): {"inconsistent"},
    ("api/main.py", "GET", "/teams/{team_id}"): set(),
    ("api/main.py", "POST", "/teams"): set(),
    ("api/main.py", "POST", "/reports/export"): {"unguarded-sensitive"},
    ("api/main.py", "POST", "/webhook/github"): set(),  # signed by GitHub, not a session
}

EXPRESS = {
    "web/server.js": """
        const express = require("express");
        const session = require("express-session");
        const routes = require("./routes");
        const app = express();
        app.use(session({ secret: process.env.SECRET }));
        routes(app);
        app.listen(3000);
        """,
    "web/routes/index.js": """
        const passport = require("passport");
        const users = require("./users");
        const jwt = passport.authenticate("jwt", { session: false });
        module.exports = (app) => {
          app.get("/", (req, res) => res.render("home"));
          app.post("/feedback", (req, res) => Feedback.create({ text: req.body.text }));
          app.use("/api/users", users);
          app.get("/api/health", (req, res) => res.send("ok"));
          app.get("/api/me", jwt, (req, res) => res.json(req.user));
        };
        """,
    "web/routes/users.js": """
        const express = require("express");
        const passport = require("passport");
        const router = express.Router();
        const jwt = passport.authenticate("jwt", { session: false });
        router.get("/", jwt, (req, res) => User.find().then((u) => res.json(u)));
        router.get("/:id", jwt, (req, res) => {
          User.findById(req.params.id).then((u) => res.json(u));
        });
        router.put("/:id", jwt, async (req, res) => {
          if (req.user.id !== req.params.id) return res.sendStatus(403);
          await User.updateOne({ _id: req.params.id }, req.body);
        });
        router.delete("/:id", async (req, res) => {
          await User.deleteOne({ _id: req.params.id });
        });
        module.exports = router;
        """,
}
EXPRESS_LABELS: dict[tuple[str, str, str], set[str]] = {
    ("web/routes/index.js", "GET", "/"): set(),
    # a public feedback form; the rule cannot tell it from a sensitive write
    ("web/routes/index.js", "POST", "/feedback"): set(),
    ("web/routes/index.js", "GET", "/api/health"): set(),
    ("web/routes/index.js", "GET", "/api/me"): set(),
    ("web/routes/users.js", "GET", "/api/users"): set(),
    ("web/routes/users.js", "GET", "/api/users/:id"): {"bola"},
    ("web/routes/users.js", "PUT", "/api/users/:id"): set(),
    ("web/routes/users.js", "DELETE", "/api/users/:id"): {"inconsistent", "bola"},
}

APPS = [
    (FLASK, FLASK_LABELS, FLASK_MANIFEST),
    (FASTAPI, FASTAPI_LABELS, None),
    (EXPRESS, EXPRESS_LABELS, None),
]


def _run(root: Path) -> tuple[dict[tuple[str, str, str], set[str]], list]:  # type: ignore[type-arg]
    found: dict[tuple[str, str, str], set[str]] = {}
    issues_all = []
    for i, (files, labels, manifest_text) in enumerate(APPS):
        app = root / f"app{i}"
        marks: dict[str, list[int]] = {}
        for name, code in files.items():
            path = app / name
            path.parent.mkdir(parents=True, exist_ok=True)
            text = textwrap.dedent(code)
            path.write_text(text, encoding="utf-8")
            marks[name] = [n for n, line in enumerate(text.splitlines(), 1) if MARK in line]
        manifest = parse_manifest(manifest_text).manifest if manifest_text else None
        authz = manifest.authz if manifest is not None else None
        routes = route_inventory(extract(app), extra_guards=authz.guards if authz else ())
        for r in routes:
            for method in r.methods:
                found.setdefault((r.file, method, r.full_path or ""), set())
        result = analyze(routes, authz.rules if authz else (), marks)
        for issue in result.issues:
            for method in issue.route.methods:
                found[(issue.route.file, method, issue.route.full_path or "")].add(issue.rule)
        issues_all += result.issues
        assert set(labels) <= set(found), sorted(set(labels) - set(found))
    return found, issues_all


def _labels() -> dict[tuple[str, str, str], set[str]]:
    return {**FLASK_LABELS, **FASTAPI_LABELS, **EXPRESS_LABELS}


def _score(rule: str, found: dict[tuple[str, str, str], set[str]]) -> tuple[int, int, int]:
    """True positives, false positives, false negatives of one rule over the labels."""
    labels = _labels()
    tp = sum(1 for k, v in labels.items() if rule in v and rule in found.get(k, set()))
    fp = sum(1 for k, v in labels.items() if rule not in v and rule in found.get(k, set()))
    fn = sum(1 for k, v in labels.items() if rule in v and rule not in found.get(k, set()))
    return tp, fp, fn


def test_every_route_of_the_suite_is_labelled_and_found(tmp_path: Path) -> None:
    found, _ = _run(tmp_path)
    assert set(found) == set(_labels())


def test_inconsistency_precision_meets_the_target(tmp_path: Path) -> None:
    found, _ = _run(tmp_path)
    tp, fp, fn = _score("inconsistent", found)
    assert tp / (tp + fp) >= PRECISION_TARGET, (tp, fp, fn)
    assert (tp, fp, fn) == (4, 0, 0)


def test_unguarded_sensitive_numbers_and_its_known_false_positives(tmp_path: Path) -> None:
    """Precision 3/5 = 0.6 here, below plan §6's 0.8 for "unguarded": pinned, not hidden.
    SCHEDULE day 5 sets the target for inconsistency only; this is reported as a gap."""
    found, _ = _run(tmp_path)
    tp, fp, fn = _score("unguarded-sensitive", found)
    assert (tp, fp, fn) == (3, 2, 0)
    # the two public forms (contact, feedback) are the false positives: a write without a
    # guard and with nothing in its name that says it is public on purpose
    wrong = sorted(
        k
        for k, v in _labels().items()
        if "unguarded-sensitive" in found.get(k, set()) and "unguarded-sensitive" not in v
    )
    assert wrong == [
        ("shop/app.py", "POST", "/contact"),
        ("web/routes/index.js", "POST", "/feedback"),
    ]


def test_policy_and_bola_match_the_labels(tmp_path: Path) -> None:
    found, _ = _run(tmp_path)
    assert _score("policy", found) == (1, 0, 0)
    tp, fp, fn = _score("bola", found)
    # the public catalogue lookup is a BOLA false positive: a hypothesis to test, by design
    assert (tp, fn) == (6, 0) and fp == 1


def test_no_bola_finding_is_more_than_a_low_hypothesis(tmp_path: Path) -> None:
    _, issues = _run(tmp_path)
    bola = [i for i in issues if i.rule == "bola"]
    assert bola and all(
        i.assurance is Assurance.HYPOTHESIS and i.severity is Severity.LOW for i in bola
    )
    assert all(i.assurance is not Assurance.VERIFIED for i in issues)
