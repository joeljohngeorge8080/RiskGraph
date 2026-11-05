"""Authorization evaluation scenario I (F-4-1, owner answer (a)): labels written FIRST.

X0 keeps authorization findings out (``run.OUTSIDE_X0``): its labels were written before
those findings existed. This scenario is their own, and is reported on its own
(``evaluation.authz``, ``docs/evaluation/AUTHZ_EVAL.md``). Nothing here touches the frozen
X0 baseline.

Written on 2026-11-05 and committed before any analysis ran on it. Two kinds of ground
truth, both by construction from the code below:

- ``EXPECTED``: the authorization issues a careful reviewer would raise on each route
  (rule names as in ``authz.analysis.RULES``). Scored as precision and recall over
  (route, rule) pairs.
- ``IMPORTANT``: the routes whose issue a reviewer would fix first: anyone, or any other
  user, can change or read money or personal data there. Scored as ranking quality of the
  findings by RiskGraph's score (nDCG, P@k), with severity order as the baseline.
"""

from __future__ import annotations

from pathlib import Path

NAME = "I_authz_exposed_api"
DESCRIPTION = (
    "An Internet-facing Flask API over a PII store: guarded and unguarded siblings, an admin "
    "policy, id lookups with and without an owner check, and public forms."
)

FILES: dict[str, str] = {
    "shop/__init__.py": "",
    "shop/app.py": """from flask import Flask, request
from flask_login import current_user, login_required

from .admin import admin
from .orders import orders

app = Flask(__name__)


@app.get("/health")
def health():
    return "ok"


@app.post("/contact")
def contact():
    send_mail(request.form["message"])
    return ""


@app.post("/newsletter")
def newsletter():
    Subscriber.create(email=request.form["email"])
    return ""


@app.get("/api/users/<int:user_id>")
@login_required
def user(user_id):
    return User.query.get_or_404(user_id).to_dict()


@app.post("/api/profile")
@login_required
def profile():
    current_user.update(request.json)
    return ""


@app.get("/api/invoices/<int:invoice_id>/pdf")
@login_required
def invoice_pdf(invoice_id):
    return Invoice.query.get_or_404(invoice_id).pdf()


app.register_blueprint(orders, url_prefix="/api/orders")
app.register_blueprint(admin, url_prefix="/api/admin")
""",
    "shop/orders.py": """from flask import Blueprint
from flask_login import current_user, login_required

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
    "shop/admin.py": """from flask import Blueprint
from flask_login import login_required

admin = Blueprint("admin", __name__)


@admin.get("/stats")
@login_required
def stats():
    return ""


@admin.post("/refund")
def refund():
    Payment.refund(request.json["payment_id"])
    return ""


@admin.get("/users")
@login_required
@admin_required
def users():
    return ""
""",
}

MANIFEST = """version: 1
services:
  - name: shop
    path: shop/
    exposure: internet
    auth: required
    runs_as: shop-role
    connects_to: [customers]
identities:
  - {name: shop-role, privilege: elevated, can_access: [customers]}
data_stores:
  - {name: customers, kind: postgres, sensitivity: pii}
criticality: {shop: high}
authz:
  guards: [admin_required]
  public: [/contact]
  rules:
    - path: /api/admin/**
      require: [admin_required]
"""

Route = tuple[str, str]  # (METHOD, full path)

# --- ground truth, written before the first run ------------------------------------------
EXPECTED: dict[Route, frozenset[str]] = {
    ("GET", "/health"): frozenset(),
    ("POST", "/contact"): frozenset(),  # public on purpose, and declared (F-4-2)
    # public on purpose but NOT declared: a reviewer raises nothing; a rule may (an FP)
    ("POST", "/newsletter"): frozenset(),
    # guarded, but anyone logged in reads any user's record: no owner check anywhere
    ("GET", "/api/users/<int:user_id>"): frozenset({"bola"}),
    ("POST", "/api/profile"): frozenset(),  # acts on current_user only
    ("GET", "/api/invoices/<int:invoice_id>/pdf"): frozenset({"bola"}),
    ("GET", "/api/orders"): frozenset(),
    ("GET", "/api/orders/<int:order_id>"): frozenset(),  # owner check in the query
    ("POST", "/api/orders"): frozenset(),
    # no guard among guarded siblings, and deletes any order by id
    ("DELETE", "/api/orders/<int:order_id>"): frozenset({"inconsistent", "bola"}),
    # logged in but not admin_required, which the manifest rule demands
    ("GET", "/api/admin/stats"): frozenset({"policy"}),
    # no guard at all on a money-moving admin write: the rule, and plainly sensitive
    ("POST", "/api/admin/refund"): frozenset({"policy", "unguarded-sensitive"}),
    ("GET", "/api/admin/users"): frozenset(),
}

# routes whose issue a reviewer fixes first: anyone or any user changes or reads money or PII
IMPORTANT: frozenset[Route] = frozenset(
    {
        ("POST", "/api/admin/refund"),  # anyone can move money
        ("DELETE", "/api/orders/<int:order_id>"),  # anyone can delete any customer's order
        ("GET", "/api/users/<int:user_id>"),  # any user reads any user's PII
        ("GET", "/api/invoices/<int:invoice_id>/pdf"),  # any user reads any invoice
    }
)


def build(dest: Path) -> Path:
    for rel, text in sorted({**FILES, "riskgraph.yaml": MANIFEST}.items()):
        p = dest / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return dest
