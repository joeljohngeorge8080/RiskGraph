"""A small deliberately vulnerable repository, built at test time.

Every scanner has something to find, and the overlaps the merge step relies on are
present: one AWS key that both Gitleaks and Trivy report on the same line, and IaC
problems that both Checkov and Trivy misconfig report. Secret-looking strings are
assembled at runtime so this source file never trips a secret scanner itself.

Also usable as a script: ``python -m tests.fixtures.repos.kitchen_sink DEST``.
"""

from __future__ import annotations

import base64
import random
import sys
from pathlib import Path

# Fixed (not random per run) so fingerprints in recorded fixtures stay stable.
FAKE_AWS_KEY_ID = "AKIA" + "QYLPMN5HHHFPZAM2"
FAKE_AWS_SECRET = "".join(reversed("ZtFOM4dP7c1vHq0hRw9L2xKsJ8eYbN3aGp5uQiTm"))


def _fake_private_key() -> str:
    rng = random.Random(1337)  # noqa: S311 - test data, not crypto
    body = base64.b64encode(bytes(rng.getrandbits(8) for _ in range(600))).decode()
    lines = [body[i : i + 64] for i in range(0, len(body), 64)]
    kind = "RSA " + "PRIVATE KEY"
    return "\n".join([f"-----BEGIN {kind}-----", *lines, f"-----END {kind}-----", ""])


FILES: dict[str, str] = {
    "requirements.txt": "django==2.2.0\nrequests==2.19.0\npyyaml==5.3\n",
    "app.py": (
        "import sqlite3\n"
        "import subprocess\n"
        "\n"
        "from flask import Flask, request\n"
        "\n"
        "app = Flask(__name__)\n"
        "\n"
        "\n"
        '@app.route("/user")\n'
        "def user():\n"
        '    name = request.args.get("name")\n'
        '    conn = sqlite3.connect("app.db")\n'
        "    cur = conn.cursor()\n"
        '    cur.execute("SELECT * FROM users WHERE name = \'" + name + "\'")\n'
        "    return str(cur.fetchall())\n"
        "\n"
        "\n"
        '@app.route("/ping")\n'
        "def ping():\n"
        '    host = request.args.get("host")\n'
        '    return subprocess.check_output("ping -c 1 " + host, shell=True)\n'
        "\n"
        "\n"
        '@app.route("/config", methods=["POST"])\n'
        "def config():\n"
        "    import yaml\n"
        "\n"
        "    return str(yaml.safe_load(request.data))\n"
    ),
    # Never imported by anything an entry point reaches: requests is L1, django L0.
    "scripts/legacy.py": (
        "import requests\n\n\ndef fetch(url):\n    return requests.get(url, timeout=5).text\n"
    ),
    "main.tf": (
        'provider "aws" {\n'
        '  region     = "us-east-1"\n'
        f'  access_key = "{FAKE_AWS_KEY_ID}"\n'
        f'  secret_key = "{FAKE_AWS_SECRET}"\n'
        "}\n"
        "\n"
        'resource "aws_s3_bucket" "data" {\n'
        '  bucket = "kitchen-sink-data"\n'
        '  acl    = "public-read"\n'
        "}\n"
        "\n"
        'resource "aws_security_group" "ssh" {\n'
        '  name = "open-ssh"\n'
        "  ingress {\n"
        "    from_port   = 22\n"
        "    to_port     = 22\n"
        '    protocol    = "tcp"\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n'
        "  }\n"
        "}\n"
    ),
    "Dockerfile": (
        "FROM python:3.8\n"
        "COPY . /app\n"
        "RUN pip install -r /app/requirements.txt\n"
        'CMD ["python", "/app/app.py"]\n'
    ),
    "deploy/id_rsa": _fake_private_key(),
}


# Deployment context for graph/attack-path tests (blueprint §11.1, ADR-0011/0013).
MANIFEST = """
version: 1
services:
  - name: app
    path: ""
    exposure: internet
    auth: none
    runs_as: app-role
    connects_to: [users-db]
identities:
  - name: app-role
    privilege: elevated
    can_access: [users-db]
    credentials: [aws]
data_stores:
  - name: users-db
    kind: sqlite
    sensitivity: pii
criticality:
  app: high
"""


def build(dest: Path) -> Path:
    for rel, content in FILES.items():
        path = dest / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return dest


if __name__ == "__main__":
    build(Path(sys.argv[1]))
