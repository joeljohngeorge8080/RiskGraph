"""Scenarios A-E (blueprint §14.6, §25.2) with ground truth by construction (§26.3).

Rubric (§26.3): a finding is *important* when an attacker with Internet access, or holding
the leaked credential, could plausibly reach confidential data or elevated privilege
through it. Labels are written from how each scenario is built, before any ranking is
computed, and every rule states its rationale. A finding no rule matches is labelled
not important and listed in the report as "defaulted", so nothing is labelled silently.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Fake AWS credentials: valid shape (Gitleaks and Trivy detect them), not a real key.
# Built at run time, as the kitchen sink does, so no committed file holds the literal.
FAKE_AWS_KEY_ID = "AKIA" + "ZQXWMP4RT7NVB2HD"
FAKE_AWS_SECRET = "".join(reversed("q8Lw3Rt7Yp2Kd9Vn5Hs1Jf6Gm4Bc0Xz8Ne2Ua7Ti"))


@dataclass(frozen=True, slots=True)
class LabelRule:
    """Matches findings by facts that do not depend on the ranking method."""

    important: bool
    rationale: str
    source_type: str | None = None
    package: str | None = None
    file_prefix: str | None = None
    rule_contains: str | None = None
    category: str | None = None

    def matches(self, f: dict[str, Any]) -> bool:
        checks = [
            self.source_type is None or f["source_type"] == self.source_type,
            self.package is None or (f.get("package") or "").lower() == self.package,
            self.file_prefix is None or (f.get("file") or "").startswith(self.file_prefix),
            self.rule_contains is None or self.rule_contains in f.get("rule_id", ""),
            self.category is None or f.get("category") == self.category,
        ]
        return all(checks)


@dataclass(frozen=True, slots=True)
class Scenario:
    name: str
    description: str
    files: dict[str, str]
    manifest: str
    labels: tuple[LabelRule, ...]
    secrets: tuple[str, ...] = field(default=())  # scrubbed from recorded reports

    def build(self, dest: Path) -> Path:
        for rel, text in sorted({**self.files, "riskgraph.yaml": self.manifest}.items()):
            p = dest / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
        return dest

    def label(self, finding: dict[str, Any]) -> tuple[bool, str, bool]:
        """(important, rationale, defaulted)."""
        for rule in self.labels:
            if rule.matches(finding):
                return rule.important, rule.rationale, False
        return False, "no rule: not on a constructed attacker path", True


A = Scenario(
    "A_high_cvss_unreachable",
    "Critical Django CVEs in a package the internal service never imports.",
    {
        "requirements.txt": "django==2.2.0\nflask==3.0.3\n",
        "svc/app.py": (
            "from flask import Flask\n\napp = Flask(__name__)\n\n\n"
            '@app.route("/health")\ndef health():\n    return "ok"\n'
        ),
    },
    """version: 1
services:
  - {name: svc, path: "", exposure: internal, auth: required, runs_as: svc-role, connects_to: [metrics]}
identities:
  - {name: svc-role, privilege: limited}
data_stores:
  - {name: metrics, kind: postgres, sensitivity: internal}
criticality: {svc: low}
""",
    (
        LabelRule(False, "django is never imported (L0) on an internal service", package="django"),
        LabelRule(False, "internal service, limited identity, internal data only"),
    ),
)

B = Scenario(
    "B_moderate_reachable_exposed",
    "An Internet-facing FastAPI route calls yaml.load (PyYAML CVEs); admin role; PII store.",
    {
        "requirements.txt": "fastapi==0.115.0\npyyaml==5.3\n",
        "api/main.py": (
            "import yaml\nfrom fastapi import FastAPI, Request\n\napp = FastAPI()\n\n\n"
            '@app.post("/import")\nasync def import_config(request: Request):\n'
            "    body = await request.body()\n"
            '    return {"config": yaml.load(body)}\n'
        ),
        "deploy/ingress.yaml": (
            "apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata: {name: api}\n"
            "spec:\n  rules:\n    - http:\n        paths:\n"
            "          - path: /\n            pathType: Prefix\n"
            "            backend: {service: {name: api, port: {number: 80}}}\n"
        ),
    },
    """version: 1
services:
  - {name: api, path: "", exposure: internet, auth: none, runs_as: api-admin, connects_to: [users-db]}
identities:
  - {name: api-admin, privilege: admin, can_access: [users-db]}
data_stores:
  - {name: users-db, kind: postgres, sensitivity: pii}
""",
    (
        LabelRule(
            True,
            "PyYAML CVE reached from an unauthenticated route; admin role; PII",
            package="pyyaml",
        ),
        LabelRule(
            True,
            "unsafe yaml.load on request data in an Internet-facing route",
            source_type="sast",
            file_prefix="api/main.py",
            category="deserialization",
        ),
        LabelRule(False, "ingress configuration hygiene, no path to data", source_type="iac"),
    ),
)

C = Scenario(
    "C_exposed_credential",
    "A frontend bundle ships an AWS key that the manifest links to an admin role over PII.",
    {
        "web/package.json": '{"name": "web", "version": "1.0.0", "private": true}\n',
        "web/dist/bundle.js": (
            "(function(){var cfg={region:'eu-west-1',\n"
            f"accessKeyId:'{FAKE_AWS_KEY_ID}',\n"
            f"secretAccessKey:'{FAKE_AWS_SECRET}'}};\n"
            "window.__cfg=cfg;})();\n"
        ),
    },
    """version: 1
services:
  - {name: web, path: web/, exposure: internet, auth: none}
identities:
  - {name: deploy-admin, privilege: admin, can_access: [customers-db], credentials: [aws]}
data_stores:
  - {name: customers-db, kind: postgres, sensitivity: pii}
""",
    (
        LabelRule(
            True, "public AWS key authenticates as an admin role over PII", source_type="secret"
        ),
    ),
    secrets=(FAKE_AWS_KEY_ID, FAKE_AWS_SECRET),
)

D = Scenario(
    "D_internal_limited",
    "An internal batch worker reaches a High CVE (L2) as a read-only identity.",
    {
        "requirements.txt": "requests==2.19.0\n",
        "worker/main.py": (
            "import requests\n\n\ndef sync():\n"
            '    return requests.get("https://example.internal/feed", timeout=5).text\n\n\n'
            'if __name__ == "__main__":\n    sync()\n'
        ),
    },
    """version: 1
services:
  - {name: worker, path: "", exposure: internal, runs_as: reader, connects_to: [cache]}
identities:
  - {name: reader, privilege: read_only, can_access: [cache]}
data_stores:
  - {name: cache, kind: redis, sensitivity: internal}
""",
    (
        LabelRule(
            False,
            "internal, read-only identity, internal data: no path to confidential data",
            package="requests",
        ),
        LabelRule(False, "internal worker with no Internet exposure"),
    ),
)

E = Scenario(
    "E_attack_path",
    "SSRF in an Internet-facing route; the role reaches the metadata credential store and PII.",
    {
        "requirements.txt": "flask==3.0.3\nrequests==2.32.4\n",
        "api/app.py": (
            "import requests\nfrom flask import Flask, request\n\napp = Flask(__name__)\n\n\n"
            '@app.route("/preview")\ndef preview():\n'
            '    url = request.args.get("url")\n'
            "    return requests.get(url, timeout=5).text\n"
        ),
    },
    """version: 1
services:
  - {name: api, path: "", exposure: internet, auth: none, runs_as: api-role}
identities:
  - {name: api-role, privilege: elevated, can_access: [instance-metadata, users-db]}
data_stores:
  - {name: instance-metadata, kind: http, sensitivity: credentials}
  - {name: users-db, kind: postgres, sensitivity: pii}
criticality: {api: high}
""",
    (
        LabelRule(
            True,
            "user-controlled URL fetched from an Internet route (SSRF) → metadata creds",
            source_type="sast",
            file_prefix="api/app.py",
            category="ssrf",
        ),
        LabelRule(False, "dependency without a constructed exploit path", source_type="sca"),
    ),
)

SCENARIOS: dict[str, Scenario] = {s.name: s for s in (A, B, C, D, E)}
