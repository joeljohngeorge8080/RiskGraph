from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest
from riskgraph.modules.reachability import run_extractor
from riskgraph.modules.reachability.extract import extract
from riskgraph.modules.reachability.graph import build
from riskgraph.modules.reachability.package_names import (
    import_names,
    python_import_names,
    used_without_import,
)
from riskgraph.modules.reachability.tiers import TierClassifier
from riskgraph.modules.scanners import RunSpec, SubprocessRunner
from riskgraph.modules.scanners.runner import SELF_PYTHON
from riskgraph.modules.scanners.trivy.parser import dependency_graph
from riskgraph.shared.vocabulary import ReachabilityTier as T
from riskgraph.shared.vocabulary import SourceType


def _write(root: Path, files: dict[str, str | bytes]) -> Path:
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content)
    return root


REPO: dict[str, str | bytes] = {
    "app.py": (
        "import os\nimport yaml as y\nfrom flask import Flask\nfrom pkg import helpers\n"
        "app = Flask(__name__)\n\n@app.route('/x')\ndef x():\n    return helpers.go()\n"
    ),
    "pkg/__init__.py": "",
    "pkg/helpers.py": "from . import util\nfrom .sub.deep import thing\nimport requests.adapters\n",
    "pkg/util.py": "import json\n",
    "pkg/sub/__init__.py": "",
    "pkg/sub/deep.py": "import jwt\n",
    "scripts/legacy.py": "import boto3\n",
    "web/package.json": json.dumps(
        {
            "main": "server.js",
            "scripts": {"start": "NODE_ENV=prod pm2-runtime server.js && npx knex migrate"},
        }
    ),
    "web/server.js": (
        "const express = require('express');\nimport lodash from 'lodash';\n"
        "import { a } from './routes';\nexport { b } from '@scope/pkg/sub';\n"
        "const fs = require('fs');\nconst x = require(`dyn${1}`);\n"
    ),
    "web/routes/index.ts": "import axios from 'axios';\n",
    "web/unused.js": "const leftPad = require('left-pad');\n",
    "web/node_modules/evil/index.js": "require('should-not-appear')\n",
}


@pytest.fixture()
def extracted(tmp_path: Path) -> dict[str, Any]:
    return extract(_write(tmp_path / "src", REPO))


def test_python_imports_and_entry_points(extracted: dict[str, Any]) -> None:
    app = extracted["files"]["app.py"]
    assert [i["module"] for i in app["imports"]] == ["os", "yaml", "flask", "pkg"]
    assert app["entry"] == ["route decorator"]
    helpers = extracted["files"]["pkg/helpers.py"]["imports"]
    assert {"module": "", "names": ["util"], "level": 1} in helpers
    assert {"module": "sub.deep", "names": ["thing"], "level": 1} in helpers


def test_js_imports_entries_and_skips(extracted: dict[str, Any]) -> None:
    server = extracted["files"]["web/server.js"]
    mods = [i["module"] for i in server["imports"]]
    assert mods == [
        "express",
        "lodash",
        "./routes",
        "@scope/pkg/sub",
        "fs",
    ]  # template literal ignored
    assert extracted["package_json"]["web/package.json"]["main"] == "server.js"
    assert not any("node_modules" in f for f in extracted["files"])


def test_hostile_inputs_do_not_break_extraction(tmp_path: Path) -> None:
    src = _write(
        tmp_path / "src",
        {
            "deep.py": "x = " + "[" * 50_000 + "]" * 50_000 + "\nimport yaml\n",
            "bin.js": b"\x00\x01\x02" * 100,
            "big.py": "import requests\n" + "#" * (3 * 1024 * 1024),
            "ok.py": "import flask\n",
        },
    )
    (src / "link.py").symlink_to("/etc/passwd")
    out = extract(src)
    assert set(out["files"]) == {"deep.py", "ok.py"}
    assert out["files"]["deep.py"]["imports"][0]["module"] == "yaml"
    assert out["skipped"] == 2


def test_module_graph_resolution(extracted: dict[str, Any]) -> None:
    g = build(extracted, manifest_entrypoints=["scripts/legacy.py"])
    assert g.edges["app.py"] == {"pkg/__init__.py", "pkg/helpers.py"}
    # "from . import util" also runs the package __init__, as in Python
    assert g.edges["pkg/helpers.py"] == {"pkg/__init__.py", "pkg/util.py", "pkg/sub/deep.py"}
    assert g.edges["web/server.js"] == {"web/routes/index.ts"}
    assert set(g.entries) == {"app.py", "web/server.js", "scripts/legacy.py"}
    assert "web/unused.js" not in g.reachable
    assert {
        "yaml",
        "flask",
        "requests",
        "jwt",
        "boto3",
        "express",
        "lodash",
        "@scope/pkg",
        "axios",
    } <= set(g.external)
    assert "os" not in g.external and "fs" not in g.external  # stdlib / node built-ins
    assert g.chain_to("pkg/sub/deep.py") == ["app.py", "pkg/helpers.py", "pkg/sub/deep.py"]


def _classifier(extracted: dict[str, Any], deps: dict[str, Any] | None = None) -> TierClassifier:
    return TierClassifier(build(extracted), deps or {})


def test_sca_tiers(extracted: dict[str, Any]) -> None:
    c = _classifier(extracted)
    assert c.sca("pip", "PyYAML", "5.3", "requirements.txt").tier is T.L2
    assert c.sca("pip", "pyjwt", "1", "requirements.txt").tier is T.L2  # name mapping + package
    boto = c.sca("pip", "boto3", "1", "requirements.txt")
    assert boto.tier is T.L1 and boto.evidence["importers"] == ["scripts/legacy.py"]
    django = c.sca("pip", "django", "2.2", "requirements.txt")
    assert (django.tier, django.confidence) == (T.L0, "medium")  # no lockfile graph
    assert c.sca("pip", "gunicorn", "20", "requirements.txt").tier is T.UNKNOWN
    assert c.sca("npm", "lodash", "4", "web/package-lock.json").tier is T.L2
    assert c.sca("npm", "left-pad", "1", "web/package-lock.json").tier is T.L1
    assert c.sca("npm", "@scope/pkg", "1", "web/package-lock.json").tier is T.L2
    assert c.sca("gomod", "x", "1", "go.mod").tier is T.UNKNOWN
    # scope: a lockfile in web/ only counts files under web/
    assert c.sca("npm", "lodash", "4", "other/package-lock.json").tier is T.UNKNOWN


def test_indirect_dependencies_inherit_from_direct_parents(extracted: dict[str, Any]) -> None:
    trivy = {
        "Results": [
            {
                "Target": "web/package-lock.json",
                "Packages": [
                    {
                        "ID": "express@4",
                        "Name": "express",
                        "Version": "4",
                        "Relationship": "direct",
                        "DependsOn": ["qs@6"],
                    },
                    {"ID": "qs@6", "Name": "qs", "Version": "6", "Relationship": "indirect"},
                    {
                        "ID": "unused@1",
                        "Name": "unused",
                        "Version": "1",
                        "Relationship": "direct",
                        "DependsOn": ["ms@2"],
                    },
                    {"ID": "ms@2", "Name": "ms", "Version": "2", "Relationship": "indirect"},
                    {
                        "ID": "orphan@1",
                        "Name": "orphan",
                        "Version": "1",
                        "Relationship": "indirect",
                    },
                ],
            }
        ]
    }
    c = _classifier(extracted, dependency_graph(trivy))
    qs = c.sca("npm", "qs", "6", "web/package-lock.json")
    assert (qs.tier, qs.evidence["via"]) == (T.L2, "express")
    unused = c.sca("npm", "unused", "1", "web/package-lock.json")
    assert (unused.tier, unused.confidence) == (T.L0, "high")  # direct, lockfile graph
    assert c.sca("npm", "ms", "2", "web/package-lock.json").tier is T.L0
    assert c.sca("npm", "orphan", "1", "web/package-lock.json").tier is T.UNKNOWN


def test_no_entry_points_never_demotes(tmp_path: Path) -> None:
    out = extract(_write(tmp_path / "src", {"lib.py": "import yaml\n"}))
    v = TierClassifier(build(out), {}).sca("pip", "pyyaml", "5", "requirements.txt")
    assert (v.tier, v.confidence) == (T.L2, "low")


def test_sast_tiers(extracted: dict[str, Any]) -> None:
    c = _classifier(extracted)
    assert c.classify(SourceType.SAST, "pkg/util.py", None).tier is T.L2
    assert c.classify(SourceType.SAST, "web/unused.js", None).tier is T.L1
    assert c.classify(SourceType.SAST, "Dockerfile", None).tier is T.UNKNOWN
    assert c.classify(SourceType.SECRET, "a.py", None).tier is T.NOT_APPLICABLE


def test_package_names() -> None:
    assert python_import_names("PyYAML") == ("yaml",)
    assert python_import_names("python-dateutil") == ("dateutil",)
    assert python_import_names("zope.interface") == ("zope_interface", "zope.interface")
    assert import_names("npm", "@a/b") == ("@a/b",)
    assert import_names("cargo", "x") is None
    assert used_without_import("pytest-cov") and used_without_import("@types/node")
    assert not used_without_import("requests")


def test_extractor_runs_isolated_through_the_runner(tmp_path: Path) -> None:
    src = _write(tmp_path / "src", REPO)
    run = run_extractor(SubprocessRunner(tmp_path / "nobin"), src, tmp_path / "work", {}, [])
    assert run.status == "ok" and run.stats["entry_points"] == 2
    assert (
        run.classify(
            SourceType.SCA,
            "requirements.txt",
            {"ecosystem": "pip", "name": "pyyaml", "version": "1"},
        ).tier
        is T.L2
    )
    gone = run_extractor(
        SubprocessRunner(tmp_path / "nobin"), tmp_path / "missing", tmp_path / "w2", {}, []
    )
    assert gone.status == "unavailable"
    assert (
        gone.classify(
            SourceType.SCA, "requirements.txt", {"ecosystem": "pip", "name": "x", "version": "1"}
        ).tier
        is T.UNKNOWN
    )


def test_memory_limit_is_enforced(tmp_path: Path) -> None:
    runner = SubprocessRunner(tmp_path)
    code = "x = bytearray(512 * 1024 * 1024)"
    result = runner.run(
        RunSpec(
            (SELF_PYTHON, "-c", code),
            tmp_path,
            tmp_path / "logs",
            30,
            memory_limit=256 * 1024 * 1024,
        )
    )
    assert result.exit_code != 0 and "MemoryError" in result.stderr_tail


def test_self_python_is_the_only_path_alias(tmp_path: Path) -> None:
    runner = SubprocessRunner(tmp_path)
    assert runner.resolve(SELF_PYTHON) == sys.executable
    assert runner.resolve(sys.executable) is None


def test_npm_script_commands_count_as_used(extracted: dict[str, Any]) -> None:
    assert extracted["package_json"]["web/package.json"]["script_commands"] == [
        "knex",
        "npx",
        "pm2-runtime",
    ]
    c = _classifier(extracted)
    assert c.sca("npm", "pm2-runtime", "1", "web/package-lock.json").tier is T.UNKNOWN
    assert c.sca("npm", "knex", "1", "web/package-lock.json").tier is T.UNKNOWN
    assert c.sca("npm", "never-used", "1", "web/package-lock.json").tier is T.L0
