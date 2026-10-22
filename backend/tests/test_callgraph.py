"""L3 on real parsed code: the extractor runs over small projects, then the call graph.

The blind-spot cases matter most: a dynamic call must stay at L2, never L3 (ADR-0015).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from riskgraph.modules.reachability.callgraph import find_l3, load_symbols
from riskgraph.modules.reachability.extract import extract
from riskgraph.modules.reachability.graph import build

YAML_SYMBOLS = frozenset({"yaml.load", "yaml.full_load", "yaml.unsafe_load"})


def _project(tmp_path: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return tmp_path


def _l3(tmp_path: Path, files: dict[str, str]):  # type: ignore[no-untyped-def]
    graph = build(extract(_project(tmp_path, files)))
    return find_l3(graph, YAML_SYMBOLS, "")


ROUTE = "from flask import Flask\napp = Flask(__name__)\n"


def test_a_direct_call_from_a_route_is_l3(tmp_path: Path) -> None:
    hit = _l3(
        tmp_path,
        {
            "app.py": ROUTE
            + "import yaml\n\n@app.route('/x')\ndef index(data):\n    return yaml.load(data)\n",
        },
    )
    assert hit is not None
    assert hit.symbol == "yaml.load" and hit.function == "index" and hit.file == "app.py"


def test_an_aliased_import_is_resolved(tmp_path: Path) -> None:
    hit = _l3(
        tmp_path,
        {
            "app.py": ROUTE
            + "import yaml as y\n\n@app.route('/')\ndef f(d):\n    return y.load(d)\n"
        },
    )
    assert hit is not None and hit.symbol == "yaml.load"


def test_a_from_import_is_resolved(tmp_path: Path) -> None:
    hit = _l3(
        tmp_path,
        {
            "app.py": ROUTE
            + "from yaml import load\n\n@app.route('/')\ndef f(d):\n    return load(d)\n"
        },
    )
    assert hit is not None and hit.symbol == "yaml.load"


def test_a_call_through_another_module_function_is_l3(tmp_path: Path) -> None:
    hit = _l3(
        tmp_path,
        {
            "app.py": ROUTE
            + "from utils import parse\n\n@app.route('/')\ndef f(d):\n    return parse(d)\n",
            "utils.py": "import yaml\n\ndef parse(d):\n    return yaml.load(d)\n",
        },
    )
    assert hit is not None
    assert hit.file == "utils.py" and hit.function == "parse"
    assert [fn for _f, fn in hit.chain] == ["f", "parse"]  # entry point, then the callee


def test_a_helper_no_entry_point_reaches_is_not_l3(tmp_path: Path) -> None:
    hit = _l3(
        tmp_path,
        {"app.py": ROUTE + "import yaml\n\ndef unused(d):\n    return yaml.load(d)\n"},
    )
    assert hit is None


def test_a_module_level_call_counts_when_the_module_is_reachable(tmp_path: Path) -> None:
    # module-level code runs on import, so an imported module's top level is an entry
    hit = _l3(
        tmp_path,
        {
            "app.py": ROUTE
            + "from config import CFG\n\n@app.route('/')\ndef f():\n    return CFG\n",
            "config.py": "import yaml\n\nCFG = yaml.load('a: 1')\n",
        },
    )
    assert hit is not None and hit.file == "config.py" and hit.function == "<module>"


@pytest.mark.parametrize(
    "body",
    [
        # getattr: the callee is not a visible name (blind spot, ADR-0015)
        "import yaml\n\n@app.route('/')\ndef f(d):\n    return getattr(yaml, 'load')(d)\n",
        # dispatch through a dict: the call is on a subscript, not a name
        "import yaml\nHANDLERS = {'a': yaml.load}\n"
        "\n@app.route('/')\ndef f(d):\n    return HANDLERS['a'](d)\n",
        # a call on the result of a call: not resolvable without types
        "import yaml\n\n@app.route('/')\ndef f(d):\n    return make()(d)\n"
        "\ndef make():\n    return yaml.load\n",
    ],
    ids=["getattr", "dict-dispatch", "call-on-result"],
)
def test_dynamic_calls_are_never_claimed(tmp_path: Path, body: str) -> None:
    assert _l3(tmp_path, {"app.py": ROUTE + body}) is None


def test_a_safe_loader_is_not_the_vulnerable_symbol(tmp_path: Path) -> None:
    hit = _l3(
        tmp_path,
        {
            "app.py": ROUTE
            + "import yaml\n\n@app.route('/')\ndef f(d):\n    return yaml.safe_load(d)\n",
        },
    )
    assert hit is None


def test_the_bundled_symbols_load_and_name_yaml_load() -> None:
    entries = load_symbols()
    assert "CVE-2020-14343" in entries
    assert "yaml.load" in entries["CVE-2020-14343"].symbols


def test_malformed_symbols_are_refused(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 2\nentries: []\n")
    with pytest.raises(ValueError, match="unsupported version"):
        load_symbols(bad)
    bad.write_text("version: 1\nentries:\n  - cve: CVE-1\n    package: x\n    symbols: []\n")
    with pytest.raises(ValueError, match="no symbols"):
        load_symbols(bad)
