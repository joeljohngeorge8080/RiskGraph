"""The 40-case source-to-sink suite (plan §6, X4) and its scorer."""

from __future__ import annotations

import ast
import json
from collections import Counter
from pathlib import Path

from evaluation import taint_suite as ts
from riskgraph.modules.scanners.semgrep import taint


def test_forty_cases_every_class_and_variant_once_per_language() -> None:
    suite = ts.cases()
    assert len(suite) == 40 and len({c.id for c in suite}) == 40
    assert Counter(c.language for c in suite) == {"python": 20, "javascript": 20}
    combos = Counter((c.language, c.cwe, c.variant) for c in suite)
    assert set(combos.values()) == {1}
    assert {c.cwe for c in suite} == {"CWE-89", "CWE-78", "CWE-22", "CWE-502", "CWE-918"}
    assert sum(not c.vulnerable for c in suite) == 10


def test_case_classes_are_catalogue_classes() -> None:
    classes = {c.id: c.cwe.split(":")[0] for c in taint.load_catalogue().classes}
    for c in ts.cases():
        assert classes[c.class_id] == c.cwe


def test_cases_have_one_marked_sink_where_the_variant_says() -> None:
    for c in ts.cases():
        marked = [
            (name, i)
            for name, text in c.files.items()
            for i, line in enumerate(text.splitlines(), 1)
            if line.rstrip().endswith(ts.MARK)
        ]
        assert marked == [(c.sink_file, c.sink_line)], c.id
        assert len(c.files) == (2 if c.variant == "cross_file" else 1), c.id
        if c.variant == "cross_file":
            assert c.sink_file != next(iter(c.files)), c.id


def test_python_cases_parse() -> None:
    for c in ts.cases():
        if c.language == "python":
            for text in c.files.values():
                ast.parse(text)


def test_write_lays_out_the_cases_and_labels(tmp_path: Path) -> None:
    suite = ts.write(tmp_path)
    labels = json.loads((tmp_path / "labels.json").read_text(encoding="utf-8"))
    assert len(labels) == 40
    for c in suite:
        for name in c.files:
            assert (tmp_path / c.id / name).is_file()


def _hit(case: ts.Case, line: int | None = None, rule: str | None = None) -> dict[str, object]:
    return {
        "check_id": rule or f"x.riskgraph.taint.{case.language}.{case.class_id}",
        "path": f"suite/{case.id}/{case.sink_file}",
        "start": {"line": line or case.sink_line},
    }


def test_the_scorer_against_hand_counted_results() -> None:
    suite = ts.cases()
    by = {(c.language, c.cwe, c.variant): c for c in suite}
    intra = [c for c in suite if c.variant == "intraprocedural"]
    doc = {
        "results": [
            *(_hit(c) for c in intra[:7]),  # 7 of 10 intraprocedural sinks found
            _hit(by["python", "CWE-89", "cross_function"]),  # 1 of 10 cross-function
            _hit(by["python", "CWE-22", "sanitized"]),  # a sanitized case flagged
            _hit(by["javascript", "CWE-78", "intraprocedural"], line=1),  # wrong line
            _hit(intra[0]),  # the same hit twice counts once
            {"check_id": "python.lang.other-rule", "path": "suite/x/app.py"},  # not ours
        ]
    }
    s = ts.score(doc, suite)
    assert s.recall("intraprocedural") == 7 / 10
    assert s.recall("cross_function") == 1 / 10
    assert s.recall("cross_file") == 0
    assert s.false_positives == 2  # the sanitized hit and the wrong line
    assert s.precision == 8 / 10
    assert (s.flagged_negatives, s.negatives) == (1, 10)
    table = ts.render(s)
    assert "| intraprocedural | 7 | 10 | 0.70 |" in table
    assert "Precision 0.80 (2 false positives)." in table


def test_a_hit_with_the_wrong_class_is_not_a_true_positive() -> None:
    suite = ts.cases()
    c = next(x for x in suite if x.cwe == "CWE-89" and x.variant == "intraprocedural")
    s = ts.score({"results": [_hit(c, rule="riskgraph.taint.python.path-traversal")]}, suite)
    assert sum(s.true_positives.values()) == 0 and s.false_positives == 1


def test_empty_or_odd_results_score_zero() -> None:
    docs: list[object] = [{}, {"results": []}, [], None]
    for doc in docs:
        s = ts.score(doc)
        assert sum(s.true_positives.values()) == 0 and s.precision is None


def test_javascript_cases_parse(tmp_path: Path) -> None:
    import shutil
    import subprocess

    import pytest

    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    ts.write(tmp_path)
    for c in ts.cases():
        if c.language == "javascript":
            for name in c.files:
                done = subprocess.run(  # noqa: S603 (fixed argv, our own generated files)
                    [node, "--check", str(tmp_path / c.id / name)],
                    capture_output=True,
                    check=False,
                    timeout=30,
                )
                assert done.returncode == 0, (c.id, done.stderr[-300:])
