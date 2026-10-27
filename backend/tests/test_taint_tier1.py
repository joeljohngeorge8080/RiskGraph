"""Tier-1 taint (X4 part 1, ADR-0021): catalogue, generated rules, trace redaction, the
taint evidence contract and correlation with generic Semgrep findings.

The rules are not run here: the real Semgrep is the owner's check (LOCAL_TASKS L-4).
"""

from __future__ import annotations

import copy
import datetime as dt
import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from riskgraph.modules.evidence import Assurance
from riskgraph.modules.normalization import merge
from riskgraph.modules.normalization.families import taint_family
from riskgraph.modules.normalization.fingerprint import stable_hash
from riskgraph.modules.normalization.merge import SINK_SPAN_LINES
from riskgraph.modules.scanners.semgrep import SemgrepScanner, parser, taint
from riskgraph.modules.scans.finding_evidence import finding_evidence
from riskgraph.shared.config import Settings

SAMPLE = Path(__file__).parent / "fixtures" / "semgrep_taint" / "sample.json"
CWES = {"CWE-89", "CWE-78", "CWE-22", "CWE-502", "CWE-918"}


def _sample() -> dict[str, Any]:
    return json.loads(SAMPLE.read_text(encoding="utf-8"))  # type: ignore[no-any-return]


def _parsed(doc: dict[str, Any] | None = None) -> list[Any]:
    redacted, _ = SemgrepScanner().redact(doc or _sample(), b"k")
    return parser.parse(redacted)


# --- catalogue and rules -------------------------------------------------------------
def test_the_catalogue_covers_every_class_in_both_languages() -> None:
    cat = taint.load_catalogue()
    assert {c.cwe.split(":")[0] for c in cat.classes} == CWES
    for c in cat.classes:
        for lang in taint.LANGUAGES:
            assert c.languages[lang].sinks, (c.id, lang)
    for lang in taint.LANGUAGES:
        assert cat.sources[lang]


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda d: d.update(extra=1), "unknown keys"),
        (lambda d: d["classes"][0].update(cwe="89"), "cwe must look like"),
        (lambda d: d["classes"][0]["python"].update(sinks=[]), "must not be empty"),
        (lambda d: d["classes"][0]["python"].update(confidence="sure"), "confidence"),
        (lambda d: d["classes"].append(copy.deepcopy(d["classes"][0])), "unique"),
        (lambda d: d["sources"]["python"][0].update(handler_parameter={}), "exactly one"),
        (lambda d: d["sources"].pop("javascript"), "missing keys"),
    ],
)
def test_a_broken_catalogue_is_refused(tmp_path: Path, change: Any, message: str) -> None:
    doc = yaml.safe_load(taint.CATALOGUE_FILE.read_text(encoding="utf-8"))
    change(doc)
    bad = tmp_path / "catalogue.yaml"
    bad.write_text(yaml.safe_dump(doc), encoding="utf-8")
    with pytest.raises(taint.CatalogueError, match=message):
        taint.load_catalogue(bad)


def test_one_rule_per_language_and_class_with_the_expected_shape() -> None:
    cat = taint.load_catalogue()
    rules = taint.build_rules(cat)
    assert len(rules) == len(taint.LANGUAGES) * len(cat.classes)
    ids = [r["id"] for r in rules]
    assert len(set(ids)) == len(ids) and all(i.startswith("riskgraph.taint.") for i in ids)
    for r in rules:
        assert r["mode"] == "taint" and r["severity"] == "ERROR"
        assert r["metadata"]["source"] == "riskgraph"
        assert r["metadata"]["license"] == "Apache-2.0"
        assert r["metadata"]["analysis"] == "intraprocedural"
        assert taint_family(r["metadata"]["cwe"][0].split(":")[0]) is not None
        assert r["pattern-sources"] and r["pattern-sinks"]
        for sink in r["pattern-sinks"]:
            if "patterns" in sink:
                pattern, focus = sink["patterns"]
                assert "$SINK" in pattern["pattern"] and focus == {"focus-metavariable": "$SINK"}
            else:
                assert "$SINK" not in sink["pattern"]


def test_every_catalogue_entry_reaches_a_rule() -> None:
    cat = taint.load_catalogue()
    text = json.dumps(taint.build_rules(cat))
    for c in cat.classes:
        for lang, lr in c.languages.items():
            assert taint.rule_id(lang, c.id) in text
            for p in (*lr.sinks, *lr.sanitizers):
                assert json.dumps(p)[1:-1] in text, p
    for sources in cat.sources.values():
        for s in sources:
            for p in s.patterns:
                assert json.dumps(p)[1:-1] in text, p


def test_the_committed_rules_file_is_what_the_catalogue_generates() -> None:
    expected = taint.render(taint.build_rules(taint.load_catalogue()))
    committed = taint.RULES_FILE.read_text(encoding="utf-8")
    assert committed == expected, "run: uv run python -m riskgraph.modules.scanners.semgrep.taint"
    doc = yaml.safe_load(committed)
    assert doc == {"rules": taint.build_rules(taint.load_catalogue())}
    assert "&id" not in committed  # no YAML anchors: every rule spells its sources out


def test_the_rules_are_a_second_config_only_when_configured(tmp_path: Path) -> None:
    from riskgraph.modules.scanners.base import ScanPaths

    paths = ScanPaths(src=tmp_path, out=tmp_path, home=tmp_path, cache=tmp_path)
    plain = SemgrepScanner().command(paths, Settings()).argv
    assert plain.count("--config") == 1
    on = Settings(semgrep_taint_rules_path=taint.RULES_FILE)
    argv = SemgrepScanner().command(paths, on).argv
    i = argv.index("--config", argv.index("--config") + 1)
    assert argv[i + 1] == str(taint.RULES_FILE) and argv[-1] == "."


# --- redaction, parsing and evidence -------------------------------------------------
def test_redaction_keeps_the_trace_locations_and_drops_its_code() -> None:
    redacted, _ = SemgrepScanner().redact(_sample(), b"k")
    text = json.dumps(redacted)
    assert "dataflow_trace" not in text
    for code in ("flask.request.args.get('name')", "req.query.c", "cur.execute(query)"):
        assert code not in text
    first = redacted["results"][0]["extra"][parser.TAINT_STEPS_KEY]
    assert [(s["line"], s["role"]) for s in first] == [
        (6, "source"),
        (7, "step"),
        (9, "sink"),
    ]


def test_taint_hits_carry_the_contract_and_generic_hits_do_not() -> None:
    by_rule = {f.rule_id: f for f in _parsed()}
    sqli = by_rule["riskgraph.taint.python.sql-injection"]
    assert sqli.attrs["analysis"] == "intraprocedural"
    assert [s["role"] for s in sqli.attrs["taint_steps"]] == ["source", "step", "sink"]
    assert sqli.cwe_ids == ("CWE-89",) and sqli.source_type.value == "sast"
    cmd = by_rule["riskgraph.taint.javascript.os-command-injection"]
    # a CliCall source: its nested location is found once (repeats are collapsed)
    assert [(s["file"], s["line"], s["role"]) for s in cmd.attrs["taint_steps"]] == [
        ("web/server.js", 12, "source"),
        ("web/server.js", 14, "sink"),
    ]
    generic = by_rule["python.lang.security.audit.formatted-sql-query"]
    assert "analysis" not in generic.attrs and "taint_steps" not in generic.attrs


def test_a_long_trace_is_capped_and_keeps_its_sink() -> None:
    doc = _sample()
    trace = doc["results"][0]["extra"]["dataflow_trace"]
    trace["intermediate_vars"] = [
        {"location": {"path": "app.py", "start": {"line": 100 + i}, "end": {"line": 100 + i}}}
        for i in range(80)
    ]
    steps = _parsed(doc)[0].attrs["taint_steps"]
    assert len(steps) == parser.MAX_TAINT_STEPS
    assert steps[0]["role"] == "source" and steps[-1] == {
        "file": "app.py",
        "line": 9,
        "role": "sink",
    }


@pytest.mark.parametrize(
    "trace",
    [None, "nope", [], {"taint_source": ["CliLoc", "x"]}, {"taint_sink": {"path": 3}}],
)
def test_a_malformed_trace_gives_no_steps_and_no_error(trace: Any) -> None:
    doc = _sample()
    doc["results"][0]["extra"]["dataflow_trace"] = trace
    sqli = _parsed(doc)[0]
    assert sqli.rule_id.startswith("riskgraph.taint.") and sqli.attrs["taint_steps"] == []


def test_hostile_stored_steps_are_dropped_by_the_parser() -> None:
    redacted, _ = SemgrepScanner().redact(_sample(), b"k")
    redacted["results"][0]["extra"][parser.TAINT_STEPS_KEY] = [
        {"file": "../../etc/passwd", "line": 3, "role": "source"},
        {"file": "app.py", "line": True, "role": "sink"},
        {"file": "app.py", "line": 5, "role": "evil"},
        "x",
    ]
    [step] = parser.parse(redacted)[0].attrs["taint_steps"]
    assert step["file"] != "../../etc/passwd" and ".." not in step["file"]


def test_the_taint_member_is_inferred_taint_flow_evidence() -> None:
    [joined] = [m for m in merge(_parsed()) if m.location.line_start == 9]
    now = dt.datetime(2026, 10, 27, tzinfo=dt.UTC)
    evidence = finding_evidence(joined, None, {}, {"semgrep": "1.182.0"}, now)
    kinds = {e.kind: e for e in evidence}
    assert set(kinds) == {"taint_flow", "code_match"}
    flow = kinds["taint_flow"]
    assert flow.assurance is Assurance.INFERRED and flow.facts["analysis"] == "intraprocedural"
    assert [(s.location.line_start, s.label) for s in flow.steps] == [
        (6, "source"),
        (7, "step"),
        (9, "sink"),
    ]
    assert kinds["code_match"].assurance is Assurance.VERIFIED


# --- correlation -----------------------------------------------------------------------
def test_a_tier1_hit_joins_the_generic_finding_at_its_sink() -> None:
    merged = merge(_parsed())
    at_sink = [m for m in merged if m.location.file == "app.py"]
    assert len(at_sink) == 1 and len(at_sink[0].members) == 2
    # the generic finding's key is kept, so its identity across scans does not change
    assert at_sink[0].merge_key == stable_hash("sast", "app.py", 9, "CWE-943")
    assert at_sink[0].cwe_ids == ("CWE-89", "CWE-943")
    # corroboration counts scanners: two Semgrep rules are still one scanner
    assert at_sink[0].detected_by == ("semgrep",)


def test_hits_on_other_lines_or_other_families_stay_apart() -> None:
    js = [m for m in merge(_parsed()) if m.location.file == "web/server.js"]
    assert sorted(m.location.line_start or 0 for m in js) == [14, 20]
    doc = _sample()
    doc["results"][1]["extra"]["metadata"]["cwe"] = ["CWE-79: Cross-site scripting"]
    apart = [m for m in merge(_parsed(doc)) if m.location.file == "app.py"]
    assert len(apart) == 2


def test_a_tier1_hit_alone_keeps_its_own_key() -> None:
    doc = _sample()
    del doc["results"][1]
    [alone] = [m for m in merge(_parsed(doc)) if m.location.file == "app.py"]
    assert alone.merge_key == stable_hash("sast", "app.py", 9, "CWE-89")


def test_generic_merge_keys_do_not_change() -> None:
    doc = _sample()
    doc["results"] = [r for r in doc["results"] if "riskgraph.taint" not in r["check_id"]]
    keys = {m.merge_key for m in merge(_parsed(doc))}
    assert keys == {
        stable_hash("sast", "app.py", 9, "CWE-943"),
        stable_hash("sast", "web/server.js", 20, "CWE-78"),
    }


TAINT_SQL = "riskgraph.taint.python.sql-injection"


def _hit(rule: str, line: int, cwe: str, end: int | None = None, file: str = "big.py") -> Any:
    from riskgraph.modules.normalization import Location, RawFinding
    from riskgraph.shared.vocabulary import ScannerName, Severity, SourceType

    return RawFinding(
        scanner=ScannerName.SEMGREP,
        source_type=SourceType.SAST,
        rule_id=rule,
        title="t",
        severity=Severity.MEDIUM,
        location=Location(file, line, end or line),
        category="injection",
        cwe_ids=(cwe,),
    )


def test_a_tier1_hit_inside_a_multiline_call_joins_the_generic_finding() -> None:
    # cursor.execute(          <- line 10, the generic rule matches the whole call
    #     "SELECT " + name     <- line 11, the tier-1 rule focuses on the argument
    # )                        <- line 12
    generic = _hit("generic.sqli", 10, "CWE-943", end=12)
    [joined] = merge([generic, _hit(TAINT_SQL, 11, "CWE-89", end=11)])
    assert len(joined.members) == 2
    assert joined.merge_key == stable_hash("sast", "big.py", 10, "CWE-943")


def test_a_tier1_hit_below_the_span_or_of_another_family_stays_apart() -> None:
    generic = _hit("generic.sqli", 10, "CWE-943", end=12)
    assert len(merge([generic, _hit(TAINT_SQL, 13, "CWE-89")])) == 2
    other = _hit("generic.cmd", 10, "CWE-78", end=12)
    assert len(merge([other, _hit(TAINT_SQL, 11, "CWE-89")])) == 2
    # a generic finding starting more than SINK_SPAN_LINES above is not this sink
    far = _hit("generic.sqli", 10, "CWE-943", end=100)
    assert len(merge([far, _hit(TAINT_SQL, 10 + SINK_SPAN_LINES + 1, "CWE-89")])) == 2


def test_the_exact_line_wins_over_a_covering_span_and_the_nearest_start_wins() -> None:
    outer = _hit("generic.outer", 10, "CWE-943", end=20)
    inner = _hit("generic.inner", 14, "CWE-89", end=16)
    exact = _hit("generic.exact", 15, "CWE-89", end=15)
    merged = merge([outer, inner, exact, _hit(TAINT_SQL, 15, "CWE-89")])
    by_rule = {m.members[0].rule_id: m for m in merged}
    assert len(by_rule["generic.exact"].members) == 2
    merged = merge([outer, inner, _hit(TAINT_SQL, 15, "CWE-89")])
    by_rule = {m.members[0].rule_id: m for m in merged}
    assert len(by_rule["generic.inner"].members) == 2
    assert len(by_rule["generic.outer"].members) == 1


def test_two_taint_hits_never_join_each_other() -> None:
    a = _hit(TAINT_SQL, 10, "CWE-89", end=12)
    b = _hit("riskgraph.taint.python.sql-injection-2", 11, "CWE-89")
    assert len(merge([a, b])) == 2


def test_joining_scales_with_many_sast_findings() -> None:
    import time

    many = [_hit("generic.rule", i, "CWE-943") for i in range(1, 4001)]
    many += [_hit(TAINT_SQL, i, "CWE-89") for i in range(1, 4001, 2)]
    # taint hits with no generic finding on their line take the look-back path
    many += [_hit(TAINT_SQL, i, "CWE-89", file="other.py") for i in range(1, 4001, 2)]
    start = time.perf_counter()
    merged = merge(many)
    assert time.perf_counter() - start < 2.0
    assert len(merged) == 4000 + 2000  # every taint hit in big.py joined its generic finding
