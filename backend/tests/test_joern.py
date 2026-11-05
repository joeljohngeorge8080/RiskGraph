"""Tier-2 taint with Joern (X4 part 2, ADR-0025): the parser on real Joern output, hostile
reports, the adapter's command against the container profile, correlation and evidence.

The golden fixtures under ``fixtures/joern/master-f6b35cd1296f/adapter/`` are the real
output of ``scanners/joern/taint.sc`` (Joern 4.0.671, the pinned digest), run with the
adapter's command on the 20 Python cases of the taint suite plus two hostile cases written
for the allow-list sanitizer (``concat-ssrf``: a constant lookup that is NOT on the flow,
still vulnerable; ``index-lookup``: ``ALLOWED[x]``, sanitized).
"""

from __future__ import annotations

import datetime as dt
import json
import re
from pathlib import Path

import pytest
from evaluation.taint_suite import cases
from riskgraph.modules.evidence import Assurance
from riskgraph.modules.normalization import merge
from riskgraph.modules.scanners import SCANNERS, ParseContext, ScanPaths
from riskgraph.modules.scanners.containers import ALLOWED_ENV, Mount, build_create_kwargs
from riskgraph.modules.scanners.joern import JoernScanner, parser
from riskgraph.modules.scanners.semgrep.parser import MAX_TAINT_STEPS
from riskgraph.modules.scanners.semgrep.taint import load_catalogue
from riskgraph.modules.scans.finding_evidence import finding_evidence
from riskgraph.shared.config import Settings
from riskgraph.shared.vocabulary import ScannerName, Severity, SourceType

from tests.scanner_fixtures import load

GOLDEN = Path(__file__).parent / "fixtures" / "joern" / "master-f6b35cd1296f" / "adapter"
CTX = ParseContext("acme/suite")
PY_CASES = {c.id: c for c in cases() if c.language == "python"}


def _golden(name: str) -> list:  # type: ignore[type-arg]
    return parser.parse(json.loads((GOLDEN / name / "joern.json").read_text()))


# --- the 20 Python cases: every flow found, no sanitized case flagged -------------------
@pytest.mark.parametrize("case_id", sorted(PY_CASES))
def test_the_real_joern_run_matches_the_suite_labels(case_id: str) -> None:
    case = PY_CASES[case_id]
    found = _golden(case_id)
    if not case.vulnerable:
        assert found == [], [f.location for f in found]
        return
    [f] = found
    assert f.rule_id == f"riskgraph.taint.python.{case.class_id}"
    assert (f.location.file, f.location.line_start) == (case.sink_file, case.sink_line)
    steps = f.attrs["taint_steps"]
    assert steps[0]["role"] == "source" and steps[-1]["role"] == "sink"
    assert (steps[-1]["file"], steps[-1]["line"]) == (case.sink_file, case.sink_line)
    if case.variant == "cross_file":
        assert len({s["file"] for s in steps}) == 2  # the flow crosses into the helper


def test_suite_numbers_meet_the_plan_targets() -> None:
    """Plan §6 for A: interprocedural recall ≥ 0.6, precision ≥ 0.7, sanitized FP ≤ 0.2.
    Measured on the real run: 10/10, 15/15, 0/5 (the spike had 2/5 sanitized flagged)."""
    tp = fp = fn = sanitized_flagged = inter_found = 0
    for cid, case in PY_CASES.items():
        hit = bool(_golden(cid))
        if case.vulnerable:
            tp += hit
            fn += not hit
            inter_found += hit and case.variant in ("cross_function", "cross_file")
        else:
            fp += hit
            sanitized_flagged += hit
    assert inter_found / 10 >= 0.6 and tp / (tp + fp) >= 0.7 and sanitized_flagged / 5 <= 0.2
    assert (tp, fp, fn, inter_found, sanitized_flagged) == (15, 0, 0, 10, 0)


def test_an_allow_list_lookup_sanitizes_and_a_constant_beside_the_flow_does_not() -> None:
    assert _golden("index-lookup") == []  # v = ALLOWED_URLS[request.args["v"]]
    [f] = _golden("concat-ssrf")  # requests.get(CONFIG["base"] + request.args["p"])
    assert f.rule_id.endswith("server-side-request-forgery")


# --- the parser on hostile reports -------------------------------------------------------
def _flow(cls: str = "sql-injection", **over: object) -> dict[str, object]:
    flow: dict[str, object] = {
        "class": cls,
        "sink": {"file": "app.py", "line": 9},
        "steps": [{"file": "app.py", "line": 3}, {"file": "app.py", "line": 9}],
    }
    return {**flow, **over}


@pytest.mark.parametrize(
    "doc",
    [
        None,
        [],
        "flows",
        {"version": 2, "flows": [_flow()]},
        {"version": 1, "flows": "x"},
        {"version": 1, "flows": [_flow("no-such-class")]},
        {"version": 1, "flows": [_flow(sink={"file": "app.py", "line": True})]},
        {"version": 1, "flows": [_flow(sink={"file": "app.py", "line": -3})]},
        {"version": 1, "flows": [_flow(sink={"file": "a" * 600, "line": 3})]},
        {"version": 1, "flows": [_flow(sink="app.py:9")]},
        {"version": 1, "flows": [42, None]},
    ],
)
def test_a_malformed_report_gives_no_finding_and_no_error(doc: object) -> None:
    assert parser.parse(doc) == []


def test_steps_are_capped_and_keep_their_sink_and_bad_steps_are_dropped() -> None:
    steps = [{"file": "app.py", "line": i} for i in range(1, 200)] + [{"file": "x", "line": 0}]
    steps.append({"file": "app.py", "line": 9})
    [f] = parser.parse({"version": 1, "flows": [_flow(steps=steps)]})
    kept = f.attrs["taint_steps"]
    assert len(kept) == MAX_TAINT_STEPS and kept[-1] == {
        "file": "app.py",
        "line": 9,
        "role": "sink",
    }


def test_flows_are_capped() -> None:
    many = [_flow(sink={"file": "app.py", "line": i + 1}) for i in range(parser.MAX_FLOWS + 50)]
    assert parser.count(parser.clean({"version": 1, "flows": many})) == parser.MAX_FLOWS


def test_a_path_outside_the_checkout_is_normalized_like_every_scanner_path() -> None:
    [f] = parser.parse(
        {"version": 1, "flows": [_flow(sink={"file": "../../etc/passwd", "line": 9})]}
    )
    assert ".." not in f.location.file


def test_several_flows_into_one_sink_are_one_finding_with_the_shortest_trace() -> None:
    long = _flow(steps=[{"file": "app.py", "line": n} for n in (1, 2, 3, 9)])
    short = _flow()
    [f] = parser.parse({"version": 1, "flows": [long, short]})
    assert [s["line"] for s in f.attrs["taint_steps"]] == [3, 9]


def test_redaction_keeps_only_what_riskgraph_reads() -> None:
    doc = {"version": 1, "language": "py", "code": "secret", "flows": [_flow(code="x = 1")]}
    clean, secrets = JoernScanner().redact(doc, b"k")
    assert secrets == set() and "code" not in json.dumps(clean)


def test_findings_are_high_confidence_tier2_sast_with_the_catalogue_cwe() -> None:
    [f] = parser.parse({"version": 1, "flows": [_flow("os-command-injection")]})
    assert f.scanner is ScannerName.JOERN and f.source_type is SourceType.SAST
    assert f.cwe_ids == ("CWE-78",) and f.category == "command_injection"
    assert f.severity is Severity.CRITICAL  # ERROR + HIGH impact + HIGH confidence, as tier 1
    assert f.attrs["analysis"] == "interprocedural"


# --- the adapter's command fits the container profile ------------------------------------
def test_the_command_is_one_argv_run_from_the_private_home(tmp_path: Path) -> None:
    paths = ScanPaths(tmp_path / "src", tmp_path / "out", tmp_path / "home", tmp_path / "cache")
    cmd = JoernScanner().command(paths, Settings())
    assert cmd.argv[:3] == ("joern", "--script", "/opt/riskgraph/joern/taint.sc")
    assert all(isinstance(a, str) for a in cmd.argv) and cmd.cwd == paths.home
    assert f"src={paths.src}" in cmd.argv and f"out={paths.out / 'joern.json'}" in cmd.argv
    lookups = next(a for a in cmd.argv if a.startswith("lookups="))
    assert lookups == "lookups=" + "|".join(load_catalogue().lookup_sanitizers["python"])
    assert cmd.env["JAVA_TOOL_OPTIONS"] == f"-Djava.io.tmpdir={paths.home / 'tmp'}"
    assert set(cmd.env) <= ALLOWED_ENV and cmd.memory == "3g"
    kwargs = build_create_kwargs(
        image="riskgraph/scanner-joern:4.0.671",
        argv=cmd.argv,
        env=cmd.env,
        working_dir=str(cmd.cwd),
        mounts=(Mount(str(paths.src), read_only=True), Mount(str(paths.home))),
        host_sources={str(paths.src): str(paths.src), str(paths.home): str(paths.home)},
        labels={},
        network="none",
        egress_network="unused",
    )
    assert kwargs["network_mode"] == "none" and kwargs["read_only"] is True
    # Joern's temp dir is under its HOME: the container /tmp stays noexec
    assert kwargs["tmpfs"]["/tmp"].startswith("rw,noexec")  # noqa: S108


def test_the_memory_setting_is_a_docker_size_only() -> None:
    with pytest.raises(ValueError, match="joern_memory"):
        Settings(joern_memory="3g; rm -rf /")


def test_the_joern_adapter_is_registered_and_parses_the_kitchen_sink() -> None:
    found = SCANNERS[ScannerName.JOERN].parse(load(ScannerName.JOERN), CTX)
    assert {(f.location.file, f.location.line_start, f.cwe_ids) for f in found} == {
        ("app.py", 14, ("CWE-89",)),
        ("app.py", 21, ("CWE-78",)),
    }


# --- the query stays in step with the catalogue -----------------------------------------
QUERY = Path(__file__).resolve().parents[2] / "scanners" / "joern" / "taint.sc"


def test_the_query_names_exactly_the_catalogue_classes() -> None:
    text = QUERY.read_text()
    named = set(re.findall(r'^\s*\("([a-z0-9-]+)",', text, flags=re.M))
    assert named == {c.id for c in load_catalogue().classes}


def test_the_query_parses_by_itself_and_writes_locations_only() -> None:
    text = QUERY.read_text()
    assert "importCode(" in text and "importCpg" not in text  # one command, no joern-parse
    # the JSON keys it writes (ADR-0021: never code)
    keys = set(re.findall(r'\\"([a-z]+)\\":|"\{\\"([a-z]+)\\"', text))
    written = set(re.findall(r'\{"([a-z]+)": |, "([a-z]+)": ', text))
    names = {k for pair in keys | written for k in pair if k}
    assert names == {"version", "language", "flows", "class", "sink", "steps", "file", "line"}


# --- evidence and correlation ------------------------------------------------------------
def test_a_tier2_member_is_inferred_interprocedural_taint_flow_evidence() -> None:
    [f] = _golden("python-cwe-918-cross-file")
    [m] = merge([f])
    now = dt.datetime(2026, 11, 5, tzinfo=dt.UTC)
    [ev] = finding_evidence(m, None, {}, {"joern": "4.0.671"}, now)
    assert ev.kind == "taint_flow" and ev.assurance is Assurance.INFERRED
    assert ev.facts["analysis"] == "interprocedural" and ev.producer == "joern@4.0.671"
    assert [(s.location.file, s.label) for s in ev.steps] == [
        ("app.py", "source"),
        ("helper.py", "step"),
        ("helper.py", "sink"),
    ]


def test_a_tier2_hit_does_not_feed_the_tier1_exploitability_row() -> None:
    """ADR-0024's taint E is for tier 1; a tier-2 E is the owner's decision (ADR-0025)."""
    from riskgraph.modules.risk.service import input_for

    [f] = _golden("python-cwe-89-cross-file")
    [m] = merge([f])
    assert input_for(m, None).taint_cwe is None


# --- the deep profile's one slot ---------------------------------------------------------
class _Lock:
    def __init__(self, log: list[tuple[str, float]], key: str, wait: float) -> None:
        self.log, self.key, self.wait = log, key, wait

    def acquire(self) -> bool:
        self.log.append((self.key, self.wait))
        return True

    def release(self) -> None:
        self.log.append(("released", 0))


class _Redis:
    def __init__(self) -> None:
        self.log: list[tuple[str, float]] = []

    def lock(self, key: str, timeout: float, blocking_timeout: float) -> _Lock:
        return _Lock(self.log, key, blocking_timeout)


def test_joern_and_trivy_runs_are_serialized_by_their_own_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from riskgraph.modules.scans import pipeline

    fake = _Redis()
    monkeypatch.setattr(pipeline, "get_redis", lambda: fake)
    for name in (ScannerName.JOERN, ScannerName.TRIVY, ScannerName.SEMGREP):
        with pipeline.redis_scanner_lock(name, 60) as acquired:
            assert acquired
    assert fake.log == [
        (pipeline.JOERN_LOCK_KEY, pipeline.JOERN_LOCK_WAIT_S),
        ("released", 0),
        (pipeline.TRIVY_LOCK_KEY, pipeline.TRIVY_LOCK_WAIT_S),
        ("released", 0),
    ]  # semgrep takes no lock
