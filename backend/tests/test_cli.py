from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from riskgraph.entrypoints.cli import EXIT_ERROR, EXIT_GATE_FAILED, EXIT_PASS, main

SCAN = {
    "id": "01a00000-0000-7000-8000-000000000001",
    "status": "QUEUED",
    "deduplicated": False,
    "commit_sha": "0123456789abcdef0123456789abcdef01234567",
    "repository": {"full_name": "acme/app"},
    "summary": {"by_priority": {"critical": 1}, "history": {"new": 1, "fixed": 0}},
}


def _transport(
    gate_passed: bool, final: str = "COMPLETED"
) -> tuple[httpx.MockTransport, list[str]]:
    seen: list[str] = []
    polls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(f"{request.method} {request.url.path}?{request.url.query.decode()}")
        if request.method == "POST":
            return httpx.Response(202, json=SCAN)
        if request.url.path.endswith("/gate"):
            violations = (
                []
                if gate_passed
                else [
                    {
                        "priority": "critical",
                        "score": 44.0,
                        "change": "new",
                        "title": "AWS | key",
                        "location": {"file": "main.tf", "line_start": 3},
                    }
                ]
            )
            return httpx.Response(
                200,
                json={
                    "passed": gate_passed,
                    "policy": {"fail_on": ["critical"]},
                    "violations": violations,
                },
            )
        polls["n"] += 1
        return httpx.Response(200, json={**SCAN, "status": final if polls["n"] > 1 else "SCANNING"})

    return httpx.MockTransport(handler), seen


def test_gate_pass_and_summary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    transport, seen = _transport(True)
    code = main(
        [
            "scan",
            "--repo",
            "https://github.com/acme/app",
            "--poll",
            "0",
            "--fail-on",
            "high",
            "--new-only",
        ],
        transport,
    )
    assert code == EXIT_PASS
    assert any("fail_on=high" in s and "new_only=true" in s for s in seen)
    assert "Gate ✅ passed" in summary.read_text()


def test_gate_failure_exit_code_and_escaping(capsys: pytest.CaptureFixture[str]) -> None:
    transport, _ = _transport(False)
    assert (
        main(["scan", "--repo", "https://github.com/acme/app", "--poll", "0"], transport)
        == EXIT_GATE_FAILED
    )
    out = capsys.readouterr().out
    assert "AWS \\| key" in out and "`main.tf:3`" in out


def test_failed_scan_and_api_errors() -> None:
    transport, _ = _transport(True, final="FAILED")
    assert (
        main(["scan", "--repo", "https://github.com/acme/app", "--poll", "0"], transport)
        == EXIT_ERROR
    )

    def boom(request: httpx.Request) -> httpx.Response:
        return httpx.Response(422, content=json.dumps({"detail": "bad url"}))

    assert main(["scan", "--repo", "x", "--poll", "0"], httpx.MockTransport(boom)) == EXIT_ERROR
