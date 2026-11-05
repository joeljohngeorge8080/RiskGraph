"""RiskGraph CLI for CI pipelines (blueprint §19, ADR-0013).

    python -m riskgraph.entrypoints.cli scan --api http://127.0.0.1:8000 \\
        --repo https://github.com/owner/repo [--ref main] \\
        [--fail-on critical --fail-on high] [--max-score 70] [--new-only]

Starts (or joins) a scan, waits for it, evaluates the gate and prints a summary. When
``GITHUB_STEP_SUMMARY`` is set the summary is also written there as Markdown.
Exit codes: 0 gate passed, 1 gate failed, 2 the scan or the API failed.

The MVP API has no authentication and listens on localhost, so in CI this runs on a
self-hosted runner next to RiskGraph (see docs/examples/riskgraph-ci.yml).
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from typing import Any

import httpx

TERMINAL = {"COMPLETED", "PARTIAL", "FAILED"}
EXIT_PASS, EXIT_GATE_FAILED, EXIT_ERROR = 0, 1, 2


def _out(text: str) -> None:
    sys.stdout.write(text + "\n")
    sys.stdout.flush()


def markdown(scan: dict[str, Any], gate: dict[str, Any]) -> str:
    summary = scan.get("summary") or {}
    prio = summary.get("by_priority") or {}
    hist = summary.get("history") or {}
    verdict = "✅ passed" if gate["passed"] else "❌ failed"
    lines = [
        f"## RiskGraph: {scan['repository']['full_name']} @ {(scan.get('commit_sha') or '')[:12]}",
        "",
        f"**Gate {verdict}** · policy `{gate['policy']}` · scan {scan['status']}",
        "",
        "| critical | high | medium | low | new | fixed |",
        "|---|---|---|---|---|---|",
        "| {} | {} | {} | {} | {} | {} |".format(
            prio.get("critical", 0),
            prio.get("high", 0),
            prio.get("medium", 0),
            prio.get("low", 0),
            hist.get("new", "—"),
            hist.get("fixed", "—"),
        ),
    ]
    if gate["violations"]:
        lines += ["", "| priority | score | change | finding | location |", "|---|---|---|---|---|"]
        for v in gate["violations"][:20]:
            loc = v.get("location") or {}
            where = f"{loc.get('file', '')}:{loc.get('line_start', '')}".rstrip(":")
            title = str(v["title"]).replace("|", "\\|")[:120]
            lines.append(
                f"| {v['priority']} | {v['score']:.1f} | {v['change']} | {title} | `{where}` |"
            )
    return "\n".join(lines) + "\n"


def run_scan(args: argparse.Namespace, client: httpx.Client) -> int:
    resp = client.post("/api/v1/scans", json={"repo_url": args.repo, "ref": args.ref or None})
    if resp.status_code not in (200, 202):
        _out(f"riskgraph: could not start scan: HTTP {resp.status_code} {resp.text[:300]}")
        return EXIT_ERROR
    scan = resp.json()
    _out(f"riskgraph: scan {scan['id']} {'joined' if scan.get('deduplicated') else 'started'}")
    deadline = time.monotonic() + args.timeout
    while scan["status"] not in TERMINAL:
        if time.monotonic() > deadline:
            _out("riskgraph: timed out waiting for the scan")
            return EXIT_ERROR
        time.sleep(args.poll)
        scan = client.get(f"/api/v1/scans/{scan['id']}").raise_for_status().json()
    if scan["status"] == "FAILED":
        _out(f"riskgraph: scan failed: {scan.get('status_reason')}")
        return EXIT_ERROR

    params: list[tuple[str, str | int | float | bool | None]] = [
        ("fail_on", p) for p in args.fail_on or ["critical"]
    ]
    if args.max_score is not None:
        params.append(("max_score", str(args.max_score)))
    if args.new_only:
        params.append(("new_only", "true"))
    gate = client.get(f"/api/v1/scans/{scan['id']}/gate", params=params).raise_for_status().json()

    report = markdown(scan, gate)
    _out(report)
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file:
        with open(summary_file, "a", encoding="utf-8") as fh:
            fh.write(report)
    return EXIT_PASS if gate["passed"] else EXIT_GATE_FAILED


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="riskgraph")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="scan a repository and evaluate the gate")
    scan.add_argument("--api", default=os.environ.get("RISKGRAPH_API", "http://127.0.0.1:8000"))
    scan.add_argument("--repo", required=True, help="https://github.com/owner/repo")
    scan.add_argument("--ref", default="")
    scan.add_argument("--fail-on", action="append", choices=["critical", "high", "medium", "low"])
    scan.add_argument("--max-score", type=float)
    scan.add_argument("--new-only", action="store_true", help="only new/reopened findings fail")
    scan.add_argument("--timeout", type=int, default=3600)
    scan.add_argument("--poll", type=float, default=5.0)
    return parser


def main(argv: list[str] | None = None, transport: httpx.BaseTransport | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        with httpx.Client(base_url=args.api, timeout=30, transport=transport) as client:
            return run_scan(args, client)
    except httpx.HTTPError as exc:
        _out(f"riskgraph: API error: {exc}")
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
