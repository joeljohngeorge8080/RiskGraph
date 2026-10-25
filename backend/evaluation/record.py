"""Record scanner reports for every scenario, and freeze the threat intel they need.

    uv run python -m evaluation.record [SCENARIO ...]

Runs the pinned scanner images once per scenario (needs Docker, and network for Trivy's
DB and for EPSS/KEV). Writes ``evaluation/fixtures/<scenario>/<scanner>/<version>/
report.json`` and ``evaluation/fixtures/intel.json``. Evaluation runs replay these files
offline, so results do not drift with feeds or scanner databases (§26.5).
"""

from __future__ import annotations

import datetime as dt
import json
import sys
import tempfile
from functools import partial
from pathlib import Path
from typing import Any

from riskgraph.modules.context.feeds import fetch_epss, fetch_kev
from riskgraph.shared.config import get_settings
from riskgraph.shared.http import OutboundClient
from riskgraph.shared.vocabulary import ScannerName
from tests.fixtures.scanners.record import clean_tmp, record_repo

from evaluation.scenarios import SCENARIOS

FIXTURES = Path(__file__).parent / "fixtures"
INTEL = FIXTURES / "intel.json"


def _cves(report: Path) -> set[str]:
    doc: Any = json.loads(report.read_text())
    return {
        str(v["VulnerabilityID"])
        for r in doc.get("Results") or []
        for v in r.get("Vulnerabilities") or []
        if str(v.get("VulnerabilityID", "")).startswith("CVE-")
    }


def _target(scenario: str, scanner: ScannerName, version: str) -> Path:
    return FIXTURES / scenario / scanner.value / version / "report.json"


def record(names: list[str]) -> None:
    settings = get_settings()
    cves: set[str] = set()
    for name in names:
        scenario = SCENARIOS[name]
        tmp = Path(tempfile.mkdtemp())
        tmp.chmod(0o711)
        try:
            written = record_repo(
                settings,
                tmp,
                scenario.build,
                set(scenario.secrets),
                partial(_target, name),
                trim_trivy=False,  # the evaluation needs every finding, not a sample
            )
        finally:
            clean_tmp(settings, tmp)
        cves |= _cves(written[ScannerName.TRIVY])
        print(f"{name}: {', '.join(p.parent.parent.name for p in written.values())}")  # noqa: T201
    _freeze_intel(cves)


def _freeze_intel(cves: set[str]) -> None:
    previous = json.loads(INTEL.read_text()) if INTEL.exists() else {"epss": {}, "kev": {}}
    client = OutboundClient()
    try:
        epss = fetch_epss(client, sorted(cves)) if cves else {}
        kev = fetch_kev(client)
    finally:
        client.close()
    snapshot = {
        "fetched_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        "source": "api.first.org (EPSS), cisa.gov (KEV)",
        "epss": {
            **previous["epss"],
            **{
                c: [str(e.epss), str(e.percentile), e.date.isoformat() if e.date else None]
                for c, e in sorted(epss.items())
            },
        },
        "kev": {**previous["kev"], **{c: kev[c] for c in sorted(cves) if c in kev}},
        "checked": sorted(set(previous.get("checked", [])) | cves),
    }
    INTEL.parent.mkdir(parents=True, exist_ok=True)
    INTEL.write_text(json.dumps(snapshot, indent=1, sort_keys=True) + "\n")
    print(f"intel: {len(snapshot['epss'])} EPSS, {len(snapshot['kev'])} KEV, {len(cves)} CVEs")  # noqa: T201


if __name__ == "__main__":
    record(sys.argv[1:] or sorted(SCENARIOS))
