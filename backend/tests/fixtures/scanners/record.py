"""Re-record scanner fixtures from the kitchen-sink repository.

    uv run python -m tests.fixtures.scanners.record

Runs the real scanners through the production adapters and runner, applies the
production redaction, then additionally scrubs the kitchen-sink's fake secrets and trims
Trivy's vulnerability list so committed fixtures stay small and secret-free. Needs the
scanner binaries (``make scanner-tools``) and network for Trivy's DB on first run.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import Any

from riskgraph.modules.scanners import (
    REDACTION_ORDER,
    SCANNERS,
    RunSpec,
    ScanPaths,
    SubprocessRunner,
    scrub,
)
from riskgraph.shared.config import get_settings
from riskgraph.shared.vocabulary import ScannerName

from tests.fixtures.repos import kitchen_sink

HERE = Path(__file__).parent
TEST_KEY = b"riskgraph-test-fixture-hmac-key!"
MAX_TRIVY_VULNS = 6


def _version(
    runner: SubprocessRunner, argv: tuple[str, ...], tmp: Path, env: dict[str, str]
) -> str:
    log_dir = tmp / "logs"
    result = runner.run(RunSpec(argv, tmp, log_dir, 60, env=env, log_name="version"))
    text = (log_dir / "version.stdout.log").read_text().strip() if result.exit_code == 0 else ""
    for token in text.replace("Version:", " ").split():
        if token[:1].isdigit():
            return token
    return "unknown"


def _trim_trivy(doc: dict[str, Any]) -> dict[str, Any]:
    """Keep MAX_TRIVY_VULNS vulnerabilities, round-robin over packages (all tiers covered)."""
    for result in doc.get("Results") or []:
        vulns = result.get("Vulnerabilities")
        if not vulns:
            continue
        per_package: dict[str, list[dict[str, Any]]] = {}
        for v in vulns:
            per_package.setdefault(v.get("PkgName", ""), []).append(v)
        kept: list[dict[str, Any]] = []
        while len(kept) < MAX_TRIVY_VULNS and any(per_package.values()):
            for name in sorted(per_package):
                if per_package[name] and len(kept) < MAX_TRIVY_VULNS:
                    kept.append(per_package[name].pop(0))
        result["Vulnerabilities"] = kept
        for v in kept:
            v["References"] = (v.get("References") or [])[:2]
    return doc


def main() -> None:
    settings = get_settings()
    runner = SubprocessRunner(settings.scanner_bin_dir)
    with tempfile.TemporaryDirectory() as tmp_name:
        tmp = Path(tmp_name)
        src = kitchen_sink.build(tmp / "src")
        docs: dict[ScannerName, Any] = {}
        versions: dict[ScannerName, str] = {}
        for name, scanner in SCANNERS.items():
            paths = ScanPaths(
                src, tmp / "out" / name, tmp / "home" / name, settings.trivy_cache_dir
            )
            for d in (paths.out, paths.home / "tmp", paths.cache):
                d.mkdir(parents=True, exist_ok=True)
            cmd = scanner.command(paths, settings)
            spec = RunSpec(
                cmd.argv, src, paths.home, scanner.timeout_s(settings), scanner.network, cmd.env
            )
            result = runner.run(spec)
            assert result.exit_code in scanner.ok_exit_codes, (name, result)
            docs[name] = json.loads((paths.out / scanner.output_name).read_text())
            versions[name] = _version(runner, scanner.version_argv(), tmp, dict(cmd.env))

        secrets: set[str] = {
            kitchen_sink.FAKE_AWS_KEY_ID,
            kitchen_sink.FAKE_AWS_SECRET,
            *kitchen_sink.FILES["deploy/id_rsa"].splitlines()[1:-1],
        }
        for name in REDACTION_ORDER:
            docs[name], found = SCANNERS[name].redact(docs[name], TEST_KEY)
            secrets |= found
        for name, doc in docs.items():
            doc = scrub(doc, secrets)
            if name is ScannerName.TRIVY:
                doc = _trim_trivy(doc)
            target = HERE / name.value / versions[name] / "kitchen_sink.json"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
            print(f"wrote {target.relative_to(HERE)}")  # noqa: T201 - CLI script output
        shutil.rmtree(tmp / "out", ignore_errors=True)


if __name__ == "__main__":
    main()
