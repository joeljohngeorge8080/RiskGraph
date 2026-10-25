"""Re-record scanner fixtures from the kitchen-sink repository.

    uv run python -m tests.fixtures.scanners.record

Runs the real scanners through the production adapters and runner, applies the
production redaction, then additionally scrubs the kitchen-sink's fake secrets and trims
Trivy's vulnerability list so committed fixtures stay small and secret-free. Needs the
scanner binaries (``make scanner-tools``) and network for Trivy's DB on first run.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from riskgraph.modules.scanners import (
    REDACTION_ORDER,
    SCANNERS,
    RunSpec,
    ScannerRunner,
    ScanPaths,
    SubprocessRunner,
    scrub,
)
from riskgraph.modules.scanners.containers import container_fields, scanner_image
from riskgraph.modules.scanners.docker_runner import DockerRunner, PathRoot, make_removable
from riskgraph.modules.scanners.tooldb import refresh_trivy_db
from riskgraph.shared.config import Settings, get_settings
from riskgraph.shared.vocabulary import ScannerName

from tests.fixtures.repos import kitchen_sink

HERE = Path(__file__).parent
TEST_KEY = b"riskgraph-test-fixture-hmac-key!"
MAX_TRIVY_VULNS = 6


def _version(
    runner: ScannerRunner,
    scanner: Any,
    tmp: Path,
    env: dict[str, str],
    fields: dict[str, Any],
) -> str:
    log_dir = tmp / "logs" / f"version-{scanner.name.value}"
    result = runner.run(
        RunSpec(
            scanner.version_argv(), tmp / "src", log_dir, 60, env=env, log_name="version", **fields
        )
    )
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


def _recording_runner(settings: Settings, tmp: Path) -> ScannerRunner:
    """Scanners run as the pinned container images by default (ADR-0014), with the same
    mounts and labels as production. ``RISKGRAPH_RECORD_RUNNER=subprocess`` uses host tools.
    Container paths are the host paths here, so the roots map onto themselves."""
    if os.environ.get("RISKGRAPH_RECORD_RUNNER", "docker") == "subprocess":
        return SubprocessRunner(settings.scanner_bin_dir)
    import docker  # the recorder is a dev tool; the production import is in docker_runner

    roots = [
        PathRoot(str(tmp), str(tmp)),
        PathRoot(str(settings.trivy_cache_dir), str(settings.trivy_cache_dir)),
        PathRoot(str(settings.data_dir), str(settings.data_dir)),
    ]
    return DockerRunner(docker.from_env(timeout=60), roots, settings.scanner_egress_network)


def _open_for_scanner_uid(*paths: Path) -> None:
    """Scanners run as nobody (65534): the directories they write to must be world-writable."""
    for p in paths:
        p.chmod(0o777)


def _make_removable_later(settings: Settings, tmp: Path) -> None:
    if os.environ.get("RISKGRAPH_RECORD_RUNNER", "docker") == "subprocess":
        return
    import docker

    roots = [PathRoot(str(tmp), str(tmp)), PathRoot(str(settings.data_dir), str(settings.data_dir))]
    runner = DockerRunner(docker.from_env(timeout=60), roots, settings.scanner_egress_network)
    make_removable(runner, str(tmp), scanner_image("checkov", "3.3.30"), tmp / "fixup-logs")


def record_repo(
    settings: Settings,
    tmp: Path,
    build: Callable[[Path], Path],
    secrets: set[str],
    target: Callable[[ScannerName, str], Path],
    *,
    trim_trivy: bool,
) -> dict[ScannerName, Path]:
    """Scan the repository ``build`` writes with every scanner; store redacted reports.

    ``secrets`` are the repository's fake credentials, scrubbed on top of the production
    redaction; ``target(scanner, version)`` names each report file.
    """
    runner = _recording_runner(settings, tmp)
    if isinstance(runner, DockerRunner):
        refresh = refresh_trivy_db(runner, settings, tmp / "logs" / "db")
        assert refresh.exit_code == 0, refresh
    src = build(tmp / "src")
    docs: dict[ScannerName, Any] = {}
    versions: dict[ScannerName, str] = {}
    for name, scanner in SCANNERS.items():
        paths = ScanPaths(src, tmp / "out" / name, tmp / "home" / name, settings.trivy_cache_dir)
        for d in (paths.out, paths.home / "tmp", paths.cache):
            d.mkdir(parents=True, exist_ok=True)
        _open_for_scanner_uid(paths.out, paths.home, paths.home / "tmp")
        cmd = scanner.command(paths, settings)
        fields = container_fields(name.value, scanner.image_tag, paths, {})
        spec = RunSpec(
            cmd.argv,
            src,
            tmp / "logs" / name.value,
            scanner.timeout_s(settings),
            scanner.network,
            cmd.env,
            log_name="scan",
            **fields,
        )
        result = runner.run(spec)
        assert result.exit_code in scanner.ok_exit_codes, (name, result)
        docs[name] = json.loads((paths.out / scanner.output_name).read_text())
        versions[name] = _version(runner, scanner, tmp, dict(cmd.env), fields)

    found_secrets = set(secrets)
    for name in REDACTION_ORDER:
        docs[name], found = SCANNERS[name].redact(docs[name], TEST_KEY)
        found_secrets |= found
    written: dict[ScannerName, Path] = {}
    for name, doc in docs.items():
        doc = scrub(doc, found_secrets)
        if name is ScannerName.TRIVY and trim_trivy:
            doc = _trim_trivy(doc)
        path = target(name, versions[name])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
        written[name] = path
    return written


def _record(settings: Settings, tmp: Path) -> None:
    secrets: set[str] = {
        kitchen_sink.FAKE_AWS_KEY_ID,
        kitchen_sink.FAKE_AWS_SECRET,
        *kitchen_sink.FILES["deploy/id_rsa"].splitlines()[1:-1],
    }
    written = record_repo(
        settings,
        tmp,
        kitchen_sink.build,
        secrets,
        lambda name, version: HERE / name.value / version / "kitchen_sink.json",
        trim_trivy=True,
    )
    for path in written.values():
        print(f"wrote {path.relative_to(HERE)}")  # noqa: T201 - CLI script output


def clean_tmp(settings: Settings, tmp: Path) -> None:
    # Scanner containers wrote files as nobody: widen them before deleting the tree.
    _make_removable_later(settings, tmp)
    shutil.rmtree(tmp, ignore_errors=True)


def main() -> None:
    settings = get_settings()
    tmp = Path(tempfile.mkdtemp())
    tmp.chmod(0o711)
    try:
        _record(settings, tmp)
    finally:
        clean_tmp(settings, tmp)


if __name__ == "__main__":
    main()
