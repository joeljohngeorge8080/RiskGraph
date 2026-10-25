"""Trusted refresh of Trivy's vulnerability DB (blueprint §9.2, §9.3).

Trivy scans run with no network, so the DB must be refreshed out of band. This module is
that out-of-band step: a Beat task runs it on a schedule, with egress, and writes only the
shared cache directory. Scans never download anything. The refresh is serialised with the
same Redis lock Trivy scans take, so a scan never reads a half-written DB.
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path

from riskgraph.modules.scanners.containers import Mount, scanner_image
from riskgraph.modules.scanners.registry import get_scanner
from riskgraph.modules.scanners.runner import RunResult, RunSpec, ScannerRunner
from riskgraph.shared.config import Settings
from riskgraph.shared.vocabulary import ScannerName

DB_FSIZE_LIMIT = 4 * 1024 * 1024 * 1024  # Trivy's DB is a few hundred MB


def refresh_argv(cache: Path) -> tuple[str, ...]:
    return (
        "trivy",
        "image",
        "--download-db-only",
        "--cache-dir",
        str(cache),
        "--quiet",
        "--skip-version-check",
        "--disable-telemetry",
    )


def refresh_trivy_db(runner: ScannerRunner, settings: Settings, log_dir: Path) -> RunResult:
    """Download the DB into the shared cache. Returns the run result; never raises."""
    cache = settings.trivy_cache_dir
    home = settings.data_dir / "tooldb" / "home"
    cache.mkdir(parents=True, exist_ok=True)
    (home / "tmp").mkdir(parents=True, exist_ok=True)
    scanner = get_scanner(ScannerName.TRIVY)
    result = runner.run(
        RunSpec(
            refresh_argv(cache),
            cwd=cache,
            log_dir=log_dir,
            timeout_s=settings.timeout_trivy_db_s,
            network="egress",
            env={"HOME": str(home), "TMPDIR": str(home / "tmp")},
            fsize_limit=DB_FSIZE_LIMIT,
            log_name="trivy-db",
            image=scanner_image("trivy", scanner.image_tag),
            mounts=(Mount(str(cache)), Mount(str(home))),
            labels={"riskgraph.role": "db-refresh"},
            # Runs as the worker's uid so the cache it writes can be made scanner-writable.
            user=f"{os.getuid()}:{os.getgid()}",
        )
    )
    if result.exit_code == 0:
        _open_cache_to_scanners(cache)
    return result


def _open_cache_to_scanners(cache: Path) -> None:
    """Trivy takes a write lock on its DB during a scan, and scans run as nobody (65534).
    The cache is one shared, single-tenant directory, so every entry is made world-writable."""
    for dirpath, dirnames, filenames in os.walk(cache):
        for name in [*dirnames, *filenames]:
            with contextlib.suppress(OSError):
                os.chmod(os.path.join(dirpath, name), 0o777 if name in dirnames else 0o666)
    with contextlib.suppress(OSError):
        cache.chmod(0o777)
