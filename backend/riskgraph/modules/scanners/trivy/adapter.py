"""Trivy adapter. Needs egress to fetch its vulnerability DB into the shared cache."""

from __future__ import annotations

from typing import Any

from riskgraph.modules.normalization import RawFinding
from riskgraph.modules.scanners.base import Command, Network, ParseContext, ScanPaths
from riskgraph.modules.scanners.redact import drop_keys
from riskgraph.modules.scanners.trivy import parser
from riskgraph.shared.config import Settings
from riskgraph.shared.vocabulary import ScannerName

# Trivy echoes source lines in these fields; they may contain secrets.
_SNIPPET_KEYS = frozenset({"Code", "Match", "Lines"})


class TrivyScanner:
    name: ScannerName = ScannerName.TRIVY
    network: Network = "none"  # the DB is refreshed by the trusted job, never here
    ok_exit_codes: frozenset[int] = frozenset({0})
    output_name: str = "trivy.json"
    image_tag: str = "0.76.0"

    def timeout_s(self, settings: Settings) -> int:
        return settings.timeout_trivy_s

    def command(self, paths: ScanPaths, settings: Settings) -> Command:
        argv = (
            "trivy",
            "fs",
            "--scanners",
            "vuln,secret,misconfig",
            "--format",
            "json",
            "--output",
            str(paths.out / self.output_name),
            "--exit-code",
            "0",
            "--cache-dir",
            str(paths.cache),
            "--timeout",
            f"{max(60, self.timeout_s(settings) - 30)}s",  # finish before the hard kill
            "--quiet",
            "--skip-version-check",
            "--skip-db-update",
            "--skip-java-db-update",
            "--disable-telemetry",
            ".",
        )
        env = {
            "HOME": str(paths.home),
            "TMPDIR": str(paths.home / "tmp"),
            # so `trivy --version` (same env) also reports the DB build time (X2 freshness)
            "TRIVY_CACHE_DIR": str(paths.cache),
        }
        return Command(argv, env)

    def version_argv(self) -> tuple[str, ...]:
        return ("trivy", "--version")

    def redact(self, doc: Any, key: bytes) -> tuple[Any, set[str]]:
        return drop_keys(doc, _SNIPPET_KEYS), set()

    def count(self, doc: Any) -> int:
        return parser.count(doc)

    def parse(self, doc: Any, ctx: ParseContext) -> list[RawFinding]:
        return parser.parse(doc)
