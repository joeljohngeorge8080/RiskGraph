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

    def image_command(self, paths: ScanPaths, settings: Settings, ref: str, output: str) -> Command:
        """``trivy image`` for one allowed public reference (X2, ADR-0018).

        The flags are the ones the fixtures were recorded with (``tests/fixtures/images``):
        a registry pull with no Docker daemon, vulnerabilities only, and every package
        listed, so the report is also the image's inventory. The layer cache stays in
        memory; only the shared vulnerability DB is read from ``paths.cache``. Needs the
        egress network (the pull); the size cap is also checked on the report afterwards.
        """
        if not ref or ref.startswith("-"):
            raise ValueError("an image reference must not look like an option")
        argv = (
            "trivy",
            "image",
            "--image-src",
            "remote",
            "--format",
            "json",
            "--output",
            output,
            "--cache-dir",
            str(paths.cache),
            "--cache-backend",
            "memory",
            "--scanners",
            "vuln",
            "--list-all-pkgs",
            "--max-image-size",
            f"{settings.image_scan_max_bytes // 1_000_000}MB",  # Trivy: human-readable, decimal
            "--timeout",
            f"{max(60, settings.timeout_trivy_image_s - 30)}s",
            "--exit-code",
            "0",
            "--quiet",
            "--skip-version-check",
            "--skip-db-update",
            "--skip-java-db-update",
            "--disable-telemetry",
            ref,
        )
        env = {"HOME": str(paths.home), "TMPDIR": str(paths.home / "tmp")}
        return Command(argv, env)

    def version_argv(self) -> tuple[str, ...]:
        return ("trivy", "--version")

    def redact(self, doc: Any, key: bytes) -> tuple[Any, set[str]]:
        return drop_keys(doc, _SNIPPET_KEYS), set()

    def count(self, doc: Any) -> int:
        return parser.count(doc)

    def parse(self, doc: Any, ctx: ParseContext) -> list[RawFinding]:
        return parser.parse(doc)
