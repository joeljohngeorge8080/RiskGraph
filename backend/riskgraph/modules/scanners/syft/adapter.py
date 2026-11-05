"""Syft adapter. Inventory only: no network, no findings, components feed the SBOM."""

from __future__ import annotations

from typing import Any

from riskgraph.modules.normalization import RawFinding
from riskgraph.modules.scanners.base import Command, Network, ParseContext, ScanPaths
from riskgraph.shared.config import Settings
from riskgraph.shared.vocabulary import ScannerName

# Must equal SYFT_VERSION in docker/scanner-versions.env (test_scanner_images enforces it).
IMAGE_TAG = "1.54.1"


class SyftScanner:
    name: ScannerName = ScannerName.SYFT
    network: Network = "none"
    ok_exit_codes: frozenset[int] = frozenset({0})
    output_name: str = "syft.cdx.json"
    image_tag: str = IMAGE_TAG

    def timeout_s(self, settings: Settings) -> int:
        return settings.timeout_syft_s

    def command(self, paths: ScanPaths, settings: Settings) -> Command:
        argv = (
            "syft",
            "scan",
            "dir:.",
            "--output",
            f"cyclonedx-json={paths.out / self.output_name}",
            "--quiet",
        )
        env = {
            "HOME": str(paths.home),
            "TMPDIR": str(paths.home / "tmp"),
            "XDG_CACHE_HOME": str(paths.home / "cache"),
            "SYFT_CHECK_FOR_APP_UPDATE": "false",
        }
        return Command(argv, env)

    def version_argv(self) -> tuple[str, ...]:
        return ("syft", "version")

    def redact(self, doc: Any, key: bytes) -> tuple[Any, set[str]]:
        return doc, set()

    def count(self, doc: Any) -> int:
        """Raw findings: none. The components are the SBOM, counted in the scan summary."""
        return 0

    def parse(self, doc: Any, ctx: ParseContext) -> list[RawFinding]:
        return []  # inventory, not findings; see parser.components()
