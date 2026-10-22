"""Semgrep adapter. Rules are vendored at install time; no network at scan time."""

from __future__ import annotations

from typing import Any

from riskgraph.modules.normalization import RawFinding
from riskgraph.modules.scanners.base import Command, Network, ParseContext, ScanPaths
from riskgraph.modules.scanners.redact import drop_keys
from riskgraph.modules.scanners.semgrep import parser
from riskgraph.shared.config import Settings
from riskgraph.shared.vocabulary import ScannerName

# Fields that carry matched source code (secrets can hide there).
_SNIPPET_KEYS = frozenset(
    {"lines", "fix", "fixed_lines", "rendered_fix", "metavars", "dataflow_trace"}
)


class SemgrepScanner:
    name: ScannerName = ScannerName.SEMGREP
    network: Network = "none"
    ok_exit_codes: frozenset[int] = frozenset({0, 1})  # 1 = findings present
    output_name: str = "semgrep.json"
    image_tag: str = "1.182.0"

    def timeout_s(self, settings: Settings) -> int:
        return settings.timeout_semgrep_s

    def command(self, paths: ScanPaths, settings: Settings) -> Command:
        argv = (
            "semgrep",
            "scan",
            "--config",
            str(settings.semgrep_rules_path),
            "--json",
            "--output",
            str(paths.out / self.output_name),
            "--metrics=off",
            "--disable-version-check",
            "--timeout",
            "30",
            "--max-target-bytes",
            "1000000",
            "--jobs",
            "2",
            "--quiet",
            ".",
        )
        env = {
            "HOME": str(paths.home),
            "TMPDIR": str(paths.home / "tmp"),
            "XDG_CACHE_HOME": str(paths.home / "cache"),
            "XDG_CONFIG_HOME": str(paths.home / "config"),
            "SEMGREP_SEND_METRICS": "off",
            "SEMGREP_ENABLE_VERSION_CHECK": "0",
        }
        return Command(argv, env)

    def version_argv(self) -> tuple[str, ...]:
        return ("semgrep", "--version")

    def redact(self, doc: Any, key: bytes) -> tuple[Any, set[str]]:
        return drop_keys(doc, _SNIPPET_KEYS), set()

    def count(self, doc: Any) -> int:
        return parser.count(doc)

    def parse(self, doc: Any, ctx: ParseContext) -> list[RawFinding]:
        return parser.parse(doc)
