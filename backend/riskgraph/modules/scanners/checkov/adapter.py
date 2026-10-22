"""Checkov adapter. IaC frameworks only: secrets belong to Gitleaks/Trivy and package
scanning to Trivy, so those Checkov frameworks are not run."""

from __future__ import annotations

from typing import Any

from riskgraph.modules.normalization import RawFinding
from riskgraph.modules.scanners.base import Command, Network, ParseContext, ScanPaths
from riskgraph.modules.scanners.checkov import parser
from riskgraph.modules.scanners.redact import drop_keys
from riskgraph.shared.config import Settings
from riskgraph.shared.vocabulary import ScannerName

FRAMEWORKS = (
    "terraform",
    "cloudformation",
    "kubernetes",
    "dockerfile",
    "helm",
    "github_actions",
    "arm",
    "bicep",
    "serverless",
)
# Source snippets and absolute workspace paths stay out of stored reports.
_DROP_KEYS = frozenset(
    {
        "code_block",
        "fixed_definition",
        "evaluations",
        "entity_tags",
        "file_abs_path",
        "definition_context_file_path",
        "caller_file_path",
        "connected_node",
    }
)


class CheckovScanner:
    name: ScannerName = ScannerName.CHECKOV
    network: Network = "none"
    ok_exit_codes: frozenset[int] = frozenset(
        {0}
    )  # --soft-fail: findings never change the exit code
    output_name: str = "results_json.json"  # fixed by checkov for -o json + --output-file-path
    image_tag: str = "3.3.30"

    def timeout_s(self, settings: Settings) -> int:
        return settings.timeout_checkov_s

    def command(self, paths: ScanPaths, settings: Settings) -> Command:
        argv = (
            "checkov",
            "-d",
            ".",
            "-o",
            "json",
            "--output-file-path",
            str(paths.out),
            "--soft-fail",
            "--skip-download",
            "--quiet",
            "--compact",
            "--framework",
            *FRAMEWORKS,
        )
        env = {
            "HOME": str(paths.home),
            "TMPDIR": str(paths.home / "tmp"),
            "BC_SKIP_MAPPING": "TRUE",
            "CHECKOV_RUN_SCA_PACKAGE_SCAN_V2": "false",
        }
        return Command(argv, env)

    def version_argv(self) -> tuple[str, ...]:
        return ("checkov", "--version")

    def redact(self, doc: Any, key: bytes) -> tuple[Any, set[str]]:
        return drop_keys(doc, _DROP_KEYS), set()

    def count(self, doc: Any) -> int:
        return parser.count(doc)

    def parse(self, doc: Any, ctx: ParseContext) -> list[RawFinding]:
        return parser.parse(doc)
