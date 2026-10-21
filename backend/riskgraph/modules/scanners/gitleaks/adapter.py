"""Gitleaks adapter.

Gitleaks runs *unredacted* so the collector can HMAC each secret; ``redact`` then
replaces every raw value before the report is written anywhere (threat T-09).
"""

from __future__ import annotations

from typing import Any

from riskgraph.modules.normalization import RawFinding
from riskgraph.modules.scanners.base import Command, Network, ParseContext, ScanPaths
from riskgraph.modules.scanners.gitleaks import parser
from riskgraph.modules.scanners.redact import mask, secret_hmac
from riskgraph.shared.config import Settings
from riskgraph.shared.vocabulary import ScannerName


class GitleaksScanner:
    name: ScannerName = ScannerName.GITLEAKS
    network: Network = "none"
    ok_exit_codes: frozenset[int] = frozenset({0})
    output_name: str = "gitleaks.json"

    def timeout_s(self, settings: Settings) -> int:
        return settings.timeout_gitleaks_s

    def command(self, paths: ScanPaths, settings: Settings) -> Command:
        argv = (
            "gitleaks",
            "dir",
            ".",
            "--report-format",
            "json",
            "--report-path",
            str(paths.out / self.output_name),
            "--exit-code",
            "0",
            "--no-banner",
            "--log-level",
            "warn",
            "--max-target-megabytes",
            "5",
        )
        return Command(argv, {"HOME": str(paths.home), "TMPDIR": str(paths.home / "tmp")})

    def version_argv(self) -> tuple[str, ...]:
        return ("gitleaks", "version")

    def redact(self, doc: Any, key: bytes) -> tuple[Any, set[str]]:
        if not isinstance(doc, list):
            return [], set()
        secrets: set[str] = set()
        out = []
        for item in doc:
            if not isinstance(item, dict):
                continue
            raw = str(item.get("Secret") or "")
            clean = {k: v for k, v in item.items() if k not in ("Secret", "Match", "Line")}
            if raw:
                secrets.add(raw)
                clean["SecretHMAC"] = secret_hmac(key, raw)
                clean["SecretMasked"] = mask(raw)
            out.append(clean)
        return out, secrets

    def count(self, doc: Any) -> int:
        return parser.count(doc)

    def parse(self, doc: Any, ctx: ParseContext) -> list[RawFinding]:
        return parser.parse(doc)
