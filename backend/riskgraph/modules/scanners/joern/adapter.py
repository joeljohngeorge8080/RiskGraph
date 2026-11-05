"""Joern adapter: tier-2 taint for Python in the opt-in ``deep`` profile (ADR-0025).

One command, no shell: ``joern --script taint.sc`` parses the checkout itself
(``importCode``) and writes the report. Joern keeps its workspace under the working
directory and unpacks a native library into the Java temp dir, so it runs from its
private HOME (writable) with ``java.io.tmpdir`` there; ``/tmp`` stays ``noexec``.
"""

from __future__ import annotations

from typing import Any

from riskgraph.modules.normalization import RawFinding
from riskgraph.modules.scanners.base import Command, Network, ParseContext, ScanPaths
from riskgraph.modules.scanners.joern import parser
from riskgraph.modules.scanners.semgrep.taint import load_catalogue
from riskgraph.shared.config import Settings
from riskgraph.shared.vocabulary import ScannerName

NEVER = "$^"  # a regex that matches nothing: no lookup sanitizers configured


class JoernScanner:
    name: ScannerName = ScannerName.JOERN
    network: Network = "none"
    ok_exit_codes: frozenset[int] = frozenset({0})
    output_name: str = "joern.json"
    image_tag: str = "4.0.671"

    def timeout_s(self, settings: Settings) -> int:
        return settings.timeout_joern_s

    def command(self, paths: ScanPaths, settings: Settings) -> Command:
        lookups = "|".join(load_catalogue().lookup_sanitizers.get(parser.LANGUAGE, ())) or NEVER
        tmp = paths.home / "tmp"
        argv = (
            "joern",
            "--script",
            str(settings.joern_query_path),
            "--param",
            f"src={paths.src}",
            "--param",
            f"out={paths.out / self.output_name}",
            "--param",
            f"lookups={lookups}",
            "--param",
            "lang=py",
        )
        env = {
            "HOME": str(paths.home),
            "TMPDIR": str(tmp),
            "JAVA_TOOL_OPTIONS": f"-Djava.io.tmpdir={tmp}",
        }
        return Command(argv, env, cwd=paths.home, memory=settings.joern_memory)

    def version_argv(self) -> tuple[str, ...]:
        # written by scanners/joern/Dockerfile after it checks the base image's version
        return ("cat", "/opt/riskgraph/joern/VERSION")

    def redact(self, doc: Any, key: bytes) -> tuple[Any, set[str]]:
        # locations only by construction; rebuilt so nothing else can pass through
        return parser.clean(doc), set()

    def count(self, doc: Any) -> int:
        return parser.count(doc)

    def parse(self, doc: Any, ctx: ParseContext) -> list[RawFinding]:
        return parser.parse(doc)
