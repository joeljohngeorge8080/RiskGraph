"""The pinned versions file is the single source of truth for scanner images (ADR-0014)."""

from __future__ import annotations

import re
from pathlib import Path

from riskgraph.modules.scanners import SCANNERS
from riskgraph.shared.vocabulary import ScannerName

ROOT = Path(__file__).resolve().parents[2]
ENV = ROOT / "docker" / "scanner-versions.env"
KEYS = {
    "trivy": "TRIVY_VERSION",
    "gitleaks": "GITLEAKS_VERSION",
    "semgrep": "SEMGREP_VERSION",
    "checkov": "CHECKOV_VERSION",
    "syft": "SYFT_VERSION",
}


def _pins() -> dict[str, str]:
    out: dict[str, str] = {}
    for line in ENV.read_text().splitlines():
        m = re.match(r"^([A-Z_]+)=(\S+)$", line.strip())
        if m:
            out[m.group(1)] = m.group(2)
    return out


def test_every_adapter_image_tag_matches_the_pinned_version() -> None:
    pins = _pins()
    for name, key in KEYS.items():
        assert SCANNERS[ScannerName(name)].image_tag == pins[key], name


def test_every_scanner_has_a_dockerfile_that_takes_its_version() -> None:
    for name, key in KEYS.items():
        dockerfile = ROOT / "scanners" / name / "Dockerfile"
        text = dockerfile.read_text()
        assert f"ARG {key}" in text, name
        assert "USER 65534:65534" in text, name  # nobody, as the runtime profile expects


def test_the_fetcher_image_exists() -> None:
    assert (ROOT / "scanners" / "git-fetcher" / "Dockerfile").is_file()
