"""Record `trivy image` reports for public images (expansion X2 part 2).

    uv run python -m tests.fixtures.images.record [IMAGE ...]

Pulls each image through the pinned Trivy image, in the same hardened profile the
pipeline uses (non-root, read-only root, no capabilities, memory and pids limits) but on
the egress network, because a pull needs the registry. ``--list-all-pkgs`` makes the
report also the image's package inventory, so Syft needs no network (ADR-0018). Writes
``tests/fixtures/images/<slug>/trivy/<version>/report.json`` with the vulnerability and
package lists trimmed so committed fixtures stay small. Needs Docker, the scanner images
(``make scanner-images``), the host Trivy DB cache and network.

Pull policy: only references on ``runtime.ALLOWED_REGISTRIES`` are accepted here too.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from riskgraph.modules.runtime import parse_ref
from riskgraph.modules.scanners import get_scanner
from riskgraph.shared.vocabulary import ScannerName

HERE = Path(__file__).parent
EGRESS = "riskgraph_egress"
TRIVY_TAG = get_scanner(ScannerName.TRIVY).image_tag
TRIVY_CACHE = Path.home() / ".cache" / "riskgraph" / "trivy"
DEFAULT_IMAGES = ("python:3.8-slim", "node:14")
MAX_VULNS = 12
TIMEOUT_S = 900


def slug(image: str) -> str:
    return image.replace("/", "_").replace(":", "_")


def _docker(image: str, mounts: list[str], argv: list[str]) -> None:
    cmd = [
        "docker", "run", "--rm",
        "--network", EGRESS,
        "--user", "65534:65534",
        "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--memory", "2g", "--pids-limit", "512",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=1g",  # noqa: S108 - inside the container
        "-e", "HOME=/tmp/home",
        *mounts,
        image, *argv,
    ]  # fmt: skip
    done = subprocess.run(cmd, timeout=TIMEOUT_S, capture_output=True, text=True)  # noqa: S603
    if done.returncode:
        raise SystemExit(f"{argv[0]} failed ({done.returncode}):\n{done.stderr[-1500:]}")


def _trim_trivy(doc: dict[str, Any]) -> dict[str, Any]:
    """Keep MAX_VULNS per result, round-robin over packages, with short references."""
    for result in doc.get("Results") or []:
        vulns = result.get("Vulnerabilities")
        if not vulns:
            continue
        per_package: dict[str, list[dict[str, Any]]] = {}
        for v in vulns:
            per_package.setdefault(v.get("PkgName", ""), []).append(v)
        kept: list[dict[str, Any]] = []
        while len(kept) < MAX_VULNS and any(per_package.values()):
            for name in sorted(per_package):
                if per_package[name] and len(kept) < MAX_VULNS:
                    kept.append(per_package[name].pop(0))
        for v in kept:
            v["References"] = (v.get("References") or [])[:2]
            v["Description"] = str(v.get("Description", ""))[:300]
        result["Vulnerabilities"] = kept
        result["Packages"] = (result.get("Packages") or [])[:60]
    return doc


def record(image: str) -> list[Path]:
    ref = parse_ref(image, "record", None, "dockerfile")
    if not ref.allowed:
        raise SystemExit(f"refusing {image}: {ref.reason}")
    work = Path(tempfile.mkdtemp(prefix="riskgraph-image-"))
    work.chmod(0o777)
    written: list[Path] = []
    try:
        _docker(
            f"riskgraph/scanner-trivy:{TRIVY_TAG}",
            ["-v", f"{TRIVY_CACHE}:/cache:ro", "-v", f"{work}:/out"],
            [
                "trivy", "image", "--image-src", "remote", "--format", "json",
                "--output", "/out/trivy.json", "--cache-dir", "/cache",
                "--cache-backend", "memory", "--scanners", "vuln", "--list-all-pkgs",
                "--skip-db-update", "--skip-java-db-update", "--skip-version-check",
                "--disable-telemetry", "--exit-code", "0", "--quiet", ref.canonical,
            ],
        )  # fmt: skip
        doc = _trim_trivy(json.loads((work / "trivy.json").read_text()))
        out = HERE / slug(image) / "trivy" / TRIVY_TAG / "report.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
        written.append(out)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return written


if __name__ == "__main__":
    for img in sys.argv[1:] or DEFAULT_IMAGES:
        for path in record(img):
            print(f"{img}: {path.relative_to(HERE)} ({path.stat().st_size // 1024} KB)")  # noqa: T201
