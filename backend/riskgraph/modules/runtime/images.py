"""Container image references a repository names (expansion X2, ADR-0018).

Sources: Dockerfile ``FROM`` lines (with their line numbers), Compose ``image:`` and
Kubernetes ``containers[].image`` / ``initContainers[].image`` (from the IaC extractor).

The repository is untrusted and chooses these references, and scanning one means pulling
it over the network. So a reference is only ``allowed`` when it is well formed, fully
resolved (no ``$VAR``) and on a public registry from ``ALLOWED_REGISTRIES``; anything
else is kept for display with the reason it will not be scanned. Paths are repo-relative
and only displayed.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from riskgraph.modules.context import IacAsset

Origin = Literal["dockerfile", "compose", "kubernetes"]

ALLOWED_REGISTRIES = frozenset(
    {
        "docker.io",
        "ghcr.io",
        "quay.io",
        "gcr.io",
        "registry.k8s.io",
        "mcr.microsoft.com",
        "public.ecr.aws",
    }
)
_DOCKER_HUB_ALIASES = frozenset({"docker.io", "index.docker.io", "registry-1.docker.io"})
SKIP_DIRS = frozenset({".git", "node_modules", ".venv", "vendor"})
MAX_FILES = 2000
MAX_FILE_BYTES = 512 * 1024
MAX_REF = 255
MAX_REFS = 50

# The docker reference grammar, simplified: lowercase path components, tag and digest.
_COMPONENT = r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"
_REPOSITORY = re.compile(rf"^{_COMPONENT}(?:/{_COMPONENT})*$")
_TAG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_DOMAIN = re.compile(r"^[A-Za-z0-9.-]+(?::[0-9]+)?$")
_FROM = re.compile(r"^\s*FROM\s+(.*)$", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class ImageRef:
    raw: str
    registry: str
    repository: str
    tag: str | None
    digest: str | None
    file: str
    line: int | None
    origin: Origin
    allowed: bool
    reason: str | None = None  # why it will not be scanned

    @property
    def canonical(self) -> str:
        out = f"{self.registry}/{self.repository}"
        if self.tag:
            out += f":{self.tag}"
        if self.digest:
            out += f"@{self.digest}"
        return out


def _refused(raw: str, file: str, line: int | None, origin: Origin, reason: str) -> ImageRef:
    return ImageRef(raw[:MAX_REF], "", "", None, None, file, line, origin, False, reason)


def parse_ref(raw: str, file: str, line: int | None, origin: Origin) -> ImageRef:
    text = raw.strip()
    if not text or len(text) > MAX_REF or any(c.isspace() for c in text):
        return _refused(raw, file, line, origin, "not a valid image reference")
    if "$" in text:
        return _refused(raw, file, line, origin, "uses a build variable, so it is unresolved")
    name, _, digest = text.partition("@")
    tag: str | None = None
    head, sep, last = name.rpartition("/")
    if ":" in last:
        last, tag = last.split(":", 1)
    name = f"{head}{sep}{last}"
    first, slash, rest = name.partition("/")
    if slash and ("." in first or ":" in first or first == "localhost"):
        registry, repository = first.lower(), rest
    else:
        registry, repository = "docker.io", name
    if registry in _DOCKER_HUB_ALIASES:
        registry = "docker.io"
        if "/" not in repository:
            repository = f"library/{repository}"
    valid = (
        _DOMAIN.match(registry) is not None
        and _REPOSITORY.match(repository) is not None
        and (tag is None or _TAG.match(tag) is not None)
        and (not digest or _DIGEST.match(digest) is not None)
    )
    if not valid:
        return _refused(raw, file, line, origin, "not a valid image reference")
    if not tag and not digest:
        tag = "latest"
    allowed = registry in ALLOWED_REGISTRIES
    reason = None if allowed else f"registry {registry} is not on the public allow-list"
    return ImageRef(
        text, registry, repository, tag, digest or None, file, line, origin, allowed, reason
    )


def _dockerfiles(root: Path) -> Iterator[Path]:
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            low = name.lower()
            if not (
                low in {"dockerfile", "containerfile"}
                or low.startswith("dockerfile.")
                or low.endswith(".dockerfile")
            ):
                continue
            count += 1
            if count > MAX_FILES:
                return
            yield Path(dirpath) / name


def _instructions(text: str) -> Iterator[tuple[int, str]]:
    """Logical lines with the number of the line they start on (backslash continuations)."""
    start = 0
    parts: list[str] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if not parts:
            if line.lstrip().startswith("#"):
                continue
            start = number
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            parts.append(stripped[:-1])
            continue
        parts.append(stripped)
        yield start, " ".join(p.strip() for p in parts)
        parts = []
    if parts:
        yield start, " ".join(p.strip() for p in parts)


def dockerfile_refs(root: Path) -> list[ImageRef]:
    out: list[ImageRef] = []
    for path in _dockerfiles(root):
        rel = path.relative_to(root).as_posix()[:512]
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="strict")
        except (OSError, UnicodeDecodeError):
            continue
        stages: set[str] = set()
        for line, instruction in _instructions(text):
            m = _FROM.match(instruction)
            if not m:
                continue
            tokens = [t for t in m.group(1).split() if not t.startswith("--")]
            if not tokens:
                continue
            image = tokens[0]
            # "FROM build" names an earlier stage, not an image; "scratch" is empty
            if image.lower() != "scratch" and image.lower() not in stages:
                out.append(parse_ref(image, rel, line, "dockerfile"))
            if len(tokens) >= 3 and tokens[1].lower() == "as":
                stages.add(tokens[2].lower())
    return out


def _iac_refs(assets: Iterable[IacAsset]) -> Iterator[ImageRef]:
    for a in assets:
        if a.kind == "service" and isinstance(a.attrs.get("image"), str):
            yield parse_ref(a.attrs["image"], a.source_path, None, "compose")
        elif a.kind == "workload":
            for image in a.attrs.get("images") or []:
                if isinstance(image, str):
                    yield parse_ref(image, a.source_path, None, "kubernetes")


def image_refs(root: Path, assets: Iterable[IacAsset]) -> list[ImageRef]:
    """Every image the repository names, deduplicated (first declaration kept)."""
    found = sorted(
        [*dockerfile_refs(root), *_iac_refs(assets)],
        key=lambda r: (r.file, r.line or 0, r.raw),
    )
    seen: set[str] = set()
    out: list[ImageRef] = []
    for ref in found:
        key = ref.canonical if ref.repository else f"?{ref.raw}"
        if key in seen:
            continue
        seen.add(key)
        out.append(ref)
    return out[:MAX_REFS]
