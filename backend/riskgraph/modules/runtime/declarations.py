"""Language runtimes a repository declares (expansion X2).

Exact pins say what runs and can produce an EOL finding: ``.python-version``,
``runtime.txt``, ``.nvmrc``, an exact ``engines.node``, and the tag of an official
``python``, ``node`` or ``golang`` image. Ranges (``requires-python = ">=3.8"``,
``engines.node: ">=16"``) and ``go.mod``'s ``go`` line state a minimum, not what runs,
so they are recorded (``exact=False``) and never produce a finding. Files are read from
the scan workspace with size and count caps; their paths are only displayed.
"""

from __future__ import annotations

import json
import os
import re
import tomllib
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

from riskgraph.modules.runtime.images import SKIP_DIRS, ImageRef

MAX_FILES = 2000
MAX_FILE_BYTES = 256 * 1024
NAMES = frozenset(
    {".python-version", "runtime.txt", ".nvmrc", "package.json", "pyproject.toml", "go.mod"}
)

# official image → (product, pattern for the cycle at the start of the tag)
_IMAGES = {
    "library/python": ("python", re.compile(r"^(\d+\.\d+)")),
    "library/node": ("nodejs", re.compile(r"^(\d+)(?:[.-]|$)")),
    "library/golang": ("go", re.compile(r"^(\d+\.\d+)")),
}
_PY = re.compile(r"^(?:python-)?(\d+)\.(\d+)(?:\.\d+)?$")
_NODE_EXACT = re.compile(r"^v?(\d+)(?:\.\d+){0,2}$")
_RANGE_MAJOR = re.compile(r"(\d+)(?:\.(\d+))?")
_GO = re.compile(r"^go\s+(\d+\.\d+)(?:\.\d+)?\s*$")


@dataclass(frozen=True, slots=True)
class RuntimeDecl:
    product: str  # endoflife.date product: python | nodejs | go
    cycle: str  # "3.8", "14", "1.19"
    version: str  # as declared
    file: str
    line: int | None
    source: str  # python-version | runtime.txt | nvmrc | engines | requires-python | go.mod | image
    exact: bool


def _files(root: Path) -> Iterator[Path]:
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            if name in NAMES:
                count += 1
                if count > MAX_FILES:
                    return
                yield Path(dirpath) / name


def _read(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeDecodeError):
        return None


def _first_line(text: str) -> tuple[int, str] | None:
    for number, line in enumerate(text.splitlines(), start=1):
        value = line.strip()
        if value and not value.startswith("#"):
            return number, value
    return None


def _from_file(path: Path, rel: str, text: str) -> Iterator[RuntimeDecl]:
    name = path.name
    if name in {".python-version", "runtime.txt"}:
        first = _first_line(text)
        if first and (m := _PY.match(first[1])):
            source = "python-version" if name == ".python-version" else "runtime.txt"
            cycle = f"{m.group(1)}.{m.group(2)}"
            yield RuntimeDecl("python", cycle, first[1][:64], rel, first[0], source, True)
    elif name == ".nvmrc":
        first = _first_line(text)
        if first and (m := _NODE_EXACT.match(first[1])):
            yield RuntimeDecl("nodejs", m.group(1), first[1][:64], rel, first[0], "nvmrc", True)
    elif name == "package.json":
        try:
            doc = json.loads(text)
        except ValueError:
            return
        engines = doc.get("engines") if isinstance(doc, dict) else None
        node = engines.get("node") if isinstance(engines, dict) else None
        if isinstance(node, str) and node.strip():
            spec = node.strip()[:64]
            if m := _NODE_EXACT.match(spec):
                yield RuntimeDecl("nodejs", m.group(1), spec, rel, None, "engines", True)
            elif m := _RANGE_MAJOR.search(spec):
                yield RuntimeDecl("nodejs", m.group(1), spec, rel, None, "engines", False)
    elif name == "pyproject.toml":
        try:
            doc = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            return
        project = doc.get("project")
        requires = project.get("requires-python") if isinstance(project, dict) else None
        if isinstance(requires, str) and (m := _RANGE_MAJOR.search(requires)) and m.group(2):
            cycle = f"{m.group(1)}.{m.group(2)}"
            yield RuntimeDecl("python", cycle, requires[:64], rel, None, "requires-python", False)
    elif name == "go.mod":
        for number, line in enumerate(text.splitlines(), start=1):
            if m := _GO.match(line.strip()):
                yield RuntimeDecl("go", m.group(1), line.strip()[:64], rel, number, "go.mod", False)
                break


def _from_images(images: Iterable[ImageRef]) -> Iterator[RuntimeDecl]:
    for ref in images:
        if ref.registry != "docker.io" or not ref.tag or ref.repository not in _IMAGES:
            continue
        product, pattern = _IMAGES[ref.repository]
        if m := pattern.match(ref.tag):
            yield RuntimeDecl(product, m.group(1), ref.raw, ref.file, ref.line, "image", True)


def declarations(root: Path, images: Iterable[ImageRef]) -> list[RuntimeDecl]:
    out: list[RuntimeDecl] = []
    if root.is_dir():
        for path in _files(root):
            text = _read(path)
            if text is not None:
                out.extend(_from_file(path, path.relative_to(root).as_posix()[:512], text))
    out.extend(_from_images(images))
    return out
