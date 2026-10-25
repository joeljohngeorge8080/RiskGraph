"""Syft CycloneDX document → package components (the SBOM rows).

Pure and defensive: the document is untrusted scanner output. Anything malformed is
skipped, never raised, and every string is length-capped before it is stored.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

MAX_TEXT = 512
MAX_COMPONENTS = 100_000


@dataclass(frozen=True, slots=True)
class Component:
    purl: str
    name: str
    version: str
    ecosystem: str  # the purl type: pypi, npm, golang, deb, apk, ...
    location: str | None  # first file the package was found in, relative to the repo


def _text(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip()[:MAX_TEXT]


def _ecosystem(purl: str) -> str:
    if not purl.startswith("pkg:"):
        return ""
    return purl[4:].split("/", 1)[0].split("@", 1)[0][:32]


def _location(entry: dict[str, Any]) -> str | None:
    for prop in entry.get("properties") or []:
        if isinstance(prop, dict) and prop.get("name") == "syft:location:0:path":
            return _text(prop.get("value"))
    return None


def components(doc: Any) -> list[Component]:
    if not isinstance(doc, dict) or not isinstance(doc.get("components"), list):
        return []
    out: list[Component] = []
    seen: set[str] = set()
    for entry in doc["components"][:MAX_COMPONENTS]:
        if not isinstance(entry, dict):
            continue
        purl = _text(entry.get("purl"))
        name = _text(entry.get("name"))
        if purl is None or name is None or purl in seen:
            continue
        seen.add(purl)
        out.append(
            Component(
                purl=purl,
                name=name,
                version=_text(entry.get("version")) or "",
                ecosystem=_ecosystem(purl),
                location=_location(entry),
            )
        )
    return out


def count(doc: Any) -> int:
    return len(components(doc))
