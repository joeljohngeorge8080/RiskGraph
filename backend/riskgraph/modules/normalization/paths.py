"""Normalize file paths reported by scanners into repository-relative display strings.

The result is an opaque label: it is shown, compared and hashed, but never used to
open a file. Anything that tries to climb out of the repository becomes a fixed marker.
"""

from __future__ import annotations

import posixpath

INVALID_PATH = "<invalid-path>"
UNKNOWN_PATH = "<unknown>"


def normalize_path(path: str | None) -> str:
    if not path:
        return UNKNOWN_PATH
    if "\x00" in path:
        return INVALID_PATH
    p = path.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    p = p.lstrip("/")
    if any(part == ".." for part in p.split("/")):
        return INVALID_PATH
    p = posixpath.normpath(p) if p else ""
    return UNKNOWN_PATH if p in ("", ".") else p
