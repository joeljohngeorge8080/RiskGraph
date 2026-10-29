"""The guard catalogue (``guards.yaml``): strict loader and name matching (ADR-0022)."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

CATALOGUE_FILE = Path(__file__).with_name("guards.yaml")
FRAMEWORKS = ("flask", "fastapi", "express")
_NAME = re.compile(r"^[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)*$")
_MODULE = re.compile(r"^[@a-z0-9][\w./@-]{0,99}$")
_HINT = re.compile(r"^[a-z]{2,20}( [a-z]{2,20})?$")
_PUBLIC = re.compile(r"^[a-z]{2,20}$")
_WORDS = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")


class CatalogueError(ValueError):
    """The catalogue breaks its schema: a bug in the repository, caught by the tests."""


@dataclass(frozen=True, slots=True)
class Framework:
    name: str
    language: str  # python | js
    app: tuple[str, ...]
    router: tuple[str, ...]
    imports: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GuardEntry:
    name: str
    module: str | None = None

    def matches(self, name: str, bindings: dict[str, Any] | None = None) -> bool:
        last = name.rsplit(".", 1)[-1]
        hit = name == self.name if "." in self.name else last == self.name
        if not hit or self.module is None:
            return hit
        return (bindings or {}).get(name.split(".", 1)[0]) == self.module


@dataclass(frozen=True, slots=True)
class Catalogue:
    frameworks: dict[str, Framework]
    guards: dict[str, tuple[GuardEntry, ...]]
    fastapi_schemes: frozenset[str]
    custom_hints: tuple[tuple[str, ...], ...]
    public_hints: tuple[str, ...] = ()

    def is_guard(self, framework: str, name: str, bindings: dict[str, Any] | None = None) -> bool:
        return any(g.matches(name, bindings) for g in self.guards.get(framework, ()))

    def with_guards(self, names: tuple[str, ...]) -> Catalogue:
        """The catalogue plus a repository's own guard names (manifest ``authz.guards``),
        for every framework."""
        if not names:
            return self
        extra = tuple(GuardEntry(n) for n in names)
        return replace(self, guards={fw: (*g, *extra) for fw, g in self.guards.items()})

    def public_by_design(self, *texts: str | None) -> bool:
        """A login, signup, OAuth callback, health probe or webhook route."""
        words = {w.lower() for t in texts if t for w in _WORDS.findall(t)}
        return any(w.startswith(h) for w in words for h in self.public_hints)

    def looks_like_auth(self, name: str) -> bool:
        words = [w.lower() for w in _WORDS.findall(name)]
        for hint in self.custom_hints:
            for i in range(len(words) - len(hint) + 1):
                if all(words[i + k].startswith(h) for k, h in enumerate(hint)):
                    return True
        return False

    def kind_of(self, callee: str | None) -> tuple[str, str] | None:
        """(framework, "app" | "router") for the callee that created a receiver."""
        if not callee:
            return None
        last = callee.rsplit(".", 1)[-1]
        for fw in self.frameworks.values():
            for role, names in (("app", fw.app), ("router", fw.router)):
                # `flask.Flask` is Flask; a dotted entry (`express.Router`) matches exactly
                if any(callee == n or ("." not in n and last == n) for n in names):
                    return fw.name, role
        return None


def _strs(value: Any, where: str, pattern: re.Pattern[str]) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(
        isinstance(v, str) and pattern.match(v) for v in value
    ):
        raise CatalogueError(f"{where} must be a list of names")
    return tuple(value)


def parse(doc: Any) -> Catalogue:
    if not isinstance(doc, dict) or doc.get("version") != 1:
        raise CatalogueError("guard catalogue must be a mapping with version: 1")
    known = {"version", "frameworks", "guards", "fastapi_schemes", "custom_hints", "public_hints"}
    unknown = set(doc) - known
    if unknown:
        raise CatalogueError(f"unknown catalogue keys {sorted(unknown)}")
    raw_fw = doc.get("frameworks")
    if not isinstance(raw_fw, dict) or set(raw_fw) != set(FRAMEWORKS):
        raise CatalogueError(f"frameworks must be exactly {list(FRAMEWORKS)}")
    frameworks: dict[str, Framework] = {}
    for name, body in raw_fw.items():
        if not isinstance(body, dict) or set(body) != {"language", "app", "router", "imports"}:
            raise CatalogueError(f"framework {name} needs language, app, router, imports")
        if body["language"] not in ("python", "js"):
            raise CatalogueError(f"framework {name}: language must be python or js")
        frameworks[name] = Framework(
            name,
            body["language"],
            _strs(body["app"], f"{name}.app", _NAME),
            _strs(body["router"], f"{name}.router", _NAME),
            _strs(body["imports"], f"{name}.imports", _MODULE),
        )
    raw_guards = doc.get("guards")
    if not isinstance(raw_guards, dict) or set(raw_guards) != set(FRAMEWORKS):
        raise CatalogueError(f"guards must have exactly {list(FRAMEWORKS)}")
    guards: dict[str, tuple[GuardEntry, ...]] = {}
    for fw, entries in raw_guards.items():
        if not isinstance(entries, list):
            raise CatalogueError(f"guards.{fw} must be a list")
        out: list[GuardEntry] = []
        for entry in entries:
            if not isinstance(entry, dict) or not set(entry) <= {"name", "module"}:
                raise CatalogueError(f"guards.{fw}: an entry is {{name, module?}}")
            name, module = entry.get("name"), entry.get("module")
            if not isinstance(name, str) or not _NAME.match(name):
                raise CatalogueError(f"guards.{fw}: bad name {name!r}")
            if module is not None and (not isinstance(module, str) or not _MODULE.match(module)):
                raise CatalogueError(f"guards.{fw}: bad module {module!r}")
            out.append(GuardEntry(name, module))
        guards[fw] = tuple(out)
    hints = _strs(doc.get("custom_hints"), "custom_hints", _HINT)
    return Catalogue(
        frameworks=frameworks,
        guards=guards,
        fastapi_schemes=frozenset(_strs(doc.get("fastapi_schemes"), "fastapi_schemes", _NAME)),
        custom_hints=tuple(tuple(h.split()) for h in hints),
        public_hints=_strs(doc.get("public_hints"), "public_hints", _PUBLIC),
    )


@lru_cache(maxsize=1)
def load_catalogue(path: Path = CATALOGUE_FILE) -> Catalogue:
    return parse(yaml.safe_load(path.read_text(encoding="utf-8")))
