"""Repository manifest ``riskgraph.yaml`` v1 (blueprint §11.1).

The manifest declares deployment context the scanners cannot see: which services exist,
how exposed they are, which identity they run as and which data stores they reach.
Validation is strict (unknown keys rejected, names must resolve). A missing or broken
manifest never fails a scan: the loader returns a status and warnings, and scoring falls
back to the "unknown" defaults.

The file is read only from fixed names at the repository root, through
``ScanWorkspace.safe_resolve`` (inside the checkout, regular file), with a size cap.
YAML aliases are refused before parsing so a hostile document cannot expand into a huge
object graph (billion laughs).
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Protocol

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

MANIFEST_NAMES = ("riskgraph.yaml", "riskgraph.yml")
MAX_MANIFEST_BYTES = 64 * 1024
MAX_ITEMS = 200
MAX_DEPTH = 8  # the v1 schema needs 4 levels
MAX_WARNINGS = 20
MAX_WARNING_CHARS = 200
_NAME = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"

Exposure = Literal["internet", "internal", "isolated"]
Auth = Literal["none", "required"]
Privilege = Literal["read_only", "limited", "elevated", "admin"]
Sensitivity = Literal["public", "internal", "confidential", "pii", "financial", "credentials"]
Criticality = Literal["low", "medium", "high"]
ManifestStatus = Literal["absent", "valid", "invalid", "unavailable"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class ServiceDecl(_Strict):
    name: str = Field(pattern=_NAME)
    path: str = ""
    language: str | None = Field(default=None, max_length=32)
    entrypoints: tuple[str, ...] = Field(default=(), max_length=MAX_ITEMS)
    exposure: Exposure | None = None
    auth: Auth | None = None
    runs_as: str | None = Field(default=None, pattern=_NAME)
    connects_to: tuple[str, ...] = Field(default=(), max_length=MAX_ITEMS)

    @field_validator("path")
    @classmethod
    def _repo_relative(cls, value: str) -> str:
        return normalize_service_path(value)


class IdentityDecl(_Strict):
    name: str = Field(pattern=_NAME)
    privilege: Privilege | None = None
    can_access: tuple[str, ...] = Field(default=(), max_length=MAX_ITEMS)


class DataStoreDecl(_Strict):
    name: str = Field(pattern=_NAME)
    kind: str | None = Field(default=None, max_length=32)
    sensitivity: Sensitivity | None = None


class Manifest(_Strict):
    version: Literal[1]
    services: tuple[ServiceDecl, ...] = Field(default=(), max_length=MAX_ITEMS)
    identities: tuple[IdentityDecl, ...] = Field(default=(), max_length=MAX_ITEMS)
    data_stores: tuple[DataStoreDecl, ...] = Field(default=(), max_length=MAX_ITEMS)
    criticality: dict[str, Criticality] = Field(default_factory=dict, max_length=MAX_ITEMS)

    @model_validator(mode="after")
    def _names_resolve(self) -> Manifest:
        services = [s.name for s in self.services]
        identities = [i.name for i in self.identities]
        stores = [d.name for d in self.data_stores]
        everything = services + identities + stores
        dupes = sorted({n for n in everything if everything.count(n) > 1})
        if dupes:
            raise ValueError(f"names must be unique across sections: {', '.join(dupes)}")
        targets = set(services) | set(stores)
        problems: list[str] = []
        for s in self.services:
            if s.runs_as is not None and s.runs_as not in identities:
                problems.append(f"service {s.name}: runs_as {s.runs_as!r} is not an identity")
            problems += [
                f"service {s.name}: connects_to {t!r} is not a service or data store"
                for t in s.connects_to
                if t not in targets
            ]
        for i in self.identities:
            problems += [
                f"identity {i.name}: can_access {t!r} is not a service or data store"
                for t in i.can_access
                if t not in targets
            ]
        problems += [
            f"criticality: {name!r} is not a service"
            for name in self.criticality
            if name not in services
        ]
        if problems:
            raise ValueError("; ".join(problems))
        return self


def normalize_service_path(value: str) -> str:
    """Repository-relative directory prefix: '' (whole repo) or 'a/b/' (always trailing /)."""
    raw = value.strip().replace("\\", "/")
    if raw.startswith("/") or "\x00" in raw:
        raise ValueError("path must be relative to the repository root")
    cleaned = posixpath.normpath(raw) if raw else "."
    if cleaned == ".." or cleaned.startswith("../"):
        raise ValueError("path must stay inside the repository")
    return "" if cleaned == "." else cleaned.rstrip("/") + "/"


class _Resolver(Protocol):
    def safe_resolve(self, relative: str) -> Path | None: ...


@dataclass(frozen=True, slots=True)
class ManifestResult:
    status: ManifestStatus
    manifest: Manifest | None = None
    file: str | None = None
    warnings: tuple[str, ...] = field(default=())


def _structure_problem(text: str) -> str | None:
    """Refuse aliases and deep nesting from the event stream, before anything recursive runs."""
    depth = 0
    for ev in yaml.parse(text, Loader=yaml.SafeLoader):
        if isinstance(ev, yaml.AliasEvent):
            return "YAML aliases are not allowed"
        if isinstance(ev, yaml.CollectionStartEvent):
            depth += 1
            if depth > MAX_DEPTH:
                return f"nested deeper than {MAX_DEPTH} levels"
        elif isinstance(ev, yaml.CollectionEndEvent):
            depth -= 1
    return None


def _short(text: str) -> str:
    return text if len(text) <= MAX_WARNING_CHARS else text[: MAX_WARNING_CHARS - 1] + "…"


def parse_manifest(text: str, file: str = MANIFEST_NAMES[0]) -> ManifestResult:
    """Parse and validate manifest text; never raises."""
    try:
        problem = _structure_problem(text)
        if problem:
            return ManifestResult("invalid", file=file, warnings=(problem,))
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" at line {mark.line + 1}" if mark is not None else ""
        return ManifestResult("invalid", file=file, warnings=(f"not valid YAML{where}",))
    if not isinstance(doc, dict):
        return ManifestResult("invalid", file=file, warnings=("top level must be a mapping",))
    try:
        manifest = Manifest.model_validate(doc)
    except ValidationError as exc:
        warnings = tuple(
            _short(f"{'.'.join(str(p) for p in err['loc']) or 'manifest'}: {err['msg']}")
            for err in exc.errors(include_url=False, include_input=False)[:MAX_WARNINGS]
        )
        return ManifestResult("invalid", file=file, warnings=warnings)
    return ManifestResult("valid", manifest=manifest, file=file)


def load_manifest(workspace: _Resolver) -> ManifestResult:
    """Find and parse the manifest at the root of a scan checkout."""
    for name in MANIFEST_NAMES:
        resolved = workspace.safe_resolve(name)
        if resolved is None:
            continue
        try:
            if resolved.stat().st_size > MAX_MANIFEST_BYTES:
                return ManifestResult(
                    "invalid", file=name, warnings=(f"larger than {MAX_MANIFEST_BYTES} bytes",)
                )
            text = resolved.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return ManifestResult("invalid", file=name, warnings=("unreadable (not UTF-8 text)",))
        return parse_manifest(text, name)
    return ManifestResult("absent")
