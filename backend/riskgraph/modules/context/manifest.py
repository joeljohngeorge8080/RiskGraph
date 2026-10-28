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
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Protocol

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from riskgraph.modules.normalization.families import SECRET_FAMILIES

MANIFEST_NAMES = ("riskgraph.yaml", "riskgraph.yml")
MAX_MANIFEST_BYTES = 64 * 1024
MAX_ITEMS = 200
MAX_DEPTH = 8  # the v1 schema needs 4 levels
MAX_WARNINGS = 20
MAX_WARNING_CHARS = 200
_NAME = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"
_GUARD = r"^[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)*$"  # a decorator, dependency or middleware
_ROUTE_SEGMENT = re.compile(r"^(\*|\*\*|[A-Za-z0-9._~:<>{}@!$&'()+,;=-]+)$")
HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})

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


class SecretLink(_Strict):
    """One committed secret that authenticates as the identity (ADR-0020): its file,
    optionally its first line and family. A secret found there is a verified link."""

    file: str = Field(min_length=1, max_length=512)
    line: int | None = Field(default=None, ge=1)
    family: str | None = None

    @field_validator("file")
    @classmethod
    def _repo_file(cls, value: str) -> str:
        cleaned = normalize_service_path(value).rstrip("/")
        if not cleaned or value.strip().endswith(("/", "\\")):
            raise ValueError("file must name a file inside the repository")
        return cleaned

    @field_validator("family")
    @classmethod
    def _known_family(cls, value: str | None) -> str | None:
        if value is not None and value not in SECRET_FAMILIES:
            raise ValueError(f"unknown credential family {value!r}")
        return value

    def matches(self, file: str | None, line: int | None, family: str | None) -> bool:
        return (
            file == self.file
            and (self.line is None or line == self.line)
            and (self.family is None or family == self.family)
        )


class IdentityDecl(_Strict):
    name: str = Field(pattern=_NAME)
    privilege: Privilege | None = None
    can_access: tuple[str, ...] = Field(default=(), max_length=MAX_ITEMS)
    # credential families (aws, github, private_key, ...) that authenticate as this
    # identity: a leaked secret of that family is an attack-graph edge to it (ADR-0013)
    credentials: tuple[str, ...] = Field(default=(), max_length=32)

    @field_validator("credentials")
    @classmethod
    def _known_families(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        unknown = sorted(set(value) - SECRET_FAMILIES)
        if unknown:
            known = ", ".join(sorted(SECRET_FAMILIES))
            raise ValueError(f"unknown credential family {unknown[0]!r} (known: {known})")
        return value

    # exact secrets that authenticate as this identity (ADR-0020); a family listed in
    # ``credentials`` alone stays a hypothesis
    owns: tuple[SecretLink, ...] = Field(default=(), max_length=32)


class DataStoreDecl(_Strict):
    name: str = Field(pattern=_NAME)
    kind: str | None = Field(default=None, max_length=32)
    sensitivity: Sensitivity | None = None


class AuthzRule(_Strict):
    """A route policy (X5, ADR-0023): routes under ``path`` need a guard. ``path`` matches
    a route's full path segment by segment; ``*`` is one segment, ``**`` any number.
    ``require`` is ``authenticated`` (any guard found) or the guard names one of which
    must be found. ``methods`` empty means every method."""

    path: str = Field(min_length=1, max_length=300)
    methods: tuple[str, ...] = Field(default=(), max_length=len(HTTP_METHODS))
    require: Literal["authenticated"] | tuple[str, ...]

    @field_validator("path")
    @classmethod
    def _route_pattern(cls, value: str) -> str:
        if value == "/":
            return value
        parts = value.split("/")
        if parts[0] != "" or not all(_ROUTE_SEGMENT.match(p) for p in parts[1:] if p):
            raise ValueError("path must start with / and use plain segments, * or **")
        return "/" + "/".join(p for p in parts[1:] if p)

    @field_validator("methods")
    @classmethod
    def _known_methods(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        upper = tuple(dict.fromkeys(m.upper() for m in value))
        unknown = sorted(set(upper) - HTTP_METHODS)
        if unknown:
            raise ValueError(f"unknown HTTP method {unknown[0]!r}")
        return upper

    @field_validator("require")
    @classmethod
    def _guard_names(cls, value: object) -> object:
        if isinstance(value, tuple):
            if not value or len(value) > 20:
                raise ValueError("require lists 1 to 20 guard names")
            bad = [v for v in value if not re.match(_GUARD, v) or len(v) > 200]
            if bad:
                raise ValueError(f"require: {bad[0]!r} is not a guard name")
        return value

    def matches(self, full_path: str | None, methods: tuple[str, ...]) -> bool:
        if full_path is None:
            return False
        if self.methods and not set(self.methods) & set(methods):
            return False
        return _segments_match(self.path.strip("/").split("/"), full_path.strip("/").split("/"))


def _segments_match(pattern: list[str], path: list[str]) -> bool:
    """Iterative glob over segments: ``*`` one, ``**`` zero or more."""
    pattern = [p for p in pattern if p]
    path = [p for p in path if p]
    i = j = 0
    star_i, star_j = -1, 0
    while j < len(path):
        if i < len(pattern) and pattern[i] == "**":
            star_i, star_j = i, j
            i += 1
        elif i < len(pattern) and pattern[i] in ("*", path[j]):
            i += 1
            j += 1
        elif star_i >= 0:
            star_j += 1
            i, j = star_i + 1, star_j
        else:
            return False
    return all(p == "**" for p in pattern[i:])


class AuthzDecl(_Strict):
    """Additive and optional (X5, ADR-0023). ``guards`` are this repository's own guard
    names, counted like catalogued ones; ``rules`` are route policies."""

    guards: tuple[str, ...] = Field(default=(), max_length=50)
    rules: tuple[AuthzRule, ...] = Field(default=(), max_length=MAX_ITEMS)

    @field_validator("guards")
    @classmethod
    def _guard_names(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        bad = [v for v in value if not re.match(_GUARD, v) or len(v) > 200]
        if bad:
            raise ValueError(f"guards: {bad[0]!r} is not a guard name")
        return value


class Manifest(_Strict):
    version: Literal[1]
    services: tuple[ServiceDecl, ...] = Field(default=(), max_length=MAX_ITEMS)
    identities: tuple[IdentityDecl, ...] = Field(default=(), max_length=MAX_ITEMS)
    data_stores: tuple[DataStoreDecl, ...] = Field(default=(), max_length=MAX_ITEMS)
    criticality: dict[str, Criticality] = Field(default_factory=dict, max_length=MAX_ITEMS)
    authz: AuthzDecl | None = None

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
