"""Tier-1 taint rules: RiskGraph's catalogue → Semgrep taint-mode rules (plan §3.A, ADR-0021).

``taint_catalogue.yaml`` lists sources, sinks and sanitizers per language and weakness
class; this module checks it strictly and renders one Semgrep rule per (language, class)
into ``taint_rules.yaml``, which is committed and kept in step by a test. Semgrep CE runs
the rules inside one function only, so a hit is an intraprocedural flow and never more
than ``inferred`` (a rule applied to parsed code).

Regenerate: ``uv run python -m riskgraph.modules.scanners.semgrep.taint``.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from riskgraph.modules.normalization.families import TAINT_RULE_PREFIX

CATALOGUE_FILE = Path(__file__).with_name("taint_catalogue.yaml")
RULES_FILE = Path(__file__).with_name("taint_rules.yaml")
LANGUAGES: dict[str, tuple[str, ...]] = {
    "python": ("python",),
    "javascript": ("javascript", "typescript"),
}
_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_CWE = re.compile(r"^CWE-\d{1,5}: .{1,80}$")
_CONFIDENCE = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW"}
_HEADER = """\
# GENERATED from taint_catalogue.yaml by
#   uv run python -m riskgraph.modules.scanners.semgrep.taint
# Do not edit by hand. RiskGraph-authored rules, Apache-2.0 (ADR-0021).
"""


class CatalogueError(ValueError):
    """The catalogue breaks its schema: a bug in the repository, caught by the tests."""


@dataclass(frozen=True, slots=True)
class Source:
    id: str
    patterns: tuple[str, ...] = ()
    decorator: str | None = None  # handler_parameter: the route decorator
    verbs: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class LanguageRules:
    confidence: str
    sinks: tuple[str, ...]
    sanitizers: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class TaintClass:
    id: str
    cwe: str
    title: str
    languages: dict[str, LanguageRules]


@dataclass(frozen=True, slots=True)
class Catalogue:
    sources: dict[str, tuple[Source, ...]]
    classes: tuple[TaintClass, ...]


def _keys(where: str, value: Any, allowed: set[str], required: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CatalogueError(f"{where}: expected a mapping")
    unknown = sorted(set(value) - allowed)
    missing = sorted(required - set(value))
    if unknown or missing:
        raise CatalogueError(f"{where}: unknown keys {unknown}, missing keys {missing}")
    return value


def _strings(where: str, value: Any, *, allow_empty: bool = True) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
        raise CatalogueError(f"{where}: expected a list of non-empty strings")
    if not value and not allow_empty:
        raise CatalogueError(f"{where}: must not be empty")
    return tuple(v.strip() for v in value)


def _ident(where: str, value: Any) -> str:
    if not isinstance(value, str) or not _ID.match(value):
        raise CatalogueError(f"{where}: bad id {value!r}")
    return value


def _source(where: str, raw: Any) -> Source:
    doc = _keys(where, raw, {"id", "patterns", "handler_parameter"}, {"id"})
    sid = _ident(where, doc["id"])
    if ("patterns" in doc) == ("handler_parameter" in doc):
        raise CatalogueError(f"{where}: give exactly one of patterns, handler_parameter")
    if "patterns" in doc:
        return Source(
            sid, patterns=_strings(f"{where}.patterns", doc["patterns"], allow_empty=False)
        )
    hp = _keys(
        f"{where}.handler_parameter",
        doc["handler_parameter"],
        {"decorator", "verbs"},
        {"decorator", "verbs"},
    )
    verbs = _strings(f"{where}.verbs", hp["verbs"], allow_empty=False)
    if not all(v.isidentifier() for v in verbs) or not isinstance(hp["decorator"], str):
        raise CatalogueError(f"{where}: verbs must be identifiers and decorator a string")
    return Source(sid, decorator=hp["decorator"], verbs=verbs)


def load_catalogue(path: Path = CATALOGUE_FILE) -> Catalogue:
    doc = _keys(
        "catalogue",
        yaml.safe_load(path.read_text(encoding="utf-8")),
        {"version", "sources", "classes"},
        {"version", "sources", "classes"},
    )
    if doc["version"] != 1:
        raise CatalogueError("catalogue: unsupported version")
    raw_sources = _keys("sources", doc["sources"], set(LANGUAGES), set(LANGUAGES))
    sources = {
        lang: tuple(_source(f"sources.{lang}[{i}]", s) for i, s in enumerate(items or []))
        for lang, items in raw_sources.items()
    }
    for lang, found in sources.items():
        if not found:
            raise CatalogueError(f"sources.{lang}: no source")
    classes: list[TaintClass] = []
    if not isinstance(doc["classes"], list):
        raise CatalogueError("classes: expected a list")
    for i, raw in enumerate(doc["classes"]):
        where = f"classes[{i}]"
        c = _keys(
            where, raw, {"id", "cwe", "title", *LANGUAGES}, {"id", "cwe", "title", *LANGUAGES}
        )
        if not isinstance(c["cwe"], str) or not _CWE.match(c["cwe"]):
            raise CatalogueError(f"{where}: cwe must look like 'CWE-89: name'")
        if not isinstance(c["title"], str) or not 0 < len(c["title"]) <= 120:
            raise CatalogueError(f"{where}: title must be 1-120 characters")
        langs: dict[str, LanguageRules] = {}
        for lang in LANGUAGES:
            lr = _keys(
                f"{where}.{lang}",
                c[lang],
                {"confidence", "sinks", "sanitizers"},
                {"confidence", "sinks", "sanitizers"},
            )
            if lr["confidence"] not in _CONFIDENCE:
                raise CatalogueError(f"{where}.{lang}: confidence must be high, medium or low")
            langs[lang] = LanguageRules(
                lr["confidence"],
                _strings(f"{where}.{lang}.sinks", lr["sinks"], allow_empty=False),
                _strings(f"{where}.{lang}.sanitizers", lr["sanitizers"]),
            )
        classes.append(TaintClass(_ident(where, c["id"]), c["cwe"], c["title"], langs))
    ids = [c.id for c in classes]
    if len(set(ids)) != len(ids):
        raise CatalogueError("classes: ids must be unique")
    return Catalogue(sources, tuple(classes))


def rule_id(language: str, class_id: str) -> str:
    return f"{TAINT_RULE_PREFIX}{language}.{class_id}"


def _source_pattern(s: Source) -> list[dict[str, Any]]:
    if s.decorator is None:
        return [{"pattern": p} for p in s.patterns]
    return [
        {
            "patterns": [
                {"pattern": f"{s.decorator}\ndef $HANDLER(..., $PARAM, ...):\n  ...\n"},
                {"focus-metavariable": "$PARAM"},
                {
                    "metavariable-regex": {
                        "metavariable": "$VERB",
                        "regex": f"^({'|'.join(s.verbs)})$",
                    }
                },
            ]
        }
    ]


def _sink_pattern(pattern: str) -> dict[str, Any]:
    if "$SINK" not in pattern:
        return {"pattern": pattern}
    return {"patterns": [{"pattern": pattern}, {"focus-metavariable": "$SINK"}]}


def build_rules(catalogue: Catalogue) -> list[dict[str, Any]]:
    """One taint-mode rule per (language, class), in catalogue order."""
    rules: list[dict[str, Any]] = []
    for lang, semgrep_languages in LANGUAGES.items():
        sources = [p for s in catalogue.sources[lang] for p in _source_pattern(s)]
        for c in catalogue.classes:
            lr = c.languages[lang]
            rule: dict[str, Any] = {
                "id": rule_id(lang, c.id),
                "mode": "taint",
                "languages": list(semgrep_languages),
                "severity": "ERROR",
                "message": f"{c.title}: data from an HTTP request reaches this call",
                "metadata": {
                    "cwe": [c.cwe],
                    "category": "security",
                    "confidence": _CONFIDENCE[lr.confidence],
                    "likelihood": "MEDIUM",
                    "impact": "HIGH",
                    "source": "riskgraph",
                    "license": "Apache-2.0",
                    "analysis": "intraprocedural",
                    "riskgraph_class": c.id,
                },
                "pattern-sources": sources,
                "pattern-sinks": [_sink_pattern(p) for p in lr.sinks],
            }
            if lr.sanitizers:
                rule["pattern-sanitizers"] = [{"pattern": p} for p in lr.sanitizers]
            rules.append(rule)
    return rules


class _NoAliases(yaml.SafeDumper):  # type: ignore[misc]
    """Every rule shares the language's source list; write it out each time, no anchors."""

    def ignore_aliases(self, data: Any) -> bool:
        return True


def render(rules: list[dict[str, Any]]) -> str:
    body = str(
        yaml.dump(
            {"rules": rules}, Dumper=_NoAliases, sort_keys=False, allow_unicode=False, width=100
        )
    )
    return _HEADER + body


def main(argv: list[str]) -> int:
    out = Path(argv[0]) if argv else RULES_FILE
    out.write_text(render(build_rules(load_catalogue())), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
