"""Authorization issues from the route inventory (X5 part 2, plan §3.B, ADR-0023).

Pure: routes, the manifest's ``authz.rules`` and the lines of the scan's code findings
in; issues out. Four rules, each with honest assurance:

- ``inconsistent``: a route with no guard whose siblings on the same resource are guarded:
  most of at least two siblings, or a guarded read next to an unguarded write. Inferred.
- ``unguarded-sensitive``: a route with no guard that writes (a mutating method) or whose
  handler contains a code finding of an injection-like category. Login, signup, callback,
  health and webhook routes are public by design and are not called sensitive for that
  alone. Inferred. An inconsistent route is reported as inconsistent only.
- ``policy``: a route a manifest rule covers that lacks the guard the rule requires.
  Inferred: the guards it compares against are themselves inferred.
- ``bola``: the handler passes a path parameter into a call and nothing in it compares
  against an owner or the current user. **Always a hypothesis**, listed as "test this".

"No guard" here is only ever the inventory's ``none_found``: the framework is known and
every place a guard could come from was resolved. ``unresolved`` and
``unknown_framework`` routes never produce an unguarded or inconsistent issue; they go to
the manual list, and so does a policy rule a route could not be checked against.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from riskgraph.modules.authz.guards import Catalogue, load_catalogue
from riskgraph.modules.authz.inventory import Route
from riskgraph.modules.context import AuthzRule
from riskgraph.modules.evidence import Assurance
from riskgraph.shared.vocabulary import Severity

RULES = ("inconsistent", "unguarded-sensitive", "policy", "bola")
MUTATING = frozenset({"POST", "PUT", "PATCH", "DELETE"})
READS = frozenset({"GET", "HEAD"})
GUARDED = frozenset({"guarded", "custom"})
UNDECIDED = frozenset({"unresolved", "unknown_framework"})
_PARAM_SEGMENT = re.compile(r"^(<[^>]+>|\{[^}]+\}|:\w+\??|\*)$")


@dataclass(frozen=True, slots=True)
class AuthzIssue:
    rule: str  # one of RULES
    route: Route
    assurance: Assurance
    severity: Severity
    title: str
    detail: str
    missing: tuple[str, ...] = ()  # what would settle it, for a person to check
    related: tuple[Route, ...] = ()  # inconsistent: the guarded siblings


@dataclass(frozen=True, slots=True)
class AuthzResult:
    issues: list[AuthzIssue]
    # route key -> the manifest rule paths it could not be checked against
    unchecked: dict[tuple[str, int, tuple[str, ...], str], tuple[str, ...]]


def resource(full_path: str | None) -> str | None:
    """The resource a route acts on: its full path without trailing parameters, so
    ``/orders``, ``/orders/<id>`` and ``/orders/:id`` are siblings."""
    if full_path is None:
        return None
    parts = [p for p in full_path.split("/") if p]
    while parts and _PARAM_SEGMENT.match(parts[-1]):
        parts.pop()
    return "/" + "/".join(parts)


def _where(r: Route) -> str:
    return f"{'/'.join(r.methods) or '?'} {r.full_path or r.path or '<dynamic path>'}"


def analyze(
    routes: list[Route],
    rules: Iterable[AuthzRule] = (),
    code_findings: Mapping[str, Iterable[int]] | None = None,
    catalogue: Catalogue | None = None,
) -> AuthzResult:
    """``code_findings``: per file, the first lines of the scan's injection-like code
    findings; a route whose handler span contains one is sensitive."""
    cat = catalogue or load_catalogue()
    lines = {f: sorted(set(ls)) for f, ls in (code_findings or {}).items()}
    issues: list[AuthzIssue] = []
    inconsistent = _inconsistent(routes)
    issues += inconsistent
    flagged = {i.route.key for i in inconsistent}
    for r in routes:
        if r.status == "none_found" and r.key not in flagged:
            issue = _unguarded_sensitive(r, lines, cat)
            if issue is not None:
                issues.append(issue)
        bola = _bola(r)
        if bola is not None:
            issues.append(bola)
    policy, unchecked = _policy(routes, tuple(rules))
    issues += policy
    issues.sort(key=lambda i: (i.route.key, RULES.index(i.rule)))
    return AuthzResult(issues, unchecked)


def _inconsistent(routes: list[Route]) -> list[AuthzIssue]:
    groups: dict[tuple[str | None, str], list[Route]] = defaultdict(list)
    for r in routes:
        res = resource(r.full_path)
        if res is not None and r.status not in UNDECIDED:
            groups[(r.framework, res)].append(r)
    out: list[AuthzIssue] = []
    for (_, res), members in sorted(groups.items(), key=lambda kv: (kv[0][0] or "", kv[0][1])):
        if len(members) < 2:
            continue
        for r in members:
            if r.status != "none_found":
                continue
            others = [o for o in members if o is not r]
            guarded = [o for o in others if o.status in GUARDED]
            majority = len(others) >= 2 and 2 * len(guarded) > len(others)
            reads = [o for o in guarded if set(o.methods) <= READS]
            write_open = bool(set(r.methods) & MUTATING) and bool(reads)
            if not (majority or write_open):
                continue
            why = (
                f"{len(guarded)} of the {len(others)} other routes on {res} have a guard"
                if majority
                else f"the read {_where(reads[0])} has a guard and this write has none"
            )
            out.append(
                AuthzIssue(
                    rule="inconsistent",
                    route=r,
                    assurance=Assurance.INFERRED,
                    severity=Severity.HIGH if set(r.methods) & MUTATING else Severity.MEDIUM,
                    title=f"{_where(r)} has no guard; its siblings on {res} do",
                    detail=(
                        f"{why}. RiskGraph resolved every place a guard could come from "
                        f"for {r.handler} and found none."
                    ),
                    missing=(f"whether {_where(r)} is meant to be public",),
                    related=tuple(guarded[:10]),
                )
            )
    return out


def _unguarded_sensitive(
    r: Route, lines: Mapping[str, list[int]], cat: Catalogue
) -> AuthzIssue | None:
    writes = bool(set(r.methods) & MUTATING)
    in_handler = [
        ln for ln in lines.get(r.file, []) if r.span is not None and r.span[0] <= ln <= r.span[1]
    ]
    if not writes and not in_handler:
        return None
    if cat.public_by_design(r.full_path, r.handler) and not in_handler:
        return None
    reasons = []
    if writes:
        reasons.append(f"it accepts {'/'.join(sorted(set(r.methods) & MUTATING))}")
    if in_handler:
        reasons.append(f"its handler has a code finding at line {in_handler[0]}")
    return AuthzIssue(
        rule="unguarded-sensitive",
        route=r,
        assurance=Assurance.INFERRED,
        severity=Severity.HIGH if in_handler else Severity.MEDIUM,
        title=f"{_where(r)} has no guard and is sensitive",
        detail=(
            f"No guard was found for {r.handler} after resolving every place one could come "
            f"from, and {' and '.join(reasons)}."
        ),
        missing=(f"whether {_where(r)} is meant to be public",),
    )


def _bola(r: Route) -> AuthzIssue | None:
    if r.ownership is not False:
        return None  # an ownership check was seen, or the handler's code was not
    loaded = [p for p in r.params if p in r.loads]
    if not loaded:
        return None
    ids = ", ".join(loaded)
    return AuthzIssue(
        rule="bola",
        route=r,
        assurance=Assurance.HYPOTHESIS,
        severity=Severity.LOW,
        title=f"{_where(r)} may return another user's object (test this)",
        detail=(
            f"{r.handler} looks up {ids} from the path and nothing in it compares against an "
            "owner or the current user. The check may live elsewhere; only a test with two "
            "users can tell."
        ),
        missing=(
            f"an ownership check on {ids} in {r.handler} or in what it calls",
            "a two-user test: user B requests user A's id",
        ),
    )


def _satisfies(r: Route, rule: AuthzRule) -> bool | None:
    """True or False when the route's guards decide the rule; None when they cannot (an
    unresolved route could still get the guard from a mount RiskGraph did not see)."""
    if rule.require == "authenticated":
        if r.status in GUARDED:
            return True
    elif any(g.name in rule.require or g.name.rsplit(".", 1)[-1] in rule.require for g in r.guards):
        return True
    return None if r.status in UNDECIDED else False


def _names(r: Route) -> str:
    return ", ".join(sorted({g.name for g in r.guards}))


def _policy(
    routes: list[Route], rules: tuple[AuthzRule, ...]
) -> tuple[list[AuthzIssue], dict[tuple[str, int, tuple[str, ...], str], tuple[str, ...]]]:
    out: list[AuthzIssue] = []
    unchecked: dict[tuple[str, int, tuple[str, ...], str], list[str]] = defaultdict(list)
    for r in routes:
        for rule in rules:
            if not rule.matches(r.full_path, r.methods):
                continue
            ok = _satisfies(r, rule)
            if ok is None:
                unchecked[r.key].append(rule.path)
                continue
            if ok:
                continue
            need = (
                "a guard"
                if rule.require == "authenticated"
                else "one of " + ", ".join(rule.require)
            )
            out.append(
                AuthzIssue(
                    rule="policy",
                    route=r,
                    assurance=Assurance.INFERRED,
                    severity=Severity.HIGH,
                    title=f"{_where(r)} breaks the manifest rule for {rule.path}",
                    detail=(
                        f"riskgraph.yaml requires {need} on {rule.path}; "
                        + (
                            f"{r.handler} has {_names(r)}."
                            if r.guards
                            else f"no guard was found for {r.handler}."
                        )
                    ),
                    missing=(f"{need} on {_where(r)}, or a narrower rule",),
                )
            )
            break  # one policy issue per route: the first rule it breaks
    return out, {k: tuple(dict.fromkeys(v)) for k, v in unchecked.items()}
