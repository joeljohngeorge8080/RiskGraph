"""Authorization issues (X5 part 2, ADR-0023): each rule, the empty cases, and the guarantee
that an undecided route never becomes an "unguarded" issue."""

from __future__ import annotations

from dataclasses import replace

import pytest
from hypothesis import given
from hypothesis import strategies as st
from riskgraph.modules.authz import STATUSES, Guard, Route, analyze, resource
from riskgraph.modules.context import AuthzRule
from riskgraph.modules.evidence import Assurance
from riskgraph.shared.vocabulary import Severity


def _route(
    full_path: str,
    method: str = "GET",
    status: str = "none_found",
    *,
    line: int = 1,
    guards: tuple[str, ...] = (),
    params: tuple[str, ...] = (),
    loads: tuple[str, ...] = (),
    ownership: bool | None = None,
    span: tuple[int, int] | None = None,
    file: str = "app.py",
    handler: str = "h",
) -> Route:
    return Route(
        file=file,
        line=line,
        framework="flask",
        basis="constructor",
        methods=(method,),
        path=full_path,
        full_path=full_path,
        handler=handler,
        params=params,
        guards=tuple(Guard(g, "decorator", status == "guarded", file, line) for g in guards),
        status=status,
        mounted=True,
        span=span,
        loads=loads,
        ownership=ownership,
    )


def _rules(issues: list, rule: str) -> list[str]:  # type: ignore[type-arg]
    return [f"{i.route.methods[0]} {i.route.full_path}" for i in issues if i.rule == rule]


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/orders", "/orders"),
        ("/orders/<int:order_id>", "/orders"),
        ("/v1/projects/{project_id}", "/v1/projects"),
        ("/notes/:noteId", "/notes"),
        ("/notes/:noteId?", "/notes"),
        ("/users/:id/posts/:postId", "/users/:id/posts"),
        ("/", "/"),
        ("/<id>", "/"),
        (None, None),
    ],
)
def test_the_resource_is_the_path_without_trailing_parameters(
    path: str | None, expected: str | None
) -> None:
    assert resource(path) == expected


def test_an_unguarded_write_among_guarded_siblings_is_inconsistent() -> None:
    routes = [
        _route("/orders", "GET", "guarded", line=1, guards=("login_required",)),
        _route("/orders/<id>", "GET", "guarded", line=2, guards=("login_required",)),
        _route("/orders", "POST", "custom", line=3, guards=("require_member",)),
        _route("/orders/<id>", "DELETE", "none_found", line=4),
    ]
    [issue] = analyze(routes).issues
    assert issue.rule == "inconsistent" and issue.assurance is Assurance.INFERRED
    assert issue.severity is Severity.HIGH and len(issue.related) == 3
    assert "3 of the 3 other routes" in issue.detail


def test_a_guarded_read_and_an_unguarded_write_is_inconsistent_even_as_a_pair() -> None:
    routes = [
        _route("/doc/<id>", "GET", "guarded", line=1, guards=("login_required",)),
        _route("/doc/<id>", "DELETE", "none_found", line=2),
    ]
    assert _rules(analyze(routes).issues, "inconsistent") == ["DELETE /doc/<id>"]


def test_a_public_read_next_to_a_guarded_write_is_not_inconsistent() -> None:
    # a login form: GET is public, POST runs the authentication
    routes = [
        _route("/login", "GET", "none_found", line=1),
        _route("/login", "POST", "guarded", line=2, guards=("passport.authenticate",)),
    ]
    assert analyze(routes).issues == []


def test_a_public_list_next_to_guarded_writes_is_not_inconsistent() -> None:
    routes = [
        _route("/posts", "GET", "none_found", line=1),
        _route("/posts", "POST", "guarded", line=2, guards=("login_required",)),
        _route("/posts/<id>", "PUT", "guarded", line=3, guards=("login_required",)),
        _route("/posts/<id>", "DELETE", "guarded", line=4, guards=("login_required",)),
    ]
    assert analyze(routes).issues == []


def test_a_public_list_next_to_a_guarded_detail_read_is_inconsistent() -> None:
    routes = [
        _route("/teams", "GET", "none_found", line=1),
        _route("/teams/<id>", "GET", "guarded", line=2, guards=("login_required",)),
        _route("/teams", "POST", "guarded", line=3, guards=("login_required",)),
    ]
    [issue] = analyze(routes).issues
    assert issue.route.full_path == "/teams" and issue.severity is Severity.MEDIUM
    assert "1 of the 1 other read routes" in issue.detail


def test_a_minority_of_guarded_siblings_is_not_inconsistent() -> None:
    routes = [
        _route("/posts", "GET", "none_found", line=1),
        _route("/posts/<id>", "GET", "none_found", line=2),
        _route("/posts/<id>/raw", "GET", "guarded", line=3, guards=("login_required",)),
    ]
    assert _rules(analyze(routes).issues, "inconsistent") == []


def test_unguarded_writes_and_handlers_with_code_findings_are_sensitive() -> None:
    routes = [
        _route("/items", "POST", line=1),
        _route("/search", "GET", line=10, span=(11, 15)),
        _route("/about", "GET", line=20, span=(21, 22)),
        _route("/signup", "POST", line=30),  # public by design
        _route("/oauth/callback", "GET", line=40, span=(41, 45)),  # ... unless a finding
    ]
    result = analyze(routes, code_findings={"app.py": [13, 43, 99]})
    assert _rules(result.issues, "unguarded-sensitive") == [
        "POST /items",
        "GET /search",
        "GET /oauth/callback",
    ]
    by_path = {i.route.full_path: i for i in result.issues}
    assert by_path["/items"].severity is Severity.MEDIUM
    assert by_path["/search"].severity is Severity.HIGH and "line 13" in by_path["/search"].detail


def test_an_inconsistent_route_is_not_also_reported_as_sensitive() -> None:
    routes = [
        _route("/doc/<id>", "GET", "guarded", line=1, guards=("login_required",)),
        _route("/doc/<id>", "DELETE", "none_found", line=2),
    ]
    assert [i.rule for i in analyze(routes).issues] == ["inconsistent"]


@pytest.mark.parametrize("status", ["unresolved", "unknown_framework"])
def test_an_undecided_route_is_never_unguarded_or_inconsistent(status: str) -> None:
    routes = [
        _route("/doc/<id>", "GET", "guarded", line=1, guards=("login_required",)),
        _route("/doc", "GET", "guarded", line=2, guards=("login_required",)),
        _route("/doc/<id>", "DELETE", status, line=3, span=(4, 9)),
    ]
    rules = [AuthzRule(path="/doc/**", require="authenticated")]
    result = analyze(routes, rules, code_findings={"app.py": [5]})
    assert result.issues == []
    assert result.unchecked == {routes[2].key: ("/doc/**",)}


def test_bola_is_a_low_hypothesis_and_needs_a_lookup_without_an_ownership_check() -> None:
    routes = [
        _route("/inv/<id>", line=1, params=("id",), loads=("id",), ownership=False),
        _route("/doc/<id>", line=2, params=("id",), loads=("id",), ownership=True),
        _route("/echo/<id>", line=3, params=("id",), loads=(), ownership=False),
        _route("/far/<id>", line=4, params=("id",), loads=("id",), ownership=None),
        _route("/user/<uid>", line=5, params=("uid",), loads=("db",), ownership=False),
    ]
    issues = analyze(routes).issues
    assert _rules(issues, "bola") == ["GET /inv/<id>"]
    [bola] = issues
    assert bola.assurance is Assurance.HYPOTHESIS and bola.severity is Severity.LOW
    assert any("two-user test" in m for m in bola.missing)


def test_policy_rules_compare_required_guards_with_found_ones() -> None:
    routes = [
        _route("/admin/users", "GET", "guarded", line=1, guards=("login_required",)),
        _route("/admin/stats", "GET", "custom", line=2, guards=("require_admin",)),
        _route("/admin/x", "GET", "custom", line=3, guards=("auth.require_admin",)),
        _route("/admin/open", "GET", "none_found", line=4),
        _route("/api/v1/orders", "POST", "custom", line=5, guards=("team_only",)),
        _route("/api/v1/orders", "GET", "none_found", line=6),
        _route("/public", "POST", "none_found", line=7),
    ]
    rules = [
        AuthzRule(path="/admin/**", require=("require_admin",)),
        AuthzRule(path="/api/**", methods=("POST",), require="authenticated"),
    ]
    issues = [i for i in analyze(routes, rules).issues if i.rule == "policy"]
    assert [i.route.full_path for i in issues] == ["/admin/users", "/admin/open"]
    assert issues[0].detail.endswith("login_required.") and issues[0].severity is Severity.HIGH
    assert "no guard was found" in issues[1].detail


def test_nothing_in_nothing_out() -> None:
    assert analyze([]).issues == [] and analyze([]).unchecked == {}
    public = [_route("/", line=1), _route("/about", line=2), _route("/faq", line=3)]
    assert analyze(public).issues == []


_PATHS = st.sampled_from(["/a", "/a/<id>", "/b", "/b/<id>", "/admin/x", None])
_METHODS = st.sampled_from(["GET", "POST", "DELETE"])


@given(
    st.lists(
        st.tuples(_PATHS, _METHODS, st.sampled_from(STATUSES), st.booleans(), st.booleans()),
        max_size=12,
    )
)
def test_properties_over_random_inventories(
    rows: list[tuple[str | None, str, str, bool, bool]],
) -> None:
    routes = [
        replace(
            _route(p or "/x", m, s, line=i, params=("id",), loads=("id",) if load else ()),
            full_path=p,
            ownership=owned,
        )
        for i, (p, m, s, load, owned) in enumerate(rows)
    ]
    rules = [AuthzRule(path="/admin/**", require="authenticated")]
    result = analyze(routes, rules, code_findings={"app.py": list(range(50))})
    for issue in result.issues:
        # only a fully resolved "no guard" is ever called unguarded or inconsistent
        if issue.rule in ("inconsistent", "unguarded-sensitive"):
            assert issue.route.status == "none_found"
        # BOLA is never more than a hypothesis, and nothing else is ever verified
        if issue.rule == "bola":
            assert issue.assurance is Assurance.HYPOTHESIS and issue.severity is Severity.LOW
        assert issue.assurance is not Assurance.VERIFIED
    # at most one inconsistent-or-sensitive issue per route
    keys = [i.route.key for i in result.issues if i.rule != "bola" and i.rule != "policy"]
    assert len(keys) == len(set(keys))


def test_issues_become_authz_findings_anchored_on_the_route_not_the_line() -> None:
    from riskgraph.modules.authz import issue_findings
    from riskgraph.modules.normalization import fingerprint
    from riskgraph.shared.vocabulary import ScannerName, SourceType

    def findings(line: int) -> list:  # type: ignore[type-arg]
        routes = [
            _route("/doc/<id>", "GET", "guarded", line=line, guards=("login_required",)),
            _route("/doc/<id>", "DELETE", "none_found", line=line + 5),
        ]
        ids = {routes[0].key: ("r0", "g0"), routes[1].key: ("r1",)}
        return issue_findings(analyze(routes).issues, ids)

    [f] = findings(10)
    assert f.scanner is ScannerName.RISKGRAPH and f.source_type is SourceType.AUTHZ
    assert f.rule_id == "authz:inconsistent" and f.cwe_ids == ("CWE-862",)
    assert f.location.resource == "DELETE /doc/<id>" and f.location.line_start == 15
    # the route's own evidence first, then the guarded sibling's route evidence
    assert f.attrs["evidence_ids"] == ["r1", "r0"] and f.attrs["assurance"] == "inferred"
    [moved] = findings(40)
    assert fingerprint(f, "acme/x") == fingerprint(moved, "acme/x")


def test_thousands_of_routes_on_one_resource_stay_linear() -> None:
    import time

    routes = [
        _route(
            "/api/<id>",
            "DELETE" if i % 2 else "GET",
            "guarded" if i % 3 else "none_found",
            line=i,
            guards=("login_required",) if i % 3 else (),
        )
        for i in range(5000)
    ]
    start = time.perf_counter()
    issues = analyze(routes).issues
    assert time.perf_counter() - start < 2.0
    assert len(issues) == 1667  # every unguarded one: most of its siblings are guarded


def test_the_largest_hostile_policy_is_bounded() -> None:
    """A repository's own manifest is untrusted input: 200 rules (the cap) that all start
    with ** against 5,000 routes (the inventory's cap) take seconds, not forever."""
    import time

    rules = [
        AuthzRule(path="/" + "/".join(["**", "a"] * 4) + f"/x{i}", require="authenticated")
        for i in range(200)
    ]
    routes = [_route(f"/a/b/a/c/a/d/a/e/{i}", "GET", line=i) for i in range(5000)]
    start = time.perf_counter()
    analyze(routes, rules)
    assert time.perf_counter() - start < 15.0
