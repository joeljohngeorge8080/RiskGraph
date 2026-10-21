from __future__ import annotations

import pytest
from riskgraph.modules.repositories import (
    InvalidRef,
    InvalidRepositoryUrl,
    clone_url_for,
    parse_github_url,
    validate_ref,
)


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://github.com/bridgecrewio/terragoat", ("bridgecrewio", "terragoat")),
        ("https://github.com/OWASP/NodeGoat.git", ("OWASP", "NodeGoat")),
        ("https://www.github.com/a-b/c.d_e/", ("a-b", "c.d_e")),
        ("https://github.com:443/o/r", ("o", "r")),
    ],
)
def test_accepts_public_github_urls(url: str, expected: tuple[str, str]) -> None:
    assert parse_github_url(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/o/r",  # not https
        "git@github.com:o/r.git",  # ssh
        "ssh://git@github.com/o/r",
        "file:///etc/passwd",
        "https://github.com.evil.com/o/r",  # look-alike host
        "https://evil.com/github.com/o/r",
        "https://user:pw@github.com/o/r",  # credentials
        "https://token@github.com/o/r",
        "https://github.com:22/o/r",  # port
        "https://140.82.112.3/o/r",  # IP literal
        "https://github.com/o/r/tree/main",  # extra path
        "https://github.com/o",  # missing name
        "https://github.com/o/r?x=1",
        "https://github.com/o/r#frag",
        "https://github.com/-o/r",  # owner cannot start with '-'
        "https://github.com/o/..",
        "https://github.com/o/r r",
        "https://github.com/" + "o" * 50 + "/r",
        "",
    ],
)
def test_rejects_everything_else(url: str) -> None:
    with pytest.raises(InvalidRepositoryUrl):
        parse_github_url(url)


def test_clone_url_is_rebuilt_not_passed_through() -> None:
    owner, name = parse_github_url("https://www.github.com/Owner/Repo.git/")
    assert clone_url_for(owner, name) == "https://github.com/Owner/Repo.git"


@pytest.mark.parametrize("ref", ["main", "release/1.2", "v1.0.0", "feature_x-y", None, ""])
def test_accepts_branch_and_tag_names(ref: str | None) -> None:
    assert validate_ref(ref) == (ref or "")


@pytest.mark.parametrize(
    "ref",
    ["-u", "--upload-pack=touch /tmp/x", "a..b", "main.lock", "a//b", "a b", "x;rm", "../x", "a/"],
)
def test_rejects_option_like_or_malformed_refs(ref: str) -> None:
    with pytest.raises(InvalidRef):
        validate_ref(ref)
