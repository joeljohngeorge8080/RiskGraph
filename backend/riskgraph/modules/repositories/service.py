"""Repository input validation and registration (threats T-03, T-05).

The clone URL is *rebuilt* from a validated owner/name, never passed through from the
request, so nothing a user types can reach ``git`` except two strictly-matched names.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from riskgraph.modules.repositories.models import Repository
from riskgraph.shared.problems import UnprocessableEntity

_OWNER = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
_NAME = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
_REF = re.compile(r"^[\w][\w./-]{0,254}$")
MAX_URL_LENGTH = 300


class InvalidRepositoryUrl(UnprocessableEntity):
    slug = "invalid-repository-url"
    title = "Invalid repository URL"


class InvalidRef(UnprocessableEntity):
    slug = "invalid-ref"
    title = "Invalid git ref"


def parse_github_url(value: str) -> tuple[str, str]:
    """``https://github.com/<owner>/<name>[.git][/]`` → (owner, name). Nothing else."""
    if not value or len(value) > MAX_URL_LENGTH or any(c.isspace() for c in value):
        raise InvalidRepositoryUrl("Use a URL like https://github.com/owner/repo")
    parts = urlsplit(value)
    try:
        port = parts.port
    except ValueError as exc:
        raise InvalidRepositoryUrl("Malformed URL") from exc
    host = (parts.hostname or "").lower()
    if parts.scheme != "https":
        raise InvalidRepositoryUrl("Only https:// URLs are accepted")
    if host not in ("github.com", "www.github.com") or parts.username or parts.password:
        raise InvalidRepositoryUrl("Only public github.com repositories are supported")
    if port not in (None, 443) or parts.query or parts.fragment:
        raise InvalidRepositoryUrl("Remove the port, query string or fragment")
    segments = parts.path.strip("/").split("/")
    if len(segments) != 2:
        raise InvalidRepositoryUrl("Use a URL like https://github.com/owner/repo")
    owner, name = segments
    name = name.removesuffix(".git")
    if not _OWNER.match(owner) or not _NAME.match(name) or name in (".", ".."):
        raise InvalidRepositoryUrl("Owner or repository name contains invalid characters")
    return owner, name


def validate_ref(ref: str | None) -> str:
    """Empty means the default branch. Branch and tag names only (no SHAs, no options)."""
    if not ref:
        return ""
    if not _REF.match(ref) or ".." in ref or ref.endswith((".lock", "/", ".")) or "//" in ref:
        raise InvalidRef("Use a branch or tag name, e.g. main or v1.2.0")
    return ref


def clone_url_for(owner: str, name: str) -> str:
    return f"https://github.com/{owner}/{name}.git"


def get_or_create(session: Session, owner: str, name: str) -> Repository:
    full_name = f"{owner}/{name}".lower()
    stmt = (
        insert(Repository)
        .values(
            provider="github",
            owner=owner,
            name=name,
            full_name=full_name,
            clone_url=clone_url_for(owner, name),
        )
        .on_conflict_do_nothing(index_elements=["full_name"])
    )
    session.execute(stmt)
    repo = session.scalars(select(Repository).where(Repository.full_name == full_name)).one()
    return repo
