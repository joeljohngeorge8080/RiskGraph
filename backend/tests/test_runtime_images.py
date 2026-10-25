"""Container image references named by a repository (expansion X2)."""

from __future__ import annotations

from pathlib import Path

import pytest
from riskgraph.modules.context import extract_iac
from riskgraph.modules.runtime import dockerfile_refs, image_refs, parse_ref


@pytest.mark.parametrize(
    ("text", "registry", "repository", "tag", "digest"),
    [
        ("python:3.8-slim", "docker.io", "library/python", "3.8-slim", None),
        ("node", "docker.io", "library/node", "latest", None),
        ("bitnami/redis:7", "docker.io", "bitnami/redis", "7", None),
        ("index.docker.io/library/nginx:1.25", "docker.io", "library/nginx", "1.25", None),
        ("ghcr.io/acme/api:v2", "ghcr.io", "acme/api", "v2", None),
        ("localhost:5000/app:dev", "localhost:5000", "app", "dev", None),
        ("python@sha256:" + "a" * 64, "docker.io", "library/python", None, "sha256:" + "a" * 64),
    ],
)
def test_references_are_normalised(
    text: str, registry: str, repository: str, tag: str | None, digest: str | None
) -> None:
    ref = parse_ref(text, "Dockerfile", 1, "dockerfile")
    assert (ref.registry, ref.repository, ref.tag, ref.digest) == (
        registry,
        repository,
        tag,
        digest,
    )


def test_only_public_registries_are_allowed() -> None:
    assert parse_ref("python:3.12", "f", 1, "dockerfile").allowed
    assert parse_ref("ghcr.io/a/b:1", "f", 1, "dockerfile").allowed
    internal = parse_ref("registry.corp.local:5000/app:1", "f", 1, "compose")
    assert not internal.allowed and "allow-list" in (internal.reason or "")
    assert not parse_ref("localhost:5000/app", "f", 1, "compose").allowed
    assert not parse_ref("10.0.0.5/app:1", "f", 1, "compose").allowed


def test_unresolved_or_malformed_references_are_never_scanned() -> None:
    for text in ("python:${VERSION}", "$BASE", "py thon:3", "a" * 300, "UPPER/case:1"):
        ref = parse_ref(text, "f", 1, "dockerfile")
        assert not ref.allowed and ref.reason, text


def _write(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def test_dockerfile_from_lines_with_stages_flags_and_continuations(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "api/Dockerfile",
        "# syntax=docker/dockerfile:1\n"
        "ARG BASE=python:3.12\n"
        "FROM --platform=linux/amd64 python:3.8-slim AS build\n"
        "RUN pip install -r requirements.txt\n"
        "from \\\n  node:14 as assets\n"
        "FROM build\n"  # an earlier stage, not an image
        "FROM scratch\n"
        "FROM ${BASE}\n",
    )
    _write(tmp_path, "web/app.Dockerfile", "FROM nginx:1.25-alpine\n")
    _write(tmp_path, "node_modules/x/Dockerfile", "FROM evil:1\n")  # skipped directory
    refs = dockerfile_refs(tmp_path)
    got = [(r.file, r.line, r.raw, r.allowed) for r in refs]
    assert got == [
        ("api/Dockerfile", 3, "python:3.8-slim", True),
        ("api/Dockerfile", 5, "node:14", True),
        ("api/Dockerfile", 9, "${BASE}", False),
        ("web/app.Dockerfile", 1, "nginx:1.25-alpine", True),
    ]


def test_compose_and_kubernetes_images_join_dockerfile_ones(tmp_path: Path) -> None:
    _write(tmp_path, "Dockerfile", "FROM python:3.8-slim\n")
    _write(
        tmp_path,
        "docker-compose.yml",
        "services:\n  api: {build: .}\n  cache: {image: 'redis:7'}\n  db: {image: postgres:16}\n",
    )
    _write(
        tmp_path,
        "deploy/app.yaml",
        "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: app}\nspec:\n  template:\n"
        "    spec:\n      initContainers: [{name: init, image: 'busybox:1.36'}]\n"
        "      containers: [{name: app, image: 'python:3.8-slim'}]\n",
    )
    refs = image_refs(tmp_path, extract_iac(tmp_path).assets)
    by = {r.canonical: r for r in refs}
    assert set(by) == {
        "docker.io/library/python:3.8-slim",
        "docker.io/library/redis:7",
        "docker.io/library/postgres:16",
        "docker.io/library/busybox:1.36",
    }
    # deduplicated, first declaration kept: the Dockerfile (it sorts first)
    assert by["docker.io/library/python:3.8-slim"].origin == "dockerfile"
    assert by["docker.io/library/redis:7"].origin == "compose"
    assert by["docker.io/library/busybox:1.36"].origin == "kubernetes"


def test_huge_or_binary_dockerfiles_are_skipped(tmp_path: Path) -> None:
    _write(tmp_path, "Dockerfile", "FROM python:3.12\n" + "#" * (600 * 1024))
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / "Dockerfile").write_bytes(b"\xff\xfeFROM x\n")
    assert dockerfile_refs(tmp_path) == []
